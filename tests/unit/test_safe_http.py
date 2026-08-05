"""Unit tests for the connection-time HTTP safety layer."""

from __future__ import annotations

import ssl
import unittest
from datetime import datetime, timezone
from email.message import Message
from unittest.mock import patch

from webguard_scanner import (
    FetchPolicy,
    SafeRequestError,
    TlsConnectionInfo,
    ValidatedTarget,
    fetch_once,
)


class FakeResponse:
    """Minimal HTTPResponse replacement for deterministic tests."""

    def __init__(
        self,
        status: int = 200,
        reason: str = "OK",
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"response",
    ) -> None:
        self.status = status
        self.reason = reason
        self._headers = (
            headers
            if headers is not None
            else [("Content-Length", str(len(body)))]
        )
        self._body = body
        self._position = 0
        self.msg = Message()

        for name, value in self._headers:
            self.msg.add_header(name, value)

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position

        chunk = self._body[
            self._position:self._position + amount
        ]
        self._position += len(chunk)

        return chunk


class FakeTlsContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True


class FakeTlsSocket:
    def __init__(
        self,
        *,
        protocol: str = "TLSv1.3",
        cipher: tuple[str, str, int] = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        ),
        certificate: dict[str, object] | None = None,
        certificate_der: bytes = b"certificate-der",
        chain_length: int | None = 3,
    ) -> None:
        self._protocol = protocol
        self._cipher = cipher
        self._certificate = certificate or {
            "notBefore": "Mar 15 00:00:00 2026 GMT",
            "notAfter": "Oct  1 00:00:00 2026 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        self._certificate_der = certificate_der
        self._chain_length = chain_length

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self._certificate_der
        return self._certificate

    def version(self) -> str:
        return self._protocol

    def cipher(self) -> tuple[str, str, int]:
        return self._cipher

    def get_verified_chain(self):
        if self._chain_length is None:
            return None
        return [object()] * self._chain_length


class FakeConnection:
    """Minimal HTTPConnection replacement for deterministic tests."""

    def __init__(
        self,
        response: FakeResponse,
        *,
        tls_socket: object | None = None,
        tls_context: object | None = None,
    ) -> None:
        self.response = response
        self.request = None
        self.headers: list[tuple[str, str]] = []
        self.closed = False
        self.sock = tls_socket if tls_socket is not None else FakeTlsSocket()
        self._context = (
            tls_context
            if tls_context is not None
            else FakeTlsContext()
        )

    def putrequest(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> None:
        self.request = (method, path, kwargs)

    def putheader(
        self,
        name: str,
        value: str,
    ) -> None:
        self.headers.append((name, value))

    def endheaders(self) -> None:
        return None

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def create_target(
    normalised_url: str = "https://example.com/",
    scheme: str = "https",
    hostname: str = "example.com",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=normalised_url,
        normalised_url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


class SafeHttpTests(unittest.TestCase):
    """Verify request pinning and response limits."""

    def test_connects_to_ip_and_sends_hostname(self) -> None:
        connection = FakeConnection(FakeResponse())

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ) as make_connection:
            response = fetch_once(create_target())

        self.assertEqual(
            make_connection.call_args.args[1],
            "93.184.216.34",
        )
        self.assertIn(
            ("Host", "example.com"),
            connection.headers,
        )
        self.assertEqual(
            response.connected_address,
            "93.184.216.34",
        )
        self.assertIsInstance(response.tls, TlsConnectionInfo)
        self.assertEqual(response.tls.protocol, "TLSv1.3")
        self.assertEqual(response.tls.cipher_bits, 256)
        self.assertEqual(response.tls.verified_chain_length, 3)
        self.assertTrue(response.tls.certificate_verified)
        self.assertTrue(response.tls.hostname_validated)
        self.assertTrue(connection.closed)

    def test_non_default_port_appears_in_host(self) -> None:
        connection = FakeConnection(FakeResponse())

        custom_target = create_target(
            normalised_url="https://example.com:8443/",
            port=8443,
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            fetch_once(custom_target)

        self.assertIn(
            ("Host", "example.com:8443"),
            connection.headers,
        )

    def test_blocks_redirect_response(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                status=302,
                reason="Found",
                headers=[
                    ("Location", "http://127.0.0.1/")
                ],
                body=b"",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "redirect_blocked",
        )
        self.assertTrue(connection.closed)

    def test_rejects_declared_oversized_body(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[("Content-Length", "100")],
                body=b"",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(
                    create_target(),
                    policy=FetchPolicy(
                        maximum_body_bytes=10
                    ),
                )

        self.assertEqual(
            context.exception.code,
            "response_body_too_large",
        )

    def test_rejects_undeclared_oversized_body(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[],
                body=b"01234567890",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(
                    create_target(),
                    policy=FetchPolicy(
                        maximum_body_bytes=10
                    ),
                )

        self.assertEqual(
            context.exception.code,
            "response_body_too_large",
        )

    def test_rejects_conflicting_content_lengths(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[
                    ("Content-Length", "5"),
                    ("Content-Length", "7"),
                ],
                body=b"hello",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "content_length_ambiguous",
        )

    def test_rejects_unapproved_method(self) -> None:
        with self.assertRaises(
            SafeRequestError
        ) as context:
            fetch_once(
                create_target(),
                method="POST",
            )

        self.assertEqual(
            context.exception.code,
            "method_not_allowed",
        )


    def test_http_response_does_not_contain_tls_metadata(self) -> None:
        connection = FakeConnection(FakeResponse())
        http_target = create_target(
            normalised_url="http://example.com/",
            scheme="http",
            port=80,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(http_target)
        self.assertIsNone(response.tls)

    def test_tls_metadata_is_captured_before_response_closes_socket(
        self,
    ) -> None:
        connection = FakeConnection(FakeResponse())
        original_getresponse = connection.getresponse

        def getresponse_and_clear_socket():
            result = original_getresponse()
            connection.sock = None
            return result

        connection.getresponse = getresponse_and_clear_socket  # type: ignore[method-assign]

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())

        self.assertIsInstance(response.tls, TlsConnectionInfo)

    def test_tls_metadata_contains_bounded_public_certificate_facts(self) -> None:
        connection = FakeConnection(FakeResponse())
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())
        assert response.tls is not None
        self.assertEqual(
            response.tls.server_hostname,
            "example.com",
        )
        self.assertEqual(
            response.tls.subject_alt_names,
            ("DNS:example.com",),
        )
        self.assertEqual(
            response.tls.certificate_not_before,
            datetime(2026, 3, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(len(response.tls.certificate_sha256), 64)
        self.assertNotIn("certificate-der", repr(response.tls))

    def test_unavailable_verified_chain_method_is_nonfatal(self) -> None:
        socket_without_chain = FakeTlsSocket()
        socket_without_chain.get_verified_chain = None  # type: ignore[method-assign]
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket_without_chain,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())
        assert response.tls is not None
        self.assertIsNone(response.tls.verified_chain_length)

    def test_rejects_https_connection_without_tls_socket(self) -> None:
        connection = FakeConnection(FakeResponse())
        connection.sock = None
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_metadata_unavailable",
        )

    def test_rejects_insecure_tls_context(self) -> None:
        class InsecureContext:
            verify_mode = ssl.CERT_NONE
            check_hostname = False

        connection = FakeConnection(
            FakeResponse(),
            tls_context=InsecureContext(),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_context_insecure",
        )

    def test_rejects_invalid_certificate_time_metadata(self) -> None:
        socket = FakeTlsSocket(
            certificate={
                "notBefore": "not-a-date",
                "notAfter": "Oct  1 00:00:00 2026 GMT",
                "subjectAltName": (("DNS", "example.com"),),
            }
        )
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_certificate_metadata_invalid",
        )

    def test_rejects_excessive_subject_alternative_names(self) -> None:
        names = tuple(
            ("DNS", f"host-{index}.example.com")
            for index in range(257)
        )
        socket = FakeTlsSocket(
            certificate={
                "notBefore": "Mar 15 00:00:00 2026 GMT",
                "notAfter": "Oct  1 00:00:00 2026 GMT",
                "subjectAltName": names,
            }
        )
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_certificate_metadata_too_large",
        )


if __name__ == "__main__":
    unittest.main()
