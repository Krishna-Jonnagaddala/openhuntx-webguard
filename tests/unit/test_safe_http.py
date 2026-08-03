"""Unit tests for the connection-time HTTP safety layer."""

from __future__ import annotations

import unittest
from email.message import Message
from unittest.mock import patch

from webguard_scanner import (
    FetchPolicy,
    SafeRequestError,
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


class FakeConnection:
    """Minimal HTTPConnection replacement for deterministic tests."""

    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request = None
        self.headers: list[tuple[str, str]] = []
        self.closed = False

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


if __name__ == "__main__":
    unittest.main()
