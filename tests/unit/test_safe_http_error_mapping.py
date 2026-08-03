"""Tests for safe HTTP transport error mapping."""

from __future__ import annotations

import errno
import http.client
import socket
import ssl
import unittest
from unittest.mock import patch

from webguard_scanner import (
    SafeRequestError,
    ValidatedTarget,
    fetch_once,
)


def target(
    addresses: tuple[str, ...] = ("127.0.0.1",),
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url="http://127.0.0.1:3000/",
        normalised_url="http://127.0.0.1:3000/",
        scheme="http",
        hostname="127.0.0.1",
        port=3000,
        resolved_addresses=addresses,
    )


class SafeHttpErrorMappingTests(unittest.TestCase):
    """Verify transport failures receive stable controlled codes."""

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_timeout(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = socket.timeout(
            "timed out"
        )

        with self.assertRaisesRegex(
            SafeRequestError,
            "All approved destination addresses failed",
        ) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "connection_timeout",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_connection_refused(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = ConnectionRefusedError(
            errno.ECONNREFUSED,
            "connection refused",
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "connection_refused",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_interrupted_connection(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = ConnectionResetError(
            errno.ECONNRESET,
            "connection reset",
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "connection_interrupted",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_unreachable_network(
        self,
        perform_mock,
    ) -> None:
        unreachable_errno = getattr(
            errno,
            "EHOSTUNREACH",
            errno.ENETUNREACH,
        )
        perform_mock.side_effect = OSError(
            unreachable_errno,
            "host unreachable",
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "network_unreachable",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_certificate_verification_failure(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = (
            ssl.SSLCertVerificationError(
                1,
                "certificate verify failed",
            )
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "tls_certificate_invalid",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_tls_handshake_failure(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = ssl.SSLError(
            1,
            "TLS handshake failed",
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "tls_handshake_failed",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_maps_http_protocol_failure(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = http.client.BadStatusLine(
            "not-http"
        )

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(target())

        self.assertEqual(
            raised.exception.code,
            "http_protocol_error",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_aggregates_only_transient_failures_as_retryable(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = [
            socket.timeout("timed out"),
            ConnectionRefusedError(
                errno.ECONNREFUSED,
                "connection refused",
            ),
        ]

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(
                target(
                    (
                        "127.0.0.1",
                        "127.0.0.2",
                    )
                )
            )

        self.assertEqual(
            raised.exception.code,
            "connection_failed",
        )

    @patch(
        "webguard_scanner.safe_http._perform_request",
    )
    def test_mixed_transient_and_tls_failures_fail_closed(
        self,
        perform_mock,
    ) -> None:
        perform_mock.side_effect = [
            socket.timeout("timed out"),
            ssl.SSLError(
                1,
                "TLS handshake failed",
            ),
        ]

        with self.assertRaises(SafeRequestError) as raised:
            fetch_once(
                target(
                    (
                        "127.0.0.1",
                        "127.0.0.2",
                    )
                )
            )

        self.assertEqual(
            raised.exception.code,
            "connection_failed_mixed",
        )


if __name__ == "__main__":
    unittest.main()
