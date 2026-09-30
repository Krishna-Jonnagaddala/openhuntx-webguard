"""Phase 6 adversarial coverage: connection.close() cleanup isolation.

_perform_request in safe_http.py performs one HTTP request inside a
try/finally that always calls connection.close(). Python's finally
semantics mean an exception raised while closing the socket can silently
replace whatever the try block produced -- a returned SafeHttpResponse or
an already-controlled SafeRequestError -- with the close() failure
instead. Every scenario below forces connection.close() to raise and
asserts the original outcome still reaches the caller unchanged.
"""

from __future__ import annotations

import errno
import socket
import ssl
import unittest
from unittest.mock import patch

from webguard_scanner import FetchPolicy, SafeRequestError, fetch_once
from webguard_scanner.error_taxonomy import is_retryable_error

from test_safe_http import (
    FakeConnection,
    FakeResponse,
    create_target,
)


class CloseRaisingConnection(FakeConnection):
    """FakeConnection whose close() always fails, like a reset socket."""

    def __init__(self, *args, close_exception: BaseException, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._close_exception = close_exception

    def close(self) -> None:
        self.closed = True
        raise self._close_exception


class TimeoutOnGetresponseConnection(CloseRaisingConnection):
    """Connection that times out before a response is ever produced."""

    def getresponse(self):
        raise socket.timeout("timed out")


def _close_failure() -> OSError:
    return OSError(errno.ECONNRESET, "Connection reset by peer")


class ConnectionCleanupIsolationTests(unittest.TestCase):
    """A cleanup-time close() failure must never replace the real outcome."""

    def test_close_failure_does_not_mask_policy_failure(self) -> None:
        connection = CloseRaisingConnection(
            FakeResponse(
                headers=[(f"X-{i}", "v") for i in range(200)],
            ),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "response_headers_too_many",
        )

    def test_close_failure_does_not_discard_successful_response(self) -> None:
        connection = CloseRaisingConnection(
            FakeResponse(),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())

        self.assertEqual(response.status, 200)
        self.assertTrue(connection.closed)

    def test_close_failure_does_not_mask_timeout(self) -> None:
        connection = TimeoutOnGetresponseConnection(
            FakeResponse(),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "connection_timeout",
        )

    def test_close_failure_does_not_mask_tls_failure(self) -> None:
        class InsecureContext:
            verify_mode = ssl.CERT_NONE
            check_hostname = False

        connection = CloseRaisingConnection(
            FakeResponse(),
            tls_context=InsecureContext(),
            close_exception=_close_failure(),
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

    def test_close_failure_does_not_mask_redirect_rejection(self) -> None:
        connection = CloseRaisingConnection(
            FakeResponse(
                status=302,
                reason="Found",
                headers=[("Location", "http://127.0.0.1/")],
                body=b"",
            ),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "redirect_blocked",
        )

    def test_close_failure_does_not_mask_oversized_response_rejection(
        self,
    ) -> None:
        connection = CloseRaisingConnection(
            FakeResponse(
                headers=[("Content-Length", "100")],
                body=b"",
            ),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(
                    create_target(),
                    policy=FetchPolicy(maximum_body_bytes=10),
                )

        self.assertEqual(
            context.exception.code,
            "response_body_too_large",
        )

    def test_close_failure_does_not_flip_policy_decision_to_retryable(
        self,
    ) -> None:
        """redirect_blocked is a NON_RETRYABLE policy decision. A close()
        failure must never cause the crawler's retry classifier to see it
        as retryable, regardless of which specific transport code the
        close() failure happens to map to."""

        connection = CloseRaisingConnection(
            FakeResponse(
                status=302,
                reason="Found",
                headers=[("Location", "http://127.0.0.1/")],
                body=b"",
            ),
            close_exception=_close_failure(),
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())

        self.assertEqual(context.exception.code, "redirect_blocked")
        self.assertFalse(
            is_retryable_error(
                stage="request",
                code=context.exception.code,
            )
        )


if __name__ == "__main__":
    unittest.main()
