from __future__ import annotations

import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from webguard_api import (
    AuthenticationError,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)

from tests.unit.service_test_support import (
    NOW,
    create_identity_fixture,
    write_authorization,
)


class SlowFailingAuthenticator:
    """Expose concurrent entry into expensive authentication."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

        self.first_entered = threading.Event()
        self.second_entered = threading.Event()
        self.release = threading.Event()

    def authenticate(
        self,
        authorization_headers: list[str],
        *,
        now,
    ):
        del authorization_headers, now

        with self._lock:
            self.calls += 1

            if self.calls == 1:
                self.first_entered.set()

            if self.calls >= 2:
                self.second_entered.set()

        self.release.wait(timeout=2)

        raise AuthenticationError(
            "api_token_invalid",
            "API token is invalid.",
        )


class Phase2RateLimitConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(
            root / "jobs.sqlite3"
        )

        self.identity, _, self.token = (
            create_identity_fixture(
                self.store.path
            )
        )

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(
                auth_dir
            ),
            identity=self.identity,
            clock=lambda: NOW,
        )

        self.authenticator = (
            SlowFailingAuthenticator()
        )

        self.server = create_server(
            "127.0.0.1",
            0,
            self.service,
            authenticator=self.authenticator,
            rate_limiter=FixedWindowRateLimiter(
                requests=1,
                window_seconds=60,
            ),
            maximum_request_bytes=1024,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )

        self.server_thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.server_thread.start()

        self.host, self.port = (
            self.server.server_address[:2]
        )

    def tearDown(self) -> None:
        self.authenticator.release.set()

        self.server.shutdown()
        self.server.server_close()

        self.server_thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self) -> int:
        connection = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=3,
        )

        try:
            connection.request(
                "GET",
                "/v1/me",
                headers={
                    "Authorization":
                        f"Bearer {self.token}",
                },
            )

            response = connection.getresponse()
            response.read()

            return response.status
        finally:
            connection.close()

    def test_pre_auth_limit_is_atomic_under_concurrency(
        self,
    ) -> None:
        statuses: list[int] = []
        errors: list[BaseException] = []

        def perform_request() -> None:
            try:
                statuses.append(
                    self.request()
                )
            except BaseException as exc:
                errors.append(exc)

        first = threading.Thread(
            target=perform_request
        )
        first.start()

        self.assertTrue(
            self.authenticator.first_entered.wait(
                timeout=1
            ),
            msg=(
                "First request never entered "
                "authentication."
            ),
        )

        second = threading.Thread(
            target=perform_request
        )
        second.start()

        # Under a vulnerable check-then-authenticate
        # sequence the second request also reaches
        # authentication before the first failure is
        # recorded.
        self.authenticator.second_entered.wait(
            timeout=0.5
        )

        self.authenticator.release.set()

        first.join(timeout=3)
        second.join(timeout=3)

        self.assertFalse(errors)

        self.assertEqual(
            sorted(statuses),
            [401, 429],
        )

        self.assertEqual(
            self.authenticator.calls,
            1,
            msg=(
                "Concurrent requests entered "
                "authentication before the "
                "pre-authentication rate limiter "
                "atomically reserved capacity."
            ),
        )


if __name__ == "__main__":
    unittest.main()
