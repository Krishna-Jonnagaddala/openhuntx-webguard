from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from webguard_api import (
    ApiTokenAuthenticator,
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


class Phase2RateLimitAuthenticationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)

        auth_dir = root / "authorizations"
        write_authorization(auth_dir)

        self.store = ScanJobStore(root / "jobs.sqlite3")

        self.identity, self.context, self.token = (
            create_identity_fixture(self.store.path)
        )

        self.service = WebGuardJobService(
            store=self.store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=self.identity,
            clock=lambda: NOW,
        )

        self.limiter = FixedWindowRateLimiter(
            requests=1,
            window_seconds=60,
        )

        self.server = create_server(
            "127.0.0.1",
            0,
            self.service,
            authenticator=ApiTokenAuthenticator(self.identity),
            rate_limiter=self.limiter,
            maximum_request_bytes=1024,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )

        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, authorization: str) -> tuple[int, dict]:
        connection = http.client.HTTPConnection(
            self.host,
            self.port,
            timeout=2,
        )

        try:
            connection.request(
                "GET",
                "/v1/me",
                headers={
                    "Authorization": authorization,
                },
            )

            response = connection.getresponse()
            payload = json.loads(response.read())

            return response.status, payload
        finally:
            connection.close()

    def wrong_secret_tokens(self) -> tuple[str, str]:
        prefix, token_id, secret = self.token.split("_", 2)

        replacements = [
            value
            for value in ("A", "B", "C")
            if value != secret[0]
        ]

        first_secret = replacements[0] + secret[1:]
        second_secret = replacements[1] + secret[1:]

        return (
            f"{prefix}_{token_id}_{first_secret}",
            f"{prefix}_{token_id}_{second_secret}",
        )

    def test_repeated_wrong_secret_attempts_are_rate_limited(
        self,
    ) -> None:
        first_wrong_token, second_wrong_token = (
            self.wrong_secret_tokens()
        )

        self.assertNotEqual(
            first_wrong_token,
            second_wrong_token,
        )

        self.assertEqual(
            first_wrong_token.split("_", 2)[1],
            second_wrong_token.split("_", 2)[1],
            msg="Adversarial guesses must target the same token ID",
        )

        first_status, first_payload = self.request(
            f"Bearer {first_wrong_token}"
        )

        second_status, second_payload = self.request(
            f"Bearer {second_wrong_token}"
        )

        self.assertEqual(first_status, 401)
        self.assertEqual(
            first_payload["error"]["code"],
            "api_token_invalid",
        )

        self.assertEqual(
            second_status,
            429,
            msg=(
                "Repeated failed authentication attempts bypass the "
                "configured API rate limiter"
            ),
        )

        self.assertEqual(
            second_payload["error"]["code"],
            "rate_limit_exceeded",
        )

    def test_authenticated_rate_limit_is_scoped_per_token(
        self,
    ) -> None:
        second = self.identity.create_token(
            self.context.principal_id,
            label="phase2-second-token",
            now=NOW,
        )

        first_status, _ = self.request(
            f"Bearer {self.token}"
        )

        exhausted_status, exhausted_payload = self.request(
            f"Bearer {self.token}"
        )

        second_token_status, _ = self.request(
            f"Bearer {second.token}"
        )

        self.assertEqual(first_status, 200)

        self.assertEqual(exhausted_status, 429)
        self.assertEqual(
            exhausted_payload["error"]["code"],
            "rate_limit_exceeded",
        )

        # Current documented model is explicitly per-token.
        self.assertEqual(second_token_status, 200)


if __name__ == "__main__":
    unittest.main()
