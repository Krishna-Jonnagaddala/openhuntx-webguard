"""Slice 11 stabilization audit: new, cross-cutting regression tests for
security-boundary properties that existing test files proved only
partially or indirectly (per the audit's own findings) --

1. Bearer/basic-auth material is never sent to an off-origin URL,
   proven through the real call chain every active detector actually
   uses (`active_detection.issue_probe`/`fetch_same_origin_page`), not
   just asserted about `apply_authentication` in isolation (which has
   no origin check of its own -- same-origin enforcement is the
   caller's job, and every real caller performs it before
   authentication is ever applied).
2. DNS-rebinding independence: a request connects to the address
   resolved and pinned at target-validation time, never re-resolving
   the hostname at request time -- proven by showing `fetch_once` never
   calls DNS resolution itself and always connects to
   `target.resolved_addresses`, even when a "live" DNS lookup would
   return something else.
3. No authentication secret ever appears in a crawl checkpoint's
   serialized state.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from webguard_scanner import (
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    AuthenticationMaterial,
    CrawlPolicy,
    DetectionCandidate,
    FetchPolicy,
    ValidatedTarget,
    crawl_same_origin,
)
from webguard_scanner.active_detection import fetch_same_origin_page, issue_probe
from webguard_scanner.safe_http import SafeHttpResponse


def _target(url: str = "http://example.com/") -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme="http",
        hostname="example.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
    )


class _RecordingConnection:
    def __init__(self) -> None:
        self.sock = None
        self._context = None
        self.received_headers: list[tuple[str, str]] = []

    def putrequest(self, method, path, **kwargs) -> None:
        return None

    def putheader(self, name, value) -> None:
        self.received_headers.append((name, value))

    def endheaders(self, message_body=None) -> None:
        return None

    def getresponse(self):
        from email.message import Message

        class _Response:
            status = 200
            reason = "OK"
            msg = Message()

            def getheaders(self):
                return []

            def read(self, amount=-1):
                return b""

        return _Response()

    def close(self) -> None:
        return None


class BearerTokenNeverSentOffOriginTests(unittest.TestCase):
    """Requirement 13: no cross-target bearer leakage -- proven through
    the actual call chain, since `apply_authentication` itself performs
    no origin check (that is deliberately the caller's responsibility,
    identically to how every other candidate/page fetch enforces
    same-origin before doing anything else)."""

    def test_issue_probe_never_connects_for_an_off_origin_candidate(self) -> None:
        connection = _RecordingConnection()
        material = AuthenticationMaterial(bearer_token="super-secret-bearer-token")
        candidate = DetectionCandidate(
            url="http://attacker.example/steal", parameter="q"
        )
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            with self.assertRaises(ActiveDetectionError) as caught:
                issue_probe(
                    _target(),
                    candidate,
                    "payload",
                    policy=ActiveDetectionPolicy(),
                    authentication_material=material,
                )
        self.assertEqual(caught.exception.code, "candidate_origin_mismatch")
        # No connection was ever attempted, so the bearer token was
        # never at risk of being transmitted anywhere.
        self.assertEqual(connection.received_headers, [])

    def test_fetch_same_origin_page_never_connects_for_an_off_origin_url(
        self,
    ) -> None:
        connection = _RecordingConnection()
        material = AuthenticationMaterial(bearer_token="super-secret-bearer-token")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            with self.assertRaises(ActiveDetectionError) as caught:
                fetch_same_origin_page(
                    _target(),
                    "http://attacker.example/steal",
                    policy=ActiveDetectionPolicy(),
                    authentication_material=material,
                )
        self.assertEqual(caught.exception.code, "candidate_origin_mismatch")
        self.assertEqual(connection.received_headers, [])

    def test_same_origin_request_does_carry_the_bearer_token(self) -> None:
        # Sanity check that the material *is* applied for the intended,
        # same-origin case -- the off-origin tests above prove absence,
        # this proves the mechanism isn't just silently broken.
        connection = _RecordingConnection()
        material = AuthenticationMaterial(bearer_token="super-secret-bearer-token")
        candidate = DetectionCandidate(url="http://example.com/search", parameter="q")
        with patch(
            "webguard_scanner.safe_http._make_connection", return_value=connection
        ):
            issue_probe(
                _target(),
                candidate,
                "payload",
                policy=ActiveDetectionPolicy(),
                authentication_material=material,
            )
        self.assertIn(
            ("Authorization", "Bearer super-secret-bearer-token"),
            connection.received_headers,
        )


class DnsRebindingIndependenceTests(unittest.TestCase):
    """Requirement 12: a request must connect to the address resolved
    and pinned at target-validation time, never a fresh DNS lookup
    performed at request time -- this is what actually defeats DNS
    rebinding, independent of any single adversarial-DNS-scenario test."""

    def test_fetch_once_never_performs_its_own_dns_resolution(self) -> None:
        import socket

        from webguard_scanner.safe_http import fetch_once

        pinned_target = _target()
        self.assertEqual(pinned_target.resolved_addresses, ("93.184.216.34",))

        connection = _RecordingConnection()
        addresses_used: list[str] = []

        def recording_make_connection(target, address, policy):
            addresses_used.append(address)
            return connection

        def dns_should_never_be_called(*args, **kwargs):
            raise AssertionError(
                "fetch_once must never perform its own DNS resolution -- "
                "it must only ever connect to target.resolved_addresses, "
                "which were pinned once at target-validation time."
            )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            side_effect=recording_make_connection,
        ), patch.object(
            socket, "getaddrinfo", side_effect=dns_should_never_be_called
        ):
            fetch_once(pinned_target, method="GET", policy=FetchPolicy())

        # Connects to the address pinned at validation time -- even
        # though a "live" DNS lookup for example.com could, in a real
        # DNS-rebinding attack, now resolve somewhere entirely
        # different (e.g. an internal address). fetch_once has no way
        # to observe that, by construction.
        self.assertEqual(addresses_used, ["93.184.216.34"])

    def test_second_request_against_the_same_pinned_target_reuses_the_pin(
        self,
    ) -> None:
        # Simulates the exact rebinding scenario: even if the
        # authoritative DNS record changed to a private/internal
        # address *between* two requests against the same already-
        # validated target, both requests still connect only to the
        # address resolved and pinned once, at validation time.
        from webguard_scanner.safe_http import fetch_once

        pinned_target = _target()
        addresses_used: list[str] = []

        def recording_make_connection(target, address, policy):
            addresses_used.append(address)
            return _RecordingConnection()

        with patch(
            "webguard_scanner.safe_http._make_connection",
            side_effect=recording_make_connection,
        ):
            fetch_once(pinned_target, method="GET", policy=FetchPolicy())
            fetch_once(pinned_target, method="GET", policy=FetchPolicy())

        self.assertEqual(addresses_used, ["93.184.216.34", "93.184.216.34"])


class CheckpointCredentialAbsenceTests(unittest.TestCase):
    """Requirement 13: no credentials in crawl checkpoints."""

    def test_authenticated_crawl_checkpoint_never_contains_the_bearer_token(
        self,
    ) -> None:
        secret_token = "super-secret-checkpoint-bearer-token"
        checkpoints = []

        def responder():
            return SafeHttpResponse(
                status=200,
                reason="OK",
                headers=(("Content-Type", "text/html"),),
                body=b"<html><body>ok</body></html>",
                connected_address="93.184.216.34",
                elapsed_milliseconds=1,
            )

        with patch("webguard_scanner.crawler.fetch_once", side_effect=lambda *a, **k: responder()):
            crawl_same_origin(
                _target(),
                crawl_policy=CrawlPolicy(maximum_pages=1, minimum_delay_seconds=0),
                authentication_material=AuthenticationMaterial(
                    bearer_token=secret_token
                ),
                on_checkpoint=checkpoints.append,
            )

        self.assertTrue(checkpoints)
        for state in checkpoints:
            serialized = repr(state)
            self.assertNotIn(secret_token, serialized)


if __name__ == "__main__":
    unittest.main()
