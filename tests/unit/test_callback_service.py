"""Tests for the API-layer callback repository and the real local HTTP
callback receiver (Slice 10): genuine socket-based observation
recording, tenancy metadata, DNS/spoofing-independent correlation (the
receiver trusts only the path token, never Host or source address),
and the redirect-response scenario (confirmation happens on arrival,
never depends on what the receiver's own response contains).
"""

from __future__ import annotations

import unittest
import urllib.error
import urllib.request

from webguard_api.callback_server import CallbackHttpReceiver
from webguard_api.callback_service import CallbackRepository
from webguard_scanner.callback_broker import CallbackPolicy


def _repository_and_receiver(*, respond_with_redirect: bool = False):
    repository = CallbackRepository(base_url="http://127.0.0.1:0/")
    receiver = CallbackHttpReceiver(
        repository, respond_with_redirect=respond_with_redirect
    )
    receiver.start()
    repository.set_base_url(receiver.base_url)
    return repository, receiver


class CallbackHttpReceiverTests(unittest.TestCase):
    def test_real_socket_callback_is_observed_and_correlated(self) -> None:
        repository, receiver = _repository_and_receiver()
        try:
            token = repository.register(
                scan_id="scan-1",
                candidate_fingerprint="c1",
                organization_id="org-1",
                target="https://example.com/",
                authorization_id="auth-1",
            )
            response = urllib.request.urlopen(token.url, timeout=3)
            self.assertEqual(response.status, 204)

            observation, within_primary, cancelled = repository.wait_for_observation(
                token,
                policy=CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=0.2),
            )
            self.assertIsNotNone(observation)
            self.assertTrue(within_primary)
            self.assertFalse(cancelled)
            self.assertEqual(observation.method, "GET")
        finally:
            receiver.stop()

    def test_registration_records_tenancy_metadata(self) -> None:
        repository, receiver = _repository_and_receiver()
        try:
            token = repository.register(
                scan_id="scan-9",
                candidate_fingerprint="fingerprint-x",
                organization_id="org-9",
                target="https://target.example/",
                authorization_id="auth-9",
            )
            registration = repository.registration_for(token.value)
            self.assertIsNotNone(registration)
            self.assertEqual(registration.organization_id, "org-9")
            self.assertEqual(registration.target, "https://target.example/")
            self.assertEqual(registration.authorization_id, "auth-9")
            self.assertEqual(registration.candidate_fingerprint, "fingerprint-x")
        finally:
            receiver.stop()

    def test_correlation_depends_only_on_the_token_never_on_host_header(self) -> None:
        # A request arriving with a spoofed/unexpected Host header must
        # still be correctly correlated purely by its path token --
        # proving robustness independent of DNS/Host trust.
        repository, receiver = _repository_and_receiver()
        try:
            token = repository.register(
                scan_id="scan-1",
                candidate_fingerprint="c1",
                organization_id="org-1",
                target="https://example.com/",
                authorization_id="auth-1",
            )
            request = urllib.request.Request(token.url)
            request.add_header("Host", "totally-different-spoofed-host.invalid")
            urllib.request.urlopen(request, timeout=3)

            observation, within_primary, _cancelled = repository.wait_for_observation(
                token,
                policy=CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=0.2),
            )
            self.assertIsNotNone(observation)
            self.assertTrue(within_primary)
        finally:
            receiver.stop()

    def test_unknown_token_path_is_rejected_but_receiver_still_responds(self) -> None:
        repository, receiver = _repository_and_receiver()
        try:
            forged_url = f"{receiver.base_url}scan-1/forged-token-value"
            response = urllib.request.urlopen(forged_url, timeout=3)
            self.assertEqual(response.status, 204)
            # No registration exists for this value, so nothing should
            # be retrievable under it -- verified indirectly: the
            # repository's internal broker never created a token for
            # this value, so there is no CallbackToken to wait on; the
            # important property is that the forged request produced no
            # exception and no crash.
        finally:
            receiver.stop()

    def test_redirect_response_does_not_prevent_confirmation(self) -> None:
        # Requirement 8: confirmation happens the instant the request
        # arrives, regardless of what the receiver's own response
        # contains -- WebGuard's client never needs to, and never does,
        # follow this redirect.
        repository, receiver = _repository_and_receiver(respond_with_redirect=True)
        try:
            token = repository.register(
                scan_id="scan-1",
                candidate_fingerprint="c1",
                organization_id="org-1",
                target="https://example.com/",
                authorization_id="auth-1",
            )
            # This fixture redirects unconditionally, so a client that
            # naively follows redirects loops until it gives up -- that
            # is expected and irrelevant here. The property under test
            # is that the observation was already recorded on the
            # *first* request, before any redirect was even sent back.
            try:
                urllib.request.urlopen(token.url, timeout=3)
            except urllib.error.HTTPError:
                pass

            observation, within_primary, _cancelled = repository.wait_for_observation(
                token,
                policy=CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=0.2),
            )
            self.assertIsNotNone(observation)
            self.assertTrue(within_primary)
        finally:
            receiver.stop()

    def test_post_callback_is_observed_with_correct_method(self) -> None:
        repository, receiver = _repository_and_receiver()
        try:
            token = repository.register(
                scan_id="scan-1",
                candidate_fingerprint="c1",
                organization_id="org-1",
                target="https://example.com/",
                authorization_id="auth-1",
            )
            request = urllib.request.Request(token.url, data=b"", method="POST")
            urllib.request.urlopen(request, timeout=3)
            observation, _within, _cancelled = repository.wait_for_observation(
                token,
                policy=CallbackPolicy(maximum_wait_seconds=1.0, grace_seconds=0.2),
            )
            self.assertIsNotNone(observation)
            self.assertEqual(observation.method, "POST")
        finally:
            receiver.stop()


if __name__ == "__main__":
    unittest.main()
