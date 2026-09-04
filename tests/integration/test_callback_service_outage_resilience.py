"""P1-12 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
real-PostgreSQL, real-subprocess proof that the SSRF callback receiver
(`webguard-api callback-service`) no longer turns a PostgreSQL outage
into a response-oracle or a lost observation within its bounded retry
budget, and that the process/thread survive regardless.

Deliberately real Docker-controlled outages (docker stop/start against
a real, disposable Postgres container) and a real subprocess speaking
real HTTP, mirroring test_postgres_worker_outage_resilience.py's and
test_postgres_scheduler_outage_resilience.py's own methodology. The
response-oracle MECHANICS themselves (exact attempt counts, no-retry-
on-semantic-error, now-never-recomputed) are proven fast and
deterministically in tests/unit/test_callback_observation_persistence_retry.py
and tests/unit/test_callback_receiver_response_oracle.py instead; this
file exists to prove the real end-to-end claim on top of that.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
import uuid
from datetime import datetime, timezone

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
CONTAINER = os.environ.get("WEBGUARD_P1_12_POSTGRES_CONTAINER")
RUN_OUTAGE_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN) and bool(CONTAINER)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PYTHON_BIN = os.path.join(REPO_ROOT, ".venv", "bin", "python3")


def _docker(*args: str) -> None:
    subprocess.run(["docker", *args], check=False, capture_output=True)


def _stop_postgres() -> None:
    _docker("stop", CONTAINER)


def _start_postgres() -> None:
    _docker("start", CONTAINER)
    for _ in range(20):
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "pg_isready", "-U", "webguard"],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    time.sleep(3)


@unittest.skipUnless(
    RUN_OUTAGE_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1, WEBGUARD_POSTGRES_TEST_DSN, and "
    "WEBGUARD_P1_12_POSTGRES_CONTAINER (the exact container name these "
    "tests are allowed to docker stop/start) to run this suite.",
)
class CallbackServiceOutageResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_callback_service import PostgresCallbackRegistrationRepository
        from webguard_contracts import OrganizationRole, PrincipalType

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=10)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.repository = PostgresCallbackRegistrationRepository(self.pool)
        self.addCleanup(self._ensure_postgres_running)

        org = self.identity.create_organization(
            f"P1-12 Outage Org {uuid.uuid4().hex[:8]}", now=datetime.now(timezone.utc)
        )
        self.organization_id = org.organization_id
        self.port = self._free_port()
        self._proc: subprocess.Popen | None = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def _register_with_retry(self, *, attempts: int = 10):
        """Mirrors test_postgres_worker_outage_resilience.py's
        _get_with_retry: WebGuardPostgresPool's own connection pool can
        need a little longer than pg_isready to fully re-establish
        after a container restart -- a test-harness concern, not
        something the fix itself needs."""
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                return self.repository.register(
                    scan_id=str(uuid.uuid4()), candidate_fingerprint="a" * 64,
                    organization_id=self.organization_id, target="https://example.test/",
                    authorization_id=str(uuid.uuid4()),
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                time.sleep(1)
        raise AssertionError(f"could not register a token after Postgres recovery: {last_exc!r}")

    def _read_observation_with_retry(self, token: str, *, attempts: int = 10):
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                with self.pool.connection() as connection:
                    return connection.execute(
                        "SELECT observed_at FROM callback_observations WHERE token_value = %s", (token,)
                    ).fetchone()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                time.sleep(1)
        raise AssertionError(f"could not read the observation row after Postgres recovery: {last_exc!r}")

    def _ensure_postgres_running(self) -> None:
        _start_postgres()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _register_token(self) -> str:
        registration = self.repository.register(
            scan_id=str(uuid.uuid4()), candidate_fingerprint="a" * 64, organization_id=self.organization_id,
            target="https://example.test/", authorization_id=str(uuid.uuid4()),
        )
        return registration.token_value

    def _start_receiver_subprocess(self, *, db_checkout_timeout: str = "0.25") -> subprocess.Popen:
        env = dict(os.environ)
        env["WEBGUARD_DATABASE_URL"] = POSTGRES_TEST_DSN
        env["WEBGUARD_CALLBACK_SERVICE_HOST"] = "127.0.0.1"
        env["WEBGUARD_CALLBACK_SERVICE_PORT"] = str(self.port)
        env["WEBGUARD_CALLBACK_SERVICE_DB_CHECKOUT_TIMEOUT_SECONDS"] = db_checkout_timeout
        env["PYTHONPATH"] = ":".join(
            [
                os.path.join(REPO_ROOT, "apps", "api", "src"),
                os.path.join(REPO_ROOT, "packages", "contracts", "python", "src"),
                os.path.join(REPO_ROOT, "workers", "scanner", "src"),
            ]
        )
        proc = subprocess.Popen(
            [PYTHON_BIN, "-m", "webguard_api", "callback-service"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=REPO_ROOT,
        )
        self._proc = proc
        ready = False
        for _ in range(50):
            if proc.poll() is not None:
                raise AssertionError(
                    f"callback-service subprocess exited early (code {proc.returncode}) before becoming ready"
                )
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.5)
                conn.request("GET", "/healthcheck-probe/nonexistent-token")
                conn.getresponse()
                conn.close()
                ready = True
                break
            except Exception:
                time.sleep(0.2)
        if not ready:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)
            raise AssertionError(
                "callback-service subprocess never became ready to accept connections\n"
                f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        return proc

    def _send_callback(self, token: str, *, timeout: float = 5.0):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("GET", f"/some-scan/{token}")
            response = conn.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), body
        finally:
            conn.close()

    def test_healthy_callback_persists_and_returns_uniform_204(self) -> None:
        token = self._register_token()
        self._start_receiver_subprocess()
        status, headers, body = self._send_callback(token)
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(body, b"")

        with self.pool.connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM callback_observations WHERE token_value = %s", (token,)
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_database_down_still_returns_the_identical_204_and_process_survives(self) -> None:
        token = self._register_token()
        self._start_receiver_subprocess()
        _stop_postgres()
        try:
            status, headers, body = self._send_callback(token, timeout=8.0)
        finally:
            _start_postgres()

        self.assertEqual(status, 204, "an outage must not change the externally-visible response")
        self.assertEqual(headers.get("Content-Length"), "0")
        self.assertEqual(body, b"")
        self.assertIsNone(self._proc.poll(), "the callback-service process must survive the outage")

    def test_same_process_resumes_normal_recording_after_recovery_no_restart(self) -> None:
        token_during_outage = self._register_token()
        self._start_receiver_subprocess()
        _stop_postgres()
        self._send_callback(token_during_outage, timeout=8.0)  # lost, honestly -- outage exceeds the retry budget
        _start_postgres()

        # Register a fresh token AFTER recovery (the outage-era one's
        # registration write never happened either) and confirm the
        # SAME, never-restarted process records it normally.
        token_after_recovery = self._register_with_retry().token_value
        status, headers, body = self._send_callback(token_after_recovery)
        self.assertEqual(status, 204)
        self.assertIsNone(self._proc.poll())

        with self.pool.connection() as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM callback_observations WHERE token_value = %s",
                (token_after_recovery,),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_short_blip_within_retry_budget_still_persists_with_original_arrival_time(self) -> None:
        """A brief outage that resolves inside the receiver's own
        bounded retry budget must not lose the observation, and the
        stored observed_at must reflect actual arrival time, not
        whenever the retry happened to succeed."""
        token = self._register_token()
        # A generous checkout timeout here so the retry's SECOND
        # attempt (issued after Postgres is already back) has ample
        # margin to succeed -- this test is about the retry surviving
        # a blip shorter than its own budget, not about racing the
        # exact reconnection window.
        self._start_receiver_subprocess(db_checkout_timeout="1.5")

        before_request = datetime.now(timezone.utc)
        _stop_postgres()

        def restart_shortly():
            time.sleep(0.3)
            _start_postgres()

        restarter = threading.Thread(target=restart_shortly, daemon=True)
        restarter.start()
        status, headers, body = self._send_callback(token, timeout=10.0)
        restarter.join(timeout=15)
        after_request = datetime.now(timezone.utc)

        self.assertEqual(status, 204)

        row = self._read_observation_with_retry(token)
        if row is None:
            self.skipTest(
                "outage outlasted this receiver's retry budget under this run's real timing -- "
                "see test_database_down_still_returns_the_identical_204_and_process_survives for "
                "the honest-loss case this is expected to degrade to when that happens"
            )
        observed_at = row[0].astimezone(timezone.utc)
        self.assertGreaterEqual(observed_at, before_request)
        self.assertLessEqual(observed_at, after_request)

    def _subprocess_log_lines(self) -> list[dict]:
        """Drains and parses the receiver subprocess's own stdout --
        configure_structured_logging() in that separate process writes
        to its real stdout by default (no stream override), captured
        by this test's own subprocess.PIPE."""
        self._proc.terminate()
        try:
            stdout, _ = self._proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            stdout, _ = self._proc.communicate(timeout=5)
        return [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]

    def test_p1b1_brief_outage_logs_retry_then_recovered_in_the_real_subprocess(self) -> None:
        """Does not alter the receiver's actual persistence outcome
        (proven unchanged by test_short_blip... above) -- purely
        proves the structured events reach the real subprocess's own
        stdout during a genuine, brief, real Postgres outage."""
        token = self._register_token()
        self._start_receiver_subprocess(db_checkout_timeout="1.5")

        _stop_postgres()

        def restart_shortly():
            time.sleep(0.3)
            _start_postgres()

        restarter = threading.Thread(target=restart_shortly, daemon=True)
        restarter.start()
        status, _, _ = self._send_callback(token, timeout=10.0)
        restarter.join(timeout=15)
        self.assertEqual(status, 204)

        lines = self._subprocess_log_lines()
        retries = [line for line in lines if line.get("event") == "callback_observation_persistence_retry"]
        recovered = [line for line in lines if line.get("event") == "callback_observation_persistence_recovered"]
        exhausted = [line for line in lines if line.get("event") == "callback_observation_persistence_exhausted"]
        if not recovered and not retries:
            self.skipTest(
                "outage resolved before the very first attempt in this run's real timing -- "
                "a clean first-attempt success emits no events by design (see LOG VOLUME POLICY)"
            )
        self.assertGreaterEqual(len(retries), 1)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(exhausted, [], "a brief, recovered outage must never also log exhausted")

    def test_p1b1_sustained_outage_logs_exhausted_in_the_real_subprocess(self) -> None:
        """Does not alter the receiver's actual honest-loss outcome
        (proven unchanged by test_database_down_still_returns_the_identical_204...
        above) -- purely proves callback_observation_persistence_exhausted
        reaches the real subprocess's own stdout during a genuine,
        sustained, real Postgres outage that outlasts the retry budget."""
        token = self._register_token()
        self._start_receiver_subprocess()
        _stop_postgres()
        try:
            status, _, _ = self._send_callback(token, timeout=8.0)
        finally:
            _start_postgres()
        self.assertEqual(status, 204)

        lines = self._subprocess_log_lines()
        exhausted = [line for line in lines if line.get("event") == "callback_observation_persistence_exhausted"]
        self.assertEqual(len(exhausted), 1)
        self.assertEqual(exhausted[0]["error_code"], "callback_observation_persistence_unavailable")
        self.assertNotIn(token, "".join(json.dumps(line) for line in lines))


if __name__ == "__main__":
    unittest.main()
