"""P1-B1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
core tests for `webguard_api.structured_logging` -- the JSON-lines
operational-telemetry module. Proves the closed allowlist (name AND
value shape), thread-safety of the underlying stdlib `logging`
machinery under concurrent emitters, and that nothing sensitive-shaped
can reach the output regardless of what a caller passes.
"""

from __future__ import annotations

import io
import json
import logging
import threading
import unittest

import webguard_api.structured_logging as structured_logging
from webguard_api.structured_logging import (
    configure_structured_logging,
    exception_fields,
    log_event,
)


def _lines(buf: io.StringIO) -> list[dict]:
    text = buf.getvalue()
    return [json.loads(line) for line in text.splitlines() if line]


class CoreEmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)

    def test_1_one_event_produces_one_valid_json_line(self) -> None:
        log_event(event="worker_started", level="info", worker_id="w-1")
        lines = self.buf.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["event"], "worker_started")
        self.assertEqual(parsed["service"], "worker")
        self.assertEqual(parsed["level"], "info")

    def test_2_concurrent_threads_do_not_interleave_or_corrupt_lines(self) -> None:
        errors: list[Exception] = []

        def emit(n: int) -> None:
            try:
                for i in range(50):
                    log_event(event="job_claimed", level="info", job_id=f"job-{n}-{i}")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=emit, args=(n,)) for n in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        text = self.buf.getvalue()
        lines = [line for line in text.splitlines() if line]
        self.assertEqual(len(lines), 20 * 50)
        # test_3: every line parses independently -- if any line were
        # corrupted/interleaved by a race, json.loads would raise here.
        for line in lines:
            json.loads(line)

    def test_3_every_output_line_parses_independently(self) -> None:
        for i in range(10):
            log_event(event="job_claimed", level="info", job_id=f"job-{i}")
        for line in self.buf.getvalue().splitlines():
            parsed = json.loads(line)  # must not raise
            self.assertIsInstance(parsed, dict)

    def test_4_unknown_field_names_are_dropped(self) -> None:
        log_event(event="worker_started", level="info", totally_unapproved_field="value", worker_id="w-1")
        parsed = _lines(self.buf)[0]
        self.assertNotIn("totally_unapproved_field", parsed)
        self.assertEqual(parsed["worker_id"], "w-1")

    def test_5_unsafe_field_values_are_dropped(self) -> None:
        # status_code must be an int in [100, 599]; a string, a float,
        # and an out-of-range int must all be dropped, not coerced.
        log_event(event="request_completed", level="info", status_code="200")
        self.assertNotIn("status_code", _lines(self.buf)[0])
        self.buf.truncate(0); self.buf.seek(0)

        log_event(event="request_completed", level="info", status_code=99999)
        self.assertNotIn("status_code", _lines(self.buf)[0])
        self.buf.truncate(0); self.buf.seek(0)

        # request_id must match the safe-token shape -- a value with
        # embedded whitespace/newline is dropped.
        log_event(event="request_completed", level="info", request_id="abc\ndef")
        self.assertNotIn("request_id", _lines(self.buf)[0])

    def test_6_authorization_header_value_cannot_appear(self) -> None:
        # A deliberately fake-shaped credential (not matching any real
        # vendor secret pattern) -- this test proves allowlist
        # redaction, not secret-scanner evasion.
        fake_credential = "fake-not-a-real-bearer-credential-0000000000"
        log_event(event="request_completed", level="info", Authorization=f"Bearer {fake_credential}")
        parsed = _lines(self.buf)[0]
        self.assertNotIn("Authorization", parsed)
        self.assertNotIn(fake_credential, json.dumps(parsed))

    def test_7_cookie_value_cannot_appear(self) -> None:
        log_event(event="request_completed", level="info", Cookie="session=abc123; other=xyz")
        parsed = _lines(self.buf)[0]
        self.assertNotIn("Cookie", parsed)
        self.assertNotIn("abc123", json.dumps(parsed))

    def test_8_callback_token_cannot_appear(self) -> None:
        log_event(event="callback_observation_persistence_exhausted", level="error", callback_token="tok_" + "x" * 40)
        parsed = _lines(self.buf)[0]
        self.assertNotIn("callback_token", parsed)
        self.assertNotIn("tok_" + "x" * 40, json.dumps(parsed))

    def test_9_api_token_cannot_appear(self) -> None:
        log_event(event="request_completed", level="info", api_token="wgt_" + "y" * 40)
        parsed = _lines(self.buf)[0]
        self.assertNotIn("api_token", parsed)
        self.assertNotIn("wgt_" + "y" * 40, json.dumps(parsed))

    def test_10_database_dsn_and_password_cannot_appear(self) -> None:
        log_event(
            event="database_outage_detected", level="warning",
            database_dsn="postgresql://user:hunter2@host:5432/db",
            database_password="hunter2",
        )
        parsed = _lines(self.buf)[0]
        self.assertNotIn("database_dsn", parsed)
        self.assertNotIn("database_password", parsed)
        self.assertNotIn("hunter2", json.dumps(parsed))

    def test_11_arbitrary_exception_str_or_repr_is_never_emitted(self) -> None:
        try:
            raise ValueError("sensitive detail: user@example.com password=hunter2")
        except ValueError as exc:
            log_event(event="request_failed", level="error", **exception_fields(exc))
        parsed = _lines(self.buf)[0]
        dumped = json.dumps(parsed)
        self.assertNotIn("sensitive detail", dumped)
        self.assertNotIn("hunter2", dumped)
        self.assertEqual(parsed["exception_type"], "ValueError")

    def test_12_absolute_source_paths_are_never_emitted(self) -> None:
        try:
            raise RuntimeError("boom")
        except RuntimeError as exc:
            fields = exception_fields(exc)
        # source_module must be the frame's __name__ (dotted, no
        # leading "/"), never a filesystem path.
        self.assertNotIn("/", fields.get("source_module", ""))
        self.assertFalse(fields.get("source_module", "").startswith("/"))
        log_event(event="request_failed", level="error", **fields)
        parsed = _lines(self.buf)[0]
        for value in parsed.values():
            if isinstance(value, str):
                self.assertFalse(value.startswith("/Users/"))
                self.assertFalse(value.startswith("/home/"))

    def test_13_newlines_and_control_characters_cannot_inject_a_second_line(self) -> None:
        log_event(event="request_completed", level="info", request_id="abc\ndef\r\nHTTP/1.1 200")
        lines = [line for line in self.buf.getvalue().splitlines() if line]
        # The malicious-shaped value must have been dropped entirely
        # (fails the safe-token regex) -- exactly one line, not two.
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertNotIn("request_id", parsed)

    def test_14_timestamp_is_timezone_aware_utc(self) -> None:
        log_event(event="worker_started", level="info")
        parsed = _lines(self.buf)[0]
        self.assertTrue(parsed["timestamp"].endswith("Z"))
        # Round-trips through fromisoformat once "Z" is normalized.
        from datetime import datetime

        parsed_dt = datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))
        self.assertIsNotNone(parsed_dt.tzinfo)

    def test_15_event_service_level_validation(self) -> None:
        with self.assertRaises(ValueError):
            log_event(event="worker_started", level="not_a_real_level")
        with self.assertRaises(ValueError):
            log_event(event="has spaces, invalid", level="info")
        with self.assertRaises(ValueError):
            configure_structured_logging(service="not_a_real_service", stream=self.buf)


class UnconfiguredLogEventIsASafeNoOpTests(unittest.TestCase):
    """Regression proof: every existing worker/scheduler/etc. test in
    this repository constructs those classes directly, never through
    the CLI's own `configure_structured_logging()` call -- log_event()
    must never raise merely because logging was never configured, or
    it would break the entire pre-existing test suite the moment any
    instrumented call site fires."""

    def setUp(self) -> None:
        self._saved_service = structured_logging._configured_service
        structured_logging._configured_service = None

    def tearDown(self) -> None:
        structured_logging._configured_service = self._saved_service

    def test_log_event_before_configure_does_not_raise(self) -> None:
        log_event(event="job_claimed", level="info", job_id="job-1")  # must not raise


class MissingFunctionNameShapeTests(unittest.TestCase):
    """Regression proof for the module-level co_name edge case found
    during P1-B1 development: Python's own synthetic frame names
    (`<module>`, `<lambda>`, ...) must be preserved, not silently
    dropped by an overly strict identifier check."""

    def test_module_level_exception_preserves_source_function(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="worker", stream=buf)
        try:
            exec("raise ValueError('x')", {"__name__": "some.module"})
        except ValueError as exc:
            fields = exception_fields(exc)
        self.assertEqual(fields.get("source_function"), "<module>")
        log_event(event="request_failed", level="error", **fields)
        parsed = json.loads(buf.getvalue().splitlines()[0])
        self.assertEqual(parsed["source_function"], "<module>")


class OutputBoundaryBypassTests(unittest.TestCase):
    """The output boundary (`_JsonLineFormatter`/`_StructuredStreamHandler`)
    must itself refuse anything unsafe, independent of `log_event()` --
    proven here by going around `log_event()` entirely and submitting
    records directly to `logging.getLogger("webguard.structured")`, the
    way any other code in the process technically could. `log_event()`
    remains the intended, convenient entry point (and still validates
    its own inputs up front, raising on a clearly-broken call -- see
    `CoreEmissionTests.test_15`), but the redaction guarantee must not
    depend on every caller going through it."""

    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="worker", stream=self.buf)
        self.raw_logger = logging.getLogger("webguard.structured")

    def test_a_direct_call_with_authorization_field_is_stripped(self) -> None:
        fake_credential = "fake-not-a-real-bearer-credential-1111111111"
        self.raw_logger.info({"service": "worker", "event": "job_claimed", "Authorization": f"Bearer {fake_credential}"})
        lines = _lines(self.buf)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("Authorization", lines[0])
        self.assertNotIn(fake_credential, json.dumps(lines[0]))

    def test_b_direct_call_with_cookie_field_is_stripped(self) -> None:
        self.raw_logger.info({"service": "worker", "event": "job_claimed", "Cookie": "session=deadbeef"})
        lines = _lines(self.buf)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("Cookie", lines[0])
        self.assertNotIn("deadbeef", json.dumps(lines[0]))

    def test_c_direct_call_with_fake_callback_token_is_stripped(self) -> None:
        token = "tok_" + "z" * 40
        self.raw_logger.info({"service": "worker", "event": "callback_observation_persistence_exhausted", "callback_token": token})
        lines = _lines(self.buf)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("callback_token", lines[0])
        self.assertNotIn(token, json.dumps(lines[0]))

    def test_d_direct_call_with_unknown_field_is_dropped(self) -> None:
        self.raw_logger.info({"service": "worker", "event": "job_claimed", "totally_unapproved_field": "value"})
        lines = _lines(self.buf)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("totally_unapproved_field", lines[0])

    def test_e_direct_call_with_control_characters_is_dropped(self) -> None:
        self.raw_logger.info({"service": "worker", "event": "job_claimed", "request_id": "abc\ndef\r\nHTTP/1.1 200"})
        lines = _lines(self.buf)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("request_id", lines[0])

    def test_f_direct_call_with_object_whose_str_leaks_a_secret_never_stringified(self) -> None:
        class _LeakySecret:
            def __str__(self) -> str:  # pragma: no cover - must never run
                return "SECRET-SHOULD-NEVER-APPEAR"

            def __repr__(self) -> str:  # pragma: no cover - must never run
                return "SECRET-SHOULD-NEVER-APPEAR"

        self.raw_logger.info(_LeakySecret())  # not a dict at all -- must be dropped, not stringified
        raw_output = self.buf.getvalue()
        self.assertEqual(raw_output, "")
        self.assertNotIn("SECRET-SHOULD-NEVER-APPEAR", raw_output)

    def test_g_direct_call_with_plain_string_message_is_dropped_without_raising(self) -> None:
        self.raw_logger.info("a plain %s-style message", "old")  # must not raise, must not emit
        self.assertEqual(self.buf.getvalue(), "")

    def test_record_missing_service_and_event_entirely_is_dropped(self) -> None:
        self.raw_logger.info({"some_random_key": "some_random_value"})
        self.assertEqual(self.buf.getvalue(), "")

    def test_record_with_unrecognized_log_level_is_dropped(self) -> None:
        # DEBUG/CRITICAL are not in LEVELS -- a caller using them directly
        # (bypassing log_event's own {info,warning,error} contract) must
        # not produce output the rest of this module treats as valid.
        self.raw_logger.critical({"service": "worker", "event": "job_claimed"})
        self.assertEqual(self.buf.getvalue(), "")


class CombinedServeIdentityTests(unittest.TestCase):
    """The combined `serve` process configures structured logging once,
    as `service="api"` -- but its embedded worker/scheduler threads
    must not have their events mislabeled `api` as a result. Each call
    site outside http_api.py passes its own `service=` explicitly
    (worker.py -> "worker", scheduler.py -> "scheduler", etc.), which
    `log_event()` uses instead of the configured default -- proven here
    without any thread-local state, just an explicit per-call
    argument."""

    def setUp(self) -> None:
        self.buf = io.StringIO()
        configure_structured_logging(service="api", stream=self.buf)

    def test_embedded_worker_event_is_labeled_worker_not_api(self) -> None:
        log_event(service="worker", event="job_claimed", level="info", worker_id="w-1", job_id="j-1")
        parsed = _lines(self.buf)[0]
        self.assertEqual(parsed["service"], "worker")

    def test_embedded_scheduler_event_is_labeled_scheduler_not_api(self) -> None:
        log_event(service="scheduler", event="schedule_materialized", level="info", schedule_id="s-1", job_id="j-1")
        parsed = _lines(self.buf)[0]
        self.assertEqual(parsed["service"], "scheduler")

    def test_apis_own_event_is_still_labeled_api(self) -> None:
        log_event(service="api", event="request_completed", level="info", status_code=200)
        parsed = _lines(self.buf)[0]
        self.assertEqual(parsed["service"], "api")

    def test_call_without_explicit_service_falls_back_to_configured_default(self) -> None:
        # Matches mail.py/service.py's own call sites, which correctly
        # have no fixed service identity of their own.
        log_event(event="mail_delivery_completed", level="info", attempt=1)
        parsed = _lines(self.buf)[0]
        self.assertEqual(parsed["service"], "api")

    def test_invalid_explicit_service_override_raises(self) -> None:
        with self.assertRaises(ValueError):
            log_event(service="not_a_real_service", event="job_claimed", level="info")


class StandaloneModeIdentityTests(unittest.TestCase):
    """Standalone single-service processes (`worker`/`scheduler` CLI
    commands) must retain their own correct identity too -- the
    combined-mode fix must not have broken the simple case."""

    def test_standalone_worker_process_retains_worker_identity(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="worker", stream=buf)
        log_event(service="worker", event="worker_started", level="info", worker_id="w-1")
        parsed = _lines(buf)[0]
        self.assertEqual(parsed["service"], "worker")

    def test_standalone_scheduler_process_retains_scheduler_identity(self) -> None:
        buf = io.StringIO()
        configure_structured_logging(service="scheduler", stream=buf)
        log_event(service="scheduler", event="scheduler_started", level="info")
        parsed = _lines(buf)[0]
        self.assertEqual(parsed["service"], "scheduler")


class DevelopmentMailProviderNeverLogsEvenWithRootLoggingEnabledTests(unittest.TestCase):
    """P1-B1 pre-commit correction: `DevelopmentMailProvider.send()`'s
    original stdlib logger call -- which wrote the full message body,
    including a real one-time token, to the application log -- has been
    removed entirely, not merely quieted. This is the strengthened
    proof a pre-commit review correctly demanded: the previous version
    of this test only established "the current root-logger
    configuration happens to suppress INFO," which is not a security
    property (any future change enabling logging would have silently
    reopened the leak). This version deliberately configures the ROOT
    logger to DEBUG -- the most permissive level, and the same
    mechanism any future code could use to turn logging on -- with its
    own capturing handler, then proves a marked fake one-time token
    embedded in the mail body cannot appear on that captured root
    output, on stdout, on stderr, or in the structured JSON stream --
    and that the structured stream is untouched entirely, matching
    `send()` being a documented no-op."""

    MARKER = "FAKE-ONE-TIME-TOKEN-MARKER-9f3ac2b7"

    def setUp(self) -> None:
        self.root_logger = logging.getLogger()
        self._saved_root_level = self.root_logger.level
        self._saved_root_handlers = list(self.root_logger.handlers)
        for handler in self._saved_root_handlers:
            self.root_logger.removeHandler(handler)
        self.root_capture = io.StringIO()
        self.root_handler = logging.StreamHandler(self.root_capture)
        self.root_logger.addHandler(self.root_handler)
        self.root_logger.setLevel(logging.DEBUG)

    def tearDown(self) -> None:
        self.root_logger.removeHandler(self.root_handler)
        for handler in self._saved_root_handlers:
            self.root_logger.addHandler(handler)
        self.root_logger.setLevel(self._saved_root_level)

    def test_marked_token_never_appears_anywhere_even_with_root_logging_at_debug(self) -> None:
        import contextlib

        from webguard_api.mail import DevelopmentMailProvider

        structured_buf = io.StringIO()
        configure_structured_logging(service="api", stream=structured_buf)

        stdout_buf, stderr_buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
            DevelopmentMailProvider().send(
                to="a@b.com",
                subject="Reset your password",
                body=f"Click here to reset: https://example.test/reset?token={self.MARKER}",
                category="reset",
            )

        self.assertNotIn(self.MARKER, self.root_capture.getvalue())
        self.assertNotIn(self.MARKER, stdout_buf.getvalue())
        self.assertNotIn(self.MARKER, stderr_buf.getvalue())
        self.assertNotIn(self.MARKER, structured_buf.getvalue())
        # Not just "no marker" -- the structured stream must be
        # completely untouched by this call.
        self.assertEqual(structured_buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
