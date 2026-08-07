"""TrustScan runtime safety enforcement and signed safety-receipt generation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from threading import Lock
from typing import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from webguard_contracts import TrustScanSafetyReceiptClaims
from webguard_scanner import SafeHttpResponse, ValidatedTarget

from .permits import PersistedTrustScanPermit, TrustScanPermitError, TrustScanSigner


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrustScanRuntimeSafetyError(RuntimeError):
    """Controlled fail-closed runtime safety decision."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class TrustScanRuntimeSafetyEngine:
    """Enforce one permit at every outbound request boundary.

    The engine is deliberately conservative. It cannot prove that a target was
    unaffected by testing; it records what WebGuard enforced and observed.
    """

    CIRCUIT_BREAKER_CONSECUTIVE_EVENTS = 3

    def __init__(
        self,
        *,
        permit: PersistedTrustScanPermit,
        signer: TrustScanSigner,
        organization_id: str,
        job_id: str,
        scan_id: str,
        target: str,
        revalidate: Callable[[], None],
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.permit = permit
        self.signer = signer
        self.organization_id = organization_id
        self.job_id = job_id
        self.scan_id = scan_id
        self.target = target
        self.revalidate = revalidate
        self.clock = clock
        self.monotonic = monotonic
        self.sleeper = sleeper
        self.started_at = clock()
        self._root_origin = self._origin(target)
        self._lock = Lock()
        self._last_permitted_at: float | None = None
        self._in_flight = 0
        self._consecutive_protective_events = 0
        self._circuit_open = False
        self.requests_attempted = 0
        self.requests_permitted = 0
        self.requests_blocked = 0
        self.responses_429 = 0
        self.responses_5xx = 0
        self.request_errors = 0
        self.throttles = 0
        self.throttle_seconds = 0.0
        self.circuit_breaker_activations = 0
        self.scope_violations = 0
        self.permit_revalidations = 0
        self.peak_concurrency = 0

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        if parsed.hostname is None or parsed.scheme not in {"http", "https"}:
            raise TrustScanRuntimeSafetyError(
                "trustscan_runtime_target_invalid",
                "Runtime request target is not a canonical HTTP or HTTPS URL.",
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise TrustScanRuntimeSafetyError(
                "trustscan_runtime_target_invalid",
                "Runtime request target contains an invalid port.",
            ) from exc
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return parsed.scheme.lower(), parsed.hostname.lower(), port

    def _block(self, code: str, message: str, *, scope_violation: bool = False) -> None:
        self.requests_blocked += 1
        if scope_violation:
            self.scope_violations += 1
        raise TrustScanRuntimeSafetyError(code, message)

    def _revalidate(self) -> None:
        self.permit_revalidations += 1
        try:
            self.revalidate()
        except TrustScanPermitError as exc:
            self._block(exc.code, exc.message)

    def before_request(self, target: ValidatedTarget, method: str) -> None:
        """Fail closed before an outbound HTTP request is allowed to begin."""

        with self._lock:
            self.requests_attempted += 1
            claims = self.permit.permit.claims
            normalised_method = method.upper()
            if self._circuit_open:
                self._block(
                    "trustscan_runtime_circuit_open",
                    "TrustScan runtime circuit breaker is open; no further request is permitted.",
                )
            if self._origin(target.normalised_url) != self._root_origin:
                self._block(
                    "trustscan_runtime_scope_violation",
                    "Runtime request target left the permit-authorised origin.",
                    scope_violation=True,
                )
            if normalised_method not in claims.allowed_http_methods:
                self._block(
                    "trustscan_runtime_method_not_allowed",
                    "Runtime HTTP method is not allowed by the TrustScan permit.",
                )
            if self.requests_permitted >= claims.maximum_request_attempts:
                self._block(
                    "trustscan_runtime_request_budget_exhausted",
                    "TrustScan permit request-attempt budget is exhausted.",
                )
            if self._in_flight >= claims.maximum_concurrency:
                self._block(
                    "trustscan_runtime_concurrency_exceeded",
                    "Runtime request concurrency would exceed the TrustScan permit.",
                )

            self._revalidate()

            minimum_interval = 1.0 / claims.maximum_requests_per_second
            now_mono = self.monotonic()
            if self._last_permitted_at is not None:
                delay = minimum_interval - (now_mono - self._last_permitted_at)
                if delay > 0:
                    self.throttles += 1
                    self.throttle_seconds += delay
                    self.sleeper(delay)
                    # Permission may change while throttled. Check again immediately
                    # before allowing network activity.
                    self._revalidate()
                    now_mono = self.monotonic()

            self._last_permitted_at = now_mono
            self.requests_permitted += 1
            self._in_flight += 1
            self.peak_concurrency = max(self.peak_concurrency, self._in_flight)

    def after_request(
        self,
        _target: ValidatedTarget,
        _method: str,
        response: SafeHttpResponse | None,
        error_code: str | None,
    ) -> None:
        """Record bounded target-health signals after one request attempt."""

        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            protective_event = False
            if error_code is not None:
                self.request_errors += 1
                protective_event = True
            elif response is not None:
                if response.status == 429:
                    self.responses_429 += 1
                    protective_event = True
                if 500 <= response.status <= 599:
                    self.responses_5xx += 1
                    protective_event = True

            if protective_event:
                self._consecutive_protective_events += 1
            else:
                self._consecutive_protective_events = 0

            if (
                not self._circuit_open
                and self._consecutive_protective_events
                >= self.CIRCUIT_BREAKER_CONSECUTIVE_EVENTS
            ):
                self._circuit_open = True
                self.circuit_breaker_activations += 1

    def signed_receipt(self, *, termination_reason: str):
        """Build and sign the final non-secret runtime safety receipt."""

        claims = self.permit.permit.claims
        receipt_claims = TrustScanSafetyReceiptClaims(
            receipt_id=str(uuid4()),
            permit_id=claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
            organization_id=self.organization_id,
            job_id=self.job_id,
            scan_id=self.scan_id,
            target=self.target,
            started_at=self.started_at,
            completed_at=self.clock(),
            maximum_request_attempts=claims.maximum_request_attempts,
            maximum_requests_per_second=claims.maximum_requests_per_second,
            maximum_concurrency=claims.maximum_concurrency,
            requests_attempted=self.requests_attempted,
            requests_permitted=self.requests_permitted,
            requests_blocked=self.requests_blocked,
            responses_429=self.responses_429,
            responses_5xx=self.responses_5xx,
            request_errors=self.request_errors,
            throttles=self.throttles,
            throttle_seconds=self.throttle_seconds,
            circuit_breaker_activations=self.circuit_breaker_activations,
            scope_violations=self.scope_violations,
            permit_revalidations=self.permit_revalidations,
            peak_concurrency=self.peak_concurrency,
            termination_reason=termination_reason,
            safety_policy_respected=self.peak_concurrency <= claims.maximum_concurrency,
        )
        return self.signer.sign_safety_receipt(receipt_claims)


__all__ = ["TrustScanRuntimeSafetyEngine", "TrustScanRuntimeSafetyError"]
