"""Application service for WebGuard scan-job API operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from webguard_contracts import (
    ScanJobLoadError,
    ScanJobRequest,
    ScanJobValidationError,
    load_scan_job_submission_json,
)

from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .store import JobStoreError, ScanJobStore


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ApiServiceError(ValueError):
    """Controlled API operation failure with an HTTP status."""

    def __init__(self, code: str, message: str, *, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class WebGuardJobService:
    """Validate requests, enforce authorizations, and persist job metadata."""

    def __init__(
        self,
        *,
        store: ScanJobStore,
        authorizations: AuthorizationRepository,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.clock = clock

    def submit(self, body: bytes, *, idempotency_key: str) -> tuple[dict, bool]:
        try:
            submission = load_scan_job_submission_json(body)
        except ScanJobLoadError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        try:
            authorization = self.authorizations.get(submission.authorization_id)
        except AuthorizationRepositoryError as exc:
            status = 404 if exc.code == "authorization_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        if authorization.target != submission.target:
            raise ApiServiceError(
                "authorization_target_mismatch",
                "The requested target does not match the server-side authorization.",
                status=400,
            )
        try:
            request = ScanJobRequest(
                idempotency_key=idempotency_key,
                target=submission.target,
                authorization_id=submission.authorization_id,
                authorization_sha256=authorization.fingerprint,
                mode=submission.mode,
                submitted_at=self.clock(),
            )
        except ScanJobValidationError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        try:
            record, created = self.store.submit(request)
        except JobStoreError as exc:
            status = 409 if exc.code == "job_idempotency_conflict" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        return record.to_public_dict(), created

    def get(self, job_id: str) -> dict:
        try:
            return self.store.get(job_id).to_public_dict()
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc

    def cancel(self, job_id: str) -> dict:
        try:
            record = self.store.request_cancellation(job_id, now=self.clock())
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        return record.to_public_dict()

    def result(self, job_id: str) -> dict:
        try:
            record = self.store.get(job_id)
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        if not record.state.is_terminal:
            raise ApiServiceError(
                "job_result_not_ready",
                "The scan job has not reached a terminal state.",
                status=409,
            )
        return {
            "job_id": record.job_id,
            "state": record.state.value,
            "scan_id": record.scan_id,
            "result_status": (
                None if record.result_status is None else record.result_status.value
            ),
            "report_ref": record.report_ref,
            "audit_ref": record.audit_ref,
            "error": (
                None
                if record.error_code is None
                else {
                    "code": record.error_code,
                    "message": record.error_message,
                }
            ),
        }


__all__ = ["ApiServiceError", "WebGuardJobService"]
