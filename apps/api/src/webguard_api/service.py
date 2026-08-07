"""Authenticated organization-scoped WebGuard job API service."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from webguard_contracts import (
    AuditOutcome,
    ScanJobLoadError,
    ScanJobRequest,
    ScanJobValidationError,
    ScanScheduleLoadError,
    ScanScheduleValidationError,
    SecurityAuditEvent,
    load_scan_job_submission_json,
    load_scan_schedule_submission_json,
)

from .auth import ApiPermission, AuthContext, AuthenticationError
from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .identity import IdentityStore, IdentityStoreError
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
    """Apply RBAC, tenant isolation, authorization ownership, and auditing."""

    def __init__(
        self,
        *,
        store: ScanJobStore,
        authorizations: AuthorizationRepository,
        identity: IdentityStore,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.identity = identity
        self.clock = clock

    def _audit(
        self,
        context: AuthContext,
        *,
        request_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: AuditOutcome,
        detail_code: str | None = None,
    ) -> None:
        try:
            self.identity.record_audit_event(
                SecurityAuditEvent(
                    event_id=str(uuid4()),
                    request_id=request_id,
                    organization_id=context.organization_id,
                    principal_id=context.principal_id,
                    token_id=context.token_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    outcome=outcome,
                    occurred_at=self.clock(),
                    detail_code=detail_code,
                )
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(
                "audit_persistence_failed",
                "The security audit event could not be persisted.",
                status=500,
            ) from exc

    def _require(
        self,
        context: AuthContext,
        permission: ApiPermission,
        *,
        request_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        try:
            context.require(permission)
        except AuthenticationError as exc:
            self._audit(
                context,
                request_id=request_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=AuditOutcome.DENIED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=exc.status) from exc

    @staticmethod
    def _internal_idempotency_key(context: AuthContext, client_key: str) -> str:
        digest = hashlib.sha256(
            f"{context.organization_id}:{client_key}".encode("utf-8")
        ).hexdigest()
        return f"tenant-{digest}"

    @staticmethod
    def _public(record, context: AuthContext) -> dict:
        payload = record.to_public_dict()
        payload["organization_id"] = context.organization_id
        return payload

    def submit(
        self,
        context: AuthContext,
        body: bytes,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> tuple[dict, bool]:
        self._require(
            context,
            ApiPermission.JOB_SUBMIT,
            request_id=request_id,
            action="jobs.submit",
            resource_type="scan_job",
            resource_id="pending",
        )
        try:
            submission = load_scan_job_submission_json(body)
        except ScanJobLoadError as exc:
            self._audit(
                context,
                request_id=request_id,
                action="jobs.submit",
                resource_type="scan_job",
                resource_id="pending",
                outcome=AuditOutcome.FAILED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        if not self.identity.authorization_is_assigned(
            context.organization_id, submission.authorization_id
        ):
            self._audit(
                context,
                request_id=request_id,
                action="jobs.submit",
                resource_type="authorization",
                resource_id=submission.authorization_id,
                outcome=AuditOutcome.DENIED,
                detail_code="authorization_not_assigned",
            )
            raise ApiServiceError(
                "authorization_not_found",
                "Authorization was not found for this organization.",
                status=404,
            )
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
            submitted_at = self.clock()
            # Validate the client key before replacing it with a tenant-scoped digest.
            ScanJobRequest(
                idempotency_key=idempotency_key,
                target=submission.target,
                authorization_id=submission.authorization_id,
                authorization_sha256=authorization.fingerprint,
                mode=submission.mode,
                submitted_at=submitted_at,
            )
            request = ScanJobRequest(
                idempotency_key=self._internal_idempotency_key(context, idempotency_key),
                target=submission.target,
                authorization_id=submission.authorization_id,
                authorization_sha256=authorization.fingerprint,
                mode=submission.mode,
                submitted_at=submitted_at,
            )
        except ScanJobValidationError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        try:
            record, created = self.store.submit(
                request,
                organization_id=context.organization_id,
                submitted_by=context.principal_id,
            )
        except JobStoreError as exc:
            status = 409 if exc.code == "job_idempotency_conflict" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="jobs.submit",
            resource_type="scan_job",
            resource_id=record.job_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return self._public(record, context), created

    def get(self, context: AuthContext, job_id: str, *, request_id: str) -> dict:
        self._require(
            context,
            ApiPermission.JOB_READ,
            request_id=request_id,
            action="jobs.read",
            resource_type="scan_job",
            resource_id=job_id,
        )
        try:
            record = self.store.get_scoped(job_id, context.organization_id)
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            self._audit(
                context,
                request_id=request_id,
                action="jobs.read",
                resource_type="scan_job",
                resource_id=job_id,
                outcome=AuditOutcome.DENIED if status == 404 else AuditOutcome.FAILED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="jobs.read",
            resource_type="scan_job",
            resource_id=job_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return self._public(record, context)

    def cancel(self, context: AuthContext, job_id: str, *, request_id: str) -> dict:
        self._require(
            context,
            ApiPermission.JOB_CANCEL,
            request_id=request_id,
            action="jobs.cancel",
            resource_type="scan_job",
            resource_id=job_id,
        )
        try:
            record = self.store.request_cancellation_scoped(
                job_id, context.organization_id, now=self.clock()
            )
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="jobs.cancel",
            resource_type="scan_job",
            resource_id=job_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return self._public(record, context)

    def result(self, context: AuthContext, job_id: str, *, request_id: str) -> dict:
        self._require(
            context,
            ApiPermission.JOB_READ,
            request_id=request_id,
            action="jobs.result.read",
            resource_type="scan_job",
            resource_id=job_id,
        )
        try:
            record = self.store.get_scoped(job_id, context.organization_id)
        except JobStoreError as exc:
            status = 404 if exc.code == "job_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        if not record.state.is_terminal:
            raise ApiServiceError(
                "job_result_not_ready",
                "The scan job has not reached a terminal state.",
                status=409,
            )
        self._audit(
            context,
            request_id=request_id,
            action="jobs.result.read",
            resource_type="scan_job",
            resource_id=job_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "job_id": record.job_id,
            "organization_id": context.organization_id,
            "state": record.state.value,
            "scan_id": record.scan_id,
            "result_status": None if record.result_status is None else record.result_status.value,
            "report_ref": record.report_ref,
            "audit_ref": record.audit_ref,
            "error": None
            if record.error_code is None
            else {"code": record.error_code, "message": record.error_message},
        }

    def create_schedule(
        self,
        context: AuthContext,
        body: bytes,
        *,
        request_id: str,
    ) -> dict:
        self._require(
            context,
            ApiPermission.SCHEDULE_CREATE,
            request_id=request_id,
            action="schedules.create",
            resource_type="scan_schedule",
            resource_id="pending",
        )
        try:
            submission = load_scan_schedule_submission_json(body)
        except ScanScheduleLoadError as exc:
            self._audit(
                context,
                request_id=request_id,
                action="schedules.create",
                resource_type="scan_schedule",
                resource_id="pending",
                outcome=AuditOutcome.FAILED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        if not self.identity.authorization_is_assigned(
            context.organization_id,
            submission.authorization_id,
        ):
            raise ApiServiceError(
                "authorization_not_found",
                "Authorization was not found for this organization.",
                status=404,
            )
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
        now = self.clock()
        if submission.starts_at < now:
            raise ApiServiceError(
                "schedule_start_in_past",
                "starts_at cannot be earlier than the current service time.",
                status=400,
            )
        if submission.starts_at > now + timedelta(days=365):
            raise ApiServiceError(
                "schedule_start_too_distant",
                "starts_at cannot be more than 365 days in the future.",
                status=400,
            )
        try:
            record = self.store.create_schedule(
                organization_id=context.organization_id,
                created_by=context.principal_id,
                name=submission.name,
                target=submission.target,
                authorization_id=submission.authorization_id,
                authorization_sha256=authorization.fingerprint,
                mode=submission.mode,
                interval_seconds=submission.interval_seconds,
                starts_at=submission.starts_at,
                now=now,
            )
        except (JobStoreError, ScanScheduleValidationError) as exc:
            status = 409 if getattr(exc, "code", "") == "schedule_conflict" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="schedules.create",
            resource_type="scan_schedule",
            resource_id=record.schedule_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict()

    def list_schedules(self, context: AuthContext, *, request_id: str) -> dict:
        self._require(
            context,
            ApiPermission.SCHEDULE_READ,
            request_id=request_id,
            action="schedules.list",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        try:
            schedules = self.store.list_schedules_scoped(context.organization_id)
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        self._audit(
            context,
            request_id=request_id,
            action="schedules.list",
            resource_type="organization",
            resource_id=context.organization_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {"schedules": [schedule.to_public_dict() for schedule in schedules]}

    def get_schedule(
        self,
        context: AuthContext,
        schedule_id: str,
        *,
        request_id: str,
    ) -> dict:
        self._require(
            context,
            ApiPermission.SCHEDULE_READ,
            request_id=request_id,
            action="schedules.read",
            resource_type="scan_schedule",
            resource_id=schedule_id,
        )
        try:
            record = self.store.get_schedule_scoped(
                schedule_id,
                context.organization_id,
            )
        except JobStoreError as exc:
            status = 404 if exc.code == "schedule_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="schedules.read",
            resource_type="scan_schedule",
            resource_id=schedule_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict()

    def pause_schedule(
        self,
        context: AuthContext,
        schedule_id: str,
        *,
        request_id: str,
    ) -> dict:
        return self._update_schedule_state(
            context,
            schedule_id,
            request_id=request_id,
            action="schedules.pause",
            resume=False,
        )

    def resume_schedule(
        self,
        context: AuthContext,
        schedule_id: str,
        *,
        request_id: str,
    ) -> dict:
        return self._update_schedule_state(
            context,
            schedule_id,
            request_id=request_id,
            action="schedules.resume",
            resume=True,
        )

    def _update_schedule_state(
        self,
        context: AuthContext,
        schedule_id: str,
        *,
        request_id: str,
        action: str,
        resume: bool,
    ) -> dict:
        self._require(
            context,
            ApiPermission.SCHEDULE_UPDATE,
            request_id=request_id,
            action=action,
            resource_type="scan_schedule",
            resource_id=schedule_id,
        )
        try:
            if resume:
                record = self.store.resume_schedule_scoped(
                    schedule_id,
                    context.organization_id,
                    now=self.clock(),
                )
            else:
                record = self.store.pause_schedule_scoped(
                    schedule_id,
                    context.organization_id,
                    now=self.clock(),
                )
        except JobStoreError as exc:
            status = 404 if exc.code == "schedule_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action=action,
            resource_type="scan_schedule",
            resource_id=schedule_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict()

    def me(self, context: AuthContext, *, request_id: str) -> dict:
        self._audit(
            context,
            request_id=request_id,
            action="identity.me.read",
            resource_type="principal",
            resource_id=context.principal_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return context.to_public_dict()

    def audit_events(self, context: AuthContext, *, request_id: str) -> dict:
        self._require(
            context,
            ApiPermission.AUDIT_READ,
            request_id=request_id,
            action="audit.read",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        events = self.identity.list_audit_events(context.organization_id)
        self._audit(
            context,
            request_id=request_id,
            action="audit.read",
            resource_type="organization",
            resource_id=context.organization_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {"events": [event.to_dict() for event in events]}


__all__ = ["ApiServiceError", "WebGuardJobService"]
