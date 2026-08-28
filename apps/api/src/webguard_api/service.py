"""Authenticated organization-scoped WebGuard job API service."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from webguard_contracts import (
    AuditOutcome,
    ScanJobLoadError,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanJobValidationError,
    ScanScheduleLoadError,
    ScanScheduleState,
    ScanScheduleValidationError,
    SecurityAuditEvent,
    TrustScanPermitClaims,
    TrustScanPermitLoadError,
    TrustScanPermitValidationError,
    load_scan_job_submission_json,
    load_scan_schedule_submission_json,
    load_trustscan_permit_submission_json,
)

from webguard_scanner.authentication import AuthenticationMaterial, SessionCookie

from .auth import ApiPermission, AuthContext, AuthenticationError
from .authentication_contexts import (
    AuthenticationContextError,
    AuthenticationContextRepository,
    AuthenticationMethod,
)
from .authorization_comparison import (
    AuthorizationComparisonError,
    AuthorizationComparisonPlanRepository,
    ResourcePairSpec,
)
from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .identity import IdentityStore, IdentityStoreError
from .pagination import PageRequest, PaginationError, SignedCursorCodec
from .permits import (
    PersistedTrustScanPermit,
    TrustScanPermitError,
    TrustScanSigner,
    validate_permit_scope,
    validate_permit_use,
)
from .store import JobStoreError, ScanJobStore


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _active_checks_audit_detail(active_checks: tuple[str, ...]) -> str | None:
    """Return a bounded, non-sensitive audit detail_code naming the
    authorized active-detector IDs, or None for a passive-only permit.

    detail_code is a strict, bounded identifier (see
    webguard_contracts.tenancy._IDENTIFIER) -- it can carry detector IDs
    (structural names, never evidence or payload content) but not an
    arbitrary structured list. Detector IDs already use dots as internal
    separators and are joined here with "_and_", which itself satisfies
    that identifier grammar.
    """

    if not active_checks:
        return None
    detail = "active_checks_" + "_and_".join(sorted(active_checks))
    if len(detail) > 128:
        return "active_checks_authorized"
    return detail


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
        cursor_codec: SignedCursorCodec | None = None,
        trustscan_signer: TrustScanSigner | None = None,
        authentication_contexts: AuthenticationContextRepository | None = None,
        authorization_comparison_plans: AuthorizationComparisonPlanRepository | None = None,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.identity = identity
        self.clock = clock
        # Optional and defaulted so every pre-Slice-7 constructor call
        # site is unaffected. A caller that needs authentication contexts
        # shared across a service and its worker/executor must pass one
        # explicitly; the default is a fresh, empty, per-instance
        # repository, which behaves as fail-closed for any context ID
        # nothing on this instance ever registered.
        self.authentication_contexts = (
            authentication_contexts
            if authentication_contexts is not None
            else AuthenticationContextRepository()
        )
        # Same rationale, same pattern, Slice 8.
        self.authorization_comparison_plans = (
            authorization_comparison_plans
            if authorization_comparison_plans is not None
            else AuthorizationComparisonPlanRepository()
        )
        try:
            key = store.cursor_signing_key() if cursor_codec is None else None
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        self.cursor_codec = (
            SignedCursorCodec(key) if cursor_codec is None else cursor_codec
        )
        try:
            permit_key = (
                store.trustscan_signing_private_key()
                if trustscan_signer is None
                else None
            )
            self.trustscan_signer = (
                TrustScanSigner(permit_key)
                if trustscan_signer is None
                else trustscan_signer
            )
        except (JobStoreError, TrustScanPermitError) as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc

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

    def _public(self, record, context: AuthContext) -> dict:
        payload = record.to_public_dict()
        payload["organization_id"] = context.organization_id
        try:
            binding = self.store.get_job_permit_binding(record.job_id)
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        payload["trustscan_permit"] = (
            None
            if binding is None
            else {"permit_id": binding[0], "permit_sha256": binding[1]}
        )
        return payload

    def _schedule_public(self, record) -> dict:
        payload = record.to_public_dict()
        try:
            binding = self.store.get_schedule_permit_binding(record.schedule_id)
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        payload["trustscan_permit"] = (
            None
            if binding is None
            else {"permit_id": binding[0], "permit_sha256": binding[1]}
        )
        return payload

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    def _decode_page(
        self,
        context: AuthContext,
        page: PageRequest,
        *,
        resource: str,
    ) -> tuple[str, str] | None:
        if page.cursor is None:
            return None
        try:
            position = self.cursor_codec.decode(
                page.cursor,
                organization_id=context.organization_id,
                resource=resource,
                filters=page.filter_map,
                now=self.clock(),
            )
        except PaginationError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        return position.ordered_at, position.resource_id

    def _next_cursor(
        self,
        context: AuthContext,
        page: PageRequest,
        *,
        resource: str,
        ordered_at: datetime,
        resource_id: str,
    ) -> str:
        try:
            return self.cursor_codec.encode(
                organization_id=context.organization_id,
                resource=resource,
                filters=page.filter_map,
                ordered_at=self._timestamp(ordered_at),
                resource_id=resource_id,
                now=self.clock(),
            )
        except PaginationError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc

    @staticmethod
    def _page_payload(limit: int, next_cursor: str | None) -> dict[str, object]:
        return {"limit": limit, "next_cursor": next_cursor}

    def trustscan_verification_key(self) -> dict[str, str]:
        """Return the public Ed25519 verification key; never expose the private seed."""

        return self.trustscan_signer.verification_key_document()

    def _permit_record(
        self, context: AuthContext, permit_id: str
    ) -> PersistedTrustScanPermit:
        try:
            return self.store.get_scan_permit_scoped(
                permit_id, context.organization_id
            )
        except JobStoreError as exc:
            status = 404 if exc.code == "trustscan_permit_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc

    @staticmethod
    def _permit_error_status(error: TrustScanPermitError) -> int:
        if error.code == "trustscan_permit_organization_mismatch":
            return 404
        if error.code in {
            "trustscan_permit_revoked",
            "trustscan_permit_pending",
            "trustscan_permit_expired",
            "trustscan_permit_mode_not_allowed",
        }:
            return 403
        return 400

    def _validate_permit_now(
        self,
        context: AuthContext,
        permit_id: str,
        *,
        authorization,
        target: str,
        mode: ScanJobMode,
    ) -> PersistedTrustScanPermit:
        record = self._permit_record(context, permit_id)
        try:
            validate_permit_use(
                record,
                signer=self.trustscan_signer,
                organization_id=context.organization_id,
                authorization=authorization,
                target=target,
                mode=mode,
                now=self.clock(),
            )
        except TrustScanPermitError as exc:
            raise ApiServiceError(
                exc.code, exc.message, status=self._permit_error_status(exc)
            ) from exc
        return record

    def issue_permit(
        self, context: AuthContext, body: bytes, *, request_id: str
    ) -> dict:
        self._require(
            context,
            ApiPermission.PERMIT_ISSUE,
            request_id=request_id,
            action="permits.issue",
            resource_type="trustscan_permit",
            resource_id="pending",
        )
        try:
            submission = load_trustscan_permit_submission_json(body)
        except TrustScanPermitLoadError as exc:
            self._audit(
                context,
                request_id=request_id,
                action="permits.issue",
                resource_type="trustscan_permit",
                resource_id="pending",
                outcome=AuditOutcome.FAILED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        if submission.active_checks:
            self._require(
                context,
                ApiPermission.PERMIT_ISSUE_ACTIVE,
                request_id=request_id,
                action="permits.issue_active",
                resource_type="trustscan_permit",
                resource_id="pending",
            )
        if submission.authentication_context_id is not None:
            self._require(
                context,
                ApiPermission.AUTHENTICATION_CONTEXT_REGISTER,
                request_id=request_id,
                action="permits.issue_authenticated",
                resource_type="trustscan_permit",
                resource_id="pending",
            )
        if submission.authorization_comparison_plan_id is not None:
            self._require(
                context,
                ApiPermission.AUTHORIZATION_COMPARISON_REGISTER,
                request_id=request_id,
                action="permits.issue_authorization_comparison",
                resource_type="trustscan_permit",
                resource_id="pending",
            )
        if not self.identity.authorization_is_assigned(
            context.organization_id, submission.authorization_id
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
        now = self.clock()
        if authorization.target != submission.target:
            raise ApiServiceError(
                "authorization_target_mismatch",
                "The requested target does not match the server-side authorization.",
                status=400,
            )
        if not authorization.issued_at <= now < authorization.expires_at:
            raise ApiServiceError(
                "authorization_not_current",
                "The underlying authorization is not currently valid.",
                status=400,
            )
        if submission.not_before < now:
            raise ApiServiceError(
                "trustscan_permit_start_in_past",
                "not_before cannot be earlier than the current service time.",
                status=400,
            )
        if submission.expires_at > authorization.expires_at:
            raise ApiServiceError(
                "trustscan_permit_exceeds_authorization",
                "TrustScan permit cannot outlive the underlying authorization.",
                status=400,
            )
        if (
            submission.maximum_request_attempts
            > authorization.limits.maximum_request_attempts
        ):
            raise ApiServiceError(
                "trustscan_permit_request_budget_too_high",
                "TrustScan request budget cannot exceed the underlying authorization.",
                status=400,
            )
        authorization_rate = 1.0 / authorization.limits.minimum_delay_seconds
        if submission.maximum_requests_per_second > authorization_rate + 1e-12:
            raise ApiServiceError(
                "trustscan_permit_rate_too_high",
                "TrustScan request rate cannot exceed the underlying authorization.",
                status=400,
            )
        if submission.authentication_context_id is not None:
            # The permit's authentication_context_id claim binds a signed
            # permit to a specific, separately-stored authentication
            # context -- never the secret material itself. Fail closed
            # unless that context already exists, is currently active,
            # and is bound to exactly this organization/target/
            # authorization; re-checked again at execution time (defense
            # in depth, same pattern as permit validation itself).
            try:
                self.authentication_contexts.require_bound(
                    submission.authentication_context_id,
                    organization_id=context.organization_id,
                    target=submission.target,
                    authorization_id=authorization.authorization_id,
                    now=now,
                )
            except AuthenticationContextError as exc:
                raise ApiServiceError(exc.code, exc.message, status=400) from exc
        if submission.authorization_comparison_plan_id is not None:
            # Mirrors the authentication_context_id binding check above,
            # plus one additional rule that is specific to comparison
            # plans: the plan's own permitted_active_check must actually
            # be requested in this submission's active_checks. A permit
            # cannot reference a comparison plan without also explicitly
            # authorizing the detector that plan exists to run --
            # referencing the plan alone must never be sufficient.
            try:
                comparison_plan = self.authorization_comparison_plans.require_bound(
                    submission.authorization_comparison_plan_id,
                    organization_id=context.organization_id,
                    target=submission.target,
                    authorization_id=authorization.authorization_id,
                    now=now,
                )
            except AuthorizationComparisonError as exc:
                raise ApiServiceError(exc.code, exc.message, status=400) from exc
            if comparison_plan.permitted_active_check not in submission.active_checks:
                raise ApiServiceError(
                    "authorization_comparison_check_not_requested",
                    "authorization_comparison_plan_id requires "
                    f"{comparison_plan.permitted_active_check!r} to also be "
                    "present in active_checks.",
                    status=400,
                )
        try:
            claims = TrustScanPermitClaims(
                permit_id=str(uuid4()),
                organization_id=context.organization_id,
                authorization_id=authorization.authorization_id,
                authorization_sha256=authorization.fingerprint,
                target=submission.target,
                issued_by=context.principal_id,
                issued_at=now,
                not_before=submission.not_before,
                expires_at=submission.expires_at,
                permitted_modes=submission.permitted_modes,
                allowed_http_methods=submission.allowed_http_methods,
                maximum_request_attempts=submission.maximum_request_attempts,
                maximum_requests_per_second=submission.maximum_requests_per_second,
                maximum_concurrency=submission.maximum_concurrency,
                active_checks=submission.active_checks,
                authentication_context_id=submission.authentication_context_id,
                authorization_comparison_plan_id=submission.authorization_comparison_plan_id,
            )
            signed = self.trustscan_signer.sign(claims)
            record = self.store.create_scan_permit(signed)
        except (TrustScanPermitValidationError, TrustScanPermitError) as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        except JobStoreError as exc:
            status = 409 if exc.code == "trustscan_permit_conflict" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        detail_code = _active_checks_audit_detail(claims.active_checks)
        if claims.authentication_context_id is not None:
            # Records that this permit was bound to authenticated scanning
            # and its structural detail_code -- never the referenced
            # context's secret material, which this audit path never even
            # has access to (only the metadata repository does).
            detail_code = (
                (detail_code + "_and_authenticated")
                if detail_code
                else "authenticated_scan_authorized"
            )
        if claims.authorization_comparison_plan_id is not None:
            detail_code = (
                (detail_code + "_and_comparison")
                if detail_code
                else "authorization_comparison_authorized"
            )
        self._audit(
            context,
            request_id=request_id,
            action="permits.issue",
            resource_type="trustscan_permit",
            resource_id=claims.permit_id,
            outcome=AuditOutcome.SUCCEEDED,
            detail_code=detail_code,
        )
        return record.to_public_dict(now=now)

    def get_permit(
        self, context: AuthContext, permit_id: str, *, request_id: str
    ) -> dict:
        self._require(
            context,
            ApiPermission.PERMIT_READ,
            request_id=request_id,
            action="permits.read",
            resource_type="trustscan_permit",
            resource_id=permit_id,
        )
        record = self._permit_record(context, permit_id)
        try:
            self.trustscan_signer.verify(record.permit)
        except TrustScanPermitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        self._audit(
            context,
            request_id=request_id,
            action="permits.read",
            resource_type="trustscan_permit",
            resource_id=permit_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict(now=self.clock())

    def revoke_permit(
        self, context: AuthContext, permit_id: str, *, request_id: str
    ) -> dict:
        self._require(
            context,
            ApiPermission.PERMIT_REVOKE,
            request_id=request_id,
            action="permits.revoke",
            resource_type="trustscan_permit",
            resource_id=permit_id,
        )
        try:
            record = self.store.revoke_scan_permit_scoped(
                permit_id,
                context.organization_id,
                revoked_by=context.principal_id,
                now=self.clock(),
            )
        except JobStoreError as exc:
            status = 404 if exc.code == "trustscan_permit_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="permits.revoke",
            resource_type="trustscan_permit",
            resource_id=permit_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict(now=self.clock())

    def register_authentication_context(
        self, context: AuthContext, body: dict, *, request_id: str
    ) -> dict:
        """Register a new authentication context: bearer token, cookie
        session, or basic-auth credentials supplied explicitly by the
        operator. Owner-only. Returns metadata only -- the caller never
        sees the secret material echoed back, even though they just
        supplied it (a write-only credential-registration pattern, the
        same principle as never returning a password after account
        creation)."""

        self._require(
            context,
            ApiPermission.AUTHENTICATION_CONTEXT_REGISTER,
            request_id=request_id,
            action="authentication_contexts.register",
            resource_type="authentication_context",
            resource_id="pending",
        )
        required = {
            "target",
            "authorization_id",
            "identity_label",
            "method",
            "expires_at",
        }
        missing = required - set(body)
        if missing:
            raise ApiServiceError(
                "authentication_context_field_missing",
                f"Missing required field {sorted(missing)[0]!r}.",
                status=400,
            )
        if not self.identity.authorization_is_assigned(
            context.organization_id, body["authorization_id"]
        ):
            raise ApiServiceError(
                "authorization_not_found",
                "Authorization was not found for this organization.",
                status=404,
            )
        try:
            authorization = self.authorizations.get(body["authorization_id"])
        except AuthorizationRepositoryError as exc:
            status = 404 if exc.code == "authorization_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        if authorization.target != body["target"]:
            raise ApiServiceError(
                "authorization_target_mismatch",
                "The requested target does not match the server-side authorization.",
                status=400,
            )
        try:
            method = AuthenticationMethod(body["method"])
        except ValueError as exc:
            raise ApiServiceError(
                "authentication_context_method_invalid",
                "method must be one of: "
                + ", ".join(m.value for m in AuthenticationMethod),
                status=400,
            ) from exc
        now = self.clock()
        try:
            expires_at = datetime.fromisoformat(
                str(body["expires_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ApiServiceError(
                "authentication_context_expiry_invalid",
                "expires_at must be an ISO-8601 timestamp.",
                status=400,
            ) from exc
        try:
            raw_cookies = body.get("cookies") or ()
            cookies = tuple(
                SessionCookie(
                    name=raw["name"],
                    value=raw["value"],
                    domain=raw["domain"],
                    port=raw["port"],
                    path=raw.get("path", "/"),
                    secure=raw.get("secure", False),
                )
                for raw in raw_cookies
            )
            secret = AuthenticationMaterial(
                bearer_token=body.get("bearer_token"),
                cookies=cookies,
                basic_username=body.get("basic_username"),
                basic_password=body.get("basic_password"),
            )
        except Exception as exc:  # noqa: BLE001 - AuthenticationError from webguard_scanner
            raise ApiServiceError(
                getattr(exc, "code", "authentication_context_secret_invalid"),
                getattr(exc, "message", "The supplied credential material is invalid."),
                status=400,
            ) from exc
        try:
            record = self.authentication_contexts.create(
                organization_id=context.organization_id,
                target=body["target"],
                authorization_id=authorization.authorization_id,
                identity_label=body["identity_label"],
                method=method,
                secret=secret,
                expires_at=expires_at,
                now=now,
            )
        except AuthenticationContextError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        self._audit(
            context,
            request_id=request_id,
            action="authentication_contexts.register",
            resource_type="authentication_context",
            resource_id=record.authentication_context_id,
            outcome=AuditOutcome.SUCCEEDED,
            detail_code=f"identity_{record.method.value}",
        )
        return record.to_public_dict(now=now)

    def revoke_authentication_context(
        self, context: AuthContext, authentication_context_id: str, *, request_id: str
    ) -> dict:
        self._require(
            context,
            ApiPermission.AUTHENTICATION_CONTEXT_REVOKE,
            request_id=request_id,
            action="authentication_contexts.revoke",
            resource_type="authentication_context",
            resource_id=authentication_context_id,
        )
        try:
            record = self.authentication_contexts.get_metadata(
                authentication_context_id
            )
            if record.organization_id != context.organization_id:
                raise AuthenticationContextError(
                    "authentication_context_not_found",
                    "No authentication context matches the requested ID.",
                )
            record = self.authentication_contexts.revoke(
                authentication_context_id, now=self.clock()
            )
        except AuthenticationContextError as exc:
            status = 404 if exc.code == "authentication_context_not_found" else 400
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="authentication_contexts.revoke",
            resource_type="authentication_context",
            resource_id=authentication_context_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict(now=self.clock())

    def register_authorization_comparison_plan(
        self, context: AuthContext, body: dict, *, request_id: str
    ) -> dict:
        """Register a new authorization-comparison plan (Slice 8): a
        reference to two already-registered authentication contexts,
        plus an explicit, operator-supplied resource scope. Owner-only.

        The two-identity requirement is enforced here, not merely
        documented: both context IDs must already exist, must both be
        ACTIVE, and must both be bound to this exact organization/
        target/authorization -- the same binding a single-identity
        authenticated permit requires, checked twice (once per
        identity).
        """

        self._require(
            context,
            ApiPermission.AUTHORIZATION_COMPARISON_REGISTER,
            request_id=request_id,
            action="authorization_comparisons.register",
            resource_type="authorization_comparison_plan",
            resource_id="pending",
        )
        required = {
            "target",
            "authorization_id",
            "primary_context_id",
            "secondary_context_id",
            "resource_scope",
            "expires_at",
        }
        missing = required - set(body)
        if missing:
            raise ApiServiceError(
                "authorization_comparison_field_missing",
                f"Missing required field {sorted(missing)[0]!r}.",
                status=400,
            )
        if not self.identity.authorization_is_assigned(
            context.organization_id, body["authorization_id"]
        ):
            raise ApiServiceError(
                "authorization_not_found",
                "Authorization was not found for this organization.",
                status=404,
            )
        try:
            authorization = self.authorizations.get(body["authorization_id"])
        except AuthorizationRepositoryError as exc:
            status = 404 if exc.code == "authorization_not_found" else 500
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        if authorization.target != body["target"]:
            raise ApiServiceError(
                "authorization_target_mismatch",
                "The requested target does not match the server-side authorization.",
                status=400,
            )
        now = self.clock()
        try:
            expires_at = datetime.fromisoformat(
                str(body["expires_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ApiServiceError(
                "authorization_comparison_expiry_invalid",
                "expires_at must be an ISO-8601 timestamp.",
                status=400,
            ) from exc

        # Requirement 3: both identities must already be registered,
        # active, and bound to this exact organization/target/
        # authorization -- checked independently for each.
        for context_id in (body["primary_context_id"], body["secondary_context_id"]):
            try:
                self.authentication_contexts.require_bound(
                    context_id,
                    organization_id=context.organization_id,
                    target=body["target"],
                    authorization_id=authorization.authorization_id,
                    now=now,
                )
            except AuthenticationContextError as exc:
                raise ApiServiceError(exc.code, exc.message, status=400) from exc

        raw_resource_scope = body["resource_scope"]
        if not isinstance(raw_resource_scope, list):
            raise ApiServiceError(
                "authorization_comparison_resource_scope_invalid",
                "resource_scope must be a JSON array.",
                status=400,
            )
        try:
            resource_scope = tuple(
                ResourcePairSpec.from_dict(item) for item in raw_resource_scope
            )
        except AuthorizationComparisonError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc

        allowed_http_methods = tuple(
            sorted(set(body.get("allowed_http_methods", ["GET"])))
        )
        enable_discovery = bool(body.get("enable_discovery", False))
        discovery_login_page_marker = str(
            body.get("discovery_login_page_marker", "") or ""
        )

        try:
            record = self.authorization_comparison_plans.create(
                organization_id=context.organization_id,
                target=body["target"],
                authorization_id=authorization.authorization_id,
                primary_context_id=body["primary_context_id"],
                secondary_context_id=body["secondary_context_id"],
                permitted_active_check="active.authorization.idor",
                allowed_http_methods=allowed_http_methods,
                resource_scope=resource_scope,
                expires_at=expires_at,
                now=now,
                enable_discovery=enable_discovery,
                discovery_login_page_marker=discovery_login_page_marker,
            )
        except AuthorizationComparisonError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc

        self._audit(
            context,
            request_id=request_id,
            action="authorization_comparisons.register",
            resource_type="authorization_comparison_plan",
            resource_id=record.comparison_plan_id,
            outcome=AuditOutcome.SUCCEEDED,
            detail_code=f"resource_pairs_{len(resource_scope)}",
        )
        return record.to_public_dict(now=now)

    def revoke_authorization_comparison_plan(
        self, context: AuthContext, comparison_plan_id: str, *, request_id: str
    ) -> dict:
        self._require(
            context,
            ApiPermission.AUTHORIZATION_COMPARISON_REVOKE,
            request_id=request_id,
            action="authorization_comparisons.revoke",
            resource_type="authorization_comparison_plan",
            resource_id=comparison_plan_id,
        )
        try:
            record = self.authorization_comparison_plans.get(comparison_plan_id)
            if record.organization_id != context.organization_id:
                raise AuthorizationComparisonError(
                    "authorization_comparison_plan_not_found",
                    "No authorization-comparison plan matches the requested ID.",
                )
            record = self.authorization_comparison_plans.revoke(
                comparison_plan_id, now=self.clock()
            )
        except AuthorizationComparisonError as exc:
            status = (
                404
                if exc.code == "authorization_comparison_plan_not_found"
                else 400
            )
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context,
            request_id=request_id,
            action="authorization_comparisons.revoke",
            resource_type="authorization_comparison_plan",
            resource_id=comparison_plan_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict(now=self.clock())

    def list_jobs(
        self,
        context: AuthContext,
        page: PageRequest,
        *,
        request_id: str,
    ) -> dict:
        self._require(
            context,
            ApiPermission.JOB_READ,
            request_id=request_id,
            action="jobs.list",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        filters = page.filter_map
        state = ScanJobState(filters["state"]) if "state" in filters else None
        mode = ScanJobMode(filters["mode"]) if "mode" in filters else None
        try:
            records, has_more = self.store.list_jobs_scoped_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="jobs"),
                state=state,
                mode=mode,
            )
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context,
                page,
                resource="jobs",
                ordered_at=last.request.submitted_at,
                resource_id=last.job_id,
            )
        self._audit(
            context,
            request_id=request_id,
            action="jobs.list",
            resource_type="organization",
            resource_id=context.organization_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "jobs": [self._public(record, context) for record in records],
            "page": self._page_payload(page.limit, next_cursor),
        }

    def submit(
        self,
        context: AuthContext,
        body: bytes,
        *,
        idempotency_key: str,
        permit_id: str,
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
        permit_record = self._validate_permit_now(
            context,
            permit_id,
            authorization=authorization,
            target=submission.target,
            mode=submission.mode,
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
                permit_id=permit_record.permit.claims.permit_id,
                permit_sha256=permit_record.permit.fingerprint,
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
        try:
            permit_binding = self.store.get_job_permit_binding(job_id)
            safety_receipt = self.store.get_job_safety_receipt(job_id)
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        return {
            "job_id": record.job_id,
            "organization_id": context.organization_id,
            "state": record.state.value,
            "scan_id": record.scan_id,
            "result_status": None if record.result_status is None else record.result_status.value,
            "report_ref": record.report_ref,
            "audit_ref": record.audit_ref,
            "trustscan_safety_receipt": (
                None
                if safety_receipt is None
                else {
                    "receipt_ref": safety_receipt[0],
                    "receipt_sha256": safety_receipt[1],
                }
            ),
            "trustscan_permit": (
                None
                if permit_binding is None
                else {
                    "permit_id": permit_binding[0],
                    "permit_sha256": permit_binding[1],
                }
            ),
            "error": None
            if record.error_code is None
            else {"code": record.error_code, "message": record.error_message},
        }

    def create_schedule(
        self,
        context: AuthContext,
        body: bytes,
        *,
        permit_id: str,
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
        permit_record = self._permit_record(context, permit_id)
        try:
            validate_permit_scope(
                permit_record,
                signer=self.trustscan_signer,
                organization_id=context.organization_id,
                authorization=authorization,
                target=submission.target,
                mode=submission.mode,
            )
        except TrustScanPermitError as exc:
            raise ApiServiceError(
                exc.code, exc.message, status=self._permit_error_status(exc)
            ) from exc
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
        permit_claims = permit_record.permit.claims
        if not permit_claims.not_before <= submission.starts_at < permit_claims.expires_at:
            raise ApiServiceError(
                "trustscan_schedule_outside_permit_window",
                "Schedule start must fall inside the TrustScan permit validity window.",
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
                permit_id=permit_record.permit.claims.permit_id,
                permit_sha256=permit_record.permit.fingerprint,
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
        return self._schedule_public(record)

    def list_schedules(
        self,
        context: AuthContext,
        page: PageRequest | None = None,
        *,
        request_id: str,
    ) -> dict:
        page = PageRequest() if page is None else page
        self._require(
            context,
            ApiPermission.SCHEDULE_READ,
            request_id=request_id,
            action="schedules.list",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        filters = page.filter_map
        state = (
            ScanScheduleState(filters["state"])
            if "state" in filters
            else None
        )
        try:
            schedules, has_more = self.store.list_schedules_scoped_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="schedules"),
                state=state,
            )
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and schedules:
            last = schedules[-1]
            next_cursor = self._next_cursor(
                context,
                page,
                resource="schedules",
                ordered_at=last.created_at,
                resource_id=last.schedule_id,
            )
        self._audit(
            context,
            request_id=request_id,
            action="schedules.list",
            resource_type="organization",
            resource_id=context.organization_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "schedules": [self._schedule_public(schedule) for schedule in schedules],
            "page": self._page_payload(page.limit, next_cursor),
        }

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
        return self._schedule_public(record)

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
        return self._schedule_public(record)

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

    def audit_events(
        self,
        context: AuthContext,
        page: PageRequest | None = None,
        *,
        request_id: str,
    ) -> dict:
        page = PageRequest() if page is None else page
        self._require(
            context,
            ApiPermission.AUDIT_READ,
            request_id=request_id,
            action="audit.read",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        filters = page.filter_map
        outcome = AuditOutcome(filters["outcome"]) if "outcome" in filters else None
        try:
            events, has_more = self.identity.list_audit_events_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="audit-events"),
                outcome=outcome,
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and events:
            last = events[-1]
            next_cursor = self._next_cursor(
                context,
                page,
                resource="audit-events",
                ordered_at=last.occurred_at,
                resource_id=last.event_id,
            )
        self._audit(
            context,
            request_id=request_id,
            action="audit.read",
            resource_type="organization",
            resource_id=context.organization_id,
            outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "events": [event.to_dict() for event in events],
            "page": self._page_payload(page.limit, next_cursor),
        }


__all__ = ["ApiServiceError", "WebGuardJobService"]
