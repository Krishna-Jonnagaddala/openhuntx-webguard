"""Authenticated organization-scoped WebGuard job API service."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from webguard_contracts import (
    AuditOutcome,
    OrganizationRole,
    PrincipalType,
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

from .artifact_store import ArtifactStoreError
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
from .finding_store import FindingStatus, FindingStoreError
from .identity import (
    EMAIL_VERIFICATION_TOKEN_TTL,
    INVITATION_TOKEN_TTL,
    PASSWORD_RESET_TOKEN_TTL,
    IdentityStoreError,
    IdentityTokenPurpose,
)
from .passwords import PasswordPolicyError, hash_password, needs_rehash, validate_password_policy, verify_password
from .rate_limit import RateLimitError
from .report_store import ReportStoreError
from .scan_store import ScanStoreError
from .target_verification import (
    TargetVerificationError,
    VerificationMethod,
    VerificationStatus,
    check_dns_txt_token,
    check_well_known_token,
)
from .targets import TargetRepositoryError
from .pagination import PageRequest, PaginationError, SignedCursorCodec
from .permits import (
    PersistedTrustScanPermit,
    TrustScanPermitError,
    TrustScanSigner,
    validate_permit_scope,
    validate_permit_use,
)
from .repository_contracts import IdentityRepository, JobRepository
from .store import JobStoreError
from .structured_logging import log_event


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonicalize_asset_url(url: str) -> str:
    """Normalize an empty path to "/" (so "https://x.example" and
    "https://x.example/" store identically) without imposing the
    stricter owned-target authorization contract (HTTPS-only, no
    query/fragment). _find_authorization_for_asset joins assets to
    authorizations by exact URL match, and authorization documents
    are always canonicalized this way by
    webguard_contracts.canonicalize_owned_target_url, so an asset
    stored exactly as typed would otherwise never match. Anything
    stricter than this would break the local well-known-verification
    test fixtures, which legitimately use plain-HTTP loopback URLs.
    """

    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("url must be an absolute URL with a scheme and hostname.")
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


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
        store: JobRepository,
        authorizations: AuthorizationRepository,
        identity: IdentityRepository,
        clock: Callable[[], datetime] = _utc_now,
        cursor_codec: SignedCursorCodec | None = None,
        trustscan_signer: TrustScanSigner | None = None,
        authentication_contexts: AuthenticationContextRepository | None = None,
        authorization_comparison_plans: AuthorizationComparisonPlanRepository | None = None,
        readiness_check: Callable[[], None] | None = None,
        finding_repository=None,
        scan_repository=None,
        coverage_repository=None,
        report_repository=None,
        artifact_store=None,
        targets=None,
        target_verifications=None,
        sessions=None,
        mail_provider=None,
        auth_rate_limiter=None,
        session_idle_timeout: timedelta | None = None,
        session_absolute_timeout: timedelta | None = None,
        web_app_base_url: str = "http://127.0.0.1:5173",
        module_entitlements=None,
        compliance_catalog=None,
        assertion_collections=None,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.identity = identity
        self.clock = clock
        # Slice 13: optional and defaulted to an in-memory backend so
        # every pre-Slice-13 constructor call site is unaffected --
        # local/unit/lab GET /v1/findings behavior is identical to
        # before this slice existed. Production wiring passes the same
        # `PostgresFindingRepository` instance the executor writes to,
        # so what a worker persists is immediately readable here.
        from .finding_store import InMemoryFindingRepository

        self.finding_repository = (
            finding_repository if finding_repository is not None else InMemoryFindingRepository()
        )
        # Same rationale, same pattern -- requirement 5 needs a
        # completed scan's own report_ref to register a report against.
        from .scan_store import InMemoryScanRepository

        self.scan_repository = (
            scan_repository if scan_repository is not None else InMemoryScanRepository()
        )
        # Phase 4 of the Coverage Truth Map (an API/report surface):
        # same optional/defaulted pattern as scan_repository/
        # finding_repository above. Coverage previously had no
        # in-memory backend at all (ScanJobExecutor's own
        # coverage_repository defaulted to None), so local/lab-mode
        # scans recorded nothing to read; this default makes local
        # demos populate real coverage data the same way they already
        # populate scans and findings.
        from .coverage_store import InMemoryCoverageRepository

        self.coverage_repository = (
            coverage_repository if coverage_repository is not None else InMemoryCoverageRepository()
        )
        # Slice 14 requirement 5: same optional/defaulted pattern as
        # every other repository above -- local/unit/lab behavior is
        # unaffected; production wiring passes `PostgresReportRepository`
        # and a `LocalArtifactStore`/future object-storage backend.
        from .report_store import InMemoryReportRepository

        self.report_repository = (
            report_repository if report_repository is not None else InMemoryReportRepository()
        )
        if artifact_store is None:
            from .artifact_store import LocalArtifactStore
            from pathlib import Path

            artifact_store = LocalArtifactStore(Path("scan-results/service"))
        self.artifact_store = artifact_store
        # Slice 15: assets/verification, same optional/defaulted pattern.
        from .targets import InMemoryTargetRepository
        from .target_verification import InMemoryTargetVerificationRepository

        self.targets = targets if targets is not None else InMemoryTargetRepository()
        self.target_verifications = (
            target_verifications if target_verifications is not None else InMemoryTargetVerificationRepository()
        )
        # Slice 12 requirement 14: a cheap, dependency-specific probe
        # `/ready` invokes. Defaults to a no-op, matching the honest
        # behavior of the pre-Slice-12 default deployment (a local
        # SQLite file has no separate "reachability" concern beyond the
        # process itself being up). A production caller wires this to
        # `WebGuardPostgresPool.check_connectivity` (or any other
        # backend's own equivalent) so readiness reflects the actual
        # configured persistence layer, not a hardcoded assumption
        # about which one is in use.
        self.readiness_check = readiness_check if readiness_check is not None else (lambda: None)
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
        # Slice 16: browser identity/session layer, same optional/
        # defaulted pattern as every repository above.
        from .sessions import DEFAULT_ABSOLUTE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, InMemorySessionRepository
        from .mail import DevelopmentMailProvider
        from .auth_rate_limit import InMemoryAuthRateLimiter

        self.sessions = sessions if sessions is not None else InMemorySessionRepository()
        self.mail_provider = mail_provider if mail_provider is not None else DevelopmentMailProvider()
        self.auth_rate_limiter = (
            auth_rate_limiter
            if auth_rate_limiter is not None
            else InMemoryAuthRateLimiter(max_attempts=10, window_seconds=900)
        )
        self.session_idle_timeout = session_idle_timeout or DEFAULT_IDLE_TIMEOUT
        self.session_absolute_timeout = session_absolute_timeout or DEFAULT_ABSOLUTE_TIMEOUT
        # Slice 17 requirement 1: verification/reset/invitation emails
        # now contain a real clickable link into the SPA, not a bare
        # token -- this is the SPA's own public origin the link is
        # built against. Defaulted to the local Vite dev port so every
        # pre-Slice-17 local/test call site is unaffected; production
        # wiring passes the real deployed frontend origin explicitly
        # (`ProductionServiceConfig.web_app_base_url`, fail-closed).
        self._web_app_base_url = web_app_base_url.rstrip("/")
        # Platform expansion (docs/PLATFORM_SCOPE.md): same optional/
        # defaulted pattern as every repository above. module_entitlements
        # already ships both an in-memory and a Postgres backend;
        # compliance_catalog/assertion_collections default to their own
        # in-memory backends so local/lab mode shows the real five-
        # framework placeholder catalog and can actually run a fixture
        # collection, the same "local demos populate real data"
        # precedent coverage_repository established.
        from .module_entitlements import InMemoryModuleEntitlementRepository
        from .compliance_catalog_store import InMemoryComplianceCatalogRepository
        from .assertion_collections import InMemoryAssertionCollectionRepository

        self.module_entitlements = (
            module_entitlements if module_entitlements is not None else InMemoryModuleEntitlementRepository()
        )
        self.compliance_catalog = (
            compliance_catalog if compliance_catalog is not None else InMemoryComplianceCatalogRepository()
        )
        self.assertion_collections = (
            assertion_collections if assertion_collections is not None else InMemoryAssertionCollectionRepository()
        )

    def _send_mail_best_effort(self, *, to: str, subject: str, body: str, category: str) -> None:
        """A delivery failure never fails the caller's own operation --
        the account/token this email refers to was already durably
        created before this is called, and blowing up the whole
        request over a downstream mail-provider hiccup would be worse
        than a customer occasionally needing "resend verification"
        (requirement 6). Critically, this also preserves requirement 4
        (anti-enumeration): `request_password_reset`'s response is
        identical whether the account exists, whether the send
        succeeds, or whether it fails -- a delivery failure must never
        become a second, distinguishable response shape. Only the
        failure *category* (never the vendor's own response text) is
        logged, matching requirement 20's "no vendor leakage" applied
        to server-side telemetry as well as the customer-facing API."""
        from .mail import MailDeliveryError

        try:
            self.mail_provider.send(to=to, subject=subject, body=body, category=category)
        except MailDeliveryError as exc:
            log_event(
                event="mail_delivery_failed", level="warning",
                error_code=exc.code, reason_code=exc.category,
            )

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
            # P1-C1: scoped independently inside the repository (a join
            # to scan_jobs/job_scopes, the authoritative job/organization
            # relation) -- not merely because `record` already came from
            # an org-scoped fetch.
            binding = self.store.get_job_permit_binding_scoped(
                record.job_id, context.organization_id
            )
        except JobStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        payload["trustscan_permit"] = (
            None
            if binding is None
            else {"permit_id": binding[0], "permit_sha256": binding[1]}
        )
        return payload

    def _schedule_public(self, record, context: AuthContext) -> dict:
        payload = record.to_public_dict()
        try:
            binding = self.store.get_schedule_permit_binding_scoped(
                record.schedule_id, context.organization_id
            )
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

    def readiness(self) -> tuple[bool, str]:
        """Safe-to-serve check (requirement 14): runs the configured
        `readiness_check` and reports only a boolean and a fixed,
        reviewed reason string on failure -- never the underlying
        exception's message, which could name a host, port, or schema
        detail (requirement 14: do not expose infrastructure
        topology)."""

        try:
            self.readiness_check()
        except Exception:  # noqa: BLE001 - deliberately generic, see docstring
            return False, "dependency_unavailable"
        return True, "ready"

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
                missing_authentication_endpoints=submission.missing_authentication_endpoints,
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
        if claims.missing_authentication_endpoints:
            detail_code = (
                (detail_code + "_and_missing_auth_scope")
                if detail_code
                else "missing_authentication_scope_authorized"
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
        # Slice 14 requirement 1: the in-memory (local/dev/test/lab)
        # repository holds secret material directly, keyed by context ID
        # -- an operator supplies it inline in this request, exactly as
        # every prior slice's E2E tests already do. The PostgreSQL
        # (production) repository never does; it only ever stores a
        # reference to secret material that already exists wherever the
        # configured SecretProvider resolves it from (e.g. an AWS
        # Secrets Manager secret an operator provisioned out-of-band).
        # `hasattr(..., "get_secret")` is the same local-vs-production
        # test `secret_provider.py`'s `LocalSecretProvider` already uses.
        if hasattr(self.authentication_contexts, "get_secret"):
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
        else:
            secret_reference_id = body.get("secret_reference_id")
            if not isinstance(secret_reference_id, str) or not secret_reference_id:
                raise ApiServiceError(
                    "authentication_context_secret_reference_missing",
                    "secret_reference_id is required: this deployment's authentication-context "
                    "repository does not store secret material directly. Register the secret "
                    "with the configured secret provider out-of-band and supply its reference.",
                    status=400,
                )
            for raw_field in ("bearer_token", "cookies", "basic_username", "basic_password"):
                if raw_field in body:
                    raise ApiServiceError(
                        "authentication_context_raw_secret_not_accepted",
                        f"{raw_field!r} cannot be submitted directly in this deployment; "
                        "supply secret_reference_id instead.",
                        status=400,
                    )
            try:
                record = self.authentication_contexts.create(
                    organization_id=context.organization_id,
                    target=body["target"],
                    authorization_id=authorization.authorization_id,
                    identity_label=body["identity_label"],
                    method=method,
                    secret_reference_id=secret_reference_id,
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
            # P1-C1: the organization scope is enforced inside the
            # repository's own SQL/lookup predicate (see
            # ``revoke_scoped``'s docstring), not by a Python-level
            # compare against an unscoped fetch -- a caller-supplied ID
            # belonging to another organization is indistinguishable
            # from one that never existed.
            record = self.authentication_contexts.revoke_scoped(
                authentication_context_id,
                organization_id=context.organization_id,
                now=self.clock(),
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
            # P1-C1: mirrors revoke_authentication_context's own fix --
            # organization scope is enforced inside the repository's SQL/
            # lookup predicate, not by a Python-level compare against an
            # unscoped fetch.
            record = self.authorization_comparison_plans.revoke_scoped(
                comparison_plan_id,
                organization_id=context.organization_id,
                now=self.clock(),
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

    @staticmethod
    def _finding_public_dict(finding) -> dict[str, object]:
        return {
            "finding_id": finding.finding_id,
            "organization_id": finding.organization_id,
            "scan_id": finding.scan_id,
            "fingerprint": finding.fingerprint,
            "check_id": finding.check_id,
            "scanner_version": finding.scanner_version,
            "check_version": finding.check_version,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "asset": finding.asset,
            "endpoint": finding.endpoint,
            "http_method": finding.http_method,
            "parameter": finding.parameter,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "references": list(finding.references),
            "status": finding.status.value,
            "first_seen_at": finding.first_seen_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "last_seen_at": finding.last_seen_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }

    def list_findings(
        self,
        context: AuthContext,
        page: PageRequest,
        *,
        request_id: str,
    ) -> dict:
        """Requirement 16: findings, retrieved through the existing
        `/v1/...` API surface -- the tenant-scoped signed-cursor
        pagination pattern every other list endpoint already uses
        (requirement 15)."""

        self._require(
            context,
            ApiPermission.FINDING_READ,
            request_id=request_id,
            action="findings.list",
            resource_type="organization",
            resource_id=context.organization_id,
        )
        filters = page.filter_map
        scan_id = filters.get("scan_id")
        status = FindingStatus(filters["status"]) if "status" in filters else None
        try:
            records, has_more = self.finding_repository.list_findings_scoped_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="findings"),
                scan_id=scan_id,
                status=status,
                severity=filters.get("severity"),
                cwe_id=filters.get("cwe_id"),
                asset=filters.get("asset"),
            )
        except FindingStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context, page, resource="findings", ordered_at=last.last_seen_at, resource_id=last.finding_id,
            )
        self._audit(
            context, request_id=request_id, action="findings.list",
            resource_type="organization", resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "findings": [self._finding_public_dict(record) for record in records],
            "page": self._page_payload(page.limit, next_cursor),
        }

    def get_finding(self, context: AuthContext, finding_id: str, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.FINDING_READ, request_id=request_id,
            action="findings.get", resource_type="finding", resource_id=finding_id,
        )
        try:
            record = self.finding_repository.get_finding_scoped(finding_id, organization_id=context.organization_id)
        except FindingStoreError as exc:
            self._audit(
                context, request_id=request_id, action="findings.get", resource_type="finding",
                resource_id=finding_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="findings.get", resource_type="finding",
            resource_id=finding_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._finding_public_dict(record)

    # A client may only ever request these four -- REOPENED is reached
    # exclusively via re-detection (finding_store.py's own re-detection
    # rule), never via this API, matching requirement 9's explicit
    # instruction. Rejecting it here, before it ever reaches
    # `assert_valid_transition`, gives a clearer error than "invalid
    # transition" would for a status that is not merely unreachable
    # from the current one but unreachable from *any* client request.
    _CLIENT_SETTABLE_FINDING_STATUSES = frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.RESOLVED,
        }
    )

    def update_finding_status(
        self,
        context: AuthContext,
        finding_id: str,
        body: dict,
        *,
        request_id: str,
    ) -> dict:
        """Requirement 9: CONFIRMED/FALSE_POSITIVE/ACCEPTED_RISK/RESOLVED
        only, tenant-scoped, RBAC-controlled, audited, idempotent on a
        repeated identical request. Never lets a client rewrite detector
        evidence -- only ``status`` and an optional ``reason`` are
        accepted; every other field on the finding is untouched."""

        self._require(
            context, ApiPermission.FINDING_UPDATE, request_id=request_id,
            action="findings.update_status", resource_type="finding", resource_id=finding_id,
        )
        if not isinstance(body, dict) or not isinstance(body.get("status"), str):
            raise ApiServiceError(
                "finding_status_body_invalid", "Request body must include a string status field.", status=400
            )
        try:
            new_status = FindingStatus(body["status"])
        except ValueError as exc:
            raise ApiServiceError(
                "finding_status_invalid", f"Unknown finding status: {body['status']!r}.", status=400
            ) from exc
        if new_status not in self._CLIENT_SETTABLE_FINDING_STATUSES:
            self._audit(
                context, request_id=request_id, action="findings.update_status", resource_type="finding",
                resource_id=finding_id, outcome=AuditOutcome.DENIED, detail_code="finding_status_not_client_settable",
            )
            raise ApiServiceError(
                "finding_status_not_client_settable",
                f"{new_status.value!r} cannot be set through the API; it is reached only by re-detection.",
                status=400,
            )
        reason = body.get("reason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 2000):
            raise ApiServiceError(
                "finding_status_reason_invalid", "reason must be a string of at most 2000 characters.", status=400
            )
        try:
            record = self.finding_repository.update_status(
                finding_id,
                organization_id=context.organization_id,
                new_status=new_status,
                now=self.clock(),
                reason=reason,
                changed_by=context.principal_id,
            )
        except FindingStoreError as exc:
            status = 404 if exc.code == "finding_not_found" else 409
            self._audit(
                context, request_id=request_id, action="findings.update_status", resource_type="finding",
                resource_id=finding_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context, request_id=request_id, action="findings.update_status", resource_type="finding",
            resource_id=finding_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._finding_public_dict(record)

    def list_finding_events(self, context: AuthContext, finding_id: str, *, request_id: str) -> dict:
        """Requirement 10: the append-only history a finding's current
        status alone cannot answer -- first found, latest occurrence,
        when/why/by-whom status changed, when it reopened."""

        self._require(
            context, ApiPermission.FINDING_READ, request_id=request_id,
            action="findings.list_events", resource_type="finding", resource_id=finding_id,
        )
        try:
            self.finding_repository.get_finding_scoped(finding_id, organization_id=context.organization_id)
            events = self.finding_repository.list_events_scoped(
                finding_id, organization_id=context.organization_id
            )
        except FindingStoreError as exc:
            self._audit(
                context, request_id=request_id, action="findings.list_events", resource_type="finding",
                resource_id=finding_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="findings.list_events", resource_type="finding",
            resource_id=finding_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "finding_id": finding_id,
            "events": [
                {
                    "event_id": event.event_id,
                    "previous_status": event.previous_status.value,
                    "new_status": event.new_status.value,
                    "reason": event.reason,
                    "changed_by": event.changed_by,
                    "created_at": event.created_at.astimezone(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                }
                for event in events
            ],
        }

    @staticmethod
    def _report_public_dict(report) -> dict[str, object]:
        return {
            "report_id": report.report_id,
            "organization_id": report.organization_id,
            "scan_id": report.scan_id,
            "format": report.format,
            "state": report.state,
            "report_ref": report.report_ref,
            "checksum": report.checksum,
            "created_at": report.created_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "completed_at": None
            if report.completed_at is None
            else report.completed_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }

    def create_report(self, context: AuthContext, body: dict, *, request_id: str) -> dict:
        """Requirement 5: registers the completed scan's existing report
        artifact as a first-class, durably-tracked entity -- it does not
        render a new report body (Scanner v1's reporting format is
        unchanged and frozen this slice); it persists metadata about the
        artifact the scan already produced, plus a checksum computed
        from the artifact's actual bytes via the injected
        ``ArtifactStore`` (requirement 6), never a trusted client-
        supplied value."""

        self._require(
            context, ApiPermission.REPORT_CREATE, request_id=request_id,
            action="reports.create", resource_type="report", resource_id="-",
        )
        if not isinstance(body, dict) or not isinstance(body.get("scan_id"), str):
            raise ApiServiceError(
                "report_body_invalid", "Request body must include a string scan_id field.", status=400
            )
        scan_id = body["scan_id"]
        try:
            scan = self.scan_repository.get_scan_scoped(scan_id, organization_id=context.organization_id)
        except ScanStoreError as exc:
            self._audit(
                context, request_id=request_id, action="reports.create", resource_type="scan",
                resource_id=scan_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        if scan.completed_at is None or not scan.report_ref:
            raise ApiServiceError(
                "report_scan_not_completed", "A report can only be created for a completed scan.", status=409
            )
        try:
            checksum = self.artifact_store.checksum(scan.report_ref)
        except ArtifactStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        record = self.report_repository.create_report(
            organization_id=context.organization_id,
            scan_id=scan_id,
            report_ref=scan.report_ref,
            now=self.clock(),
            format="json",
            state="completed",
            checksum=checksum,
            completed_at=self.clock(),
        )
        self._audit(
            context, request_id=request_id, action="reports.create", resource_type="report",
            resource_id=record.report_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._report_public_dict(record)

    def get_report(self, context: AuthContext, report_id: str, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.REPORT_READ, request_id=request_id,
            action="reports.get", resource_type="report", resource_id=report_id,
        )
        try:
            record = self.report_repository.get_report_scoped(report_id, organization_id=context.organization_id)
        except ReportStoreError as exc:
            self._audit(
                context, request_id=request_id, action="reports.get", resource_type="report",
                resource_id=report_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="reports.get", resource_type="report",
            resource_id=report_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._report_public_dict(record)

    def list_reports(self, context: AuthContext, page: PageRequest, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.REPORT_READ, request_id=request_id,
            action="reports.list", resource_type="organization", resource_id=context.organization_id,
        )
        filters = page.filter_map
        scan_id = filters.get("scan_id")
        try:
            records, has_more = self.report_repository.list_reports_scoped_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="reports"),
                scan_id=scan_id,
            )
        except ReportStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context, page, resource="reports", ordered_at=last.created_at, resource_id=last.report_id,
            )
        self._audit(
            context, request_id=request_id, action="reports.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "reports": [self._report_public_dict(record) for record in records],
            "page": self._page_payload(page.limit, next_cursor),
        }

    @staticmethod
    def _scan_public_dict(scan) -> dict[str, object]:
        def _ts(value):
            return None if value is None else value.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")

        return {
            "scan_id": scan.scan_id,
            "organization_id": scan.organization_id,
            "job_id": scan.job_id,
            "target": scan.target,
            "authorization_id": scan.authorization_id,
            "mode": scan.mode,
            "status": scan.status,
            "scanner_version": scan.scanner_version,
            "permit_id": scan.permit_id,
            "requested_checks": list(scan.requested_checks),
            "finding_count": scan.finding_count,
            "report_ref": scan.report_ref,
            "cancellation_requested": scan.cancellation_requested,
            "created_at": _ts(scan.created_at),
            "started_at": _ts(scan.started_at),
            "completed_at": _ts(scan.completed_at),
            "cancelled_at": _ts(scan.cancelled_at),
        }

    def list_scans(self, context: AuthContext, page: PageRequest, *, request_id: str) -> dict:
        """Requirement 11/12: scans are now a first-class listable
        resource -- previously reachable only indirectly through a
        job's own `scan_id`. Filterable by target/state, per
        requirement 12's explicit list."""

        self._require(
            context, ApiPermission.JOB_READ, request_id=request_id,
            action="scans.list", resource_type="organization", resource_id=context.organization_id,
        )
        filters = page.filter_map
        target = filters.get("target")
        status = filters.get("status")
        try:
            records, has_more = self.scan_repository.list_scans_scoped_page(
                context.organization_id,
                limit=page.limit,
                after=self._decode_page(context, page, resource="scans"),
                target=target,
                status=status,
            )
        except ScanStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context, page, resource="scans", ordered_at=last.created_at, resource_id=last.scan_id,
            )
        self._audit(
            context, request_id=request_id, action="scans.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "scans": [self._scan_public_dict(record) for record in records],
            "page": self._page_payload(page.limit, next_cursor),
        }

    def get_scan(self, context: AuthContext, scan_id: str, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.JOB_READ, request_id=request_id,
            action="scans.get", resource_type="scan", resource_id=scan_id,
        )
        try:
            record = self.scan_repository.get_scan_scoped(scan_id, organization_id=context.organization_id)
        except ScanStoreError as exc:
            self._audit(
                context, request_id=request_id, action="scans.get", resource_type="scan",
                resource_id=scan_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="scans.get", resource_type="scan",
            resource_id=scan_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._scan_public_dict(record)

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
            permit_binding = self.store.get_job_permit_binding_scoped(
                job_id, context.organization_id
            )
            safety_receipt = self.store.get_job_safety_receipt_scoped(
                job_id, context.organization_id
            )
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
        return self._schedule_public(record, context)

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
                target=filters.get("target"),
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
            "schedules": [self._schedule_public(schedule, context) for schedule in schedules],
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
        return self._schedule_public(record, context)

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
        return self._schedule_public(record, context)

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

    # -- Browser authentication (Slice 16) --------------------------------
    # Sessions, passwords, and identity tokens resolve into the exact
    # same AuthContext/ApiPermission model an API token does (see
    # auth.py's BrowserSessionAuthenticator) -- there is no separate,
    # frontend-only permission model here (requirement 15).

    def _audit_identity_event(
        self,
        *,
        organization_id: str,
        principal_id: str,
        request_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: AuditOutcome,
        detail_code: str | None = None,
    ) -> None:
        """Same shape as `_audit`, for the handful of identity events
        that happen before a session exists (registration, a login
        failure against a real account, a password-reset/email-
        verification confirmation) or after one has already been
        consumed. `token_id` is a fresh, unused UUID in these cases --
        there is no real credential to attribute the event to, and the
        audit contract requires a canonical UUID there regardless."""

        try:
            self.identity.record_audit_event(
                SecurityAuditEvent(
                    event_id=str(uuid4()),
                    request_id=request_id,
                    organization_id=organization_id,
                    principal_id=principal_id,
                    token_id=str(uuid4()),
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
                "audit_persistence_failed", "The security audit event could not be persisted.", status=500
            ) from exc

    def _issue_session_context(self, principal, organization, issued) -> AuthContext:
        return AuthContext(
            organization_id=organization.organization_id,
            organization_name=organization.name,
            principal_id=principal.principal_id,
            principal_name=principal.display_name,
            role=principal.role,
            token_id=issued.record.session_id,
            auth_method="browser_session",
        )

    def register_account(
        self, body: dict, *, request_id: str, user_agent: str | None, ip_address: str | None
    ) -> tuple[AuthContext, object]:
        """Self-service signup (requirement 9): creates a new
        organization and its owner in one step. There is no "join an
        existing organization by email domain" flow -- joining an
        existing organization only ever happens through an explicit
        owner/administrator invitation (`invite_team_member` /
        `accept_invitation`), never by guessing or matching on email
        domain, which would let an attacker join any organization that
        shares their own employer's domain."""

        if not isinstance(body, dict):
            raise ApiServiceError("register_body_invalid", "Request body must be a JSON object.", status=400)
        organization_name = body.get("organization_name")
        display_name = body.get("display_name")
        email = body.get("email")
        password = body.get("password")
        if not isinstance(organization_name, str) or not organization_name.strip():
            raise ApiServiceError("register_body_invalid", "organization_name is required.", status=400)
        if not isinstance(display_name, str) or not display_name.strip():
            raise ApiServiceError("register_body_invalid", "display_name is required.", status=400)
        if not isinstance(email, str) or not email.strip():
            raise ApiServiceError("register_body_invalid", "email is required.", status=400)
        try:
            validate_password_policy(password)
        except PasswordPolicyError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc

        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"register:{ip_address}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        if self.identity.get_principal_by_email(email.strip()) is not None:
            raise ApiServiceError(
                "register_email_in_use", "An account with that email address already exists.", status=409
            )
        try:
            organization = self.identity.create_organization(organization_name.strip(), now=now)
            principal = self.identity.create_principal(
                organization.organization_id, display_name.strip(),
                principal_type=PrincipalType.USER, role=OrganizationRole.OWNER, now=now,
                email=email.strip(),
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        # Platform expansion: every organization is meant to carry
        # exactly one entitlement row per PlatformModule from the moment
        # it exists (module_entitlements.py's own module docstring).
        # production_startup.py's PostgresIdentityRepository already
        # grants this internally when constructed with a
        # module_entitlements repository (its own create_organization
        # calls grant_default_entitlements directly) -- but that made
        # the guarantee an implementation detail of one specific
        # identity backend, not something this service promised for
        # every organization it registers. cli.py's local/lab IdentityStore
        # (SQLite-backed) has no module_entitlements wiring at all, so
        # local/lab registration left every organization with zero
        # entitlement rows until this line.
        #
        # Guarded by a read first: grant_default_entitlements is a
        # plain INSERT with no ON CONFLICT handling (by design --
        # PostgresModuleEntitlementRepository.grant_default_entitlements
        # is meant to run exactly once per organization, at creation).
        # Calling it unconditionally here would raise a unique-
        # constraint violation for every organization whose identity
        # backend (PostgresIdentityRepository) already granted defaults
        # internally a few lines above -- confirmed the hard way: this
        # broke registration outright against a real database (CI's
        # Playwright E2E job, all three specs that register through the
        # real HTTP route). Checking first makes this call a genuine
        # backstop for a backend that did not already grant (local/lab),
        # not a second write against one that did (production).
        if not self.module_entitlements.list_entitlements(organization.organization_id):
            self.module_entitlements.grant_default_entitlements(organization.organization_id, now=now)
        self.identity.set_password_hash(
            principal.principal_id, organization.organization_id,
            algorithm="argon2id", password_hash=hash_password(password), now=now,
        )
        verification = self.identity.create_identity_token(
            principal.principal_id, organization.organization_id,
            purpose=IdentityTokenPurpose.EMAIL_VERIFICATION, ttl=EMAIL_VERIFICATION_TOKEN_TTL, now=now,
        )
        self._send_mail_best_effort(
            to=principal.email,
            subject="Verify your WebGuard email address",
            body=(
                "Confirm your email address by opening this link:\n"
                f"{self._web_app_base_url}/verify-email?token={verification.token}"
            ),
            category="email_verification",
        )
        issued = self.sessions.create_session(
            principal.principal_id, organization.organization_id, now=now,
            idle_ttl=self.session_idle_timeout, absolute_ttl=self.session_absolute_timeout,
            user_agent=user_agent, ip_address=ip_address,
        )
        self.identity.touch_last_login(principal.principal_id, organization.organization_id, now=now)
        context = self._issue_session_context(principal, organization, issued)
        self._audit(
            context, request_id=request_id, action="auth.register", resource_type="principal",
            resource_id=principal.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return context, issued

    def login(
        self, body: dict, *, request_id: str, user_agent: str | None, ip_address: str | None
    ) -> tuple[AuthContext, object]:
        if not isinstance(body, dict) or not isinstance(body.get("email"), str) or not isinstance(
            body.get("password"), str
        ):
            raise ApiServiceError("login_body_invalid", "email and password are required.", status=400)
        email = body["email"].strip()
        password = body["password"]
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"login:{ip_address}:{email.casefold()}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc

        generic_failure = ApiServiceError("invalid_credentials", "Invalid email or password.", status=401)
        principal = self.identity.get_principal_by_email(email)
        if principal is None:
            # No real account to scope an audit event to -- see
            # `_audit_identity_event`'s docstring on why this is the
            # one login-failure shape this codebase's audit contract
            # cannot represent, and requirement 11's own anti-
            # enumeration principle means the response must not differ
            # from every other failure mode anyway.
            raise generic_failure
        stored_hash = self.identity.get_password_hash(principal.principal_id)
        if (
            stored_hash is None
            or not principal.active
            or not verify_password(password, stored_hash)
        ):
            self._audit_identity_event(
                organization_id=principal.organization_id, principal_id=principal.principal_id,
                request_id=request_id, action="auth.login", resource_type="principal",
                resource_id=principal.principal_id, outcome=AuditOutcome.FAILED, detail_code="invalid-credentials",
            )
            raise generic_failure
        if needs_rehash(stored_hash):
            self.identity.set_password_hash(
                principal.principal_id, principal.organization_id,
                algorithm="argon2id", password_hash=hash_password(password), now=now,
            )
        organization = self.identity.get_organization(principal.organization_id)
        issued = self.sessions.create_session(
            principal.principal_id, organization.organization_id, now=now,
            idle_ttl=self.session_idle_timeout, absolute_ttl=self.session_absolute_timeout,
            user_agent=user_agent, ip_address=ip_address,
        )
        self.identity.touch_last_login(principal.principal_id, organization.organization_id, now=now)
        context = self._issue_session_context(principal, organization, issued)
        self._audit(
            context, request_id=request_id, action="auth.login", resource_type="principal",
            resource_id=principal.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return context, issued

    def logout(self, context: AuthContext, *, request_id: str) -> None:
        self.sessions.revoke_session(context.token_id, principal_id=context.principal_id, now=self.clock())
        self._audit(
            context, request_id=request_id, action="auth.logout", resource_type="session",
            resource_id=context.token_id, outcome=AuditOutcome.SUCCEEDED,
        )

    def logout_all_sessions(self, context: AuthContext, *, request_id: str) -> dict:
        count = self.sessions.revoke_all_sessions_for_principal(context.principal_id, now=self.clock())
        self._audit(
            context, request_id=request_id, action="auth.logout_all", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"revoked_count": count}

    def get_session_info(self, context: AuthContext, *, request_id: str) -> dict:
        payload = context.to_public_dict()
        if context.auth_method == "browser_session":
            session = self.sessions.get_session(context.token_id)
            if session is not None:
                payload["session"] = session.to_public_dict()
        self._audit(
            context, request_id=request_id, action="auth.session.read", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return payload

    def change_password(self, context: AuthContext, body: dict, *, request_id: str) -> None:
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("current_password"), str)
            or not isinstance(body.get("new_password"), str)
        ):
            raise ApiServiceError(
                "password_change_body_invalid", "current_password and new_password are required.", status=400
            )
        stored_hash = self.identity.get_password_hash(context.principal_id)
        if stored_hash is None or not verify_password(body["current_password"], stored_hash):
            self._audit(
                context, request_id=request_id, action="auth.password_change", resource_type="principal",
                resource_id=context.principal_id, outcome=AuditOutcome.FAILED, detail_code="current-password-incorrect",
            )
            raise ApiServiceError("current_password_incorrect", "Current password is incorrect.", status=401)
        try:
            validate_password_policy(body["new_password"])
        except PasswordPolicyError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        now = self.clock()
        self.identity.set_password_hash(
            context.principal_id, context.organization_id,
            algorithm="argon2id", password_hash=hash_password(body["new_password"]), now=now,
        )
        except_session = context.token_id if context.auth_method == "browser_session" else None
        self.sessions.revoke_all_sessions_for_principal(
            context.principal_id, now=now, except_session_id=except_session
        )
        principal = self.identity.get_principal(context.principal_id)
        if principal.email:
            self._send_mail_best_effort(
                to=principal.email,
                subject="Your WebGuard password was changed",
                body=(
                    "Your password was just changed. If this wasn't you, reset your "
                    f"password immediately: {self._web_app_base_url}/forgot-password"
                ),
                category="password_changed",
            )
        self._audit(
            context, request_id=request_id, action="auth.password_change", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )

    def request_password_reset(self, body: dict, *, request_id: str, ip_address: str | None) -> dict:
        """Requirement 11: the response is identical whether or not the
        email matches a real account -- an attacker must not be able to
        enumerate registered accounts through this endpoint."""

        if not isinstance(body, dict) or not isinstance(body.get("email"), str) or not body["email"].strip():
            raise ApiServiceError("password_reset_body_invalid", "email is required.", status=400)
        email = body["email"].strip()
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"password_reset:{ip_address}:{email.casefold()}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        generic_response = {
            "message": "If an account with that email address exists, a password reset link has been sent."
        }
        principal = self.identity.get_principal_by_email(email)
        if principal is None or not principal.active:
            return generic_response
        self.identity.invalidate_identity_tokens(
            principal.principal_id, principal.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now,
        )
        issued = self.identity.create_identity_token(
            principal.principal_id, principal.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET, ttl=PASSWORD_RESET_TOKEN_TTL, now=now,
        )
        self._send_mail_best_effort(
            to=principal.email,
            subject="Reset your WebGuard password",
            body=(
                "Reset your password (this link expires in 1 hour):\n"
                f"{self._web_app_base_url}/reset-password?token={issued.token}"
            ),
            category="password_reset",
        )
        self._audit_identity_event(
            organization_id=principal.organization_id, principal_id=principal.principal_id,
            request_id=request_id, action="auth.password_reset_requested", resource_type="principal",
            resource_id=principal.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return generic_response

    def confirm_password_reset(self, body: dict, *, request_id: str, ip_address: str | None) -> dict:
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("token"), str)
            or not isinstance(body.get("new_password"), str)
        ):
            raise ApiServiceError(
                "password_reset_confirm_body_invalid", "token and new_password are required.", status=400
            )
        try:
            validate_password_policy(body["new_password"])
        except PasswordPolicyError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"password_reset_confirm:{ip_address}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        try:
            record = self.identity.consume_identity_token(
                body["token"], purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        self.identity.set_password_hash(
            record.principal_id, record.organization_id,
            algorithm="argon2id", password_hash=hash_password(body["new_password"]), now=now,
        )
        self.sessions.revoke_all_sessions_for_principal(record.principal_id, now=now)
        principal = self.identity.get_principal(record.principal_id)
        if principal.email:
            self._send_mail_best_effort(
                to=principal.email,
                subject="Your WebGuard password was reset",
                body=(
                    "Your password was just reset and every active session was signed "
                    "out. If this wasn't you, contact your organization's WebGuard owner."
                ),
                category="password_changed",
            )
        self._audit_identity_event(
            organization_id=record.organization_id, principal_id=record.principal_id,
            request_id=request_id, action="auth.password_reset_completed", resource_type="principal",
            resource_id=record.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"message": "Password has been reset. Sign in with your new password."}

    def request_email_verification(self, context: AuthContext, *, request_id: str) -> dict:
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"email_verify:{context.principal_id}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        principal = self.identity.get_principal(context.principal_id)
        if principal.email is None:
            raise ApiServiceError("no_email_on_file", "This account has no email address on file.", status=400)
        if principal.email_verified_at is not None:
            return {"message": "Email address is already verified."}
        self.identity.invalidate_identity_tokens(
            principal.principal_id, principal.organization_id,
            purpose=IdentityTokenPurpose.EMAIL_VERIFICATION, now=now,
        )
        issued = self.identity.create_identity_token(
            principal.principal_id, context.organization_id,
            purpose=IdentityTokenPurpose.EMAIL_VERIFICATION, ttl=EMAIL_VERIFICATION_TOKEN_TTL, now=now,
        )
        self._send_mail_best_effort(
            to=principal.email,
            subject="Verify your WebGuard email address",
            body=(
                "Confirm your email address by opening this link:\n"
                f"{self._web_app_base_url}/verify-email?token={issued.token}"
            ),
            category="email_verification",
        )
        self._audit(
            context, request_id=request_id, action="auth.email_verification_requested", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"message": "Verification email sent."}

    def confirm_email_verification(self, body: dict, *, request_id: str, ip_address: str | None) -> dict:
        if not isinstance(body, dict) or not isinstance(body.get("token"), str):
            raise ApiServiceError("email_verification_body_invalid", "token is required.", status=400)
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"email_verify_confirm:{ip_address}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        try:
            record = self.identity.consume_identity_token(
                body["token"], purpose=IdentityTokenPurpose.EMAIL_VERIFICATION, now=now
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        self.identity.set_principal_email_verified(record.principal_id, record.organization_id, now=now)
        self._audit_identity_event(
            organization_id=record.organization_id, principal_id=record.principal_id,
            request_id=request_id, action="auth.email_verified", resource_type="principal",
            resource_id=record.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"message": "Email address verified."}

    def accept_invitation(
        self, body: dict, *, request_id: str, user_agent: str | None, ip_address: str | None
    ) -> tuple[AuthContext, object]:
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("token"), str)
            or not isinstance(body.get("password"), str)
        ):
            raise ApiServiceError(
                "invitation_accept_body_invalid", "token and password are required.", status=400
            )
        try:
            validate_password_policy(body["password"])
        except PasswordPolicyError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        now = self.clock()
        try:
            self.auth_rate_limiter.check_and_record(f"invitation_accept:{ip_address}", now=now)
        except RateLimitError as exc:
            raise ApiServiceError(exc.code, exc.message, status=429) from exc
        try:
            record = self.identity.consume_identity_token(
                body["token"], purpose=IdentityTokenPurpose.INVITATION, now=now
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        self.identity.set_password_hash(
            record.principal_id, record.organization_id,
            algorithm="argon2id", password_hash=hash_password(body["password"]), now=now,
        )
        # Accepting an emailed invitation link is itself proof of
        # control of that mailbox -- a second, separate verification
        # round-trip would confirm nothing a working invitation flow
        # has not already confirmed.
        self.identity.set_principal_email_verified(record.principal_id, record.organization_id, now=now)
        principal = self.identity.get_principal(record.principal_id)
        organization = self.identity.get_organization(record.organization_id)
        issued = self.sessions.create_session(
            principal.principal_id, organization.organization_id, now=now,
            idle_ttl=self.session_idle_timeout, absolute_ttl=self.session_absolute_timeout,
            user_agent=user_agent, ip_address=ip_address,
        )
        self.identity.touch_last_login(principal.principal_id, organization.organization_id, now=now)
        context = self._issue_session_context(principal, organization, issued)
        self._audit(
            context, request_id=request_id, action="auth.invitation_accepted", resource_type="principal",
            resource_id=principal.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return context, issued

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

    # -- Assets (Slice 15 requirement 2) --------------------------------

    _ASSET_MODES = frozenset({"single_page", "crawl"})
    _VERIFICATION_METHODS = frozenset(method.value for method in VerificationMethod)

    def _find_authorization_for_asset(self, organization_id: str, url: str):
        """Targets and authorizations are deliberately separate entities
        (a target is just a URL an org has registered interest in; an
        authorization is the actual scan-permission grant) -- there is
        no foreign key between them, matching by URL is the only
        correct join. Returns ``None`` if no assigned authorization
        currently covers this exact URL; never invents one."""

        for authorization_id in self.identity.list_assigned_authorization_ids(organization_id):
            try:
                authorization = self.authorizations.get(authorization_id)
            except AuthorizationRepositoryError:
                continue
            if authorization.target == url:
                return authorization
        return None

    def _asset_public_dict(self, context: AuthContext, target, *, detailed: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "target_id": target.target_id,
            "organization_id": target.organization_id,
            "url": target.url,
            "label": target.label,
            "default_mode": target.default_mode,
            "created_at": target.created_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
            "archived_at": None
            if target.archived_at is None
            else target.archived_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        }
        if not detailed:
            return payload
        verification = self.target_verifications.get_current(
            target.target_id, organization_id=context.organization_id
        )
        payload["verification"] = None if verification is None else verification.to_public_dict()
        authorization = self._find_authorization_for_asset(context.organization_id, target.url)
        if authorization is None:
            payload["authorization"] = None
        else:
            now = self.clock()
            payload["authorization"] = {
                "authorization_id": authorization.authorization_id,
                "issued_at": authorization.issued_at.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "expires_at": authorization.expires_at.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "state": (
                    "expired"
                    if now >= authorization.expires_at
                    else "expiring_soon"
                    if authorization.expires_at - now <= timedelta(days=7)
                    else "active"
                ),
            }
        try:
            scans, _ = self.scan_repository.list_scans_scoped_page(
                context.organization_id, limit=1, target=target.url
            )
        except ScanStoreError:
            scans = ()
        payload["last_scan"] = self._scan_public_dict(scans[0]) if scans else None
        try:
            findings, _ = self.finding_repository.list_findings_scoped_page(
                context.organization_id, limit=100, asset=target.url
            )
        except FindingStoreError:
            findings = ()
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        payload["finding_counts"] = counts
        payload["finding_count_is_capped"] = len(findings) >= 100
        return payload

    def create_asset(self, context: AuthContext, body: dict, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.ASSET_MANAGE, request_id=request_id,
            action="assets.create", resource_type="target", resource_id="pending",
        )
        if not isinstance(body, dict) or not isinstance(body.get("url"), str) or not body["url"].strip():
            raise ApiServiceError("asset_body_invalid", "Request body must include a non-empty url field.", status=400)
        label = body.get("label")
        if label is not None and not isinstance(label, str):
            raise ApiServiceError("asset_label_invalid", "label must be a string.", status=400)
        default_mode = body.get("default_mode")
        if default_mode is not None and default_mode not in self._ASSET_MODES:
            raise ApiServiceError(
                "asset_default_mode_invalid",
                f"default_mode must be one of: {', '.join(sorted(self._ASSET_MODES))}.",
                status=400,
            )
        try:
            canonical_url = _canonicalize_asset_url(body["url"].strip())
        except ValueError as exc:
            self._audit(
                context, request_id=request_id, action="assets.create", resource_type="target",
                resource_id="pending", outcome=AuditOutcome.DENIED, detail_code="asset_url_invalid",
            )
            raise ApiServiceError("asset_url_invalid", str(exc), status=400) from exc
        try:
            record = self.targets.create_target(
                context.organization_id, canonical_url, created_by=context.principal_id,
                now=self.clock(), label=label, default_mode=default_mode,
            )
        except TargetRepositoryError as exc:
            status = 409 if exc.code == "target_conflict" else 400
            self._audit(
                context, request_id=request_id, action="assets.create", resource_type="target",
                resource_id="pending", outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        self._audit(
            context, request_id=request_id, action="assets.create", resource_type="target",
            resource_id=record.target_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._asset_public_dict(context, record, detailed=False)

    def list_assets(self, context: AuthContext, page: PageRequest, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.ASSET_READ, request_id=request_id,
            action="assets.list", resource_type="organization", resource_id=context.organization_id,
        )
        try:
            records, has_more = self.targets.list_targets_scoped_page(
                context.organization_id, limit=page.limit,
                after=self._decode_page(context, page, resource="assets"),
            )
        except TargetRepositoryError as exc:
            raise ApiServiceError(exc.code, exc.message, status=500) from exc
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context, page, resource="assets", ordered_at=last.created_at, resource_id=last.target_id,
            )
        self._audit(
            context, request_id=request_id, action="assets.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "assets": [self._asset_public_dict(context, record, detailed=False) for record in records],
            "page": self._page_payload(page.limit, next_cursor),
        }

    def get_asset(self, context: AuthContext, target_id: str, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.ASSET_READ, request_id=request_id,
            action="assets.get", resource_type="target", resource_id=target_id,
        )
        try:
            record = self.targets.get_target(target_id, organization_id=context.organization_id)
        except TargetRepositoryError as exc:
            self._audit(
                context, request_id=request_id, action="assets.get", resource_type="target",
                resource_id=target_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="assets.get", resource_type="target",
            resource_id=target_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._asset_public_dict(context, record, detailed=True)

    def list_asset_coverage(
        self, context: AuthContext, target_id: str, page: PageRequest, *, request_id: str
    ) -> dict:
        """Coverage Truth Map v1 read surface (product vision pillar
        5). Tenant identity is derived entirely from context.organization_id,
        the server-resolved caller identity from the authenticated
        request; nothing here accepts a caller-supplied organization
        id. get_target already fails closed (404) on a target that
        exists but belongs to a different organization, so a coverage
        read for one tenant can never resolve a different tenant's
        asset in the first place.

        Returns actually recorded rows only, plus a page-independent
        status-count summary of every row for this asset (not just
        this page), so a paginated client can still show an honest
        denominator. Never claims a state (discovered/authorized) that
        v1 does not populate, and never manufactures a percentage: a
        caller with zero recorded rows sees an empty list and a
        summary of all zeros, not a fabricated "100% covered."
        identity_label is always "unauthenticated" today (see
        coverage_store.py's own module docstring); surfaced verbatim,
        not smoothed over.
        """

        self._require(
            context, ApiPermission.ASSET_READ, request_id=request_id,
            action="assets.coverage.list", resource_type="target", resource_id=target_id,
        )
        try:
            target = self.targets.get_target(target_id, organization_id=context.organization_id)
        except TargetRepositoryError as exc:
            self._audit(
                context, request_id=request_id, action="assets.coverage.list", resource_type="target",
                resource_id=target_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        from .coverage_store import coverage_cursor_key, split_asset_and_path

        asset, _ = split_asset_and_path(target.url)
        records, has_more = self.coverage_repository.list_coverage_for_asset_page(
            context.organization_id, asset, limit=page.limit,
            after=self._decode_page(context, page, resource="asset_coverage"),
        )
        next_cursor = None
        if has_more and records:
            last = records[-1]
            next_cursor = self._next_cursor(
                context, page, resource="asset_coverage",
                ordered_at=last.last_observed_at, resource_id=coverage_cursor_key(last),
            )
        status_counts = self.coverage_repository.count_coverage_by_status(context.organization_id, asset)
        self._audit(
            context, request_id=request_id, action="assets.coverage.list", resource_type="target",
            resource_id=target_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "asset": asset,
            "coverage": [
                {
                    "path": record.path,
                    "http_method": record.http_method,
                    "identity_label": record.identity_label,
                    "check_id": record.check_id,
                    "status": record.status.value,
                    "scanner_version": record.scanner_version,
                    "check_version": record.check_version,
                    "last_scan_id": record.last_scan_id,
                    "last_finding_id": record.last_finding_id,
                    "first_observed_at": self._timestamp(record.first_observed_at),
                    "last_observed_at": self._timestamp(record.last_observed_at),
                }
                for record in records
            ],
            "status_counts": {
                "completed": status_counts.get("completed", 0),
                "blocked": status_counts.get("blocked", 0),
                "unreachable": status_counts.get("unreachable", 0),
            },
            "not_populated_states": ["discovered", "authorized"],
            "page": self._page_payload(page.limit, next_cursor),
        }

    def update_asset(self, context: AuthContext, target_id: str, body: dict, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.ASSET_MANAGE, request_id=request_id,
            action="assets.update", resource_type="target", resource_id=target_id,
        )
        if not isinstance(body, dict):
            raise ApiServiceError("asset_body_invalid", "Request body must be a JSON object.", status=400)
        kwargs: dict[str, object] = {}
        if "label" in body:
            if body["label"] is not None and not isinstance(body["label"], str):
                raise ApiServiceError("asset_label_invalid", "label must be a string or null.", status=400)
            kwargs["label"] = body["label"]
        if "default_mode" in body:
            if body["default_mode"] is not None and body["default_mode"] not in self._ASSET_MODES:
                raise ApiServiceError(
                    "asset_default_mode_invalid",
                    f"default_mode must be null or one of: {', '.join(sorted(self._ASSET_MODES))}.",
                    status=400,
                )
            kwargs["default_mode"] = body["default_mode"]
        try:
            record = self.targets.update_target(
                target_id, organization_id=context.organization_id, **kwargs
            )
        except TargetRepositoryError as exc:
            self._audit(
                context, request_id=request_id, action="assets.update", resource_type="target",
                resource_id=target_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="assets.update", resource_type="target",
            resource_id=target_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._asset_public_dict(context, record, detailed=True)

    def start_asset_verification(self, context: AuthContext, target_id: str, body: dict, *, request_id: str) -> dict:
        """Requirement 3: server-generated token only -- the frontend
        never marks an asset verified; it only ever displays what this
        returns and later asks for a check. The caller chooses which
        method to attempt (``well_known_http`` or ``dns_txt``, see
        ``target_verification.py``'s own module docstring for why both
        exist): a domain fronted by a host with no file-publishing
        surface has no way to complete the first, and needs the
        second."""

        self._require(
            context, ApiPermission.ASSET_MANAGE, request_id=request_id,
            action="assets.verification.start", resource_type="target", resource_id=target_id,
        )
        if not isinstance(body, dict) or body.get("method") not in self._VERIFICATION_METHODS:
            raise ApiServiceError(
                "asset_verification_method_invalid",
                f"method must be one of: {', '.join(sorted(self._VERIFICATION_METHODS))}.",
                status=400,
            )
        try:
            self.targets.get_target(target_id, organization_id=context.organization_id)
        except TargetRepositoryError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        record = self.target_verifications.initiate(
            target_id, organization_id=context.organization_id,
            method=VerificationMethod(body["method"]), now=self.clock(),
        )
        self._audit(
            context, request_id=request_id, action="assets.verification.start", resource_type="target",
            resource_id=target_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return record.to_public_dict()

    def check_asset_verification(self, context: AuthContext, target_id: str, *, request_id: str) -> dict:
        """The only path that can ever set ``status=verified`` -- by
        performing the real, server-side check itself (requirement 3:
        verification state must come from server-side validation).

        A check that neither matches nor has expired is a retryable,
        informational outcome, not a terminal one: DNS propagation and
        CDN cache warm-up routinely take minutes to hours, and a real
        customer publishing the right value should never be forced to
        throw it away and publish a brand new one just because the
        first check ran before it had spread. Only a genuine match
        (``verified``) or the token's own 24-hour expiry
        (``expired``) changes the stored status; anything else leaves
        the pending verification, and its own still-valid token,
        completely untouched, and reports the attempt's own detail
        back to the caller without persisting it."""

        self._require(
            context, ApiPermission.ASSET_MANAGE, request_id=request_id,
            action="assets.verification.check", resource_type="target", resource_id=target_id,
        )
        try:
            target = self.targets.get_target(target_id, organization_id=context.organization_id)
        except TargetRepositoryError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        current = self.target_verifications.get_current(target_id, organization_id=context.organization_id)
        if current is None or current.status.value != "pending":
            raise ApiServiceError(
                "target_verification_not_pending",
                "Start a verification before requesting a check.",
                status=409,
            )
        now = self.clock()
        if current.expires_at is not None and now >= current.expires_at:
            record = self.target_verifications.record_result(
                current.verification_id, organization_id=context.organization_id,
                status=VerificationStatus.EXPIRED, detail="verification_token_expired", now=now,
            )
            self._audit(
                context, request_id=request_id, action="assets.verification.check", resource_type="target",
                resource_id=target_id, outcome=AuditOutcome.FAILED, detail_code="verification_token_expired",
            )
            return record.to_public_dict()
        try:
            token = self.target_verifications.get_pending_token(
                current.verification_id, organization_id=context.organization_id
            )
        except TargetVerificationError as exc:
            raise ApiServiceError(exc.code, exc.message, status=409) from exc
        if current.method is VerificationMethod.DNS_TXT:
            matched, detail = check_dns_txt_token(target.url, token)
        else:
            matched, detail = check_well_known_token(target.url, token)
        if matched:
            record = self.target_verifications.record_result(
                current.verification_id, organization_id=context.organization_id,
                status=VerificationStatus.VERIFIED, detail=detail, now=now,
            )
            self._audit(
                context, request_id=request_id, action="assets.verification.check", resource_type="target",
                resource_id=target_id, outcome=AuditOutcome.SUCCEEDED, detail_code=detail,
            )
            return record.to_public_dict()
        self._audit(
            context, request_id=request_id, action="assets.verification.check", resource_type="target",
            resource_id=target_id, outcome=AuditOutcome.FAILED, detail_code=detail,
        )
        payload = current.to_public_dict()
        payload["last_check_detail"] = detail
        payload["last_checked_at"] = (
            now.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
        return payload

    # -- Dashboard (Slice 15 requirement 1) -----------------------------

    def dashboard_summary(self, context: AuthContext, *, request_id: str) -> dict:
        """Real counts only -- no fabricated risk score. If a defensible
        risk-scoring model exists in the future, it is additive to this
        payload, never a replacement for the underlying counts."""

        self._require(
            context, ApiPermission.JOB_READ, request_id=request_id,
            action="dashboard.summary", resource_type="organization", resource_id=context.organization_id,
        )
        organization_id = context.organization_id
        assets = self.targets.list_targets(organization_id)
        verified_assets = 0
        for asset in assets:
            verification = self.target_verifications.get_current(asset.target_id, organization_id=organization_id)
            if verification is not None and verification.status.value == "verified":
                verified_assets += 1
        scans, _ = self.scan_repository.list_scans_scoped_page(organization_id, limit=100)
        active_scans = sum(1 for s in scans if s.status in ("running", "queued"))
        completed_scans = sum(1 for s in scans if s.status == "completed")
        failed_scans = sum(1 for s in scans if s.status in ("failed", "completed_with_errors"))
        findings, _ = self.finding_repository.list_findings_scoped_page(organization_id, limit=100)
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        recent_high_critical = []
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_status[finding.status.value] = by_status.get(finding.status.value, 0) + 1
            if finding.severity in ("high", "critical") and len(recent_high_critical) < 5:
                recent_high_critical.append(self._finding_public_dict(finding))
        self._audit(
            context, request_id=request_id, action="dashboard.summary", resource_type="organization",
            resource_id=organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "total_assets": len(assets),
            "verified_assets": verified_assets,
            "active_scans": active_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "findings_by_severity": by_severity,
            "findings_by_status": by_status,
            "recent_scans": [self._scan_public_dict(s) for s in scans[:5]],
            "recent_high_or_critical_findings": recent_high_critical,
            "counts_capped_at": 100,
        }

    # -- Team (Slice 15 requirement 4) -----------------------------------

    @staticmethod
    def _principal_public_dict(principal) -> dict[str, object]:
        def _ts(value):
            return None if value is None else value.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")

        return {
            "principal_id": principal.principal_id,
            "organization_id": principal.organization_id,
            "display_name": principal.display_name,
            "principal_type": principal.principal_type.value,
            "role": principal.role.value,
            "active": principal.active,
            "created_at": _ts(principal.created_at),
            "email": principal.email,
            "email_verified_at": _ts(principal.email_verified_at),
            "last_login_at": _ts(principal.last_login_at),
        }

    def list_team(self, context: AuthContext, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.TEAM_READ, request_id=request_id,
            action="team.list", resource_type="organization", resource_id=context.organization_id,
        )
        members = self.identity.list_principals(context.organization_id)
        self._audit(
            context, request_id=request_id, action="team.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"members": [self._principal_public_dict(m) for m in members]}

    def list_module_entitlements(self, context: AuthContext, *, request_id: str) -> dict:
        """Which of WebGuard/SOC/Compliance this organization can
        access (docs/PLATFORM_SCOPE.md). An organization created before
        this route existed, or before ``register_account`` started
        calling ``grant_default_entitlements``, may legitimately have
        zero rows here -- that is reported as an empty list, never
        fabricated as "all enabled" or "all disabled"."""

        self._require(
            context, ApiPermission.MODULE_ENTITLEMENTS_READ, request_id=request_id,
            action="module_entitlements.list", resource_type="organization",
            resource_id=context.organization_id,
        )
        entitlements = self.module_entitlements.list_entitlements(context.organization_id)
        self._audit(
            context, request_id=request_id, action="module_entitlements.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "entitlements": [
                {
                    "module": entitlement.module.value,
                    "status": entitlement.status.value,
                    "updated_at": entitlement.updated_at.isoformat(),
                    "enabled_at": entitlement.enabled_at.isoformat() if entitlement.enabled_at else None,
                }
                for entitlement in entitlements
            ]
        }

    def set_module_entitlement(
        self, context: AuthContext, module_id: str, body: dict, *, request_id: str
    ) -> dict:
        """Turns SOC or Compliance on or off for this organization.
        Owner-only (MODULE_ENTITLEMENTS_MANAGE): the administrator
        exclusion set in auth.py carves this out for the same reason
        it carves out PERMIT_ISSUE_ACTIVE and the AUTHENTICATION_CONTEXT_*
        permissions. WebGuard itself is not manageable through this
        route at all. It is the platform's foundational module,
        always enabled, so "webguard" in the URL is rejected outright
        rather than accepted and silently ignored."""

        self._require(
            context, ApiPermission.MODULE_ENTITLEMENTS_MANAGE, request_id=request_id,
            action="module_entitlements.manage", resource_type="organization",
            resource_id=context.organization_id,
        )
        # resource_id is the module itself (mirrors update_asset's
        # resource_id=target_id / update_team_member's resource_id=
        # principal_id: the specific object mutated, not its parent
        # organization). Without this, two SUCCEEDED audit rows for the
        # same organization are indistinguishable -- SOC disabled twice,
        # or SOC once and Compliance once, defeating the "reconstruct
        # who changed what" point of auditing this action at all.
        if module_id == "webguard":
            self._audit(
                context, request_id=request_id, action="module_entitlements.manage",
                resource_type="module_entitlement", resource_id=module_id,
                outcome=AuditOutcome.DENIED, detail_code="module_entitlement_not_manageable",
            )
            raise ApiServiceError(
                "module_entitlement_not_manageable",
                "The webguard module is always enabled and cannot be changed.",
                status=400,
            )
        if module_id not in ("soc", "compliance"):
            self._audit(
                context, request_id=request_id, action="module_entitlements.manage",
                resource_type="module_entitlement", resource_id=module_id,
                outcome=AuditOutcome.DENIED, detail_code="module_entitlement_unknown",
            )
            raise ApiServiceError(
                "module_entitlement_unknown", f"{module_id!r} is not a known module.", status=400
            )
        if not isinstance(body, dict) or body.get("status") not in ("enabled", "disabled"):
            self._audit(
                context, request_id=request_id, action="module_entitlements.manage",
                resource_type="module_entitlement", resource_id=module_id,
                outcome=AuditOutcome.DENIED, detail_code="module_entitlement_body_invalid",
            )
            raise ApiServiceError(
                "module_entitlement_body_invalid", "status must be 'enabled' or 'disabled'.", status=400
            )
        from .module_entitlements import ModuleEntitlementError
        from webguard_contracts import ModuleEntitlementStatus, PlatformModule

        try:
            entitlement = self.module_entitlements.set_entitlement(
                context.organization_id, PlatformModule(module_id),
                status=ModuleEntitlementStatus(body["status"]),
                now=self.clock(), changed_by=context.principal_id,
            )
        except ModuleEntitlementError as exc:
            self._audit(
                context, request_id=request_id, action="module_entitlements.manage",
                resource_type="module_entitlement", resource_id=module_id,
                outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="module_entitlements.manage",
            resource_type="module_entitlement", resource_id=module_id,
            outcome=AuditOutcome.SUCCEEDED, detail_code=entitlement.status.value,
        )
        return {
            "module": entitlement.module.value,
            "status": entitlement.status.value,
            "updated_at": entitlement.updated_at.isoformat(),
            "enabled_at": entitlement.enabled_at.isoformat() if entitlement.enabled_at else None,
        }

    def list_soc_connectors(self, context: AuthContext, *, request_id: str) -> dict:
        """SOC connector manifests (soc_connectors.py): what this
        codebase's own connector contracts declare, not any
        organization's live connection state -- none exists yet, since
        no connector here has a live HTTP client (every manifest's own
        ``live_validation_state`` is ``contract_designed``). Global
        reference data, the same as the Compliance framework catalog:
        every organization sees the identical list."""

        self._require(
            context, ApiPermission.SOC_CONNECTOR_READ, request_id=request_id,
            action="soc.connectors.list", resource_type="organization",
            resource_id=context.organization_id,
        )
        from .soc_connectors import SOC_CONNECTOR_REGISTRY

        connectors = []
        for manifest in SOC_CONNECTOR_REGISTRY.values():
            connectors.append(
                {
                    "connector_id": manifest.connector_id,
                    "display_name": manifest.display_name,
                    "vendor": manifest.vendor,
                    "api_family": manifest.api_family,
                    "licensing_dependency": manifest.licensing_dependency,
                    "live_validation_state": manifest.live_validation_state.value,
                    "permissions": [
                        {"name": p.name, "permission_type": p.permission_type.value, "purpose": p.purpose}
                        for p in manifest.permissions
                    ],
                    "endpoint_count": len(manifest.endpoints),
                    "known_limitations": list(manifest.known_limitations),
                }
            )
        self._audit(
            context, request_id=request_id, action="soc.connectors.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"connectors": sorted(connectors, key=lambda c: c["connector_id"])}

    def list_compliance_frameworks(self, context: AuthContext, *, request_id: str) -> dict:
        """The Compliance framework catalog (global reference data,
        identical for every organization -- see webguard_contracts.compliance's
        own module docstring for why this carries no organization_id at
        all). Every framework here is FrameworkStatus.PLACEHOLDER with
        zero MasterControl rows: named and cited to its authoritative
        source, no legally-reviewed control content loaded yet. That is
        reported honestly (control_count=0), never hidden or padded."""

        self._require(
            context, ApiPermission.COMPLIANCE_CATALOG_READ, request_id=request_id,
            action="compliance.frameworks.list", resource_type="organization",
            resource_id=context.organization_id,
        )
        frameworks = self.compliance_catalog.list_frameworks()
        payload = []
        for framework in frameworks:
            controls = self.compliance_catalog.list_master_controls(framework.framework_id)
            payload.append({**framework.to_dict(), "control_count": len(controls)})
        self._audit(
            context, request_id=request_id, action="compliance.frameworks.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"frameworks": payload}

    def list_compliance_assertions(self, context: AuthContext, *, request_id: str) -> dict:
        """The technical assertion catalog (technical_assertions.py):
        what this codebase knows how to check, not any organization's
        own result. Global reference data, same as the framework
        catalog and the SOC connector manifests."""

        self._require(
            context, ApiPermission.COMPLIANCE_ASSERTION_READ, request_id=request_id,
            action="compliance.assertions.list", resource_type="organization",
            resource_id=context.organization_id,
        )
        from .assertion_collections import EvidenceSource, FIXTURE_EVIDENCE_SETS
        from .technical_assertions import TECHNICAL_ASSERTION_REGISTRY

        assertions = [
            {
                "assertion_id": assertion.assertion_id,
                "title": assertion.title,
                "objective": assertion.objective,
                "version": assertion.version,
                "source_connector_id": assertion.source_connector_id,
                "required_permissions": list(assertion.required_permissions),
                "evaluatable": assertion.assertion_id in {"entra_conditional_access_policy_mode"},
            }
            for assertion in TECHNICAL_ASSERTION_REGISTRY.values()
        ]
        self._audit(
            context, request_id=request_id, action="compliance.assertions.list", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "assertions": sorted(assertions, key=lambda a: a["assertion_id"]),
            "fixture_evidence_sets": sorted(FIXTURE_EVIDENCE_SETS.keys()),
        }

    def _assertion_collection_dict(self, record) -> dict:
        return {
            "collection_id": record.collection_id,
            "assertion_id": record.assertion_id,
            "assertion_version": record.assertion_version,
            "evidence_source": record.evidence_source.value,
            "evidence_provenance": record.evidence_provenance,
            "collection_status": record.collection_status.value,
            "collection_error": record.collection_error,
            "collected_by": record.collected_by,
            "collected_at": record.collected_at.isoformat(),
            "outcome": record.outcome.value if record.outcome else None,
            "outcome_detail": record.outcome_detail,
            "evaluated_at": record.evaluated_at.isoformat() if record.evaluated_at else None,
        }

    def list_assertion_collections(self, context: AuthContext, assertion_id: str, *, request_id: str) -> dict:
        """One organization's own collection/evaluation history against
        one assertion, most recent first. An assertion nobody has ever
        attempted returns an empty list -- NOT_TESTED is the absence of
        a row here, never a fabricated record (assertion_collections.py's
        own module docstring)."""

        self._require(
            context, ApiPermission.COMPLIANCE_ASSERTION_READ, request_id=request_id,
            action="compliance.assertion_collections.list", resource_type="assertion", resource_id=assertion_id,
        )
        from .technical_assertions import TECHNICAL_ASSERTION_REGISTRY

        if assertion_id not in TECHNICAL_ASSERTION_REGISTRY:
            raise ApiServiceError(
                "technical_assertion_unknown", f"{assertion_id!r} is not a known assertion.", status=404
            )
        records = self.assertion_collections.list_for_assertion(context.organization_id, assertion_id)
        self._audit(
            context, request_id=request_id, action="compliance.assertion_collections.list",
            resource_type="assertion", resource_id=assertion_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"collections": [self._assertion_collection_dict(r) for r in records]}

    def collect_assertion(self, context: AuthContext, assertion_id: str, body: dict, *, request_id: str) -> dict:
        """Runs one collection attempt (assertion_collections.collect_and_evaluate)
        and persists it. evidence_source must be "fixture" (with
        fixture_name naming one of FIXTURE_EVIDENCE_SETS) or "manual"
        (with manual_evidence, shaped the same way a real connector
        response eventually will be) -- never both, never neither.
        Nothing here talks to a live Microsoft tenant: no SOC connector
        in this codebase has a live HTTP client yet."""

        self._require(
            context, ApiPermission.COMPLIANCE_ASSERTION_COLLECT, request_id=request_id,
            action="compliance.assertion_collections.create", resource_type="assertion", resource_id=assertion_id,
        )
        # Module entitlement, not RBAC: role says whether THIS principal
        # may collect within an organization that has Compliance at
        # all; this says whether the organization does. Enforced here,
        # the one place this route actually creates persisted tenant
        # state -- the read-only catalog/manifest routes above stay
        # ungated, since letting a not-yet-entitled organization preview
        # what Compliance offers leaks no tenant data and no other
        # tenant's information (they are the same static catalog for
        # every organization). A missing entitlement row (an
        # organization that predates this route) fails closed the same
        # as an explicit "disabled" status -- never treated as implicitly
        # enabled.
        from .module_entitlements import ModuleEntitlementError
        from webguard_contracts import ModuleEntitlementStatus, PlatformModule

        try:
            entitlement = self.module_entitlements.get_entitlement(
                context.organization_id, PlatformModule.COMPLIANCE
            )
        except ModuleEntitlementError:
            entitlement = None
        if entitlement is None or entitlement.status not in (
            ModuleEntitlementStatus.ENABLED,
            ModuleEntitlementStatus.TRIAL,
        ):
            self._audit(
                context, request_id=request_id, action="compliance.assertion_collections.create",
                resource_type="assertion", resource_id=assertion_id, outcome=AuditOutcome.DENIED,
                detail_code="compliance_module_not_entitled",
            )
            raise ApiServiceError(
                "compliance_module_not_entitled",
                "This organization's Compliance module is not enabled.",
                status=403,
            )
        from .assertion_collections import AssertionCollectionError, EvidenceSource, collect_and_evaluate

        if not isinstance(body, dict):
            raise ApiServiceError("assertion_collection_body_invalid", "Request body must be a JSON object.", status=400)
        source = body.get("evidence_source")
        if source not in ("fixture", "manual"):
            raise ApiServiceError(
                "assertion_collection_body_invalid", "evidence_source must be 'fixture' or 'manual'.", status=400
            )
        fixture_name = body.get("fixture_name")
        manual_evidence = body.get("manual_evidence")
        if source == "fixture" and (not isinstance(fixture_name, str) or manual_evidence is not None):
            raise ApiServiceError(
                "assertion_collection_body_invalid",
                "evidence_source='fixture' requires fixture_name and no manual_evidence.", status=400,
            )
        if source == "manual" and (not isinstance(manual_evidence, list) or fixture_name is not None):
            raise ApiServiceError(
                "assertion_collection_body_invalid",
                "evidence_source='manual' requires a manual_evidence array and no fixture_name.", status=400,
            )
        try:
            record = collect_and_evaluate(
                organization_id=context.organization_id,
                assertion_id=assertion_id,
                evidence_source=EvidenceSource(source),
                collected_by=context.principal_id,
                now=self.clock(),
                fixture_name=fixture_name,
                manual_evidence=manual_evidence,
            )
        except AssertionCollectionError as exc:
            self._audit(
                context, request_id=request_id, action="compliance.assertion_collections.create",
                resource_type="assertion", resource_id=assertion_id, outcome=AuditOutcome.DENIED,
                detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        record = self.assertion_collections.record(record)
        self._audit(
            context, request_id=request_id, action="compliance.assertion_collections.create",
            resource_type="assertion", resource_id=assertion_id, outcome=AuditOutcome.SUCCEEDED,
            detail_code=record.collection_status.value,
        )
        return self._assertion_collection_dict(record)

    def invite_team_member(self, context: AuthContext, body: dict, *, request_id: str) -> dict:
        """Slice 16 revision: Slice 15 issued an initial API bearer
        token directly here, because no email infrastructure existed to
        deliver anything else. That reason is gone -- this slice builds
        the mail-provider/identity-token layer requirement 26 asks for
        -- so this now creates the principal (no password credential
        yet) and issues a single-use, expiry-bounded invitation token
        via the mail provider instead. The invitee sets their own
        password when they accept it (`accept_invitation`); an API
        bearer token remains available afterward through the ordinary
        self-service `/v1/api-keys` route, unrelated to invitation."""

        self._require(
            context, ApiPermission.TEAM_MANAGE, request_id=request_id,
            action="team.invite", resource_type="principal", resource_id="pending",
        )
        if not isinstance(body, dict) or not isinstance(body.get("display_name"), str) or not body["display_name"].strip():
            raise ApiServiceError("team_invite_body_invalid", "display_name is required.", status=400)
        if not isinstance(body.get("email"), str) or not body["email"].strip():
            raise ApiServiceError("team_invite_body_invalid", "email is required.", status=400)
        try:
            role = OrganizationRole(body.get("role", "viewer"))
        except ValueError as exc:
            raise ApiServiceError(
                "team_invite_role_invalid",
                "role must be one of: " + ", ".join(r.value for r in OrganizationRole),
                status=400,
            ) from exc
        if role is OrganizationRole.OWNER and context.role is not OrganizationRole.OWNER:
            raise ApiServiceError(
                "team_owner_role_requires_owner", "Only an owner may grant the owner role.", status=403
            )
        now = self.clock()
        try:
            principal = self.identity.create_principal(
                context.organization_id, body["display_name"].strip(),
                principal_type=PrincipalType.USER, role=role, now=now,
                email=body["email"].strip(),
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        issued = self.identity.create_identity_token(
            principal.principal_id, context.organization_id,
            purpose=IdentityTokenPurpose.INVITATION, ttl=INVITATION_TOKEN_TTL, now=now,
        )
        self._send_mail_best_effort(
            to=principal.email,
            subject="You've been invited to WebGuard",
            body=(
                f"{context.principal_name} invited you to join their WebGuard organization "
                f"as {role.value}. Accept your invitation (expires in {INVITATION_TOKEN_TTL.days} "
                f"days) by opening this link:\n"
                f"{self._web_app_base_url}/accept-invitation?token={issued.token}"
            ),
            category="invitation",
        )
        self._audit(
            context, request_id=request_id, action="team.invite", resource_type="principal",
            resource_id=principal.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._principal_public_dict(principal)

    def update_team_member(self, context: AuthContext, principal_id: str, body: dict, *, request_id: str) -> dict:
        self._require(
            context, ApiPermission.TEAM_MANAGE, request_id=request_id,
            action="team.update", resource_type="principal", resource_id=principal_id,
        )
        if principal_id == context.principal_id:
            raise ApiServiceError(
                "team_cannot_modify_self", "Use another owner/administrator account to change your own role.",
                status=403,
            )
        if not isinstance(body, dict) or not isinstance(body.get("role"), str):
            raise ApiServiceError("team_update_body_invalid", "Request body must include a string role field.", status=400)
        try:
            role = OrganizationRole(body["role"])
        except ValueError as exc:
            raise ApiServiceError(
                "team_update_role_invalid",
                "role must be one of: " + ", ".join(r.value for r in OrganizationRole),
                status=400,
            ) from exc
        try:
            current = self.identity.get_principal_scoped(principal_id, organization_id=context.organization_id)
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        if (role is OrganizationRole.OWNER or current.role is OrganizationRole.OWNER) and context.role is not OrganizationRole.OWNER:
            raise ApiServiceError(
                "team_owner_role_requires_owner", "Only an owner may grant or remove the owner role.", status=403
            )
        try:
            updated = self.identity.update_principal_role(
                principal_id, organization_id=context.organization_id, role=role, now=self.clock()
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        # Requirement 5: rotate/revoke at privilege-change boundaries.
        # There is no "current session of the principal whose role
        # changed" to rotate in place from the admin's own request --
        # the admin is a different principal -- so the equivalent,
        # correct action is revoking the target's existing sessions:
        # their next authenticated request re-resolves the new role
        # from a fresh session rather than a stale, already-issued one.
        self.sessions.revoke_all_sessions_for_principal(principal_id, now=self.clock())
        self._audit(
            context, request_id=request_id, action="team.update", resource_type="principal",
            resource_id=principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._principal_public_dict(updated)

    def remove_team_member(self, context: AuthContext, principal_id: str, *, request_id: str) -> dict:
        """A "remove" is a deactivation (``active=False``), matching this
        codebase's standing revoke-over-delete convention -- never a row
        deletion."""

        self._require(
            context, ApiPermission.TEAM_MANAGE, request_id=request_id,
            action="team.remove", resource_type="principal", resource_id=principal_id,
        )
        if principal_id == context.principal_id:
            raise ApiServiceError(
                "team_cannot_modify_self", "Use another owner/administrator account to remove your own access.",
                status=403,
            )
        try:
            current = self.identity.get_principal_scoped(principal_id, organization_id=context.organization_id)
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        if current.role is OrganizationRole.OWNER and context.role is not OrganizationRole.OWNER:
            raise ApiServiceError(
                "team_owner_role_requires_owner", "Only an owner may remove another owner.", status=403
            )
        try:
            updated = self.identity.set_principal_active(
                principal_id, organization_id=context.organization_id, active=False, now=self.clock()
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self.sessions.revoke_all_sessions_for_principal(principal_id, now=self.clock())
        self._audit(
            context, request_id=request_id, action="team.remove", resource_type="principal",
            resource_id=principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._principal_public_dict(updated)

    # -- API keys (Slice 15 requirement 5) -------------------------------
    # Self-service by design: every principal manages only their own
    # tokens, mirroring how personal-access tokens work in most
    # developer-facing products -- no cross-principal visibility, no new
    # RBAC decision about who may see or revoke someone else's key.

    @staticmethod
    def _api_key_public_dict(metadata) -> dict[str, object]:
        def _ts(value):
            return None if value is None else value.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")

        return {
            "token_id": metadata.token_id,
            "label": metadata.label,
            "created_at": _ts(metadata.created_at),
            "expires_at": _ts(metadata.expires_at),
            "revoked_at": _ts(metadata.revoked_at),
            "last_used_at": _ts(metadata.last_used_at),
        }

    def list_api_keys(self, context: AuthContext, *, request_id: str) -> dict:
        tokens = self.identity.list_tokens_for_principal(context.principal_id, context.organization_id)
        self._audit(
            context, request_id=request_id, action="api_keys.list", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {"api_keys": [self._api_key_public_dict(t) for t in tokens]}

    def create_api_key(self, context: AuthContext, body: dict, *, request_id: str) -> dict:
        if not isinstance(body, dict) or not isinstance(body.get("label"), str) or not body["label"].strip():
            raise ApiServiceError("api_key_body_invalid", "label is required.", status=400)
        validity_days = body.get("validity_days")
        kwargs = {}
        if validity_days is not None:
            if isinstance(validity_days, bool) or not isinstance(validity_days, int):
                raise ApiServiceError("api_key_validity_invalid", "validity_days must be an integer.", status=400)
            kwargs["validity_days"] = validity_days
        try:
            issued = self.identity.create_token(
                context.principal_id, label=body["label"].strip(), now=self.clock(), **kwargs
            )
        except IdentityStoreError as exc:
            raise ApiServiceError(exc.code, exc.message, status=400) from exc
        self._audit(
            context, request_id=request_id, action="api_keys.create", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        payload = self._api_key_public_dict(issued.metadata)
        payload["token"] = issued.token
        return payload

    def revoke_api_key(self, context: AuthContext, token_id: str, *, request_id: str) -> dict:
        try:
            metadata = self.identity.revoke_token_owned(
                token_id, context.organization_id, principal_id=context.principal_id, now=self.clock()
            )
        except IdentityStoreError as exc:
            self._audit(
                context, request_id=request_id, action="api_keys.revoke", resource_type="principal",
                resource_id=context.principal_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        self._audit(
            context, request_id=request_id, action="api_keys.revoke", resource_type="principal",
            resource_id=context.principal_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return self._api_key_public_dict(metadata)

    # -- Settings (Slice 15 requirement 6) -------------------------------

    def get_settings(self, context: AuthContext, *, request_id: str) -> dict:
        """Only genuine, currently-backed settings -- an organization's
        name and this principal's own profile. No notification/session-
        preference storage exists yet; this deliberately does not
        invent placeholder fields for a screen that would otherwise be
        empty (requirement 6)."""

        organization = self.identity.get_organization(context.organization_id)
        principal = self.identity.get_principal(context.principal_id)
        self._audit(
            context, request_id=request_id, action="settings.get", resource_type="organization",
            resource_id=context.organization_id, outcome=AuditOutcome.SUCCEEDED,
        )
        return {
            "organization": {
                "organization_id": organization.organization_id,
                "name": organization.name,
                "status": organization.status.value,
                "created_at": organization.created_at.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
            },
            "account": self._principal_public_dict(principal),
        }

    # -- Report download (Slice 15 requirement 7) ------------------------

    def download_report(self, context: AuthContext, report_id: str, *, request_id: str) -> tuple[bytes, str, str]:
        """Never exposes ``report_ref`` (an internal artifact reference,
        never a filesystem path, bucket name, or S3 URL) to the caller
        -- only the bytes it resolves to, after a tenant-ownership
        check and an integrity check, through the same ``ArtifactStore``
        abstraction, real S3-backed in production since Slice 17
        requirement 7 (`object_storage_not_implemented` no longer
        occurs; retained in the status mapping below only for an
        operator who has not yet reconfigured a pre-Slice-17
        deployment)."""

        self._require(
            context, ApiPermission.REPORT_READ, request_id=request_id,
            action="reports.download", resource_type="report", resource_id=report_id,
        )
        try:
            record = self.report_repository.get_report_scoped(report_id, organization_id=context.organization_id)
        except ReportStoreError as exc:
            self._audit(
                context, request_id=request_id, action="reports.download", resource_type="report",
                resource_id=report_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=404) from exc
        from .artifact_store import ArtifactStoreError

        try:
            content = self.artifact_store.get_reference(record.report_ref)
        except ArtifactStoreError as exc:
            status = 404 if exc.code == "artifact_not_found" else 503
            self._audit(
                context, request_id=request_id, action="reports.download", resource_type="report",
                resource_id=report_id, outcome=AuditOutcome.DENIED, detail_code=exc.code,
            )
            raise ApiServiceError(exc.code, exc.message, status=status) from exc
        # Slice 17 requirement 14: never serve bytes that don't match
        # the checksum computed and persisted at report-creation time
        # (`create_report`, from the artifact's own bytes, never a
        # client-supplied value) -- a truncated read, a corrupted
        # object, or a wrong object entirely all fail closed here
        # rather than silently handing the customer bad report bytes.
        if record.checksum is not None and hashlib.sha256(content).hexdigest() != record.checksum:
            self._audit(
                context, request_id=request_id, action="reports.download", resource_type="report",
                resource_id=report_id, outcome=AuditOutcome.DENIED, detail_code="report_integrity_check_failed",
            )
            raise ApiServiceError(
                "report_integrity_check_failed",
                "The report artifact failed integrity verification and cannot be served.",
                status=500,
            )
        self._audit(
            context, request_id=request_id, action="reports.download", resource_type="report",
            resource_id=report_id, outcome=AuditOutcome.SUCCEEDED,
        )
        content_type = "application/json" if record.format == "json" else "application/octet-stream"
        filename = f"report-{report_id}.{record.format}"
        return content, content_type, filename


__all__ = ["ApiServiceError", "WebGuardJobService"]
