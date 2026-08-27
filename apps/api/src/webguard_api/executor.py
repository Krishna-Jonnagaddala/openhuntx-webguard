"""Safe owned-target scanner execution for queued service jobs."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, replace as dataclasses_replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from webguard_contracts import (
    OwnedTargetContractError,
    ScanJobMode,
    ScanJobRecord,
    ScanStatus,
    WebGuardReport,
    write_owned_target_audit_file,
)
from webguard_scanner import (
    ACTIVE_DETECTOR_REGISTRY,
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    CrawlCancellationToken,
    CrawlPolicy,
    FetchPolicy,
    MAXIMUM_DISCOVERED_CANDIDATES,
    OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
    OWNED_DEFAULT_CRAWL_DEPTH,
    OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
    OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
    OWNED_DEFAULT_CRAWL_PAGES,
    OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    RetryPolicy,
    ValidatedTarget,
    ValidationMode,
    ValidationPolicy,
    discover_get_form_candidates,
    fetch_same_origin_page,
    validate_owned_target_preflight,
    validate_target_url,
    run_passive_crawl_scan,
    run_passive_header_scan,
)

from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .permits import TrustScanPermitError, TrustScanSigner, validate_permit_use
from .safety import TrustScanRuntimeSafetyEngine, TrustScanRuntimeSafetyError
from .store import JobStoreError, ScanJobStore


_ACTIVE_DETECTION_ELIGIBLE_STATUSES = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS}
)


def _discover_and_detect_page(
    target: ValidatedTarget,
    page_url: str,
    detectors: list[tuple[str, Callable]],
    context: ActiveDetectionContext,
    policy: ActiveDetectionPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_check: Callable[[], bool],
    restrict_to_page_path: str | None = None,
) -> list:
    if cancellation_check():
        return []

    response = fetch_same_origin_page(
        target,
        page_url,
        policy=policy,
        before_request=safety.before_request,
        after_request=safety.after_request,
    )
    if response is None:
        return []

    candidates = discover_get_form_candidates(target, page_url, response.body)
    if restrict_to_page_path is not None:
        # A crawl page's findings must all belong to that page's own URL
        # (an existing, audited CrawlPageScanResult invariant). A
        # discovered form whose action targets a different page cannot be
        # attributed to this page slot, so only self-submitting forms
        # (search boxes and similar) are testable in crawl mode today.
        candidates = tuple(
            candidate
            for candidate in candidates
            if urlsplit(candidate.url).path == restrict_to_page_path
        )
    if not candidates:
        return []
    candidates = candidates[: policy.maximum_probe_requests]

    findings = []
    for _check_id, runner in detectors:
        if cancellation_check():
            break
        try:
            result = runner(
                target,
                candidates,
                context,
                policy=policy,
                before_request=safety.before_request,
                after_request=safety.after_request,
                cancellation_check=cancellation_check,
            )
        except ActiveDetectionError:
            # A code-level active-detection guard (e.g. a candidate-budget
            # mismatch), not a security-relevant runtime safety decision.
            # The passive result already obtained must not be discarded
            # over this -- skip this detector for this page.
            continue
        findings.extend(result.findings)
    return findings


def _apply_active_detection(
    report: WebGuardReport,
    *,
    target: ValidatedTarget,
    active_checks: tuple[str, ...],
    scan_id: str,
    authorization_id: str,
    permit_id: str,
    permit_fingerprint: str,
    fetch_policy: FetchPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_token: CrawlCancellationToken,
) -> WebGuardReport:
    """Run authorized active detectors and merge findings into the report.

    Fails closed by construction: if ``active_checks`` is empty (the
    default for every permit that has not explicitly opted in), this
    returns ``report`` completely unchanged -- no discovery fetch, no
    probe, nothing observably different from passive-only execution.
    """

    if not active_checks:
        return report

    detectors = [
        (check_id, ACTIVE_DETECTOR_REGISTRY[check_id])
        for check_id in active_checks
        if check_id in ACTIVE_DETECTOR_REGISTRY
    ]
    if not detectors:
        return report

    context = ActiveDetectionContext(
        scan_id=scan_id,
        authorization_id=authorization_id,
        permit_id=permit_id,
        permit_fingerprint=permit_fingerprint,
    )
    policy = ActiveDetectionPolicy(
        fetch_policy=fetch_policy,
        maximum_probe_requests=MAXIMUM_DISCOVERED_CANDIDATES,
    )

    def cancellation_check() -> bool:
        return cancellation_token.is_cancelled

    if hasattr(report, "pages"):
        changed = False
        updated_pages = []
        for page in report.pages:
            if (
                cancellation_check()
                or page.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES
            ):
                updated_pages.append(page)
                continue
            active_findings = _discover_and_detect_page(
                target,
                page.url,
                detectors,
                context,
                policy,
                safety,
                cancellation_check,
                restrict_to_page_path=urlsplit(page.url).path or "/",
            )
            if not active_findings:
                updated_pages.append(page)
                continue
            changed = True
            updated_pages.append(
                dataclasses_replace(
                    page,
                    findings=page.findings + tuple(active_findings),
                )
            )
        if not changed:
            return report
        return dataclasses_replace(report, pages=tuple(updated_pages))

    if (
        report.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES
        or cancellation_check()
    ):
        return report
    active_findings = _discover_and_detect_page(
        target,
        target.normalised_url,
        detectors,
        context,
        policy,
        safety,
        cancellation_check,
    )
    if not active_findings:
        return report
    return dataclasses_replace(
        report,
        findings=report.findings + tuple(active_findings),
    )


class JobExecutionError(ValueError):
    """Controlled service-side execution failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.safety_receipt_ref = safety_receipt_ref
        self.safety_receipt_sha256 = safety_receipt_sha256


@dataclass(frozen=True, slots=True)
class JobExecutionOutcome:
    """Result and safe relative artifact references from one worker run."""

    report: WebGuardReport
    report_ref: str
    audit_ref: str
    safety_receipt_ref: str | None = None
    safety_receipt_sha256: str | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_create_failed",
            f"Unable to create private artifact directory {path}.",
        ) from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_inspection_failed",
            f"Unable to inspect artifact directory {path}.",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise JobExecutionError(
            "artifact_directory_invalid",
            "Artifact directories must be real directories, not links.",
        )
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_permissions_failed",
            "Unable to apply owner-only artifact directory permissions.",
        ) from exc


def _write_report(report: WebGuardReport, path: Path) -> None:
    try:
        exists = os.path.lexists(path)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_path_inspection_failed",
            f"Unable to inspect report path {path}.",
        ) from exc
    if exists:
        raise JobExecutionError(
            "artifact_path_exists",
            "A service job artifact path already exists.",
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            descriptor = None
            output.write(report.to_json())
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise JobExecutionError(
            "artifact_write_failed",
            f"Unable to write scan report {path}.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_signed_safety_receipt(receipt, path: Path) -> str:
    document = receipt.to_json() + "\n"
    try:
        exists = os.path.lexists(path)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_path_inspection_failed",
            f"Unable to inspect safety receipt path {path}.",
        ) from exc
    if exists:
        raise JobExecutionError(
            "artifact_path_exists",
            "A service job artifact path already exists.",
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = None
            output.write(document)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise JobExecutionError(
            "artifact_write_failed",
            f"Unable to write TrustScan safety receipt {path}.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return receipt.fingerprint


class ScanJobExecutor:
    """Execute one validated, server-authorized passive scanner job."""

    def __init__(
        self,
        *,
        authorizations: AuthorizationRepository,
        store: ScanJobStore,
        trustscan_signer: TrustScanSigner,
        artifact_directory: Path,
        clock: Callable[[], datetime] = _utc_now,
        single_scanner: Callable[..., WebGuardReport] = run_passive_header_scan,
        crawl_scanner: Callable[..., WebGuardReport] = run_passive_crawl_scan,
        organization_resolver: Callable[[str], str | None] | None = None,
        authorization_assignment_checker: (
            Callable[[str, str], bool] | None
        ) = None,
    ) -> None:
        self.authorizations = authorizations
        self.store = store
        self.trustscan_signer = trustscan_signer
        self.artifact_directory = Path(artifact_directory).expanduser()
        self.clock = clock
        self.single_scanner = single_scanner
        self.crawl_scanner = crawl_scanner
        self.organization_resolver = organization_resolver
        self.authorization_assignment_checker = (
            authorization_assignment_checker
        )

    def _policies(self, authorization, permit, mode: ScanJobMode):
        limits = authorization.limits
        claims = permit.permit.claims
        fetch_policy = FetchPolicy(
            timeout_seconds=min(10.0, limits.timeout_seconds),
            maximum_body_bytes=min(1_048_576, limits.maximum_body_bytes),
            maximum_header_bytes=min(65_536, limits.maximum_header_bytes),
            maximum_header_count=min(100, limits.maximum_header_count),
            allowed_methods=frozenset(claims.allowed_http_methods),
        )
        retry_policy = RetryPolicy(maximum_attempts=1)
        if mode is ScanJobMode.SINGLE_PAGE:
            return fetch_policy, retry_policy, None
        crawl_policy = CrawlPolicy(
            maximum_pages=min(OWNED_DEFAULT_CRAWL_PAGES, limits.maximum_pages),
            maximum_depth=min(OWNED_DEFAULT_CRAWL_DEPTH, limits.maximum_depth),
            maximum_links_per_page=min(
                OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
                limits.maximum_links_per_page,
            ),
            minimum_delay_seconds=max(
                OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
                limits.minimum_delay_seconds,
                1.0 / claims.maximum_requests_per_second,
            ),
            maximum_execution_seconds=min(
                OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
                limits.maximum_execution_seconds,
            ),
            maximum_request_attempts=min(
                OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
                limits.maximum_request_attempts,
                claims.maximum_request_attempts,
            ),
        )
        return fetch_policy, retry_policy, crawl_policy

    def execute(
        self,
        record: ScanJobRecord,
        *,
        cancellation_token: CrawlCancellationToken | None = None,
    ) -> JobExecutionOutcome:
        if record.state.value != "running":
            raise JobExecutionError(
                "job_not_running",
                "Only a running job can be executed.",
            )
        if cancellation_token is not None and cancellation_token.is_cancelled:
            raise JobExecutionError(
                "job_cancelled_before_execution",
                "The job was cancelled before scanner execution.",
            )
        try:
            authorization = self.authorizations.get(record.request.authorization_id)
        except AuthorizationRepositoryError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc
        if authorization.fingerprint != record.request.authorization_sha256:
            raise JobExecutionError(
                "authorization_changed_after_submission",
                "The server-side authorization changed after the job was submitted.",
            )
        if authorization.target != record.request.target:
            raise JobExecutionError(
                "authorization_target_mismatch",
                "The job target no longer matches the server-side authorization.",
            )
        scope = self.store.get_scope(record.job_id)
        if scope is None:
            raise JobExecutionError(
                "trustscan_job_scope_missing",
                "The service job does not contain organization scope metadata.",
            )
        if self.authorization_assignment_checker is not None:
            try:
                assignment_current = (
                    self.authorization_assignment_checker(
                        scope[0],
                        record.request.authorization_id,
                    )
                )
            except Exception as exc:
                raise JobExecutionError(
                    "authorization_assignment_check_failed",
                    (
                        "Unable to verify the organization "
                        "authorization assignment."
                    ),
                ) from exc

            if not assignment_current:
                raise JobExecutionError(
                    "authorization_not_assigned",
                    (
                        "The authorization is no longer assigned "
                        "to this organization."
                    ),
                )

        binding = self.store.get_job_permit_binding(record.job_id)
        if binding is None:
            raise JobExecutionError(
                "trustscan_permit_missing",
                "The service job is not bound to a TrustScan permit.",
            )
        try:
            permit = self.store.get_scan_permit_scoped(binding[0], scope[0])
        except JobStoreError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc
        if permit.permit.fingerprint != binding[1]:
            raise JobExecutionError(
                "trustscan_permit_binding_changed",
                "The job TrustScan permit fingerprint does not match the persisted permit.",
            )
        try:
            validate_permit_use(
                permit,
                signer=self.trustscan_signer,
                organization_id=scope[0],
                authorization=authorization,
                target=record.request.target,
                mode=record.request.mode,
                now=self.clock(),
            )
        except TrustScanPermitError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc

        try:
            target = validate_target_url(
                record.request.target,
                ValidationPolicy(mode=ValidationMode.COMMERCIAL),
            )
        except ValueError as exc:
            raise JobExecutionError(
                getattr(exc, "code", "target_validation_failed"),
                str(exc),
            ) from exc

        fetch_policy, retry_policy, crawl_policy = self._policies(
            authorization,
            permit,
            record.request.mode,
        )
        scan_id = str(uuid4())
        try:
            preflight = validate_owned_target_preflight(
                authorization,
                target,
                confirmation=authorization.authorization_id,
                scan_id=scan_id,
                fetch_policy=fetch_policy,
                retry_policy=retry_policy,
                crawl_policy=crawl_policy,
                now=self.clock(),
            )
        except ValueError as exc:
            raise JobExecutionError(
                getattr(exc, "code", "owned_target_preflight_failed"),
                str(exc),
            ) from exc

        if cancellation_token is not None and cancellation_token.is_cancelled:
            raise JobExecutionError(
                "job_cancelled_before_execution",
                "The job was cancelled before scanner execution.",
            )

        organization_id = (
            None
            if self.organization_resolver is None
            else self.organization_resolver(record.job_id)
        )
        relative_directory = (
            Path("jobs") / record.job_id
            if organization_id is None
            else Path("organizations") / organization_id / "jobs" / record.job_id
        )
        report_ref = (relative_directory / "report.json").as_posix()
        audit_ref = (relative_directory / "authorization-audit.json").as_posix()
        safety_receipt_ref = (relative_directory / "trustscan-safety-receipt.json").as_posix()
        _prepare_private_directory(self.artifact_directory)
        job_directory = self.artifact_directory / relative_directory
        _prepare_private_directory(job_directory)
        report_path = self.artifact_directory / report_ref
        audit_path = self.artifact_directory / audit_ref
        safety_receipt_path = self.artifact_directory / safety_receipt_ref

        try:
            write_owned_target_audit_file(
                preflight.audit_record,
                audit_path,
                overwrite=False,
            )
        except OwnedTargetContractError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc

        def revalidate_runtime_permission() -> None:
            try:
                current_authorization = self.authorizations.get(
                    record.request.authorization_id
                )
            except AuthorizationRepositoryError as exc:
                raise TrustScanPermitError(exc.code, exc.message) from exc
            if current_authorization.fingerprint != authorization.fingerprint:
                raise TrustScanPermitError(
                    "authorization_changed_during_execution",
                    "The server-side authorization changed during scanner execution.",
                )
            if self.authorization_assignment_checker is not None:
                try:
                    assignment_current = (
                        self.authorization_assignment_checker(
                            scope[0],
                            record.request.authorization_id,
                        )
                    )
                except Exception as exc:
                    raise TrustScanPermitError(
                        "authorization_assignment_check_failed",
                        (
                            "Unable to verify the organization "
                            "authorization assignment."
                        ),
                    ) from exc

                if not assignment_current:
                    raise TrustScanPermitError(
                        "authorization_not_assigned",
                        (
                            "The authorization is no longer assigned "
                            "to this organization."
                        ),
                    )

            current_binding = self.store.get_job_permit_binding(record.job_id)
            if current_binding is None or current_binding != binding:
                raise TrustScanPermitError(
                    "trustscan_permit_binding_changed",
                    "The job TrustScan permit binding changed during execution.",
                )
            try:
                current_permit = self.store.get_scan_permit_scoped(
                    binding[0], scope[0]
                )
            except JobStoreError as exc:
                raise TrustScanPermitError(exc.code, exc.message) from exc
            if current_permit.permit.fingerprint != binding[1]:
                raise TrustScanPermitError(
                    "trustscan_permit_binding_changed",
                    "The persisted TrustScan permit changed during execution.",
                )
            validate_permit_use(
                current_permit,
                signer=self.trustscan_signer,
                organization_id=scope[0],
                authorization=current_authorization,
                target=record.request.target,
                mode=record.request.mode,
                now=self.clock(),
            )

        safety = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=self.trustscan_signer,
            organization_id=scope[0],
            job_id=record.job_id,
            scan_id=scan_id,
            target=record.request.target,
            revalidate=revalidate_runtime_permission,
            clock=self.clock,
        )

        token = cancellation_token or CrawlCancellationToken()
        try:
            if crawl_policy is None:
                report = self.single_scanner(
                    target,
                    fetch_policy=fetch_policy,
                    retry_policy=retry_policy,
                    scan_id=scan_id,
                    before_request=safety.before_request,
                    after_request=safety.after_request,
                )
            else:
                report = self.crawl_scanner(
                    target,
                    crawl_policy=crawl_policy,
                    fetch_policy=fetch_policy,
                    retry_policy=retry_policy,
                    scan_id=scan_id,
                    cancellation_token=token,
                    before_request=safety.before_request,
                    after_request=safety.after_request,
                )
            report = _apply_active_detection(
                report,
                target=target,
                active_checks=permit.permit.claims.active_checks,
                scan_id=scan_id,
                authorization_id=record.request.authorization_id,
                permit_id=permit.permit.claims.permit_id,
                permit_fingerprint=permit.permit.fingerprint,
                fetch_policy=fetch_policy,
                safety=safety,
                cancellation_token=token,
            )
        except TrustScanRuntimeSafetyError as exc:
            receipt = safety.signed_receipt(termination_reason="safety_blocked")
            digest = _write_signed_safety_receipt(receipt, safety_receipt_path)
            raise JobExecutionError(
                exc.code,
                exc.message,
                safety_receipt_ref=safety_receipt_ref,
                safety_receipt_sha256=digest,
            ) from exc

        receipt = safety.signed_receipt(termination_reason=report.status.value)
        _write_report(report, report_path)
        digest = _write_signed_safety_receipt(receipt, safety_receipt_path)
        return JobExecutionOutcome(
            report=report,
            report_ref=report_ref,
            audit_ref=audit_ref,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=digest,
        )


__all__ = [
    "JobExecutionError",
    "JobExecutionOutcome",
    "ScanJobExecutor",
]
