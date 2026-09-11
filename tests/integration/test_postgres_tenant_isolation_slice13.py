"""Cross-tenant negative tests for every PostgreSQL repository
introduced in Slice 13 (requirement 19): scans, jobs, schedules,
findings, authentication contexts, authorization-comparison plans, and
reports. For every one, a cross-tenant access attempt must be
indistinguishable from a genuinely unknown resource -- the identical
error code, never a distinct "forbidden" that would leak existence.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`).
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode, ScanJobRequest

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime.now(timezone.utc)

# P1-2 Phase H: claim_next_leased, renew_lease, and recover_expired_leases
# now run entirely through webguard_control functions under
# worker_tenant_data (see postgres_pool.py's role_scoped_connection and
# postgres_jobs.py's own methods), so this test's own job-claiming
# section needs the same role/ACL/function/runtime-grant bootstrap
# tests/contract/test_identity_repository_contract.py's own setUpClass
# applies, in the same order.
_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
_ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
_TENANT_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
_FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
_CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"
_RUNTIME_GRANT_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_runtime_grant.sql"
_ALL_BOOTSTRAP_ROLES = (
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL tenant-isolation test.",
)
class Slice13TenantIsolationTests(unittest.TestCase):
    @classmethod
    def _connect(cls):
        import psycopg

        return psycopg.connect(POSTGRES_TEST_DSN)

    @classmethod
    def setUpClass(cls) -> None:
        for sql_path in (
            _ROLES_SQL_PATH,
            _TENANT_ACL_SQL_PATH,
            _FUNCTION_ACL_SQL_PATH,
            _CONTROL_FUNCTIONS_SQL_PATH,
            _RUNTIME_GRANT_SQL_PATH,
        ):
            with cls._connect() as connection:
                connection.execute(sql_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        with cls._connect() as connection:
            connection.autocommit = True
            connection.execute("DROP SCHEMA IF EXISTS webguard_control CASCADE")
            for role in _ALL_BOOTSTRAP_ROLES:
                connection.execute(f'DROP OWNED BY "{role}"')
                connection.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository

        self.pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=8)
        self.addCleanup(self.pool.close)
        with self.pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self.identity = PostgresIdentityRepository(self.pool)
        self.org_a = self.identity.create_organization(f"Org A {uuid4()}", now=NOW)
        self.org_b = self.identity.create_organization(f"Org B {uuid4()}", now=NOW)
        self.owner_a = self.identity.create_principal(
            self.org_a.organization_id, "Owner A", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )

    def _submit_job_for_org_a(self, jobs):
        req = ScanJobRequest(
            idempotency_key=f"tenant-isolation-{uuid4().hex}",
            target="https://tenant-iso.example/",
            authorization_id=str(uuid4()),
            authorization_sha256="a" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        record, _ = jobs.submit(req, organization_id=self.org_a.organization_id, submitted_by=self.owner_a.principal_id)
        return record

    def test_jobs_cross_tenant_read_and_cancel_fail_closed(self) -> None:
        """P1-C1 correction round: explicitly proves ``get_scoped`` --
        the primary tenant-facing job lookup whose atomic-scoping fix
        the P1-C1 report named as one of its two highest-traffic
        corrections -- both fails closed for ORG_B against an ORG_A job
        AND still succeeds for ORG_A itself, immediately after the
        cross-org attempt, so a wrong-org read can never be mistaken for
        having silently broken the correct-org path too."""

        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.store import JobStoreError

        jobs = PostgresJobRepository(self.pool)
        job = self._submit_job_for_org_a(jobs)

        with self.assertRaises(JobStoreError) as own_org_missing:
            jobs.get_scoped(str(uuid4()), self.org_a.organization_id)
        with self.assertRaises(JobStoreError) as cross_org:
            jobs.get_scoped(job.job_id, self.org_b.organization_id)
        self.assertEqual(own_org_missing.exception.code, "job_not_found")
        self.assertEqual(cross_org.exception.code, "job_not_found")

        # Explicit correct-org proof: the same job_id, same method,
        # immediately after the cross-org attempt above, must still
        # resolve correctly for its real owner.
        own_org_record = jobs.get_scoped(job.job_id, self.org_a.organization_id)
        self.assertEqual(own_org_record.job_id, job.job_id)

        with self.assertRaises(JobStoreError) as cross_cancel:
            jobs.request_cancellation_scoped(job.job_id, self.org_b.organization_id, now=NOW)
        self.assertEqual(cross_cancel.exception.code, "job_not_found")

        # The cross-org cancellation attempt must not have mutated the
        # job -- it must still be cancellable (not already cancelled)
        # under its real organization.
        still_uncancelled = jobs.get_scoped(job.job_id, self.org_a.organization_id)
        self.assertFalse(still_uncancelled.cancellation_requested)
        cancelled = jobs.request_cancellation_scoped(job.job_id, self.org_a.organization_id, now=NOW)
        self.assertTrue(cancelled.cancellation_requested)

        # The org-B listing must never show org-A's job.
        page, _ = jobs.list_jobs_scoped_page(self.org_b.organization_id, limit=10)
        self.assertNotIn(job.job_id, [record.job_id for record in page])

    def test_scans_cross_tenant_read_fails_closed(self) -> None:
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_scans import PostgresScanRepository
        from webguard_api.scan_store import ScanStoreError

        jobs = PostgresJobRepository(self.pool)
        scans = PostgresScanRepository(self.pool)
        job = self._submit_job_for_org_a(jobs)
        scan = scans.create_scan(
            organization_id=self.org_a.organization_id, job_id=job.job_id, target=job.request.target,
            authorization_id=job.request.authorization_id, mode="single_page", scanner_version="1.0", now=NOW,
        )

        with self.assertRaises(ScanStoreError) as cross_org:
            scans.get_scan_scoped(scan.scan_id, organization_id=self.org_b.organization_id)
        with self.assertRaises(ScanStoreError) as unknown:
            scans.get_scan_scoped(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_org.exception.code, "scan_not_found")
        self.assertEqual(unknown.exception.code, "scan_not_found")
        self.assertEqual(scans.list_scans_scoped(self.org_b.organization_id), ())

    def test_findings_cross_tenant_read_and_update_fail_closed(self) -> None:
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_scans import PostgresScanRepository
        from webguard_api.postgres_findings import PostgresFindingRepository
        from webguard_api.finding_store import FindingStatus, FindingStoreError

        jobs = PostgresJobRepository(self.pool)
        scans = PostgresScanRepository(self.pool)
        findings = PostgresFindingRepository(self.pool)
        job = self._submit_job_for_org_a(jobs)
        scan = scans.create_scan(
            organization_id=self.org_a.organization_id, job_id=job.job_id, target=job.request.target,
            authorization_id=job.request.authorization_id, mode="single_page", scanner_version="1.0", now=NOW,
        )
        finding = findings.record_finding(
            organization_id=self.org_a.organization_id, scan_id=scan.scan_id, fingerprint=f"fp-{uuid4()}",
            check_id="active.sqli.error", scanner_version="1.0", title="SQLi", severity="high",
            confidence="confirmed", asset="https://tenant-iso.example", endpoint="/x", http_method="GET", now=NOW,
        )

        with self.assertRaises(FindingStoreError) as cross_org:
            findings.get_finding_scoped(finding.finding_id, organization_id=self.org_b.organization_id)
        with self.assertRaises(FindingStoreError) as unknown:
            findings.get_finding_scoped(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_org.exception.code, "finding_not_found")
        self.assertEqual(unknown.exception.code, "finding_not_found")

        with self.assertRaises(FindingStoreError) as cross_update:
            findings.update_status(
                finding.finding_id, organization_id=self.org_b.organization_id,
                new_status=FindingStatus.CONFIRMED, now=NOW,
            )
        self.assertEqual(cross_update.exception.code, "finding_not_found")
        self.assertEqual(
            findings.list_findings_scoped_page(self.org_b.organization_id, limit=10)[0], ()
        )

    def test_schedules_cross_tenant_read_pause_resume_fail_closed(self) -> None:
        from webguard_api.postgres_schedules import PostgresScheduleRepository
        from webguard_api.store import JobStoreError

        schedules = PostgresScheduleRepository(self.pool)
        sched = schedules.create_schedule(
            organization_id=self.org_a.organization_id, created_by=self.owner_a.principal_id,
            name="daily", target="https://tenant-iso.example/", authorization_id=str(uuid4()),
            authorization_sha256="b" * 64, mode=ScanJobMode.SINGLE_PAGE, interval_seconds=86400,
            starts_at=NOW, now=NOW,
        )

        with self.assertRaises(JobStoreError) as cross_org:
            schedules.get_schedule_scoped(sched.schedule_id, self.org_b.organization_id)
        with self.assertRaises(JobStoreError) as unknown:
            schedules.get_schedule_scoped(str(uuid4()), self.org_b.organization_id)
        self.assertEqual(cross_org.exception.code, "schedule_not_found")
        self.assertEqual(unknown.exception.code, "schedule_not_found")

        with self.assertRaises(JobStoreError) as cross_pause:
            schedules.pause_schedule_scoped(sched.schedule_id, self.org_b.organization_id, now=NOW)
        self.assertEqual(cross_pause.exception.code, "schedule_not_found")

        page, _ = schedules.list_schedules_scoped_page(self.org_b.organization_id, limit=10)
        self.assertEqual(page, ())

    def test_authentication_contexts_cross_tenant_require_bound_fails_closed(self) -> None:
        from webguard_api.postgres_authentication_contexts import PostgresAuthenticationContextRepository
        from webguard_api.authentication_contexts import AuthenticationContextError, AuthenticationMethod

        contexts = PostgresAuthenticationContextRepository(self.pool)
        authorization_id = str(uuid4())
        ctx = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-a",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )

        with self.assertRaises(AuthenticationContextError) as cross_org:
            contexts.require_bound(
                ctx.authentication_context_id, organization_id=self.org_b.organization_id,
                target="https://tenant-iso.example/", authorization_id=authorization_id, now=NOW,
            )
        self.assertEqual(cross_org.exception.code, "authentication_context_organization_mismatch")

        with self.assertRaises(AuthenticationContextError) as cross_revoke_read:
            contexts.get_metadata(str(uuid4()))
        self.assertEqual(cross_revoke_read.exception.code, "authentication_context_not_found")

    def test_authentication_contexts_cross_tenant_scoped_read_and_revoke_fail_closed(self) -> None:
        """P1-C1: the atomically org-scoped ``get_metadata_scoped``/
        ``revoke_scoped`` pair added to close the gap where
        ``service.py``'s HTTP-facing revoke endpoint relied on a
        Python-level compare over an unscoped repository fetch (see
        ``postgres_authentication_contexts.py``). Cross-org read AND
        cross-org mutation must both fail closed, with the identical
        error a nonexistent ID produces -- and the record must remain
        un-revoked afterward."""

        from webguard_api.postgres_authentication_contexts import PostgresAuthenticationContextRepository
        from webguard_api.authentication_contexts import AuthenticationContextError, AuthenticationMethod

        contexts = PostgresAuthenticationContextRepository(self.pool)
        authorization_id = str(uuid4())
        ctx = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-a",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )

        with self.assertRaises(AuthenticationContextError) as cross_read:
            contexts.get_metadata_scoped(
                ctx.authentication_context_id, organization_id=self.org_b.organization_id
            )
        with self.assertRaises(AuthenticationContextError) as unknown_read:
            contexts.get_metadata_scoped(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_read.exception.code, "authentication_context_not_found")
        self.assertEqual(unknown_read.exception.code, "authentication_context_not_found")

        with self.assertRaises(AuthenticationContextError) as cross_revoke:
            contexts.revoke_scoped(
                ctx.authentication_context_id, organization_id=self.org_b.organization_id, now=NOW
            )
        self.assertEqual(cross_revoke.exception.code, "authentication_context_not_found")

        # The cross-org revoke attempt must not have mutated anything --
        # the context is still readable, unrevoked, under its own org.
        still_active = contexts.get_metadata_scoped(
            ctx.authentication_context_id, organization_id=self.org_a.organization_id
        )
        self.assertIsNone(still_active.revoked_at)

        # A correct-org revoke, by contrast, must succeed.
        revoked = contexts.revoke_scoped(
            ctx.authentication_context_id, organization_id=self.org_a.organization_id, now=NOW
        )
        self.assertIsNotNone(revoked.revoked_at)

    def test_comparison_plans_cross_tenant_require_bound_fails_closed(self) -> None:
        from webguard_api.postgres_authentication_contexts import PostgresAuthenticationContextRepository
        from webguard_api.postgres_authorization_comparison import PostgresAuthorizationComparisonPlanRepository
        from webguard_api.authentication_contexts import AuthenticationMethod
        from webguard_api.authorization_comparison import AuthorizationComparisonError, ResourcePairSpec

        contexts = PostgresAuthenticationContextRepository(self.pool)
        plans = PostgresAuthorizationComparisonPlanRepository(self.pool)
        authorization_id = str(uuid4())
        ctx1 = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-a",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )
        ctx2 = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-b",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )
        plan = plans.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, primary_context_id=ctx1.authentication_context_id,
            secondary_context_id=ctx2.authentication_context_id, permitted_active_check="active.idor.authorization",
            allowed_http_methods=("GET",),
            resource_scope=(
                ResourcePairSpec(
                    resource_type="basket", method="GET", primary_endpoint="/basket/1",
                    secondary_endpoint="/basket/2", identifier_location="path",
                    identifier_name="id", expected_access="private_to_owner",
                ),
            ),
            expires_at=NOW + timedelta(days=1), now=NOW,
        )

        with self.assertRaises(AuthorizationComparisonError) as cross_org:
            plans.require_bound(
                plan.comparison_plan_id, organization_id=self.org_b.organization_id,
                target="https://tenant-iso.example/", authorization_id=authorization_id, now=NOW,
            )
        self.assertEqual(cross_org.exception.code, "authorization_comparison_organization_mismatch")

        with self.assertRaises(AuthorizationComparisonError) as unknown:
            plans.get(str(uuid4()))
        self.assertEqual(unknown.exception.code, "authorization_comparison_plan_not_found")

    def test_comparison_plans_cross_tenant_scoped_read_and_revoke_fail_closed(self) -> None:
        """P1-C1: mirrors the authentication-context test above for the
        analogous ``get_scoped``/``revoke_scoped`` pair added to
        ``postgres_authorization_comparison.py``."""

        from webguard_api.postgres_authentication_contexts import PostgresAuthenticationContextRepository
        from webguard_api.postgres_authorization_comparison import PostgresAuthorizationComparisonPlanRepository
        from webguard_api.authentication_contexts import AuthenticationMethod
        from webguard_api.authorization_comparison import AuthorizationComparisonError, ResourcePairSpec

        contexts = PostgresAuthenticationContextRepository(self.pool)
        plans = PostgresAuthorizationComparisonPlanRepository(self.pool)
        authorization_id = str(uuid4())
        ctx1 = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-a",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )
        ctx2 = contexts.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, identity_label="user-b",
            method=AuthenticationMethod.COOKIE_SESSION, expires_at=NOW + timedelta(days=1), now=NOW,
        )
        plan = plans.create(
            organization_id=self.org_a.organization_id, target="https://tenant-iso.example/",
            authorization_id=authorization_id, primary_context_id=ctx1.authentication_context_id,
            secondary_context_id=ctx2.authentication_context_id, permitted_active_check="active.idor.authorization",
            allowed_http_methods=("GET",),
            resource_scope=(
                ResourcePairSpec(
                    resource_type="basket", method="GET", primary_endpoint="/basket/1",
                    secondary_endpoint="/basket/2", identifier_location="path",
                    identifier_name="id", expected_access="private_to_owner",
                ),
            ),
            expires_at=NOW + timedelta(days=1), now=NOW,
        )

        with self.assertRaises(AuthorizationComparisonError) as cross_read:
            plans.get_scoped(plan.comparison_plan_id, organization_id=self.org_b.organization_id)
        with self.assertRaises(AuthorizationComparisonError) as unknown_read:
            plans.get_scoped(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_read.exception.code, "authorization_comparison_plan_not_found")
        self.assertEqual(unknown_read.exception.code, "authorization_comparison_plan_not_found")

        with self.assertRaises(AuthorizationComparisonError) as cross_revoke:
            plans.revoke_scoped(plan.comparison_plan_id, organization_id=self.org_b.organization_id, now=NOW)
        self.assertEqual(cross_revoke.exception.code, "authorization_comparison_plan_not_found")

        still_active = plans.get_scoped(plan.comparison_plan_id, organization_id=self.org_a.organization_id)
        self.assertIsNone(still_active.revoked_at)

        revoked = plans.revoke_scoped(plan.comparison_plan_id, organization_id=self.org_a.organization_id, now=NOW)
        self.assertIsNotNone(revoked.revoked_at)

    def test_reports_cross_tenant_read_fails_closed(self) -> None:
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_scans import PostgresScanRepository
        from webguard_api.postgres_reports import PostgresReportRepository
        from webguard_api.report_store import ReportStoreError

        jobs = PostgresJobRepository(self.pool)
        scans = PostgresScanRepository(self.pool)
        reports = PostgresReportRepository(self.pool)
        job = self._submit_job_for_org_a(jobs)
        scan = scans.create_scan(
            organization_id=self.org_a.organization_id, job_id=job.job_id, target=job.request.target,
            authorization_id=job.request.authorization_id, mode="single_page", scanner_version="1.0", now=NOW,
        )
        report = reports.create_report(
            organization_id=self.org_a.organization_id, scan_id=scan.scan_id, report_ref="reports/x.json", now=NOW,
        )

        with self.assertRaises(ReportStoreError) as cross_org:
            reports.get_report_scoped(report.report_id, organization_id=self.org_b.organization_id)
        with self.assertRaises(ReportStoreError) as unknown:
            reports.get_report_scoped(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_org.exception.code, "report_not_found")
        self.assertEqual(unknown.exception.code, "report_not_found")
        records, has_more = reports.list_reports_scoped_page(self.org_b.organization_id, limit=10)
        self.assertEqual(records, ())
        self.assertFalse(has_more)

    def test_scan_permits_cross_tenant_read_fails_closed(self) -> None:
        """P1-C1: ``get_scan_permit_scoped`` -- reached directly from a
        caller-supplied HTTP path parameter via ``service.py``'s
        ``_permit_record`` -- used to fetch the permit unscoped and
        compare ``organization_id`` in Python; now the SQL predicate
        itself is scoped (see ``postgres_jobs.py``)."""

        import os

        from webguard_contracts import ScanJobMode, TrustScanPermitClaims

        from webguard_api.permits import TrustScanSigner
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.store import JobStoreError

        jobs = PostgresJobRepository(self.pool)
        signer = TrustScanSigner(os.urandom(32))
        claims = TrustScanPermitClaims(
            permit_id=str(uuid4()),
            organization_id=self.org_a.organization_id,
            authorization_id=str(uuid4()),
            authorization_sha256="c" * 64,
            target="https://tenant-iso.example/",
            issued_by=self.owner_a.principal_id,
            issued_at=NOW,
            not_before=NOW,
            expires_at=NOW + timedelta(days=7),
            permitted_modes=(ScanJobMode.SINGLE_PAGE,),
            allowed_http_methods=("GET",),
            maximum_request_attempts=3,
            maximum_requests_per_second=1.0,
            maximum_concurrency=1,
            active_checks=(),
        )
        persisted = jobs.create_scan_permit(signer.sign(claims))

        with self.assertRaises(JobStoreError) as cross_org:
            jobs.get_scan_permit_scoped(
                persisted.permit.claims.permit_id, self.org_b.organization_id
            )
        with self.assertRaises(JobStoreError) as unknown:
            jobs.get_scan_permit_scoped(str(uuid4()), self.org_b.organization_id)
        self.assertEqual(cross_org.exception.code, "trustscan_permit_not_found")
        self.assertEqual(unknown.exception.code, "trustscan_permit_not_found")

        # Correct-org read must still succeed.
        own = jobs.get_scan_permit_scoped(
            persisted.permit.claims.permit_id, self.org_a.organization_id
        )
        self.assertEqual(own.permit.claims.permit_id, persisted.permit.claims.permit_id)

    def test_target_verification_cross_tenant_read_and_mutate_fail_closed(self) -> None:
        """P1-C1 (Section 4): ``PostgresTargetVerificationRepository`` had
        no dedicated cross-tenant coverage before this slice. Every
        method already takes ``organization_id`` as an atomic SQL
        predicate -- this proves it under a real database rather than
        only by code reading."""

        from webguard_api.postgres_target_verification import PostgresTargetVerificationRepository
        from webguard_api.postgres_targets import PostgresTargetRepository
        from webguard_api.target_verification import TargetVerificationError, VerificationMethod

        targets = PostgresTargetRepository(self.pool)
        verification = PostgresTargetVerificationRepository(self.pool)
        target = targets.create_target(
            self.org_a.organization_id, "https://tenant-iso-verify.example/",
            created_by=self.owner_a.principal_id, now=NOW,
        )
        target_id = target.target_id
        initiated = verification.initiate(
            target_id, organization_id=self.org_a.organization_id,
            method=VerificationMethod.WELL_KNOWN_HTTP, now=NOW,
        )

        # Cross-org read of the current verification must see nothing.
        self.assertIsNone(
            verification.get_current(target_id, organization_id=self.org_b.organization_id)
        )
        self.assertIsNotNone(
            verification.get_current(target_id, organization_id=self.org_a.organization_id)
        )

        with self.assertRaises(TargetVerificationError) as cross_token:
            verification.get_pending_token(
                initiated.verification_id, organization_id=self.org_b.organization_id
            )
        self.assertEqual(cross_token.exception.code, "target_verification_not_found")

        with self.assertRaises(TargetVerificationError) as cross_record:
            verification.record_result(
                initiated.verification_id, organization_id=self.org_b.organization_id,
                matched=True, detail="cross-tenant-attempt", now=NOW,
            )
        self.assertEqual(cross_record.exception.code, "target_verification_not_found")

        # The cross-org mutation attempt must not have changed anything.
        still_pending = verification.get_current(target_id, organization_id=self.org_a.organization_id)
        self.assertEqual(still_pending.status.value, "pending")

        recorded = verification.record_result(
            initiated.verification_id, organization_id=self.org_a.organization_id,
            matched=True, detail="own-org-verified", now=NOW,
        )
        self.assertEqual(recorded.status.value, "verified")

    def test_targets_cross_tenant_read_update_archive_fail_closed(self) -> None:
        """P1-C1 (Section 4): ``PostgresTargetRepository`` had no
        dedicated cross-tenant coverage before this slice."""

        from webguard_api.postgres_targets import PostgresTargetRepository
        from webguard_api.targets import TargetRepositoryError

        targets = PostgresTargetRepository(self.pool)
        target = targets.create_target(
            self.org_a.organization_id, "https://tenant-iso-target.example/",
            created_by=self.owner_a.principal_id, now=NOW,
        )

        with self.assertRaises(TargetRepositoryError) as cross_read:
            targets.get_target(target.target_id, organization_id=self.org_b.organization_id)
        with self.assertRaises(TargetRepositoryError) as unknown_read:
            targets.get_target(str(uuid4()), organization_id=self.org_b.organization_id)
        self.assertEqual(cross_read.exception.code, "target_not_found")
        self.assertEqual(unknown_read.exception.code, "target_not_found")

        with self.assertRaises(TargetRepositoryError) as cross_update:
            targets.update_target(
                target.target_id, organization_id=self.org_b.organization_id, label="hijacked"
            )
        self.assertEqual(cross_update.exception.code, "target_not_found")

        with self.assertRaises(TargetRepositoryError) as cross_archive:
            targets.archive_target(target.target_id, organization_id=self.org_b.organization_id, now=NOW)
        self.assertEqual(cross_archive.exception.code, "target_not_found")

        # Neither cross-org attempt mutated the target.
        still_own = targets.get_target(target.target_id, organization_id=self.org_a.organization_id)
        self.assertIsNone(still_own.label)
        self.assertIsNone(still_own.archived_at)
        self.assertNotIn(target.target_id, [t.target_id for t in targets.list_targets(self.org_b.organization_id)])

    def _create_signed_permit_for_org_a(self, jobs):
        import os

        from webguard_contracts import TrustScanPermitClaims

        from webguard_api.permits import TrustScanSigner

        signer = TrustScanSigner(os.urandom(32))
        claims = TrustScanPermitClaims(
            permit_id=str(uuid4()),
            organization_id=self.org_a.organization_id,
            authorization_id=str(uuid4()),
            authorization_sha256="d" * 64,
            target="https://tenant-iso.example/",
            issued_by=self.owner_a.principal_id,
            issued_at=NOW,
            not_before=NOW,
            expires_at=NOW + timedelta(days=7),
            permitted_modes=(ScanJobMode.SINGLE_PAGE,),
            allowed_http_methods=("GET",),
            maximum_request_attempts=3,
            maximum_requests_per_second=1.0,
            maximum_concurrency=1,
            active_checks=(),
        )
        return jobs.create_scan_permit(signer.sign(claims))

    def test_secondary_enrichment_lookups_cross_tenant_fail_closed(self) -> None:
        """P1-C1 correction round, Section 2: ``job_permits``,
        ``job_safety_receipts``, and ``schedule_permits`` carry no
        ``organization_id`` column of their own -- tenant scope for
        these enrichment lookups can only be proven by joining to the
        authoritative job/schedule -> organization relation. Before this
        round, ``service.py`` relied on already having an org-scoped
        parent record and then called the *unscoped* binding lookups;
        that is the exact P1-1 pattern being closed here. Proves the
        new ``_scoped`` methods independently enforce tenant ownership
        for a job permit binding, a job safety receipt, and a schedule
        permit binding -- reads only (these are enrichment lookups, not
        mutations) -- with no cross-tenant existence oracle (a wrong-org
        lookup returns ``None``, identical to "no binding exists at
        all"), and that the correct-org read still succeeds afterward."""

        from webguard_contracts import ScanStatus

        from webguard_api.postgres_jobs import PostgresJobRepository

        jobs = PostgresJobRepository(self.pool)
        permit = self._create_signed_permit_for_org_a(jobs)
        permit_id = permit.permit.claims.permit_id
        permit_sha256 = permit.permit.fingerprint

        # claim_next_leased()'s claimability predicate requires the
        # job's authorization to be currently assigned to its
        # organization -- without this, the job would never be
        # claimable and the safety-receipt half of this test could
        # never proceed.
        self.identity.assign_authorization(
            self.org_a.organization_id, permit.permit.claims.authorization_id,
            assigned_by=self.owner_a.principal_id, now=NOW,
        )

        req = ScanJobRequest(
            idempotency_key=f"secondary-enrichment-{uuid4().hex}",
            target="https://tenant-iso.example/",
            authorization_id=permit.permit.claims.authorization_id,
            authorization_sha256="d" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        job, _ = jobs.submit(
            req, organization_id=self.org_a.organization_id, submitted_by=self.owner_a.principal_id,
            permit_id=permit_id, permit_sha256=permit_sha256,
        )

        # -- job permit binding -----------------------------------------
        self.assertIsNone(
            jobs.get_job_permit_binding_scoped(job.job_id, self.org_b.organization_id)
        )
        self.assertIsNone(
            jobs.get_job_permit_binding_scoped(str(uuid4()), self.org_b.organization_id)
        )
        own_binding = jobs.get_job_permit_binding_scoped(job.job_id, self.org_a.organization_id)
        self.assertEqual(own_binding, (permit_id, permit_sha256))

        # -- job safety receipt -------------------------------------------
        lease = jobs.claim_next_leased(now=NOW, worker_id="p1-c1-secondary-worker", lease_seconds=30)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.record.job_id, job.job_id)
        jobs.finish_result_leased(
            job.job_id, worker_id=lease.worker_id, lease_token=lease.lease_token,
            scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
            report_ref="secondary-enrichment.json", audit_ref="secondary-enrichment.json",
            now=NOW + timedelta(seconds=1),
            safety_receipt_ref="receipts/secondary-enrichment.json",
            safety_receipt_sha256="e" * 64,
        )
        self.assertIsNone(
            jobs.get_job_safety_receipt_scoped(job.job_id, self.org_b.organization_id)
        )
        own_receipt = jobs.get_job_safety_receipt_scoped(job.job_id, self.org_a.organization_id)
        self.assertEqual(own_receipt, ("receipts/secondary-enrichment.json", "e" * 64))

        # -- schedule permit binding --------------------------------------
        from webguard_api.postgres_schedules import PostgresScheduleRepository

        schedules = PostgresScheduleRepository(self.pool)
        schedule = schedules.create_schedule(
            organization_id=self.org_a.organization_id, created_by=self.owner_a.principal_id,
            name="secondary-enrichment", target="https://tenant-iso.example/",
            authorization_id=permit.permit.claims.authorization_id, authorization_sha256="d" * 64,
            mode=ScanJobMode.SINGLE_PAGE, interval_seconds=86400, starts_at=NOW, now=NOW,
            permit_id=permit_id, permit_sha256=permit_sha256,
        )
        self.assertIsNone(
            schedules.get_schedule_permit_binding_scoped(schedule.schedule_id, self.org_b.organization_id)
        )
        self.assertIsNone(
            schedules.get_schedule_permit_binding_scoped(str(uuid4()), self.org_b.organization_id)
        )
        own_schedule_binding = schedules.get_schedule_permit_binding_scoped(
            schedule.schedule_id, self.org_a.organization_id
        )
        self.assertEqual(own_schedule_binding, (permit_id, permit_sha256))

    def test_principal_role_and_active_mutations_are_atomically_scoped(self) -> None:
        """P1-C1 correction round, Section 7: ``update_principal_role``/
        ``set_principal_active`` already called ``get_principal_scoped``
        internally before mutating (never a bare service-layer-only
        check), but the ``UPDATE`` predicate itself did not repeat
        ``organization_id`` -- correct today only because
        ``organization_id`` is never mutated on ``principals``, not
        because the mutation was self-scoped. Both are now atomically
        scoped in their own SQL predicate. Proves a wrong-org mutation
        attempt fails closed and leaves the principal completely
        unmutated, and that the correct-org mutation still succeeds
        afterward."""

        from webguard_api.identity import IdentityStoreError

        member = self.identity.create_principal(
            self.org_a.organization_id, "Member A", principal_type=PrincipalType.USER,
            role=OrganizationRole.VIEWER, now=NOW,
        )

        with self.assertRaises(IdentityStoreError) as cross_role:
            self.identity.update_principal_role(
                member.principal_id, organization_id=self.org_b.organization_id,
                role=OrganizationRole.OWNER, now=NOW,
            )
        self.assertEqual(cross_role.exception.code, "principal_not_found")
        with self.assertRaises(IdentityStoreError) as cross_active:
            self.identity.set_principal_active(
                member.principal_id, organization_id=self.org_b.organization_id,
                active=False, now=NOW,
            )
        self.assertEqual(cross_active.exception.code, "principal_not_found")

        # Neither cross-org attempt mutated the principal.
        unchanged = self.identity.get_principal_scoped(
            member.principal_id, organization_id=self.org_a.organization_id
        )
        self.assertEqual(unchanged.role, OrganizationRole.VIEWER)
        self.assertTrue(unchanged.active)

        # The correct-org mutations still succeed.
        promoted = self.identity.update_principal_role(
            member.principal_id, organization_id=self.org_a.organization_id,
            role=OrganizationRole.ADMINISTRATOR, now=NOW,
        )
        self.assertEqual(promoted.role, OrganizationRole.ADMINISTRATOR)
        deactivated = self.identity.set_principal_active(
            member.principal_id, organization_id=self.org_a.organization_id,
            active=False, now=NOW,
        )
        self.assertFalse(deactivated.active)


if __name__ == "__main__":
    unittest.main()
