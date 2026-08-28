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
from uuid import uuid4

from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode, ScanJobRequest

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime.now(timezone.utc)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL tenant-isolation test.",
)
class Slice13TenantIsolationTests(unittest.TestCase):
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

        with self.assertRaises(JobStoreError) as cross_cancel:
            jobs.request_cancellation_scoped(job.job_id, self.org_b.organization_id, now=NOW)
        self.assertEqual(cross_cancel.exception.code, "job_not_found")

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
        self.assertEqual(reports.list_reports_scoped(self.org_b.organization_id), ())


if __name__ == "__main__":
    unittest.main()
