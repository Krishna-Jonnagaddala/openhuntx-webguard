"""Contract tests for the Slice 13 live-wired repositories (requirement
9, applied to jobs/scans/findings): identical test bodies against the
SQLite/in-memory backend and PostgreSQL, proving domain behavior is
independent of backend for the entities the production runtime
actually serves live.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanStatus,
)

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)
NOW = datetime.now(timezone.utc)


class JobRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def make_organization_and_owner(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def assign_authorization(self, organization_id: str, authorization_id: str, owner_id: str) -> None:
        # pragma: no cover - overridden
        raise NotImplementedError

    def _submit_claimable_job(self, jobs, organization_id, owner_id, *, idempotency_key=None):
        """A job that can actually be claimed: its authorization is
        genuinely assigned to the organization, matching both backends'
        real claim-eligibility predicate (requirement 3's safety
        property -- see PostgresJobRepository.claim_next_leased's
        module comment)."""

        authorization_id = str(uuid4())
        self.assign_authorization(organization_id, authorization_id, owner_id)
        request = ScanJobRequest(
            idempotency_key=idempotency_key or f"contract-claimable-{uuid4().hex}",
            target="https://contract.example/",
            authorization_id=authorization_id,
            authorization_sha256="a" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        record, created = jobs.submit(request, organization_id=organization_id, submitted_by=owner_id)
        return record, created

    def test_submit_is_idempotent_on_retry(self) -> None:
        jobs = self.make_repository()
        organization_id, owner_id = self.make_organization_and_owner()
        request = ScanJobRequest(
            idempotency_key=f"contract-idem-{uuid4().hex}",
            target="https://contract.example/",
            authorization_id=str(uuid4()),
            authorization_sha256="a" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        first, created_first = jobs.submit(request, organization_id=organization_id, submitted_by=owner_id)
        second, created_second = jobs.submit(request, organization_id=organization_id, submitted_by=owner_id)
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(first.job_id, second.job_id)

    def test_claim_next_leased_is_atomic_under_concurrent_workers(self) -> None:
        import threading

        jobs = self.make_repository()
        organization_id, owner_id = self.make_organization_and_owner()
        job_ids = []
        for i in range(3):
            record, _ = self._submit_claimable_job(jobs, organization_id, owner_id)
            job_ids.append(record.job_id)

        results = []
        lock = threading.Lock()

        def worker(worker_id: str) -> None:
            leased = jobs.claim_next_leased(now=datetime.now(timezone.utc), worker_id=worker_id, lease_seconds=30)
            with lock:
                results.append(leased.record.job_id if leased else None)

        threads = [threading.Thread(target=worker, args=(f"contract-worker-{i}",)) for i in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [job_id for job_id in results if job_id is not None]
        self.assertEqual(len(winners), 3)
        self.assertEqual(len(set(winners)), 3)

    def test_terminal_transition_requires_a_current_lease(self) -> None:
        jobs = self.make_repository()
        organization_id, owner_id = self.make_organization_and_owner()
        record, _ = self._submit_claimable_job(jobs, organization_id, owner_id)
        leased = jobs.claim_next_leased(now=NOW, worker_id="contract-worker", lease_seconds=30)
        self.assertEqual(leased.record.job_id, record.job_id)

        from webguard_api.store import JobStoreError

        with self.assertRaises(JobStoreError) as caught:
            jobs.finish_result_leased(
                record.job_id, worker_id="contract-worker", lease_token="wrong-token",
                scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
                report_ref="reports/x.json", audit_ref="audit/x.json", now=NOW,
            )
        self.assertEqual(caught.exception.code, "job_lease_lost")

        finished = jobs.finish_result_leased(
            record.job_id, worker_id=leased.worker_id, lease_token=leased.lease_token,
            scan_id=str(uuid4()), result_status=ScanStatus.COMPLETED,
            report_ref="reports/x.json", audit_ref="audit/x.json", now=NOW,
        )
        self.assertEqual(finished.state.value, "completed")


class SqliteJobRepositoryContractTests(JobRepositoryContractMixin, unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.identity import IdentityStore
        from webguard_api.store import ScanJobStore

        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self._db_path = Path(self._tempdir.name) / "jobs.sqlite3"
        self._store = ScanJobStore(self._db_path)
        self._identity = IdentityStore(self._db_path)

    def make_repository(self):
        return self._store

    def make_organization_and_owner(self):
        org = self._identity.create_organization(f"Contract Org {uuid4()}", now=NOW)
        owner = self._identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        return org.organization_id, owner.principal_id

    def assign_authorization(self, organization_id: str, authorization_id: str, owner_id: str) -> None:
        self._identity.assign_authorization(organization_id, authorization_id, assigned_by=owner_id, now=NOW)


@unittest.skipUnless(
    RUN_POSTGRES_TESTS, "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test."
)
class PostgresJobRepositoryContractTests(JobRepositoryContractMixin, unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=15)
        self.addCleanup(self._pool.close)
        with self._pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self._identity = PostgresIdentityRepository(self._pool)
        self._jobs = PostgresJobRepository(self._pool)

    def make_repository(self):
        return self._jobs

    def make_organization_and_owner(self):
        org = self._identity.create_organization(f"Contract Org {uuid4()}", now=NOW)
        owner = self._identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        return org.organization_id, owner.principal_id

    def assign_authorization(self, organization_id: str, authorization_id: str, owner_id: str) -> None:
        self._identity.assign_authorization(organization_id, authorization_id, assigned_by=owner_id, now=NOW)

    def test_failing_a_job_reconciles_its_incomplete_scan_record(self) -> None:
        """Slice 14 requirements 7-8: a job reaching FAILED must not
        leave an associated scan record stuck incomplete forever -- the
        reconciliation in `_terminal_update` runs in the same
        transaction as the job's own terminal write."""

        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self._pool)
        organization_id, owner_id = self.make_organization_and_owner()
        record, _ = self._submit_claimable_job(self._jobs, organization_id, owner_id)
        leased = self._jobs.claim_next_leased(now=NOW, worker_id="contract-worker", lease_seconds=30)
        self.assertEqual(leased.record.job_id, record.job_id)

        scan = scans.create_scan(
            organization_id=organization_id, job_id=record.job_id, target="https://contract.example/",
            authorization_id=leased.record.request.authorization_id, mode="single_page",
            scanner_version="1.0", now=NOW,
        )
        self.assertIsNone(scan.completed_at)

        self._jobs.fail_leased(
            record.job_id, worker_id=leased.worker_id, lease_token=leased.lease_token,
            error_code="worker_internal_error", error_message="simulated failure", now=NOW,
        )

        reread = scans.get_scan_scoped(scan.scan_id, organization_id=organization_id)
        self.assertEqual(reread.status, "failed")
        self.assertIsNotNone(reread.completed_at)

    def test_cancelling_a_job_reconciles_its_incomplete_scan_record(self) -> None:
        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self._pool)
        organization_id, owner_id = self.make_organization_and_owner()
        record, _ = self._submit_claimable_job(self._jobs, organization_id, owner_id)
        leased = self._jobs.claim_next_leased(now=NOW, worker_id="contract-worker", lease_seconds=30)

        scan = scans.create_scan(
            organization_id=organization_id, job_id=record.job_id, target="https://contract.example/",
            authorization_id=leased.record.request.authorization_id, mode="single_page",
            scanner_version="1.0", now=NOW,
        )

        self._jobs.cancel_running_leased(
            record.job_id, worker_id=leased.worker_id, lease_token=leased.lease_token, now=NOW,
        )

        reread = scans.get_scan_scoped(scan.scan_id, organization_id=organization_id)
        self.assertEqual(reread.status, "cancelled")
        self.assertIsNotNone(reread.completed_at)

    def test_scan_record_cannot_reference_a_nonexistent_job(self) -> None:
        """Requirement 7's first invariant ("a submitted scan cannot
        exist without its initial job") is enforced by the database's
        own foreign key, not merely by application convention."""

        from webguard_api.db_errors import DatabaseIntegrityError
        from webguard_api.postgres_scans import PostgresScanRepository

        scans = PostgresScanRepository(self._pool)
        organization_id, _ = self.make_organization_and_owner()
        with self.assertRaises(DatabaseIntegrityError):
            scans.create_scan(
                organization_id=organization_id, job_id=str(uuid4()), target="https://contract.example/",
                authorization_id=str(uuid4()), mode="single_page", scanner_version="1.0", now=NOW,
            )


class ScanRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def test_create_and_complete_scan_lifecycle(self) -> None:
        scans = self.make_repository()
        organization_id = str(uuid4())
        scan = scans.create_scan(
            organization_id=organization_id, job_id=str(uuid4()), target="https://contract.example/",
            authorization_id=str(uuid4()), mode="single_page", scanner_version="1.0", now=NOW,
        )
        self.assertEqual(scan.status, "running")
        completed = scans.complete_scan(
            scan.scan_id, organization_id=organization_id, status="completed",
            report_ref="reports/x.json", finding_count=2, now=NOW,
        )
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.finding_count, 2)


class InMemoryScanRepositoryContractTests(ScanRepositoryContractMixin, unittest.TestCase):
    def make_repository(self):
        from webguard_api.scan_store import InMemoryScanRepository

        return InMemoryScanRepository()


@unittest.skipUnless(
    RUN_POSTGRES_TESTS, "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test."
)
class PostgresScanRepositoryContractTests(ScanRepositoryContractMixin, unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_scans import PostgresScanRepository

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=8)
        self.addCleanup(self._pool.close)
        with self._pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self._identity = PostgresIdentityRepository(self._pool)
        self._jobs = PostgresJobRepository(self._pool)
        self._scans = PostgresScanRepository(self._pool)

    def make_repository(self):
        return _ScanRepositoryWithRealJob(self._scans, self._jobs, self._identity)


class _ScanRepositoryWithRealJob:
    """`scan_records` FK-constrains organization_id/job_id to real
    rows; this wrapper creates them transparently so the shared
    contract-test body (which mints arbitrary UUIDs, matching the
    in-memory backend's lack of FK constraints) works unmodified
    against Postgres."""

    def __init__(self, scans, jobs, identity) -> None:
        self._scans = scans
        self._jobs = jobs
        self._identity = identity
        self._real_organization_ids: dict[str, str] = {}

    def create_scan(self, *, organization_id, job_id, **kwargs):
        org = self._identity.create_organization(f"Scan Contract Org {uuid4()}", now=NOW)
        self._real_organization_ids[organization_id] = org.organization_id
        owner = self._identity.create_principal(
            org.organization_id, "Owner", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW,
        )
        request = ScanJobRequest(
            idempotency_key=f"scan-contract-{uuid4().hex}",
            target=kwargs.get("target", "https://contract.example/"),
            authorization_id=kwargs.get("authorization_id", str(uuid4())),
            authorization_sha256="a" * 64,
            mode=ScanJobMode.SINGLE_PAGE,
            submitted_at=NOW,
        )
        job, _ = self._jobs.submit(request, organization_id=org.organization_id, submitted_by=owner.principal_id)
        return self._scans.create_scan(organization_id=org.organization_id, job_id=job.job_id, **kwargs)

    def complete_scan(self, scan_id, *, organization_id, **kwargs):
        real_organization_id = self._real_organization_ids.get(organization_id, organization_id)
        return self._scans.complete_scan(scan_id, organization_id=real_organization_id, **kwargs)


class FindingRepositoryContractMixin:
    def make_repository(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def _record(self, findings, **overrides):
        defaults = dict(
            organization_id=str(uuid4()),
            scan_id=str(uuid4()),
            fingerprint=f"fp-{uuid4()}",
            check_id="active.sqli.error",
            scanner_version="1.0",
            title="SQLi",
            severity="high",
            confidence="confirmed",
            asset="https://contract.example",
            endpoint="/x",
            http_method="GET",
            now=NOW,
        )
        defaults.update(overrides)
        return findings.record_finding(**defaults)

    def test_same_fingerprint_dedupes_to_one_finding(self) -> None:
        findings = self.make_repository()
        organization_id = str(uuid4())
        fingerprint = f"fp-{uuid4()}"
        first = self._record(findings, organization_id=organization_id, fingerprint=fingerprint)
        second = self._record(findings, organization_id=organization_id, fingerprint=fingerprint)
        self.assertEqual(first.finding_id, second.finding_id)

    def test_different_organization_same_fingerprint_is_independent(self) -> None:
        findings = self.make_repository()
        fingerprint = f"fp-{uuid4()}"
        first = self._record(findings, organization_id=str(uuid4()), fingerprint=fingerprint)
        second = self._record(findings, organization_id=str(uuid4()), fingerprint=fingerprint)
        self.assertNotEqual(first.finding_id, second.finding_id)

    def test_resolved_finding_reopens_on_redetection(self) -> None:
        from webguard_api.finding_store import FindingStatus

        findings = self.make_repository()
        organization_id = str(uuid4())
        fingerprint = f"fp-{uuid4()}"
        finding = self._record(findings, organization_id=organization_id, fingerprint=fingerprint)
        findings.update_status(
            finding.finding_id, organization_id=organization_id, new_status=FindingStatus.RESOLVED, now=NOW
        )
        reappeared = self._record(findings, organization_id=organization_id, fingerprint=fingerprint)
        self.assertEqual(reappeared.status, FindingStatus.REOPENED)


class InMemoryFindingRepositoryContractTests(FindingRepositoryContractMixin, unittest.TestCase):
    def make_repository(self):
        from webguard_api.finding_store import InMemoryFindingRepository

        return InMemoryFindingRepository()


@unittest.skipUnless(
    RUN_POSTGRES_TESTS, "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL contract test."
)
class PostgresFindingRepositoryContractTests(FindingRepositoryContractMixin, unittest.TestCase):
    def setUp(self) -> None:
        from webguard_api.postgres_pool import WebGuardPostgresPool
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_jobs import PostgresJobRepository
        from webguard_api.postgres_scans import PostgresScanRepository
        from webguard_api.postgres_findings import PostgresFindingRepository

        self._pool = WebGuardPostgresPool(POSTGRES_TEST_DSN, maximum_connections=8)
        self.addCleanup(self._pool.close)
        with self._pool.connection() as connection:
            connection.execute("TRUNCATE organizations CASCADE")
        self._identity = PostgresIdentityRepository(self._pool)
        self._jobs = PostgresJobRepository(self._pool)
        self._scans = PostgresScanRepository(self._pool)
        self._findings = PostgresFindingRepository(self._pool)

    def make_repository(self):
        return _FindingRepositoryWithRealScan(self._findings, self._scans, self._jobs, self._identity)


class _FindingRepositoryWithRealScan:
    """`findings` FK-constrains organization_id/scan_id to real rows;
    this wrapper transparently creates a fresh organization + job +
    scan per distinct (organization_id, scan_id) pair the shared
    contract-test body supplies."""

    def __init__(self, findings, scans, jobs, identity) -> None:
        self._findings = findings
        self._scans = scans
        self._jobs = jobs
        self._identity = identity
        self._organizations: dict[str, str] = {}
        self._scan_ids: dict[str, str] = {}

    def _real_organization(self, requested_organization_id: str) -> str:
        if requested_organization_id not in self._organizations:
            org = self._identity.create_organization(f"Finding Contract Org {uuid4()}", now=NOW)
            self._organizations[requested_organization_id] = org.organization_id
        return self._organizations[requested_organization_id]

    def _real_scan(self, requested_organization_id: str, requested_scan_id: str) -> str:
        key = (requested_organization_id, requested_scan_id)
        if requested_scan_id not in self._scan_ids:
            real_org_id = self._real_organization(requested_organization_id)
            owner = self._identity.create_principal(
                real_org_id, "Owner", principal_type=PrincipalType.USER,
                role=OrganizationRole.OWNER, now=NOW,
            )
            request = ScanJobRequest(
                idempotency_key=f"finding-contract-{uuid4().hex}",
                target="https://contract.example/",
                authorization_id=str(uuid4()),
                authorization_sha256="a" * 64,
                mode=ScanJobMode.SINGLE_PAGE,
                submitted_at=NOW,
            )
            job, _ = self._jobs.submit(request, organization_id=real_org_id, submitted_by=owner.principal_id)
            scan = self._scans.create_scan(
                organization_id=real_org_id, job_id=job.job_id, target=request.target,
                authorization_id=request.authorization_id, mode="single_page",
                scanner_version="1.0", now=NOW,
            )
            self._scan_ids[requested_scan_id] = scan.scan_id
        return self._scan_ids[requested_scan_id]

    def record_finding(self, *, organization_id, scan_id, **kwargs):
        real_org_id = self._real_organization(organization_id)
        real_scan_id = self._real_scan(organization_id, scan_id)
        return self._findings.record_finding(organization_id=real_org_id, scan_id=real_scan_id, **kwargs)

    def update_status(self, finding_id, *, organization_id, **kwargs):
        real_org_id = self._real_organization(organization_id)
        return self._findings.update_status(finding_id, organization_id=real_org_id, **kwargs)


if __name__ == "__main__":
    unittest.main()
