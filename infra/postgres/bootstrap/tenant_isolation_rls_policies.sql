-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): Phase G of
-- the tenant-isolation plumbing. Defines row-level-security policies
-- for every tenant-owned table, using the read-only helper Phase B
-- introduced (public.webguard_current_tenant(), migration
-- 0012_tenant_context_interpretation.sql). Run this file only after
-- tenant_isolation_roles.sql, tenant_isolation_acl.sql,
-- tenant_isolation_function_acl.sql, and
-- tenant_isolation_control_functions.sql: every role a policy targets
-- below must already exist with its Phase D/E table ACL already in
-- place.
--
-- THIS FILE DOES NOT ENABLE ROW LEVEL SECURITY ON ANY TABLE. It
-- contains CREATE POLICY only -- no ALTER TABLE ... ENABLE ROW LEVEL
-- SECURITY, no FORCE ROW LEVEL SECURITY, no DISABLE ROW LEVEL
-- SECURITY. A policy with no RLS enabled on its table is completely
-- inert: PostgreSQL only ever consults pg_policy once
-- relrowsecurity is true for that table. Running this file changes
-- nothing about what any current query can see or do; it only
-- defines the policy set a later, separate phase can turn on. Every
-- table this file targets has relrowsecurity = false and
-- relforcerowsecurity = false both before and after this file runs
-- (proven by tests.integration.test_postgres_rls_policies).
--
-- THREAT MODEL (unchanged from the rest of P1-2, restated because RLS
-- is the part of this plumbing most likely to be misread as stronger
-- than it is): this protects against an application or repository
-- bug that omits a tenant predicate it should have included. It does
-- NOT protect against a caller who can execute arbitrary SQL with the
-- runtime database credential, including one who simply runs
-- `SELECT set_config('webguard.current_organization_id', '<any
-- org>', true)` and then queries -- that GUC is intentionally
-- self-settable by any session (see postgres_pool.py's own
-- tenant_connection()/set_tenant_context()), and no policy below
-- changes that. Defending against a compromised database credential
-- or arbitrary SQL execution is a different, larger threat model this
-- phase does not claim to address.
--
-- CLASSIFICATION (all 27 tables in the schema; see the Phase-G design
-- record for the full per-table trace). Tenant OWNERSHIP and current
-- POLICY COVERAGE are two separate questions -- a table can be
-- tenant-owned today and still carry no policy yet, if no role
-- currently has any ACL on it (a policy with no grantee protects
-- nothing and would be speculative coverage ahead of a real caller).
--
-- 26 of the 27 tables are tenant-owned: 21 carry organization_id
-- directly and are given a direct equality policy against it
-- (organizations itself is the 21st direct case, using its own
-- primary key -- which happens to already be named organization_id --
-- as the tenant identifier: the same predicate shape as every other
-- direct table, not a special case in the SQL below, only in which
-- column the tenant identity happens to live in); 5 more
-- (callback_observations, job_permits, schedule_permits,
-- job_safety_receipts, password_credentials) have no organization_id
-- column of their own, and derive tenant ownership through the
-- shortest verified foreign-key path to a direct-tenant parent
-- (EXISTS subqueries below).
--
-- Of those 26 tenant-owned tables, only 25 receive a policy in this
-- file: crawl_checkpoints is tenant-owned (it carries organization_id
-- directly) but currently has ZERO ACL grantees on any role -- Phase
-- D's own file already withholds all privilege from it ("no live
-- writer or reader anywhere in this codebase"). No policy is written
-- for a table no role can currently touch: that would be speculative
-- coverage for a caller that does not exist, and Phase D's own
-- precedent already treats an unused table this way. When a future
-- phase grants crawl_checkpoints privilege to some role, that same
-- phase must add its policy here -- until then, if a future FORCE ROW
-- LEVEL SECURITY activation ever enables it with no matching policy,
-- the correct and expected result is default-deny for every caller,
-- proven by this suite's disposable-probe test rather than assumed.
--
-- auth_rate_limit_events is the one NON-tenant-owned table (27th):
-- it has no organization_id column and cannot be given one without
-- changing its schema (out of scope for this phase), it is used
-- exclusively on pre-authentication routes (register, login,
-- password-reset, email-verify, invitation-accept) where no tenant is
-- known yet, and its bucket_key is always an IP address, an email
-- address, or a principal_id -- never an organization_id, confirmed
-- by reading every call site in service.py. It is excluded from RLS
-- entirely, not merely from this file's current policy set.
--
-- CLASSIFICATION UPDATE, 2026-09-15 (5 tables added since Phase G by
-- migrations 0013-0016, none previously classified here or policied):
-- coverage_records, module_entitlements, and scoped_control_implementations
-- are direct-organization_id tenant-owned tables, each with a real ACL
-- grantee, and each now receives a policy below, the same discipline
-- Phase G applied to every other direct table (found unenforced by
-- the OpenHuntX Scope & Progress Audit, 2026-09-14, closed in this
-- pass). frameworks and master_controls (migration 0015) are global
-- reference data with no organization_id column at all, correctly
-- excluded from RLS entirely, the same treatment auth_rate_limit_events
-- already established for a genuinely non-tenant table: a "policy" on
-- either would have to be a hardcoded USING (true), and hardcoding
-- true is exactly the "unconditional ordinary-role policy" this file's
-- own test suite (test_no_unconditional_ordinary_role_policy) already
-- forbids for tenant-data roles, for the same reason it forbids it
-- everywhere else: it would mask, not implement, "this table has no
-- tenant to filter by." Current totals: 32 tables, 29 tenant-owned (28
-- policied, crawl_checkpoints still the sole zero-ACL exception), 3
-- non-tenant-owned (auth_rate_limit_events, frameworks, master_controls).
--
-- ORDINARY-ROLE POLICIES (api_tenant_data, worker_tenant_data,
-- scheduler_tenant_data) always use the tenant predicate, never
-- `USING (true)`. Every policy below is command-appropriate rather
-- than a single `FOR ALL`: a SELECT policy takes only USING, an
-- INSERT policy takes only WITH CHECK, and an UPDATE policy takes
-- BOTH USING and WITH CHECK with the identical predicate, so a tenant
-- cannot read/own a row and then UPDATE its own tenant-identifying
-- column to a different organization (WITH CHECK re-evaluates the
-- predicate against the row as it would exist AFTER the update, so a
-- mismatched new organization_id fails the same check the USING
-- clause already enforced against the row's prior state). No ordinary
-- role has DELETE granted on any RLS-managed table today (the only
-- DELETE grant anywhere is api_tenant_data on auth_rate_limit_events,
-- which is exempt from RLS), so no DELETE policy exists here.
--
-- FUNCTION-OWNER POLICIES (identity_function_owner,
-- worker_function_owner, scheduler_function_owner,
-- callback_function_owner) use `USING (true)` / `WITH CHECK (true)`,
-- but ONLY for the exact (table, command) pairs each owner's Phase-E
-- table ACL already grants -- never broader. A `true` policy does not
-- widen what these NOBYPASSRLS roles can do: Postgres checks table
-- ACL first and RLS second, so a function owner attempting a command
-- its ACL never granted is still rejected with "permission denied for
-- table," regardless of any RLS policy naming it (proven by
-- tests.integration.test_postgres_rls_policies). These `true`
-- policies exist purely so that a FUTURE FORCE ROW LEVEL SECURITY
-- activation (deferred; not part of this phase) does not silently
-- break Phase F's own control functions, which run cross-tenant by
-- design and cannot satisfy a tenant-equality predicate. This file's
-- own policy/ACL cross-check test enforces that no function-owner
-- policy's command set ever exceeds its Phase-E ACL's command set for
-- that table.
--
-- IDEMPOTENCY: PostgreSQL has no `CREATE POLICY IF NOT EXISTS` and no
-- `CREATE OR REPLACE POLICY`. Each policy below is therefore preceded
-- by a plain `DROP POLICY IF EXISTS <name> ON <table>` (never
-- CASCADE, never touching RLS enablement, never touching any other
-- policy) immediately followed by the matching `CREATE POLICY`. Since
-- no table below has RLS enabled, this drop-then-recreate pair is
-- inert either way as far as production enforcement goes; it exists
-- only to make re-running this file produce byte-identical policy
-- metadata rather than an error on the second run.
--
-- No dynamic SQL, no DO block: every statement below is a literal,
-- readable CREATE POLICY naming a fixed role and a fixed predicate,
-- matching this project's existing preference for explicit bootstrap
-- SQL over generated loops wherever the target syntax already
-- supports a direct idempotent form (unlike Phase C's CREATE ROLE,
-- DROP POLICY IF EXISTS needs no PL/pgSQL wrapper to be safe to
-- re-run).

BEGIN;

-- organizations -------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_organizations_select" ON public.organizations;
CREATE POLICY "wg_api_organizations_select" ON public.organizations
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_organizations_insert" ON public.organizations;
CREATE POLICY "wg_api_organizations_insert" ON public.organizations
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_identity_owner_organizations_select" ON public.organizations;
CREATE POLICY "wg_identity_owner_organizations_select" ON public.organizations
    FOR SELECT TO identity_function_owner
    USING (true);


-- principals ----------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_principals_select" ON public.principals;
CREATE POLICY "wg_api_principals_select" ON public.principals
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_principals_insert" ON public.principals;
CREATE POLICY "wg_api_principals_insert" ON public.principals
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_principals_update" ON public.principals;
CREATE POLICY "wg_api_principals_update" ON public.principals
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_identity_owner_principals_select" ON public.principals;
CREATE POLICY "wg_identity_owner_principals_select" ON public.principals
    FOR SELECT TO identity_function_owner
    USING (true);


-- memberships ---------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_memberships_insert" ON public.memberships;
CREATE POLICY "wg_api_memberships_insert" ON public.memberships
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- api_tokens ----------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_api_tokens_select" ON public.api_tokens;
CREATE POLICY "wg_api_api_tokens_select" ON public.api_tokens
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_api_tokens_insert" ON public.api_tokens;
CREATE POLICY "wg_api_api_tokens_insert" ON public.api_tokens
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_api_tokens_update" ON public.api_tokens;
CREATE POLICY "wg_api_api_tokens_update" ON public.api_tokens
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_identity_owner_api_tokens_select" ON public.api_tokens;
CREATE POLICY "wg_identity_owner_api_tokens_select" ON public.api_tokens
    FOR SELECT TO identity_function_owner
    USING (true);


-- organization_authorizations -----------------------------------------
DROP POLICY IF EXISTS "wg_api_organization_authorizations_select" ON public.organization_authorizations;
CREATE POLICY "wg_api_organization_authorizations_select" ON public.organization_authorizations
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_organization_authorizations_select" ON public.organization_authorizations;
CREATE POLICY "wg_worker_organization_authorizations_select" ON public.organization_authorizations
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_scheduler_organization_authorizations_select" ON public.organization_authorizations;
CREATE POLICY "wg_scheduler_organization_authorizations_select" ON public.organization_authorizations
    FOR SELECT TO scheduler_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_owner_organization_authorizations_select" ON public.organization_authorizations;
CREATE POLICY "wg_worker_owner_organization_authorizations_select" ON public.organization_authorizations
    FOR SELECT TO worker_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_organization_authorizations_select" ON public.organization_authorizations;
CREATE POLICY "wg_scheduler_owner_organization_authorizations_select" ON public.organization_authorizations
    FOR SELECT TO scheduler_function_owner
    USING (true);


-- security_audit_events -----------------------------------------------
DROP POLICY IF EXISTS "wg_api_security_audit_events_select" ON public.security_audit_events;
CREATE POLICY "wg_api_security_audit_events_select" ON public.security_audit_events
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_security_audit_events_insert" ON public.security_audit_events;
CREATE POLICY "wg_api_security_audit_events_insert" ON public.security_audit_events
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- targets -------------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_targets_select" ON public.targets;
CREATE POLICY "wg_api_targets_select" ON public.targets
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_targets_insert" ON public.targets;
CREATE POLICY "wg_api_targets_insert" ON public.targets
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_targets_update" ON public.targets;
CREATE POLICY "wg_api_targets_update" ON public.targets
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- target_verifications ------------------------------------------------
DROP POLICY IF EXISTS "wg_api_target_verifications_select" ON public.target_verifications;
CREATE POLICY "wg_api_target_verifications_select" ON public.target_verifications
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_target_verifications_insert" ON public.target_verifications;
CREATE POLICY "wg_api_target_verifications_insert" ON public.target_verifications
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_target_verifications_update" ON public.target_verifications;
CREATE POLICY "wg_api_target_verifications_update" ON public.target_verifications
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- callback_registrations ----------------------------------------------
DROP POLICY IF EXISTS "wg_worker_callback_registrations_select" ON public.callback_registrations;
CREATE POLICY "wg_worker_callback_registrations_select" ON public.callback_registrations
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_callback_registrations_insert" ON public.callback_registrations;
CREATE POLICY "wg_worker_callback_registrations_insert" ON public.callback_registrations
    FOR INSERT TO worker_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_callback_owner_callback_registrations_select" ON public.callback_registrations;
CREATE POLICY "wg_callback_owner_callback_registrations_select" ON public.callback_registrations
    FOR SELECT TO callback_function_owner
    USING (true);


-- callback_observations -----------------------------------------------
DROP POLICY IF EXISTS "wg_worker_callback_observations_select" ON public.callback_observations;
CREATE POLICY "wg_worker_callback_observations_select" ON public.callback_observations
    FOR SELECT TO worker_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.callback_registrations AS cr
        WHERE cr.token_value = callback_observations.token_value
          AND cr.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_callback_owner_callback_observations_insert" ON public.callback_observations;
CREATE POLICY "wg_callback_owner_callback_observations_insert" ON public.callback_observations
    FOR INSERT TO callback_function_owner
    WITH CHECK (true);


-- scan_permits --------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_scan_permits_select" ON public.scan_permits;
CREATE POLICY "wg_api_scan_permits_select" ON public.scan_permits
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_permits_insert" ON public.scan_permits;
CREATE POLICY "wg_api_scan_permits_insert" ON public.scan_permits
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_permits_update" ON public.scan_permits;
CREATE POLICY "wg_api_scan_permits_update" ON public.scan_permits
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_scan_permits_select" ON public.scan_permits;
CREATE POLICY "wg_worker_scan_permits_select" ON public.scan_permits
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_scheduler_scan_permits_select" ON public.scan_permits;
CREATE POLICY "wg_scheduler_scan_permits_select" ON public.scan_permits
    FOR SELECT TO scheduler_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_owner_scan_permits_select" ON public.scan_permits;
CREATE POLICY "wg_worker_owner_scan_permits_select" ON public.scan_permits
    FOR SELECT TO worker_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_scan_permits_select" ON public.scan_permits;
CREATE POLICY "wg_scheduler_owner_scan_permits_select" ON public.scan_permits
    FOR SELECT TO scheduler_function_owner
    USING (true);


-- job_permits ---------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_job_permits_select" ON public.job_permits;
CREATE POLICY "wg_api_job_permits_select" ON public.job_permits
    FOR SELECT TO api_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.scan_jobs AS j
        WHERE j.job_id = job_permits.job_id
          AND j.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_api_job_permits_insert" ON public.job_permits;
CREATE POLICY "wg_api_job_permits_insert" ON public.job_permits
    FOR INSERT TO api_tenant_data
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.scan_jobs AS j
        WHERE j.job_id = job_permits.job_id
          AND j.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_worker_owner_job_permits_select" ON public.job_permits;
CREATE POLICY "wg_worker_owner_job_permits_select" ON public.job_permits
    FOR SELECT TO worker_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_job_permits_insert" ON public.job_permits;
CREATE POLICY "wg_scheduler_owner_job_permits_insert" ON public.job_permits
    FOR INSERT TO scheduler_function_owner
    WITH CHECK (true);


-- job_safety_receipts -------------------------------------------------
DROP POLICY IF EXISTS "wg_api_job_safety_receipts_select" ON public.job_safety_receipts;
CREATE POLICY "wg_api_job_safety_receipts_select" ON public.job_safety_receipts
    FOR SELECT TO api_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.scan_jobs AS j
        WHERE j.job_id = job_safety_receipts.job_id
          AND j.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_worker_owner_job_safety_receipts_insert" ON public.job_safety_receipts;
CREATE POLICY "wg_worker_owner_job_safety_receipts_insert" ON public.job_safety_receipts
    FOR INSERT TO worker_function_owner
    WITH CHECK (true);


-- scan_jobs -----------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_scan_jobs_select" ON public.scan_jobs;
CREATE POLICY "wg_api_scan_jobs_select" ON public.scan_jobs
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_jobs_insert" ON public.scan_jobs;
CREATE POLICY "wg_api_scan_jobs_insert" ON public.scan_jobs
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_jobs_update" ON public.scan_jobs;
CREATE POLICY "wg_api_scan_jobs_update" ON public.scan_jobs
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_owner_scan_jobs_select" ON public.scan_jobs;
CREATE POLICY "wg_worker_owner_scan_jobs_select" ON public.scan_jobs
    FOR SELECT TO worker_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_worker_owner_scan_jobs_update" ON public.scan_jobs;
CREATE POLICY "wg_worker_owner_scan_jobs_update" ON public.scan_jobs
    FOR UPDATE TO worker_function_owner
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_scan_jobs_select" ON public.scan_jobs;
CREATE POLICY "wg_scheduler_owner_scan_jobs_select" ON public.scan_jobs
    FOR SELECT TO scheduler_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_scan_jobs_insert" ON public.scan_jobs;
CREATE POLICY "wg_scheduler_owner_scan_jobs_insert" ON public.scan_jobs
    FOR INSERT TO scheduler_function_owner
    WITH CHECK (true);


-- scan_schedules ------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_scan_schedules_select" ON public.scan_schedules;
CREATE POLICY "wg_api_scan_schedules_select" ON public.scan_schedules
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_schedules_insert" ON public.scan_schedules;
CREATE POLICY "wg_api_scan_schedules_insert" ON public.scan_schedules
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scan_schedules_update" ON public.scan_schedules;
CREATE POLICY "wg_api_scan_schedules_update" ON public.scan_schedules
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_scheduler_owner_scan_schedules_select" ON public.scan_schedules;
CREATE POLICY "wg_scheduler_owner_scan_schedules_select" ON public.scan_schedules
    FOR SELECT TO scheduler_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_scheduler_owner_scan_schedules_update" ON public.scan_schedules;
CREATE POLICY "wg_scheduler_owner_scan_schedules_update" ON public.scan_schedules
    FOR UPDATE TO scheduler_function_owner
    USING (true)
    WITH CHECK (true);


-- schedule_permits ----------------------------------------------------
DROP POLICY IF EXISTS "wg_api_schedule_permits_select" ON public.schedule_permits;
CREATE POLICY "wg_api_schedule_permits_select" ON public.schedule_permits
    FOR SELECT TO api_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.scan_schedules AS s
        WHERE s.schedule_id = schedule_permits.schedule_id
          AND s.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_api_schedule_permits_insert" ON public.schedule_permits;
CREATE POLICY "wg_api_schedule_permits_insert" ON public.schedule_permits
    FOR INSERT TO api_tenant_data
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.scan_schedules AS s
        WHERE s.schedule_id = schedule_permits.schedule_id
          AND s.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_scheduler_owner_schedule_permits_select" ON public.schedule_permits;
CREATE POLICY "wg_scheduler_owner_schedule_permits_select" ON public.schedule_permits
    FOR SELECT TO scheduler_function_owner
    USING (true);


-- scan_records --------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_scan_records_select" ON public.scan_records;
CREATE POLICY "wg_api_scan_records_select" ON public.scan_records
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_scan_records_select" ON public.scan_records;
CREATE POLICY "wg_worker_scan_records_select" ON public.scan_records
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_scan_records_insert" ON public.scan_records;
CREATE POLICY "wg_worker_scan_records_insert" ON public.scan_records
    FOR INSERT TO worker_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_scan_records_update" ON public.scan_records;
CREATE POLICY "wg_worker_scan_records_update" ON public.scan_records
    FOR UPDATE TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_owner_scan_records_select" ON public.scan_records;
CREATE POLICY "wg_worker_owner_scan_records_select" ON public.scan_records
    FOR SELECT TO worker_function_owner
    USING (true);

DROP POLICY IF EXISTS "wg_worker_owner_scan_records_update" ON public.scan_records;
CREATE POLICY "wg_worker_owner_scan_records_update" ON public.scan_records
    FOR UPDATE TO worker_function_owner
    USING (true)
    WITH CHECK (true);


-- findings ------------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_findings_select" ON public.findings;
CREATE POLICY "wg_api_findings_select" ON public.findings
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_findings_update" ON public.findings;
CREATE POLICY "wg_api_findings_update" ON public.findings
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_findings_select" ON public.findings;
CREATE POLICY "wg_worker_findings_select" ON public.findings
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_findings_insert" ON public.findings;
CREATE POLICY "wg_worker_findings_insert" ON public.findings
    FOR INSERT TO worker_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_findings_update" ON public.findings;
CREATE POLICY "wg_worker_findings_update" ON public.findings
    FOR UPDATE TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- finding_events ------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_finding_events_select" ON public.finding_events;
CREATE POLICY "wg_api_finding_events_select" ON public.finding_events
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_finding_events_insert" ON public.finding_events;
CREATE POLICY "wg_api_finding_events_insert" ON public.finding_events
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_finding_events_insert" ON public.finding_events;
CREATE POLICY "wg_worker_finding_events_insert" ON public.finding_events
    FOR INSERT TO worker_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- reports -------------------------------------------------------------
DROP POLICY IF EXISTS "wg_api_reports_select" ON public.reports;
CREATE POLICY "wg_api_reports_select" ON public.reports
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_reports_insert" ON public.reports;
CREATE POLICY "wg_api_reports_insert" ON public.reports
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- authentication_contexts ---------------------------------------------
DROP POLICY IF EXISTS "wg_api_authentication_contexts_select" ON public.authentication_contexts;
CREATE POLICY "wg_api_authentication_contexts_select" ON public.authentication_contexts
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_authentication_contexts_insert" ON public.authentication_contexts;
CREATE POLICY "wg_api_authentication_contexts_insert" ON public.authentication_contexts
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_authentication_contexts_update" ON public.authentication_contexts;
CREATE POLICY "wg_api_authentication_contexts_update" ON public.authentication_contexts
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_authentication_contexts_select" ON public.authentication_contexts;
CREATE POLICY "wg_worker_authentication_contexts_select" ON public.authentication_contexts
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());


-- authorization_comparison_plans --------------------------------------
DROP POLICY IF EXISTS "wg_api_authorization_comparison_plans_select" ON public.authorization_comparison_plans;
CREATE POLICY "wg_api_authorization_comparison_plans_select" ON public.authorization_comparison_plans
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_authorization_comparison_plans_insert" ON public.authorization_comparison_plans;
CREATE POLICY "wg_api_authorization_comparison_plans_insert" ON public.authorization_comparison_plans
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_authorization_comparison_plans_update" ON public.authorization_comparison_plans;
CREATE POLICY "wg_api_authorization_comparison_plans_update" ON public.authorization_comparison_plans
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_authorization_comparison_plans_select" ON public.authorization_comparison_plans;
CREATE POLICY "wg_worker_authorization_comparison_plans_select" ON public.authorization_comparison_plans
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());


-- identity_tokens -----------------------------------------------------
-- P1-2 Phase-D correction (tenant_isolation_acl.sql): api_tenant_data
-- now holds narrow column SELECT (token_id, principal_id, purpose,
-- used_at) -- required because consume_identity_token's post-
-- resolution UPDATE and invalidate_identity_tokens's UPDATE both
-- reference columns in their own WHERE clauses, and PostgreSQL
-- requires SELECT on any column a WHERE clause reads, independent of
-- RLS. This policy is the RLS-side counterpart of that grant: it uses
-- the exact same direct organization_id predicate already proven
-- correct by this table's own INSERT/UPDATE policies below, so the
-- DML dependency stays tenant-scoped once RLS is eventually enabled,
-- never USING (true) and never table-wide read access. It does not
-- widen what api_tenant_data can see: the ACL still withholds
-- table-level SELECT, and this policy would only ever matter once RLS
-- is enabled, which this file does not do.
DROP POLICY IF EXISTS "wg_api_identity_tokens_select" ON public.identity_tokens;
CREATE POLICY "wg_api_identity_tokens_select" ON public.identity_tokens
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_identity_tokens_insert" ON public.identity_tokens;
CREATE POLICY "wg_api_identity_tokens_insert" ON public.identity_tokens
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_identity_tokens_update" ON public.identity_tokens;
CREATE POLICY "wg_api_identity_tokens_update" ON public.identity_tokens
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_identity_owner_identity_tokens_select" ON public.identity_tokens;
CREATE POLICY "wg_identity_owner_identity_tokens_select" ON public.identity_tokens
    FOR SELECT TO identity_function_owner
    USING (true);


-- browser_sessions ----------------------------------------------------
DROP POLICY IF EXISTS "wg_api_browser_sessions_select" ON public.browser_sessions;
CREATE POLICY "wg_api_browser_sessions_select" ON public.browser_sessions
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_browser_sessions_insert" ON public.browser_sessions;
CREATE POLICY "wg_api_browser_sessions_insert" ON public.browser_sessions
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_browser_sessions_update" ON public.browser_sessions;
CREATE POLICY "wg_api_browser_sessions_update" ON public.browser_sessions
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_identity_owner_browser_sessions_select" ON public.browser_sessions;
CREATE POLICY "wg_identity_owner_browser_sessions_select" ON public.browser_sessions
    FOR SELECT TO identity_function_owner
    USING (true);


-- password_credentials ------------------------------------------------
-- P1-2 Phase-D correction (tenant_isolation_acl.sql): api_tenant_data
-- now holds narrow column SELECT (principal_id) -- required because
-- set_password_hash's INSERT ... ON CONFLICT (principal_id) DO
-- NOTHING needs SELECT on its conflict-target column, and the
-- conditional UPDATE that follows needs SELECT on its own WHERE-
-- clause column, both the same column, independent of RLS. This
-- table has no organization_id of its own (it is keyed by
-- principal_id, one row per principal, matching the file header's
-- own note on password_credentials' storage shape), so its tenant
-- predicate is derived through principals -- the same EXISTS shape
-- already proven correct by this table's own INSERT/UPDATE policies
-- below, never USING (true) and never table-wide read access. It does
-- not widen what api_tenant_data can see: the ACL still withholds
-- table-level SELECT and password_hash itself stays ungranted; this
-- policy would only ever matter once RLS is enabled, which this file
-- does not do.
DROP POLICY IF EXISTS "wg_api_password_credentials_select" ON public.password_credentials;
CREATE POLICY "wg_api_password_credentials_select" ON public.password_credentials
    FOR SELECT TO api_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.principals AS p
        WHERE p.principal_id = password_credentials.principal_id
          AND p.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_api_password_credentials_insert" ON public.password_credentials;
CREATE POLICY "wg_api_password_credentials_insert" ON public.password_credentials
    FOR INSERT TO api_tenant_data
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.principals AS p
        WHERE p.principal_id = password_credentials.principal_id
          AND p.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_api_password_credentials_update" ON public.password_credentials;
CREATE POLICY "wg_api_password_credentials_update" ON public.password_credentials
    FOR UPDATE TO api_tenant_data
    USING (EXISTS (
        SELECT 1 FROM public.principals AS p
        WHERE p.principal_id = password_credentials.principal_id
          AND p.organization_id = public.webguard_current_tenant()
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.principals AS p
        WHERE p.principal_id = password_credentials.principal_id
          AND p.organization_id = public.webguard_current_tenant()
    ));

DROP POLICY IF EXISTS "wg_identity_owner_password_credentials_select" ON public.password_credentials;
CREATE POLICY "wg_identity_owner_password_credentials_select" ON public.password_credentials
    FOR SELECT TO identity_function_owner
    USING (true);


-- coverage_records (migration 0013, platform expansion / product ----
-- vision pillar 5): direct organization_id, same shape as scan_records
-- above. api_tenant_data has SELECT only (no live API reader yet, per
-- tenant_isolation_acl.sql's own comment, but the ACL and this policy
-- are written for the repository method that already exists);
-- worker_tenant_data has the full SELECT/INSERT/UPDATE its upsert
-- (record_coverage) needs.
DROP POLICY IF EXISTS "wg_api_coverage_records_select" ON public.coverage_records;
CREATE POLICY "wg_api_coverage_records_select" ON public.coverage_records
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_coverage_records_select" ON public.coverage_records;
CREATE POLICY "wg_worker_coverage_records_select" ON public.coverage_records
    FOR SELECT TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_coverage_records_insert" ON public.coverage_records;
CREATE POLICY "wg_worker_coverage_records_insert" ON public.coverage_records
    FOR INSERT TO worker_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_worker_coverage_records_update" ON public.coverage_records;
CREATE POLICY "wg_worker_coverage_records_update" ON public.coverage_records
    FOR UPDATE TO worker_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- module_entitlements (migration 0014, platform expansion): direct ---
-- organization_id, api-serve-process-only per tenant_isolation_acl.sql's
-- own comment (no worker/scheduler/callback path ever touches it), so
-- only api_tenant_data gets a policy here.
DROP POLICY IF EXISTS "wg_api_module_entitlements_select" ON public.module_entitlements;
CREATE POLICY "wg_api_module_entitlements_select" ON public.module_entitlements
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_module_entitlements_insert" ON public.module_entitlements;
CREATE POLICY "wg_api_module_entitlements_insert" ON public.module_entitlements
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_module_entitlements_update" ON public.module_entitlements;
CREATE POLICY "wg_api_module_entitlements_update" ON public.module_entitlements
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());


-- scoped_control_implementations (migration 0016, platform expansion):
-- direct organization_id, same api-serve-process-only shape as
-- module_entitlements above (every write is a human decision made
-- through the API; no worker/scheduler path touches it).
DROP POLICY IF EXISTS "wg_api_scoped_control_implementations_select" ON public.scoped_control_implementations;
CREATE POLICY "wg_api_scoped_control_implementations_select" ON public.scoped_control_implementations
    FOR SELECT TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scoped_control_implementations_insert" ON public.scoped_control_implementations;
CREATE POLICY "wg_api_scoped_control_implementations_insert" ON public.scoped_control_implementations
    FOR INSERT TO api_tenant_data
    WITH CHECK (organization_id = public.webguard_current_tenant());

DROP POLICY IF EXISTS "wg_api_scoped_control_implementations_update" ON public.scoped_control_implementations;
CREATE POLICY "wg_api_scoped_control_implementations_update" ON public.scoped_control_implementations
    FOR UPDATE TO api_tenant_data
    USING (organization_id = public.webguard_current_tenant())
    WITH CHECK (organization_id = public.webguard_current_tenant());

COMMIT;
