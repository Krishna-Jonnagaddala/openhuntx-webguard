# Row-Level-Security Staging Activation and Rollback (P1-2 remaining half)

## Status

**Procedure only. Nothing in this document has been executed.** `infra/postgres/bootstrap/tenant_isolation_rls_policies.sql` already defines every policy (29 tables policied, `crawl_checkpoints` deliberately left with zero policies, see that file's own header), but its own comment block states plainly that it does not turn RLS on anywhere: no `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, no `FORCE`, on any table, in production or staging. `tests.integration.test_postgres_rls_policies` proves the full activated behavior today, but only against a disposable database this suite creates, bootstraps, activates, and drops for itself inside CI. That is evidence the policies are correct, not evidence the real staging database has ever had them turned on. This document is what closes that gap: the exact commands, the order they need to run in, what to check afterward before calling it good, and how to undo it if something goes wrong. Running it still requires a staging environment that does not exist yet (`infra/terraform/postgres.tf` has never been applied against a real AWS account) and an owner's go-ahead to run it there.

## 1. Preconditions

Everything below assumes `infra/postgres/migrations/` is already fully applied (`scripts/run-postgres-migrations.py`, no dry-run diff) and that the bootstrap files have already been run, in this exact order, against the target database:

1. `tenant_isolation_roles.sql` (creates the seven NOLOGIN roles)
2. `tenant_isolation_acl.sql` (ordinary-role table grants)
3. `tenant_isolation_function_acl.sql` (function-owner table grants)
4. `tenant_isolation_control_functions.sql` (the SECURITY DEFINER control functions)
5. `tenant_isolation_rls_policies.sql` (the policies themselves, still inert without this document's step 3 below)
6. `tenant_isolation_runtime_grant.sql` (grants `webguard` membership in the three tenant-data roles, so the running application can actually `SET ROLE` into them)

Skipping or reordering any of these produces a database where FORCE RLS would either deny every ordinary query outright (policies not yet defined) or let a query through with no filtering at all (RLS not yet forced), neither of which is the intended activation state. `tests.integration.test_postgres_rls_policies` runs this exact sequence every time it builds its disposable database, so a staging run that reproduces it step for step is not doing anything CI has not already exercised, it is doing it against a database CI does not have.

The second precondition is on the application side, not the database: Phase H's runtime tenant-context conversion (`docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md`, PRs #30-#47, plus this session's `organization_id_for_job` closure) has to already be deployed to whatever process will run against the activated database. A repository method still using an unrestricted pool connection, calling into a table this activation now forces RLS on, does not fail loudly, it silently sees zero rows or gets rejected depending on which role that connection happens to run as. Activating RLS before Phase H's code is live turns a latent bug into a customer-visible outage; activating it after is what actually proves the isolation claim end to end.

## 2. Activation

Run as a single transaction, against the target database, as a role with `ALTER TABLE` privilege on all thirty tables (the RDS master/admin role, never `webguard` itself, which should never hold table-ownership-level privilege in the first place):

```sql
BEGIN;

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organization_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_authorizations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.targets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.target_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.target_verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE public.callback_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.callback_registrations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.callback_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.callback_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_permits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_permits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.job_permits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job_permits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.schedule_permits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.schedule_permits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.job_safety_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job_safety_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_schedules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scan_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports FORCE ROW LEVEL SECURITY;
ALTER TABLE public.authentication_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authentication_contexts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.authorization_comparison_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authorization_comparison_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE public.crawl_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crawl_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE public.finding_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.finding_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.password_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE public.browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.browser_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.coverage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.coverage_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.module_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.module_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE public.scoped_control_implementations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scoped_control_implementations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.technical_assertion_collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.technical_assertion_collections FORCE ROW LEVEL SECURITY;

COMMIT;
```

That is all thirty tenant-owned tables, including `crawl_checkpoints`. It gets forced along with the rest on purpose even though it carries no policy at all: `tenant_isolation_rls_policies.sql`'s own header calls this out as the intended outcome, forcing RLS on a table with zero policies makes every ordinary-role query against it return zero rows rather than the schema's default of unrestricted access. That is default-deny for a table nothing should be reading in the first place, not an oversight. `auth_rate_limit_events`, `frameworks`, and `master_controls` are deliberately absent from this list. None of the three carries an `organization_id`, and a tenant-equality predicate has nothing to filter on for any of them.

`ENABLE`/`FORCE ROW LEVEL SECURITY` only flips two booleans in `pg_class` (`relrowsecurity`, `relforcerowsecurity`). Neither rewrites the table or touches a single row, so the thirty statements above should complete in milliseconds against any data volume. The catch is the lock, not the work: each `ALTER TABLE` takes `ACCESS EXCLUSIVE` on that table for the instant it runs, which blocks concurrent reads and writes against it. Thirty brief exclusive locks in sequence is still enough to visibly stall live traffic if it lands during a busy period, so this should run in a maintenance window or a deliberately quiet stretch, not opportunistically mid-day.

## 3. Adversarial acceptance checks

`test_postgres_rls_policies` already proves every property below against its own disposable database, in CI, on every commit. Running it there again proves nothing new about staging; the checks below are the same properties, re-verified against the database this activation actually touched.

1. **Cross-tenant read denial.** As `api_tenant_data` with `webguard.current_organization_id` set to tenant A, `SELECT` from a table seeded with tenant B rows and confirm zero rows come back, not an error, not tenant B's data. Then flip the GUC to tenant B on the same connection and confirm A's rows are now the ones invisible. A connection that can see both by resetting its own GUC is expected (`tenant_isolation_rls_policies.sql`'s own threat model section says this plainly: RLS defends against a missing predicate, not a caller with arbitrary SQL access to a session-settable GUC), a connection that sees the wrong tenant's rows *without* resetting anything is the actual failure this check exists to catch.
2. **Default-deny on `crawl_checkpoints`.** Confirm no role, ordinary or function-owner, can read or write it post-activation. It had zero ACL grantees before this document's changes and should have zero effective access after; if the answer is anything else, either the ACL bootstrap drifted or a later change added a live caller to a table this whole activation assumed was unused, and either way activation should stop until that is understood.
3. **Function-owner control paths still work.** Exercise at least one call through each of the four SECURITY DEFINER control-function owners (`identity_function_owner`, `worker_function_owner`, `scheduler_function_owner`, `callback_function_owner`) end to end, not just a raw `SELECT` as that role. These are the paths Phase F built specifically to keep working cross-tenant under FORCE RLS (`tenant_isolation_rls_policies.sql`'s function-owner policies use `USING (true)` for exactly this reason); a failure here means the `true` policies do not actually cover the same (table, command) surface the control functions need, which is a real regression, not a tenant-isolation success.
4. **Application smoke pass.** Run the full `tests/contract` and `tests/integration` suites against the now-activated database, pointing them at it the same way `test_postgres_rls_policies` points at its own disposable one. A pass here is what actually connects this activation to the rest of the code base's own coverage instead of leaving it as a database-only exercise.
5. **Bake period.** Watch application error logs and the database's own `pg_stat_database` error counters for a fixed window (a full business day covers most traffic patterns better than a shorter spot check) before considering activation final. A repository method that still uses an unrestricted connection somewhere Phase H's review missed will not show up in a five-minute check, it shows up as `permission denied for table` or an unexplained empty result under whatever code path first happens to exercise it in real traffic.

## 4. Rollback

```sql
BEGIN;

ALTER TABLE public.organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.organizations DISABLE ROW LEVEL SECURITY;
-- ... repeat NO FORCE + DISABLE for the remaining twenty-nine tables
-- listed in section 2, same order, same table names.

COMMIT;
```

Like activation, this is a metadata-only change: no data is touched, no rewrite happens, and it takes effect the instant the transaction commits. There is no partial or gradual rollback state to manage, a table is either forced or it is not. Reasons to invoke it: any of the acceptance checks in section 3 failing, an unexpected `permission denied for table` rate increase during the bake period, or a support/monitoring signal that an application code path is silently returning fewer rows than it should against real customer data. Rolling back does not require re-running any bootstrap file. Once the policies exist, disabling and re-enabling RLS on the same table is symmetric; the policies stay defined and inert exactly as they were before section 2 ever ran, ready for a second activation attempt once whatever triggered the rollback is fixed.

## 5. What this document does not do

It does not apply `infra/terraform/postgres.tf`, provision a staging RDS instance, or authorize spending against one, all of which some owner decision outside this document has to make first. It does not, by itself, close P1-2, closing that requires this procedure to actually run against a real environment and its acceptance checks to actually pass there, not just to be written down correctly here. And it does not change anything about the database this repository's CI already exercises: `tests.integration.test_postgres_rls_policies` keeps building, activating, and tearing down its own disposable database exactly as it does today, entirely independent of whether the procedure above has ever been run anywhere else.
