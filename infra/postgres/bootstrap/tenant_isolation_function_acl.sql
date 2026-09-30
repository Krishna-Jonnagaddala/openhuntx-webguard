-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): Phase E of
-- the tenant-isolation plumbing, ordinary PostgreSQL table ACLs for
-- the four NOLOGIN function-owner roles Phase C created
-- (tenant_isolation_roles.sql). Run this file after both
-- tenant_isolation_roles.sql and tenant_isolation_acl.sql: every role
-- granted here must already exist, and this file changes nothing
-- about the three tenant-data roles' own grants.
--
-- These four roles do not yet own any function. No SECURITY DEFINER
-- function, no CREATE FUNCTION, and no webguard_control schema exist
-- yet; that is a later phase. This file only establishes the
-- privilege boundary those future functions will execute within, so
-- the boundary can be reasoned about and tested on its own, ahead of
-- any function body being written.
--
-- Each grant below is tied to a specific future control-plane or
-- pre-authentication resolver function, and to the CURRENT repository
-- code path that function will eventually replace or wrap. Every one
-- of those current code paths was re-read directly against this
-- commit, not carried over from an earlier design pass. Two
-- corrections came out of that re-reading, recorded here rather than
-- silently folded in:
--
-- `enqueue_due_schedule` (postgres_schedules.py), the current
-- equivalent of the future scheduler function, does an INSERT into
-- scan_jobs but then reads the row back with a separate
-- `SELECT ... FROM scan_jobs WHERE job_id = %s` rather than an
-- `INSERT ... RETURNING`. An INSERT-only grant on scan_jobs would
-- make that readback fail, so scheduler_function_owner needs SELECT
-- on scan_jobs alongside INSERT, not INSERT alone.
--
-- `recover_expired_leases` (postgres_jobs.py) issues
-- `UPDATE scan_records SET status = ..., completed_at = ...
-- WHERE job_id = %s AND completed_at IS NULL` with no separate SELECT
-- anywhere in that method. PostgreSQL requires SELECT on any column
-- read by an UPDATE's WHERE clause, not just UPDATE on the columns
-- being assigned, confirmed empirically against a disposable Postgres
-- 16 instance (an UPDATE-only role's identical statement failed with
-- "permission denied for table," and succeeded once SELECT was added
-- alongside it). worker_function_owner's SELECT on scan_records was
-- already required by `_terminal_update`'s own reconciliation write,
-- so this does not change the final grant, only the reasoning for
-- which function actually requires it.
--
-- Writes that happen strictly AFTER a resolver has established which
-- tenant a request belongs to (an API token's last_used_at, a browser
-- session's idle_expires_at, an identity token's used_at, a
-- principal's last_login_at, a password rehash) are deliberately
-- absent from identity_function_owner's grants below. Those run
-- through the ordinary tenant role, in the same transaction, after
-- set_tenant_context(connection, organization_id) -- see
-- postgres_pool.py's own docstring for that primitive. Making the
-- pre-auth resolver itself able to write any of those tables would
-- give it more authority than the resolution step actually needs.
--
-- No control-plane INSERT/UPDATE that is genuinely part of ordinary
-- tenant-scoped worker execution is granted here: worker_function_owner
-- gets nothing on findings, finding_events, or scan_records INSERT,
-- because create_scan()/complete_scan()/record_finding() are ordinary
-- tenant-scoped operations already granted to worker_tenant_data in
-- Phase D. The distinction is not "does worker code touch this table"
-- but "does a future cross-tenant SECURITY DEFINER function need this
-- command," and the two grants are kept deliberately separate to
-- avoid blurring an ordinary write into a control-plane one.
--
-- terminal_transition's atomicity, reconfirmed directly against
-- postgres_jobs.py's `_terminal_update`: within one transaction it
-- does the scan_jobs CAS transition, then (only when the new state is
-- FAILED or CANCELLED) a scan_records reconciliation UPDATE, then
-- (only when a safety receipt reference was supplied) a
-- job_safety_receipts INSERT, then a scan_jobs readback SELECT. A
-- SUCCEEDED completion is NOT part of this transaction: the comment
-- in `_terminal_update` itself says the executor's own
-- `complete_scan()` call already ran, in an earlier, separate, short
-- transaction, before `_terminal_update` is ever invoked. Nothing
-- about that separate SUCCEEDED path is collapsed into this grant.
--
-- No privilege here is a substitute for row-level security, and no
-- SECURITY DEFINER function exists yet to make any of this reachable
-- from a runtime credential. This file only proves the privilege
-- ceiling those future functions will run under.
--
-- GRANT is naturally idempotent in PostgreSQL: re-running this file
-- against a database where these privileges already exist raises no
-- error and changes nothing. Nothing here is DROPed, REVOKEd, or
-- CASCADEd, and nothing here touches api_tenant_data, worker_tenant_data,
-- or scheduler_tenant_data.

GRANT USAGE ON SCHEMA public
    TO identity_function_owner, worker_function_owner,
       scheduler_function_owner, callback_function_owner;

-- identity_function_owner ------------------------------------------------
-- Future functions: resolve_api_token, resolve_browser_session,
-- resolve_principal_by_email, resolve_identity_token. All four are
-- pure read resolvers: given a bearer secret (or, for
-- resolve_principal_by_email, an email address plus a password to
-- verify against the stored hash), each one looks up the record(s)
-- needed to establish which tenant a not-yet-authenticated request
-- belongs to. None of them writes anything.
--
-- resolve_api_token replaces postgres_identity.py's
-- authenticate_token(): SELECT api_tokens (find by token_id, verify
-- the secret hash), SELECT principals, SELECT organizations. Its own
-- UPDATE api_tokens SET last_used_at is a post-resolution write and
-- moves to the ordinary tenant role.
--
-- resolve_browser_session replaces postgres_sessions.py's
-- authenticate_session() plus auth.py's
-- BrowserSessionAuthenticator.authenticate(): SELECT browser_sessions,
-- SELECT principals, SELECT organizations. Its own
-- UPDATE browser_sessions SET last_used_at, idle_expires_at is the
-- same kind of post-resolution write and moves to the ordinary tenant
-- role.
--
-- resolve_principal_by_email replaces postgres_identity.py's
-- get_principal_by_email() and get_password_hash(), both called
-- together from service.py's login(): SELECT principals (find by
-- email), SELECT password_credentials (read the hash to verify),
-- SELECT organizations (resolve the organization for the returned
-- context, mirroring resolve_api_token's shape). login()'s own
-- touch_last_login() UPDATE and any needs_rehash() password rewrite
-- are post-resolution writes and move to the ordinary tenant role.
--
-- resolve_identity_token replaces postgres_identity.py's
-- consume_identity_token(): SELECT identity_tokens only (find by
-- token_id, verify the secret hash, check purpose/expiry). Its own
-- UPDATE identity_tokens SET used_at is a post-resolution write and
-- moves to the ordinary tenant role; nothing calls it needs a
-- principals or organizations read from within this one function.
GRANT SELECT ON api_tokens TO identity_function_owner;
GRANT SELECT ON principals TO identity_function_owner;
GRANT SELECT ON organizations TO identity_function_owner;
GRANT SELECT ON browser_sessions TO identity_function_owner;
GRANT SELECT ON identity_tokens TO identity_function_owner;
GRANT SELECT ON password_credentials TO identity_function_owner;

-- worker_function_owner ---------------------------------------------------
-- Future functions: claim_next_job, recover_expired_leases,
-- renew_lease, resolve_job_organization, terminal_transition. These
-- are the cross-tenant lease/claim/terminal-transition operations a
-- worker process performs across every tenant's queue, distinct from
-- worker_tenant_data's ordinary tenant-scoped scan_records/findings
-- writes (Phase D).
--
-- claim_next_job replaces postgres_jobs.py's claim_next_leased():
-- SELECT scan_jobs (the claimable-row query, joined to job_permits,
-- with EXISTS checks against organization_authorizations and
-- scan_permits, plus a self-join back to scan_jobs for the
-- already-running-on-this-permit check), UPDATE scan_jobs (the CAS
-- claim transition), SELECT job_permits, SELECT scan_permits,
-- SELECT organization_authorizations.
--
-- recover_expired_leases replaces postgres_jobs.py's own method of
-- that name: SELECT scan_jobs (the expired-lease query, FOR UPDATE
-- SKIP LOCKED), UPDATE scan_jobs (one of three terminal/requeue
-- branches), and, only for the CANCELLED/FAILED branches, UPDATE
-- scan_records (reconciliation). See the file header for why that
-- UPDATE also needs SELECT on scan_records.
--
-- renew_lease replaces postgres_jobs.py's own method of that name:
-- SELECT scan_jobs, UPDATE scan_jobs. Nothing else.
--
-- resolve_job_organization replaces postgres_jobs.py's
-- organization_id_for_job() (itself a thin wrapper over get_scope()):
-- SELECT scan_jobs only.
--
-- terminal_transition replaces postgres_jobs.py's _terminal_update():
-- SELECT scan_jobs, UPDATE scan_jobs, SELECT scan_records, UPDATE
-- scan_records (both only reached for FAILED/CANCELLED, never
-- SUCCEEDED, see the file header), INSERT job_safety_receipts (only
-- reached when a safety receipt reference was supplied).
GRANT SELECT, UPDATE ON scan_jobs TO worker_function_owner;
GRANT SELECT ON job_permits TO worker_function_owner;
GRANT SELECT ON scan_permits TO worker_function_owner;
GRANT SELECT ON organization_authorizations TO worker_function_owner;
GRANT SELECT, UPDATE ON scan_records TO worker_function_owner;
GRANT INSERT ON job_safety_receipts TO worker_function_owner;

-- scheduler_function_owner --------------------------------------------------
-- Future functions: list_due_schedules, enqueue_due_schedule,
-- block_due_schedule. Unlike the identity and worker groups, these
-- three already exist under these exact names in
-- postgres_schedules.py today, called directly from scheduler.py's
-- run_once(); this phase only re-verifies their table requirements,
-- it does not invent new function names.
--
-- list_due_schedules: SELECT scan_schedules only (the due-schedule
-- query).
--
-- enqueue_due_schedule: SELECT scan_schedules (FOR UPDATE, the
-- current-state read), SELECT organization_authorizations (the
-- assignment check), SELECT schedule_permits (the permit binding
-- read), SELECT scan_permits (the permit validity check), INSERT
-- scan_jobs, INSERT job_permits, UPDATE scan_schedules (advancing
-- next_run_at/revision), and SELECT scan_jobs (the post-INSERT
-- readback; see the file header for why INSERT alone is not enough).
--
-- block_due_schedule: SELECT scan_schedules, UPDATE scan_schedules
-- (both the CAS pause-and-record-error write and its own readback).
--
-- No DELETE anywhere in this group.
GRANT SELECT, UPDATE ON scan_schedules TO scheduler_function_owner;
GRANT SELECT ON organization_authorizations TO scheduler_function_owner;
GRANT SELECT ON schedule_permits TO scheduler_function_owner;
GRANT SELECT ON scan_permits TO scheduler_function_owner;
GRANT SELECT, INSERT ON scan_jobs TO scheduler_function_owner;
GRANT INSERT ON job_permits TO scheduler_function_owner;

-- callback_function_owner --------------------------------------------------
-- Future function: resolve_and_record_callback_observation, one
-- atomic function by design (see the P1-2 design record for why
-- splitting it into a separate resolve step and a separate insert
-- step would reintroduce a TOCTOU window between the registration
-- check and the observation write). Replaces
-- postgres_callback_service.py's PostgresCallbackRegistrationRepository
-- .record_observation(): SELECT callback_registrations (WHERE
-- token_value, checking revoked_at/expires_at), INSERT
-- callback_observations. No UPDATE, no DELETE.
--
-- This is deliberately distinct from Phase D's worker_tenant_data
-- grants on the same two tables (SELECT, INSERT on
-- callback_registrations and SELECT on callback_observations): that
-- pair serves the ordinary tenant-scoped registration/read path
-- (register()/get_registration()/_latest_observation(), all inside an
-- authenticated request already carrying an organization_id).
-- callback_function_owner serves the opposite, public, pre-
-- authentication ingress path, where no tenant is known yet until the
-- token itself is resolved. The two roles are never granted the same
-- direction on the same table: worker_tenant_data can INSERT a
-- registration and SELECT an observation; callback_function_owner can
-- SELECT a registration and INSERT an observation.
GRANT SELECT ON callback_registrations TO callback_function_owner;
GRANT INSERT ON callback_observations TO callback_function_owner;
