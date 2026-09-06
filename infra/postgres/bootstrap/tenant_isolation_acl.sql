-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): Phase D of
-- the tenant-isolation plumbing -- ordinary PostgreSQL table ACLs for
-- the three service-specific tenant-data roles Phase C created
-- (infra/postgres/bootstrap/tenant_isolation_roles.sql). Run this
-- file only after that one: every role granted here must already
-- exist.
--
-- Every grant below is tied to a live, currently-called repository
-- method AND its actual calling process (the WebGuard API `serve`
-- process specifically, for api_tenant_data -- not merely "some
-- repository method exists that a caller somewhere invokes"),
-- re-verified against the current source directly, not assumed from
-- an earlier design pass. Three corrections worth recording here
-- rather than silently folding in:
--
-- `target_verifications` DOES have live API callers today
-- (`initiate`/`get_current`/`get_pending_token`/`record_result`, all
-- in service.py) -- an earlier investigation this project's own
-- history describes as "no code writes to this yet" was about the
-- DNS-verification *mechanism* not existing, not about the
-- repository methods being uncalled, and that distinction matters
-- here.
--
-- `callback_registrations.revoke_registration`
-- (`postgres_callback_broker.py`'s own wrapper) has zero live callers
-- anywhere in this codebase -- no UPDATE grant is given for it,
-- matching "if a privilege cannot be tied to a live current method,
-- do not grant it."
--
-- `organization_authorizations` INSERT was originally granted to
-- api_tenant_data because `IdentityStore.assign_authorization`
-- exists and is reachable, but its only actual caller anywhere in
-- this codebase is `cli.py`'s `_authorization_assign_command`
-- (the `authorization assign` operator subcommand) -- the WebGuard
-- API `serve` process never calls it. Phase D grants service-level
-- least privilege for the API process specifically, so this INSERT
-- does not belong to api_tenant_data; it is a DEFERRED OPERATOR/
-- ADMIN DATABASE CAPABILITY for a later role/deployment phase, not
-- something this phase grants to anyone. SELECT stays: service.py
-- calls `authorization_is_assigned`/`list_assigned_authorization_ids`
-- directly from several API-serve-reachable methods (permit issuance,
-- authentication-context/authorization-comparison-plan registration,
-- job submission, schedule creation, and asset display).
--
-- No privilege here is a substitute for row-level security. A role
-- with SELECT on a tenant table and no RLS policy enabled can see
-- every row it has table-level permission to read, across every
-- tenant -- these grants establish only SERVICE-LEVEL LEAST-PRIVILEGE
-- STRUCTURE (which service can touch which table at all, and with
-- which command), not tenant row isolation. RLS activation is a later
-- phase.
--
-- No control-plane/cross-tenant operation is granted here. scan_jobs,
-- job_permits, scan_schedules, schedule_permits, job_safety_receipts,
-- and callback_observations' write path all remain ungranted to the
-- ordinary tenant-data roles wherever the underlying operation is
-- inherently cross-tenant (worker lease/claim/terminal-transition,
-- scheduler discovery/materialization, callback ingress) -- those
-- belong to a future SECURITY DEFINER function-owner phase, not this
-- one. Where a table has BOTH an ordinary tenant-scoped path and a
-- separate control-plane path (e.g. scan_records: worker's ordinary
-- create_scan()/complete_scan() calls vs. the future terminal-
-- transition function's own reconciliation write), only the ordinary
-- path's privilege is granted here.
--
-- Dormant/unused tables receive nothing: crawl_checkpoints has no
-- live writer or reader anywhere in this codebase. callback_observations
-- receives SELECT for worker_tenant_data only (its one live read,
-- _latest_observation) and no INSERT for any tenant-data role, since
-- its one write path (record_observation) is the pre-authentication
-- callback-ingress function's future domain, not an ordinary
-- tenant-scoped operation at all.
--
-- GRANT is naturally idempotent in PostgreSQL: re-running this file
-- against a database where these privileges already exist raises no
-- error and changes nothing. Nothing here is DROPed, REVOKEd, or
-- CASCADEd.

GRANT USAGE ON SCHEMA public TO api_tenant_data, worker_tenant_data, scheduler_tenant_data;

-- api_tenant_data -------------------------------------------------------

GRANT SELECT, INSERT ON organizations TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON principals TO api_tenant_data;
GRANT INSERT ON memberships TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON api_tokens TO api_tenant_data;
-- INSERT deliberately withheld: assign_authorization's only live
-- caller is cli.py's operator subcommand, not the API serve process.
-- See the file header for detail.
GRANT SELECT ON organization_authorizations TO api_tenant_data;
GRANT SELECT, INSERT ON security_audit_events TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON targets TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON target_verifications TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON scan_jobs TO api_tenant_data;
GRANT SELECT, INSERT ON job_permits TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON scan_schedules TO api_tenant_data;
GRANT SELECT, INSERT ON schedule_permits TO api_tenant_data;
GRANT SELECT ON scan_records TO api_tenant_data;
GRANT SELECT, UPDATE ON findings TO api_tenant_data;
GRANT SELECT, INSERT ON finding_events TO api_tenant_data;
GRANT SELECT, INSERT ON reports TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON authentication_contexts TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON authorization_comparison_plans TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON scan_permits TO api_tenant_data;
GRANT SELECT ON job_safety_receipts TO api_tenant_data;
-- No SELECT: password_credentials' only read (get_password_hash, for
-- login) is inherently pre-authentication -- a future identity
-- function owner's resolver domain, not this role's. The only
-- operation this role performs on this table is the upsert in
-- set_password_hash, which needs INSERT and UPDATE (for its
-- ON CONFLICT DO UPDATE branch), never a SELECT.
GRANT INSERT, UPDATE ON password_credentials TO api_tenant_data;
-- No SELECT: identity_tokens' only read (consume_identity_token) is
-- the same pre-authentication case -- there is no other read of this
-- table anywhere in the current codebase.
GRANT INSERT, UPDATE ON identity_tokens TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON browser_sessions TO api_tenant_data;
GRANT SELECT, INSERT, DELETE ON auth_rate_limit_events TO api_tenant_data;

-- worker_tenant_data ------------------------------------------------------

GRANT SELECT ON authentication_contexts TO worker_tenant_data;
GRANT SELECT ON authorization_comparison_plans TO worker_tenant_data;
GRANT SELECT, INSERT ON callback_registrations TO worker_tenant_data;
GRANT SELECT ON callback_observations TO worker_tenant_data;
GRANT SELECT ON scan_permits TO worker_tenant_data;
GRANT SELECT ON organization_authorizations TO worker_tenant_data;
GRANT SELECT, INSERT, UPDATE ON scan_records TO worker_tenant_data;
GRANT SELECT, INSERT, UPDATE ON findings TO worker_tenant_data;
GRANT INSERT ON finding_events TO worker_tenant_data;

-- scheduler_tenant_data ---------------------------------------------------

GRANT SELECT ON organization_authorizations TO scheduler_tenant_data;
GRANT SELECT ON scan_permits TO scheduler_tenant_data;
