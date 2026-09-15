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
-- an earlier design pass. Four corrections worth recording here
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
-- `identity_tokens` and `password_credentials` were originally
-- granted INSERT/UPDATE with no SELECT at all, on the theory that a
-- future identity-resolver function owner would own every read these
-- tables need. That theory did not account for PostgreSQL requiring
-- SELECT privilege on any column an UPDATE's WHERE clause reads, or
-- that an INSERT ... ON CONFLICT DO UPDATE requires SELECT on its
-- conflict-target column and on every column its DO UPDATE SET clause
-- references via EXCLUDED -- both confirmed empirically, and both
-- true independent of RLS entirely. Re-tracing the actual current SQL
-- (postgres_identity.py's consume_identity_token,
-- invalidate_identity_tokens, and set_password_hash) found this
-- ordinary role's own writes could not succeed under the original
-- no-SELECT grant. The correction is narrow column-level SELECT on
-- exactly the columns each statement's WHERE clause (or, for
-- password_credentials, conflict-target/DO-UPDATE-SET clause)
-- demonstrably requires -- proven empirically, one column at a time,
-- rather than granted for convenience -- never table-level SELECT,
-- and never on a column with sensitive content. password_credentials'
-- original single-statement upsert would have forced SELECT on
-- password_hash itself to satisfy this same rule; set_password_hash
-- was rewritten instead (see its own grant below) so this role's
-- required SELECT surface on that table stays exactly
-- `principal_id`, never the hash.
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
-- coverage_records (P1-2 Phase H follow-on, product vision pillar 5):
-- api_tenant_data has no live reader yet (no API/report surface
-- exists this slice), but this mirrors the same worker-writes/api-
-- reads split findings/scan_records already use, and
-- list_coverage_for_asset is a real, test-exercised repository
-- method today even without an HTTP caller yet, the same
-- "converted anyway for consistency" precedent postgres_scans.py's
-- list_scans_scoped already established.
GRANT SELECT ON coverage_records TO api_tenant_data;
-- No whole-row SELECT: password_credentials' own read
-- (get_password_hash, for login) is inherently pre-authentication --
-- a future identity function owner's resolver domain, not this
-- role's. But PostgreSQL requires SELECT privilege on any column an
-- INSERT ... ON CONFLICT DO UPDATE references, on the conflict target
-- column AND on every column the DO UPDATE SET clause reads (even via
-- EXCLUDED, the proposed row, not the existing one) -- confirmed
-- empirically, and true regardless of whether a conflict actually
-- occurs at runtime (PostgreSQL checks this at parse time against the
-- statement's shape). set_password_hash's original single-statement
-- upsert (`... DO UPDATE SET algorithm = EXCLUDED.algorithm,
-- password_hash = EXCLUDED.password_hash, updated_at =
-- EXCLUDED.updated_at`) would therefore have forced SELECT on
-- password_hash itself to satisfy this role's own write -- direct
-- read access to a credential hash by an ordinary tenant-scoped role,
-- which is exactly what routing password reads through a privileged
-- resolver exists to avoid needing. set_password_hash was rewritten
-- (P1-2 Phase-D correction) to two statements inside the same
-- transaction -- `INSERT ... ON CONFLICT (principal_id) DO NOTHING`
-- then, only if that inserted nothing, a plain `UPDATE ... WHERE
-- principal_id = %s` whose SET clause assigns caller-supplied
-- parameters directly, never EXCLUDED or the table's own existing
-- values -- so only the conflict-target/WHERE column, principal_id,
-- ever needs SELECT. Proven empirically (six-way concurrent race on
-- both the fresh-row and existing-row paths, transaction rollback on
-- both paths, created_at preservation) to be semantically equivalent
-- to the original single-statement upsert in every observable way.
GRANT INSERT, UPDATE ON password_credentials TO api_tenant_data;
GRANT SELECT (principal_id) ON password_credentials TO api_tenant_data;
-- No whole-row SELECT: identity_tokens' own read
-- (consume_identity_token's initial lookup) is the same pre-
-- authentication case, a future resolver's domain. But both
-- consume_identity_token's `UPDATE identity_tokens SET used_at = %s
-- WHERE token_id = %s` and invalidate_identity_tokens's `UPDATE
-- identity_tokens SET used_at = %s WHERE principal_id = %s AND
-- purpose = %s AND used_at IS NULL` reference columns in their own
-- WHERE clauses, and PostgreSQL requires SELECT on any column an
-- UPDATE's WHERE clause reads (the same rule already established
-- elsewhere in this file for recover_expired_leases' SELECT-alongside-
-- UPDATE requirement on scan_records) -- confirmed empirically,
-- independent of RLS entirely. token_id, principal_id, purpose, and
-- used_at are the exact four columns referenced across both
-- statements' WHERE clauses, each proven individually necessary
-- (removing any one reproduces the failure) and together sufficient;
-- no other column, in particular not secret_hash, is ever referenced
-- by either statement's WHERE clause, so none of the rest needs
-- SELECT.
GRANT INSERT, UPDATE ON identity_tokens TO api_tenant_data;
GRANT SELECT (token_id, principal_id, purpose, used_at) ON identity_tokens TO api_tenant_data;
GRANT SELECT, INSERT, UPDATE ON browser_sessions TO api_tenant_data;
GRANT SELECT, INSERT, DELETE ON auth_rate_limit_events TO api_tenant_data;
-- module_entitlements (platform expansion, docs/adr/0033): purely an
-- API serve-process concern, no worker/scheduler/callback path ever
-- reads or writes it, so api_tenant_data is the only role granted
-- anything here.
GRANT SELECT, INSERT, UPDATE ON module_entitlements TO api_tenant_data;
-- frameworks/master_controls (platform expansion, docs/adr/0034):
-- global reference data, not tenant data, the first tables in this
-- schema with no organization_id at all. SELECT only: writes (adding
-- a framework or control to the catalog) are an OpenHuntX-operator
-- concern with no live API-serve-process caller, the same shape
-- postgres_identity.py's assign_authorization/revoke_token already
-- established, so no INSERT/UPDATE is granted to any role here.
GRANT SELECT ON frameworks TO api_tenant_data;
GRANT SELECT ON master_controls TO api_tenant_data;
-- scoped_control_implementations (platform expansion, handoff section
-- 10.1-10.2): unlike frameworks/master_controls, this genuinely is
-- tenant data (organization_id present), an organization's own
-- applicability decision against the shared catalog. Same api-serve-
-- process-only shape as module_entitlements: every write is a human
-- decision made through the API, no worker/scheduler path touches it.
GRANT SELECT, INSERT, UPDATE ON scoped_control_implementations TO api_tenant_data;
-- technical_assertion_collections (platform expansion, handoff
-- section 10.2, Phase 5 of the 2026-09-14 scope audit): same
-- api-serve-process-only shape as scoped_control_implementations
-- above (no worker/scheduler path collects or evaluates an
-- assertion; that happens synchronously inside one API request in
-- this version). No UPDATE: a collection attempt is an immutable
-- historical record once written, the same append-only reasoning
-- finding_events already established; a wrong or stale collection
-- gets superseded by a new attempt, never edited in place.
GRANT SELECT, INSERT ON technical_assertion_collections TO api_tenant_data;

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
-- coverage_records's own record_coverage is an upsert
-- (INSERT ... ON CONFLICT ... DO UPDATE); full SELECT, INSERT, UPDATE
-- covers both the conflict-target columns and the DO UPDATE SET
-- clause's EXCLUDED references without needing a narrower column
-- list, the same shape findings' own worker grant already uses.
GRANT SELECT, INSERT, UPDATE ON coverage_records TO worker_tenant_data;

-- scheduler_tenant_data ---------------------------------------------------

GRANT SELECT ON organization_authorizations TO scheduler_tenant_data;
GRANT SELECT ON scan_permits TO scheduler_tenant_data;
