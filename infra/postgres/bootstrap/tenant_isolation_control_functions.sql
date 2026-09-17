-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): Phase F of
-- the tenant-isolation plumbing. Creates the webguard_control schema
-- and the 13 SECURITY DEFINER control functions the four function-
-- owner roles (Phase C) already have exactly the table privileges
-- for (Phase E). Run this file only after tenant_isolation_roles.sql,
-- tenant_isolation_acl.sql, and tenant_isolation_function_acl.sql:
-- every role granted EXECUTE here must already exist with its Phase-E
-- table ACL already in place.
--
-- Nothing here is reachable from live WebGuard runtime yet. No
-- repository method calls any of these functions (that is a later,
-- separate phase); no RLS policy exists; no production LOGIN role
-- exists. This file only proves that 13 dormant, narrowly-privileged
-- functions exist, are owned by the right role, run inside exactly
-- that role's Phase-E ACL envelope (not the bootstrap admin's), and
-- cannot be reached by PUBLIC or by any unintended caller.
--
-- OWNERSHIP MECHANICS: this file must work for a NON-SUPERUSER
-- bootstrap actor (the accepted deployment model, since AWS RDS's
-- own master user is NOSUPERUSER -- the same reason Phase C/D/E
-- never rely on BYPASSRLS), not merely for the disposable dev/CI
-- Postgres's superuser convenience. Each of the four function-owner
-- blocks below claims a narrow, self-contained temporary window
-- (never shared with the other three blocks), does its own work
-- entirely while impersonating that owner via `SET ROLE`, then
-- reverses the window before the next block starts. Ownership of
-- each function arises naturally from `CREATE OR REPLACE FUNCTION`
-- running while `CURRENT_USER` is already the intended owner --
-- there is no `ALTER FUNCTION ... OWNER TO` anywhere in this file.
--
-- PostgreSQL 16 changed CREATEROLE semantics so that a CREATEROLE
-- (non-superuser) actor who runs CREATE ROLE is automatically granted
-- membership, WITH ADMIN OPTION, in every role it creates -- confirmed
-- directly against pg_auth_members after running
-- tenant_isolation_roles.sql as this non-superuser actor. Admin
-- option alone does not let the actor act as the target role (SET
-- ROLE fails with "permission denied to set role" despite
-- admin_option=true), because PG16 separates ADMIN, INHERIT, and SET
-- as three independent grant options
-- (pg_auth_members.admin_option/inherit_option/set_option), and
-- acting as another role specifically needs SET. But a role holding
-- ADMIN OPTION on another role can grant itself any combination of
-- those options on that role, including SET -- confirmed:
-- `GRANT <owner_role> TO CURRENT_USER WITH SET TRUE` succeeded using
-- only the admin option Phase C's own CREATE ROLE already conferred
-- automatically. No change to tenant_isolation_roles.sql, and no new
-- bootstrap role, is required: the existing flat role graph already
-- expresses everything this file needs, once this file claims it.
--
-- A temporary CREATE-on-schema grant is required in addition to SET:
-- `CREATE OR REPLACE FUNCTION webguard_control.<fn>` while
-- impersonating the owner still fails with "permission denied for
-- schema webguard_control" if that owner lacks CREATE on it. USAGE on
-- webguard_control is also required, separately from CREATE, for the
-- REVOKE/GRANT EXECUTE statements that follow each function's
-- creation: those statements reference the function by its schema-
-- qualified name, and resolving that name needs USAGE on the schema,
-- not just ownership of the function itself. This file grants USAGE
-- standingly (below, once, to all seven roles) rather than claiming
-- it temporarily per block, since every one of these roles legitimately
-- needs it for the long run: the four function-owner roles need it
-- for this file's own owner-context bootstrap mechanics every time it
-- is re-run, and the three tenant-data roles need it to actually call
-- these functions once a later repository-conversion phase wires
-- them in. USAGE and CREATE are independent schema privileges; this
-- file relies on that independence to keep USAGE standing while
-- keeping CREATE (a much broader capability: the power to define new
-- objects, not merely reference existing ones) strictly temporary.
--
-- PG16 keeps admin/inherit/set as three independent options per
-- (role, member, grantor) row in pg_auth_members, not one flag per
-- (role, member) pair. A `GRANT <owner_role> TO CURRENT_USER WITH
-- SET TRUE` issued against a role the actor already holds ADMIN
-- OPTION on (from CREATE ROLE) does not update that existing row --
-- it inserts a SECOND row, keyed apart by grantor. Confirmed
-- empirically: any option a fresh GRANT statement does not mention
-- takes its default from the grantee's own attributes, not from the
-- pre-existing row, so a bare `WITH SET TRUE` leaves that new row's
-- inherit_option defaulting to the bootstrap actor's own rolinherit
-- (true for an ordinary LOGIN role). Left uncorrected, that default
-- would stand permanently: the closing `REVOKE SET OPTION FOR
-- <owner_role> FROM CURRENT_USER` only clears set_option on that
-- same row, never inherit_option, so the bootstrap actor would keep
-- automatically inheriting every privilege each function-owner role
-- holds -- no SET ROLE required -- for good. `WITH INHERIT FALSE` is
-- therefore claimed on the same row, before `WITH SET TRUE`, so that
-- row never carries inherit_option=true to begin with.
--
-- Each owner block below is therefore, independently: (1) `GRANT
-- <owner_role> TO CURRENT_USER WITH INHERIT FALSE` then `GRANT
-- <owner_role> TO CURRENT_USER WITH SET TRUE` (both against the same
-- self-granted row, using the admin option Phase C's CREATE ROLE
-- already gave this actor); (2) `GRANT CREATE ON SCHEMA
-- webguard_control TO <owner_role>` (temporary); (3) `SET ROLE
-- <owner_role>`; (4) every `CREATE OR REPLACE FUNCTION` and EXECUTE-
-- ACL statement for that owner's functions, running as that owner;
-- (5) `RESET ROLE`; (6) `REVOKE CREATE ON SCHEMA webguard_control
-- FROM <owner_role>`; (7) `REVOKE SET OPTION FOR <owner_role> FROM
-- CURRENT_USER`. Steps 6-7 leave the function-owner role's own CREATE
-- privilege on webguard_control at FALSE again (Section 28). After
-- step 7, pg_auth_members still holds TWO rows for the bootstrap
-- actor against that function-owner role (the original CREATE-ROLE
-- row and this file's own self-granted row) -- REVOKE SET OPTION FOR
-- does not remove the self-granted row, it only flips its set_option
-- back to false -- and the actor's EFFECTIVE state across both rows
-- is admin_option=true (harmless, from Phase C, never touched here),
-- inherit_option=false (guarded by step 1 above), set_option=false
-- (reversed by step 7). The actor retains no standing ability to
-- assume, or automatically inherit the privileges of, any function-
-- owner role once this file finishes -- confirmed both by catalog
-- inspection and by a direct access attempt (SET ROLE and an
-- attempted use of a privilege granted only to a function-owner role
-- both fail after cleanup). This entire sequence is a correctness
-- no-op for a superuser bootstrap actor (superuser bypasses every
-- check these statements exist to satisfy) but is required, and was
-- verified required, for the non-superuser, RDS-compatible actor
-- this project's own architecture targets. Because each block's
-- window is independent, running this whole file a second time (or
-- more) is safe: `CREATE OR REPLACE FUNCTION` while impersonating the
-- already-correct owner succeeds identically whether the function is
-- being created for the first time or replaced with the same
-- definition, with no `ALTER ... OWNER TO` step ever needed to make a
-- second run behave differently from the first.
--
-- FUNCTION SECURITY BASELINE (Section 6): every function below is
-- SECURITY DEFINER, sets a fixed `search_path = pg_catalog, pg_temp`
-- (the narrowest search_path that still lets each function
-- body run at all: pg_catalog for built-in types/operators/functions,
-- pg_temp so a session's own temp objects are still reachable but
-- never resolved ahead of a schema-qualified name), and every single
-- WebGuard table or function reference inside every function body is
-- explicitly schema-qualified (public.scan_jobs, public.api_tokens,
-- webguard_control.<other function>, etc.) rather than left to
-- resolve against the caller's search_path. No function here uses
-- EXECUTE '<dynamic sql>' anywhere; every caller-supplied value is a
-- typed parameter bound through the function's own argument list, and
-- no identifier (table/column/schema name) is ever caller-supplied.
--
-- SEMANTICS: every function's body was written to reproduce the
-- CURRENT SQL, transaction boundary, ordering, filters, CAS
-- conditions, returned columns, and not-found/error-outcome shape of
-- the existing Python repository method it stands in for, re-read
-- directly against this commit (not carried over from the design
-- round). Each function's own comment block below states its current
-- source method and calls out the few narrow, deliberate places where
-- full parity was not attempted.
--
-- Two existing Python-side validations were re-traced against their
-- actual current failure type and security relevance rather than
-- dismissed as a class:
--
-- worker_id shape (postgres_jobs.py's `_worker_id()`: non-empty after
-- stripping, 1-128 visible ASCII characters) is a data-hygiene guard,
-- not a tenant-isolation or authorization control -- a malformed
-- worker_id cannot let one worker claim or tamper with another's
-- leased job (that protection is the lease-token comparison, already
-- reproduced exactly). It is nonetheless reproduced below, in
-- claim_next_job, renew_lease, and terminal_transition, matching the
-- preference that a privileged worker function reject what the
-- current operation rejects.
--
-- The safety-receipt reference/digest format check (path-traversal
-- and lower-case-hex validation, currently in postgres_jobs.py's
-- `_terminal_update()`) is genuinely security-relevant, not
-- orthogonal: terminal_transition PERSISTS this value into
-- job_safety_receipts, and a future reader of that column (an
-- artifact-store path join, for instance) may reasonably trust an
-- already-persisted reference as pre-validated rather than
-- re-checking it. Skipping this check here would let an unsanitized
-- path (e.g. containing `..` or an absolute `/` prefix) reach
-- permanent storage. It is reproduced below in terminal_transition,
-- checked before the CAS update runs (current Python checks it after
-- the CAS, immediately before the INSERT, but since a raised
-- exception at either point aborts the entire enclosing transaction
-- either way, the two orderings are observably identical: nothing
-- commits on a validation failure regardless of which order the
-- checks run in).
--
-- Secret verification (scrypt/argon2) stays in Python, as instructed:
-- every identity resolver returns a secret hash for Python to verify,
-- never verifies it in SQL.
--
-- No RLS policy, no ENABLE/FORCE ROW LEVEL SECURITY, no repository
-- conversion, no production LOGIN role, no production credential
-- change. GRANT/REVOKE and CREATE OR REPLACE FUNCTION are all
-- idempotent in PostgreSQL: re-running this file changes nothing.
--
-- TRANSACTIONALITY: the temporary SET-option/CREATE-on-schema window
-- claimed for ownership transfer (above) must never be left partially
-- committed -- a failure anywhere between claiming it and revoking it
-- must leave no trace, not a function-owner role holding CREATE, not
-- the bootstrap actor holding SET. `psql -f` does NOT guarantee this
-- on its own: by default it autocommits each statement separately,
-- so a later statement's failure does not undo an earlier statement
-- that already committed (confirmed against PostgreSQL's own
-- documented default, and distinct from how this project's own test
-- harness invokes this file, which sends the whole file as one
-- multi-statement simple-query message and gets an implicit single
-- transaction as a result of that protocol behavior, not from
-- anything this file itself declares). Phase C's own role-bootstrap
-- file sidesteps this entirely by wrapping its own logic in one
-- `DO $$ ... $$` block, which is inherently atomic regardless of
-- invocation method; this file has no equivalent structure of its
-- own until the explicit BEGIN/COMMIT below. This file is therefore
-- explicitly wrapped in one transaction, so it is self-atomic under
-- ANY invocation method (`psql -f`, `psql -1 -f`, a driver's own
-- multi-statement call, etc.), not dependent on the caller supplying
-- `--single-transaction`/`ON_ERROR_STOP`. A future production
-- bootstrap runner may still reasonably choose to invoke this file
-- with `psql -v ON_ERROR_STOP=1 -1 -f tenant_isolation_control_functions.sql`
-- (stopping immediately on error, rather than continuing past it) as
-- defense in depth, but that choice does not change whether the
-- temporary-privilege window itself can be partially committed: this
-- BEGIN/COMMIT pair is what actually guarantees that, independent of
-- how the file is invoked. No production deployment framework is
-- introduced here; this is exactly the same kind of self-contained
-- atomicity Phase C's DO block already relies on for the same reason.

BEGIN;

CREATE SCHEMA IF NOT EXISTS webguard_control;

REVOKE CREATE, USAGE ON SCHEMA webguard_control FROM PUBLIC;

-- EXECUTE on a function requires USAGE on its schema too; grant it
-- only to the four function-owner roles (so a future ownership-owned
-- caller path works) and to the three tenant-data roles that will
-- eventually be the ones actually invoking these functions once a
-- later repository-conversion phase wires them in. No LOGIN role is
-- granted anything here.
GRANT USAGE ON SCHEMA webguard_control
    TO identity_function_owner, worker_function_owner,
       scheduler_function_owner, callback_function_owner,
       api_tenant_data, worker_tenant_data, scheduler_tenant_data,
       callback_receiver;

-- Non-superuser, RDS-compatible ownership mechanics (see the file
-- header): claim the SET option on this function-owner role (using
-- the ADMIN OPTION Phase C's own CREATE ROLE already conferred to
-- whichever actor ran it) and grant it temporary CREATE on this
-- schema, so `SET ROLE` below can impersonate it for the whole
-- IDENTITY block. Both are reversed right after `RESET ROLE`, once
-- every function in this block has been created while impersonating
-- this owner. A no-op for a superuser bootstrap actor.
--
-- WITH INHERIT FALSE is claimed first, on the same self-granted row,
-- before WITH SET TRUE: PG16 defaults an unmentioned option on a new
-- grant to the grantee's own attribute, not to false, so a bare WITH
-- SET TRUE here would leave this row's inherit_option matching the
-- bootstrap actor's own rolinherit (true for an ordinary LOGIN role)
-- -- and the REVOKE SET OPTION FOR at the end of this file clears
-- only set_option, never inherit_option. Without this line, the
-- bootstrap actor would keep standingly inheriting every privilege
-- each function-owner role holds after this file finishes, with no
-- SET ROLE needed. See the file header for the full explanation.
GRANT identity_function_owner TO CURRENT_USER WITH INHERIT FALSE;
GRANT identity_function_owner TO CURRENT_USER WITH SET TRUE;
GRANT CREATE ON SCHEMA webguard_control TO identity_function_owner;

SET ROLE identity_function_owner;

-- =========================================================================
-- IDENTITY (identity_function_owner) -- pure read resolvers, no writes.
-- =========================================================================

-- resolve_api_token: current source is postgres_identity.py's
-- authenticate_token(). Current SQL: SELECT token_id, organization_id,
-- principal_id, label, secret_hash, created_at, expires_at,
-- revoked_at, last_used_at FROM api_tokens WHERE token_id = %s, then
-- (if found) a separate SELECT of the principal's _PRINCIPAL_COLUMNS
-- and a separate SELECT of the organization's (organization_id, name,
-- status, created_at). Current ordering: revoked_at/expires_at are
-- checked BEFORE the principal/organization lookups even happen; this
-- function preserves that by returning the token's own revocation/
-- expiry fields unconditionally (even when no principal/organization
-- row resolves) via LEFT JOIN rather than an inner join, so a future
-- caller can still replicate the exact "check revoked, then check
-- expired, then check principal/org missing" sequence, all from one
-- returned row (or zero rows if the token_id itself was never found).
-- Current returned data actually used by the token's one live caller
-- (auth.py's ApiTokenAuthenticator.authenticate): metadata.token_id,
-- organization.organization_id, organization.name, principal.
-- principal_id, principal.display_name, principal.role, plus
-- metadata.revoked_at/expires_at and principal.active/organization.
-- status for validation. secret_hash is returned because Python keeps
-- secret verification (never verified in SQL here). last_used_at,
-- label, created_at are the current write target and audit metadata,
-- not needed by any read decision, and are deliberately omitted
-- (Section 13 output minimization).
CREATE OR REPLACE FUNCTION webguard_control.resolve_api_token(
    p_token_id uuid
) RETURNS TABLE (
    token_id uuid,
    secret_hash text,
    token_revoked_at timestamptz,
    token_expires_at timestamptz,
    principal_id uuid,
    principal_display_name text,
    principal_role text,
    principal_active boolean,
    organization_id uuid,
    organization_name text,
    organization_status text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT
        t.token_id,
        t.secret_hash,
        t.revoked_at,
        t.expires_at,
        p.principal_id,
        p.display_name,
        p.role,
        p.active,
        o.organization_id,
        o.name,
        o.status
    FROM public.api_tokens AS t
    LEFT JOIN public.principals AS p ON p.principal_id = t.principal_id
    LEFT JOIN public.organizations AS o ON o.organization_id = t.organization_id
    WHERE t.token_id = p_token_id;
$$;

-- resolve_browser_session: current source is postgres_sessions.py's
-- authenticate_session() plus auth.py's BrowserSessionAuthenticator.
-- authenticate()'s own get_principal()/get_organization() calls right
-- after it. Current SQL: SELECT session_id, principal_id,
-- organization_id, secret_hash, csrf_hash, assurance_level,
-- issued_at, idle_expires_at, absolute_expires_at, last_used_at,
-- revoked_at, user_agent, ip_address FROM browser_sessions WHERE
-- session_id = %s, then the same two separate principal/organization
-- lookups. Same LEFT JOIN reasoning as resolve_api_token: return the
-- session's own fields unconditionally so a future caller can check
-- is_usable()-equivalent expiry/revocation logic before deciding
-- principal/organization resolution matters. csrf_hash is returned
-- because the current code's CSRF check (_verify_secret(csrf_header,
-- row[4])) also stays in Python. user_agent/ip_address/last_used_at
-- are audit/session-touch fields, not needed by any read decision,
-- and are omitted (Section 13).
CREATE OR REPLACE FUNCTION webguard_control.resolve_browser_session(
    p_session_id uuid
) RETURNS TABLE (
    session_id uuid,
    secret_hash text,
    csrf_hash text,
    assurance_level text,
    idle_expires_at timestamptz,
    absolute_expires_at timestamptz,
    session_revoked_at timestamptz,
    principal_id uuid,
    principal_display_name text,
    principal_role text,
    principal_active boolean,
    organization_id uuid,
    organization_name text,
    organization_status text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT
        s.session_id,
        s.secret_hash,
        s.csrf_hash,
        s.assurance_level,
        s.idle_expires_at,
        s.absolute_expires_at,
        s.revoked_at,
        p.principal_id,
        p.display_name,
        p.role,
        p.active,
        o.organization_id,
        o.name,
        o.status
    FROM public.browser_sessions AS s
    LEFT JOIN public.principals AS p ON p.principal_id = s.principal_id
    LEFT JOIN public.organizations AS o ON o.organization_id = s.organization_id
    WHERE s.session_id = p_session_id;
$$;

-- resolve_principal_by_email: current source is postgres_identity.py's
-- get_principal_by_email() and get_password_hash(), called together
-- from service.py's login() (Phase E's own committed ACL comment
-- already established this as one combined function covering all
-- three tables: principals, password_credentials, organizations).
-- get_principal_by_email() itself lower-cases and strips the email
-- (email.strip().casefold()) before the lookup; this function expects
-- the caller to have already normalized it identically, matching
-- get_principal_by_email()'s own normalization exactly rather than
-- re-implementing it in SQL. password_hash is nullable (a principal
-- can exist without a password_credentials row); no other password
-- metadata (algorithm, created_at, updated_at) is returned, since
-- login()'s only use of the stored hash is verify_password(password,
-- stored_hash), never anything else (Section 13).
CREATE OR REPLACE FUNCTION webguard_control.resolve_principal_by_email(
    p_email text
) RETURNS TABLE (
    principal_id uuid,
    principal_display_name text,
    principal_role text,
    principal_active boolean,
    password_hash text,
    organization_id uuid,
    organization_name text,
    organization_status text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT
        p.principal_id,
        p.display_name,
        p.role,
        p.active,
        c.password_hash,
        o.organization_id,
        o.name,
        o.status
    FROM public.principals AS p
    LEFT JOIN public.password_credentials AS c ON c.principal_id = p.principal_id
    LEFT JOIN public.organizations AS o ON o.organization_id = p.organization_id
    WHERE p.email = p_email;
$$;

-- resolve_password_hash: current source is postgres_identity.py's
-- get_password_hash(). P1-2 Phase H gap closure: unlike the four
-- functions above (each keyed by a bearer secret, a session, or an
-- email address), this method's own two live callers, service.py's
-- login() (already has a resolved Principal from
-- resolve_principal_by_email, but that function deliberately drops
-- its own password_hash column, Section 13 output minimization,
-- since get_principal_by_email's own contract never returns it) and
-- change_password() (only ever holds an already-authenticated
-- context.principal_id, never an email at all), both key by a bare
-- principal_id, which none of the 13 functions above resolve by.
-- Returns ONLY password_hash, nothing else: no role, no organization,
-- no display name, matching the same Section 13 output-minimization
-- principle as every function above. Exact-match on principal_id
-- (principals' own primary key), never a caller-controlled filter.
-- NULL back (no such principal, or a principal with no
-- password_credentials row at all) is not distinguished from any
-- other failure by this function: login()'s own generic-
-- invalid-credentials response and change_password()'s own
-- current-password-incorrect response already collapse every failure
-- shape the same way today, so this introduces no new oracle.
CREATE OR REPLACE FUNCTION webguard_control.resolve_password_hash(
    p_principal_id uuid
) RETURNS text
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT password_hash FROM public.password_credentials WHERE principal_id = p_principal_id;
$$;

-- resolve_identity_token: P1-2 Phase H gap closure, 2026-09-17,
-- widened to add created_at, the one column consume_identity_token's
-- own IdentityTokenRecord contract needs that this function did not
-- yet return (its own original comment above already explains why it
-- was left off: no caller needed it when this function was written,
-- since every caller resolved principal/organization separately
-- rather than resolving via consume_identity_token itself). Every
-- other repository.py caller of this exact name was re-checked before
-- this change: the only other reference anywhere in this codebase is
-- tests/integration/test_postgres_control_functions.py's own
-- `SELECT * FROM webguard_control.resolve_identity_token(%s)`, which
-- reads columns by name/position from the SELECT * result and gains
-- the new trailing column automatically. Adding a column at the end
-- of a SELECT * result never breaks a caller that only reads the
-- columns it already expects by position 0..6. PostgreSQL does not
-- allow CREATE OR REPLACE FUNCTION to change an existing function's
-- result type at all (confirmed directly against this project's own
-- disposable Postgres 16: attempting it raises "cannot change return
-- type of existing function" even when only appending a column), so
-- this replacement is DROP FUNCTION then CREATE FUNCTION, not CREATE
-- OR REPLACE. The REVOKE/GRANT EXECUTE below re-establishes the
-- exact same grant DROP FUNCTION removes, so the net privilege state
-- after this file finishes is unchanged from before.
DROP FUNCTION IF EXISTS webguard_control.resolve_identity_token(uuid);
CREATE FUNCTION webguard_control.resolve_identity_token(
    p_token_id uuid
) RETURNS TABLE (
    token_id uuid,
    principal_id uuid,
    organization_id uuid,
    purpose text,
    secret_hash text,
    expires_at timestamptz,
    used_at timestamptz,
    created_at timestamptz
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT
        t.token_id,
        t.principal_id,
        t.organization_id,
        t.purpose,
        t.secret_hash,
        t.expires_at,
        t.used_at,
        t.created_at
    FROM public.identity_tokens AS t
    WHERE t.token_id = p_token_id;
$$;

REVOKE ALL ON FUNCTION webguard_control.resolve_api_token(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_browser_session(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_principal_by_email(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_identity_token(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_password_hash(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION webguard_control.resolve_api_token(uuid) TO api_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_browser_session(uuid) TO api_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_principal_by_email(text) TO api_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_identity_token(uuid) TO api_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_password_hash(uuid) TO api_tenant_data;

RESET ROLE;

-- Function-owner CREATE on webguard_control returns to FALSE; the
-- bootstrap actor loses standing ability to SET ROLE to this role
-- (it retains only the ADMIN OPTION PG16's CREATEROLE conferred
-- automatically in Phase C, which lets it re-claim SET again in a
-- future run if genuinely needed, but confers no privilege by
-- itself). A no-op for a superuser bootstrap actor.
REVOKE CREATE ON SCHEMA webguard_control FROM identity_function_owner;
REVOKE SET OPTION FOR identity_function_owner FROM CURRENT_USER;

-- Non-superuser, RDS-compatible ownership-transfer mechanics: see the
-- IDENTITY block above (and the file header) for the full explanation
-- of why WITH INHERIT FALSE must be claimed before WITH SET TRUE.
GRANT worker_function_owner TO CURRENT_USER WITH INHERIT FALSE;
GRANT worker_function_owner TO CURRENT_USER WITH SET TRUE;
GRANT CREATE ON SCHEMA webguard_control TO worker_function_owner;

SET ROLE worker_function_owner;

-- =========================================================================
-- WORKER (worker_function_owner) -- cross-tenant lease/claim/terminal-
-- transition control plane.
-- =========================================================================

-- claim_next_job: current source is postgres_jobs.py's
-- claim_next_leased(). Preserves the exact claimable-row predicate
-- (queued, not cancellation-requested, authorization still assigned
-- or job has no organization_id, permit binding either absent or
-- valid-and-not-already-driving-another-RUNNING-job), the exact
-- ORDER BY submitted_at, job_id, the exact FOR UPDATE OF jobs SKIP
-- LOCKED concurrency behavior, and the exact optimistic-CAS UPDATE
-- (state/revision-guarded WHERE clause) before the readback. Returns
-- zero rows when nothing is claimable or the CAS lost the race
-- (updated.rowcount != 1 in current code returns None), exactly one
-- row of the full job record plus its now-current lease fields
-- otherwise. p_worker_id reproduces current code's _worker_id() shape
-- check (non-empty after stripping, 1-128 visible ASCII characters,
-- Section 5 review); a failure raises an exception rather than
-- returning zero rows, matching current code's own exception-raising
-- behavior for this specific case. p_lease_seconds' [0.1, 3600] range
-- check is not reproduced (lower security relevance than worker_id
-- shape, and make_interval() already rejects a negative value on its
-- own with a native error).
--
-- One deliberate deviation from "exact reproduction": started_at,
-- updated_at, heartbeat_at, and the lease_expires_at derived from them
-- are floored to the claimed row's own submitted_at (GREATEST(p_now,
-- submitted_at)) rather than using p_now unconditionally. p_now is
-- read in Python before this function is even called, so a submission
-- that commits a later submitted_at while this call's own row lock
-- was queued behind it can otherwise leave p_now earlier than the row
-- it just claimed, and scan_jobs.py's ScanJobRecord then refuses to
-- construct (updated_at/started_at cannot precede submitted_at). The
-- claimable-row predicate itself still has no submitted_at <= p_now
-- filter (unchanged, see above); only the value written for these
-- four columns is floored.
CREATE OR REPLACE FUNCTION webguard_control.claim_next_job(
    p_worker_id text,
    p_lease_seconds numeric,
    p_now timestamptz
) RETURNS TABLE (
    job_id uuid,
    target text,
    authorization_id text,
    authorization_sha256 text,
    mode text,
    state text,
    revision integer,
    cancellation_requested boolean,
    submitted_at timestamptz,
    updated_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    scan_id text,
    result_status text,
    report_ref text,
    audit_ref text,
    error_code text,
    error_message text,
    idempotency_key text,
    worker_id text,
    lease_token text,
    lease_expires_at timestamptz,
    attempt_count integer
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_job_id uuid;
    v_revision integer;
    v_submitted_at timestamptz;
    v_effective_now timestamptz;
    v_lease_token text := gen_random_uuid()::text;
    v_lease_expires_at timestamptz;
    v_updated integer;
    v_trimmed_worker_id text;
BEGIN
    -- Reproduces postgres_jobs.py's _worker_id(): non-empty after
    -- stripping, 1-128 visible ASCII characters (Section 5 review).
    v_trimmed_worker_id := btrim(p_worker_id);
    IF p_worker_id IS NULL OR length(v_trimmed_worker_id) < 1
       OR length(v_trimmed_worker_id) > 128 OR v_trimmed_worker_id ~ '[^\x21-\x7E]' THEN
        RAISE EXCEPTION 'job_worker_id_invalid: worker_id must contain 1 to 128 visible ASCII characters';
    END IF;

    SELECT jobs.job_id, jobs.revision, jobs.submitted_at
    INTO v_job_id, v_revision, v_submitted_at
    FROM public.scan_jobs AS jobs
    LEFT JOIN public.job_permits AS binding ON binding.job_id = jobs.job_id
    WHERE jobs.state = 'queued'
      AND jobs.cancellation_requested = FALSE
      AND (
        jobs.organization_id IS NULL
        OR EXISTS (
            SELECT 1 FROM public.organization_authorizations AS assignment
            WHERE assignment.organization_id = jobs.organization_id
              AND assignment.authorization_id = jobs.authorization_id
        )
      )
      AND (
        binding.permit_id IS NULL
        OR (
            EXISTS (
                SELECT 1 FROM public.scan_permits AS permit
                WHERE permit.permit_id = binding.permit_id
                  AND permit.permit_sha256 = binding.permit_sha256
                  AND permit.revoked_at IS NULL
                  AND permit.not_before <= p_now
                  AND p_now < permit.expires_at
            )
            AND NOT EXISTS (
                SELECT 1 FROM public.scan_jobs AS running
                JOIN public.job_permits AS running_binding
                  ON running_binding.job_id = running.job_id
                WHERE running.state = 'running'
                  AND running_binding.permit_id = binding.permit_id
            )
        )
      )
    ORDER BY jobs.submitted_at, jobs.job_id
    LIMIT 1
    FOR UPDATE OF jobs SKIP LOCKED;

    IF v_job_id IS NULL THEN
        RETURN;
    END IF;

    -- p_now is read in Python (ScanJobWorker.run_once) before this
    -- function is even called, so it can be stale by the time this
    -- statement runs: this call's own row lock can queue behind a
    -- concurrent submission that reads its own, later `now` for
    -- submitted_at and commits first, and the SELECT above has no
    -- submitted_at <= p_now filter (by design, see this function's
    -- own header comment). GREATEST() floors the moment actually
    -- written (and the lease derived from it) to this row's own
    -- submitted_at, so ScanJobRecord's invariant (started_at/
    -- updated_at cannot precede submitted_at, in scan_jobs.py) holds
    -- by construction. This mirrors store.py's _no_earlier_than fix
    -- for the identical race in the SQLite-backed job store.
    v_effective_now := GREATEST(p_now, v_submitted_at);
    v_lease_expires_at := v_effective_now + make_interval(secs => p_lease_seconds);

    UPDATE public.scan_jobs
    SET state = 'running', started_at = v_effective_now, updated_at = v_effective_now, revision = v_revision + 1,
        worker_id = v_trimmed_worker_id, lease_token = v_lease_token, lease_expires_at = v_lease_expires_at,
        heartbeat_at = v_effective_now, attempt_count = scan_jobs.attempt_count + 1
    WHERE scan_jobs.job_id = v_job_id AND scan_jobs.state = 'queued' AND scan_jobs.revision = v_revision;
    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        j.job_id, j.target, j.authorization_id, j.authorization_sha256, j.mode, j.state,
        j.revision, j.cancellation_requested, j.submitted_at, j.updated_at, j.started_at,
        j.completed_at, j.scan_id, j.result_status, j.report_ref, j.audit_ref, j.error_code,
        j.error_message, j.idempotency_key, j.worker_id, j.lease_token, j.lease_expires_at,
        j.attempt_count
    FROM public.scan_jobs AS j
    WHERE j.job_id = v_job_id;
END;
$$;

-- recover_expired_leases: current source is postgres_jobs.py's own
-- method of that name. Preserves the exact expired-lease selection
-- (RUNNING, lease_expires_at not null and <= now, FOR UPDATE SKIP
-- LOCKED, ordered by lease_expires_at then job_id), the exact
-- three-way branch (cancellation_requested -> CANCELLED,
-- attempt_count >= maximum_attempts -> FAILED with the same fixed
-- error_code/error_message, otherwise -> QUEUED with started_at
-- cleared), and the exact scan_records reconciliation (UPDATE ...
-- WHERE job_id = %s AND completed_at IS NULL, only for the CANCELLED/
-- FAILED branches). worker_function_owner's SELECT on scan_records
-- (Phase E) is required by this UPDATE's own WHERE clause, not merely
-- by terminal_transition's use of the same table (see Phase E's own
-- ACL file header for the empirical proof). Returns the same
-- (requeued, cancelled, failed) counts as the current
-- LeaseRecoverySummary.
CREATE OR REPLACE FUNCTION webguard_control.recover_expired_leases(
    p_now timestamptz,
    p_maximum_attempts integer
) RETURNS TABLE (
    requeued integer,
    cancelled integer,
    failed integer
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_requeued integer := 0;
    v_cancelled integer := 0;
    v_failed integer := 0;
    v_row RECORD;
    v_updated integer;
    v_effective_now timestamptz;
BEGIN
    FOR v_row IN
        SELECT job_id, revision, lease_token, cancellation_requested, attempt_count, submitted_at
        FROM public.scan_jobs
        WHERE state = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= p_now
        ORDER BY lease_expires_at, job_id
        FOR UPDATE SKIP LOCKED
    LOOP
        -- See claim_next_job's own comment on this exact race/fix.
        -- Structurally, this loop's own WHERE clause already implies
        -- p_now >= lease_expires_at >= submitted_at (once claim_next_job/
        -- renew_lease correctly floor lease_expires_at against
        -- submitted_at) for every row reached here, so this floor is
        -- defense-in-depth rather than an independently reachable gap.
        -- It is applied for the same reason store.py's SQLite
        -- equivalent applies it to every write site, not because this
        -- one is known to be exploitable on its own.
        v_effective_now := GREATEST(p_now, v_row.submitted_at);
        IF v_row.cancellation_requested THEN
            UPDATE public.scan_jobs
            SET state = 'cancelled', completed_at = v_effective_now, updated_at = v_effective_now, revision = revision + 1,
                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
            WHERE job_id = v_row.job_id AND state = 'running' AND revision = v_row.revision
              AND lease_token = v_row.lease_token;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            v_cancelled := v_cancelled + v_updated;
            IF v_updated > 0 THEN
                UPDATE public.scan_records SET status = 'cancelled', completed_at = COALESCE(completed_at, v_effective_now)
                WHERE job_id = v_row.job_id AND completed_at IS NULL;
            END IF;
        ELSIF v_row.attempt_count >= p_maximum_attempts THEN
            UPDATE public.scan_jobs
            SET state = 'failed', completed_at = v_effective_now, updated_at = v_effective_now, revision = revision + 1,
                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL,
                error_code = 'worker_lease_attempts_exhausted',
                error_message = 'The scan job exceeded the permitted worker recovery attempts.'
            WHERE job_id = v_row.job_id AND state = 'running' AND revision = v_row.revision
              AND lease_token = v_row.lease_token;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            v_failed := v_failed + v_updated;
            IF v_updated > 0 THEN
                UPDATE public.scan_records SET status = 'failed', completed_at = COALESCE(completed_at, v_effective_now)
                WHERE job_id = v_row.job_id AND completed_at IS NULL;
            END IF;
        ELSE
            UPDATE public.scan_jobs
            SET state = 'queued', started_at = NULL, updated_at = v_effective_now, revision = revision + 1,
                worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
            WHERE job_id = v_row.job_id AND state = 'running' AND revision = v_row.revision
              AND lease_token = v_row.lease_token;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            v_requeued := v_requeued + v_updated;
        END IF;
    END LOOP;

    RETURN QUERY SELECT v_requeued, v_cancelled, v_failed;
END;
$$;

-- renew_lease: current source is postgres_jobs.py's own method of
-- that name. Preserves the exact ownership/token/expiry check
-- (_require_active_lease: state must be RUNNING, worker_id and
-- lease_token must match exactly, lease_expires_at must be in the
-- future) and the exact CAS UPDATE (state/revision/worker_id/
-- lease_token-guarded WHERE clause). Because a SQL function cannot
-- raise the three distinct current JobStoreError codes (job_not_found,
-- job_lease_lost, job_lease_expired) as an application-level
-- exception a future caller can pattern-match on, this function
-- returns them as an explicit outcome column instead of raising:
-- exactly one row is always returned, with outcome = 'ok' (and the
-- full renewed job/lease record) on success, or outcome =
-- 'not_found' / 'lease_lost' / 'lease_expired' (with every job field
-- NULL) matching the exact condition current code raises for. A
-- future repository-conversion phase maps outcome back to the same
-- JobStoreError codes/messages it raises today.
CREATE OR REPLACE FUNCTION webguard_control.renew_lease(
    p_job_id uuid,
    p_worker_id text,
    p_lease_token text,
    p_now timestamptz,
    p_lease_seconds numeric
) RETURNS TABLE (
    outcome text,
    job_id uuid,
    target text,
    authorization_id text,
    authorization_sha256 text,
    mode text,
    state text,
    revision integer,
    cancellation_requested boolean,
    submitted_at timestamptz,
    updated_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    scan_id text,
    result_status text,
    report_ref text,
    audit_ref text,
    error_code text,
    error_message text,
    idempotency_key text,
    worker_id text,
    lease_token text,
    lease_expires_at timestamptz,
    attempt_count integer
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_state text;
    v_worker_id text;
    v_lease_token text;
    v_lease_expires_at timestamptz;
    v_revision integer;
    v_submitted_at timestamptz;
    v_effective_now timestamptz;
    v_new_expires_at timestamptz;
    v_updated integer;
    v_trimmed_worker_id text;
BEGIN
    -- Reproduces postgres_jobs.py's _worker_id() (Section 5 review).
    v_trimmed_worker_id := btrim(p_worker_id);
    IF p_worker_id IS NULL OR length(v_trimmed_worker_id) < 1
       OR length(v_trimmed_worker_id) > 128 OR v_trimmed_worker_id ~ '[^\x21-\x7E]' THEN
        RETURN QUERY SELECT 'worker_id_invalid', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::timestamptz, NULL::integer;
        RETURN;
    END IF;

    SELECT scan_jobs.state, scan_jobs.worker_id, scan_jobs.lease_token, scan_jobs.lease_expires_at,
           scan_jobs.revision, scan_jobs.submitted_at
    INTO v_state, v_worker_id, v_lease_token, v_lease_expires_at, v_revision, v_submitted_at
    FROM public.scan_jobs
    WHERE scan_jobs.job_id = p_job_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::timestamptz, NULL::integer;
        RETURN;
    END IF;

    IF v_state <> 'running' OR v_worker_id IS DISTINCT FROM v_trimmed_worker_id
       OR v_lease_token IS DISTINCT FROM p_lease_token THEN
        RETURN QUERY SELECT 'lease_lost', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::timestamptz, NULL::integer;
        RETURN;
    END IF;

    IF v_lease_expires_at IS NULL OR v_lease_expires_at <= p_now THEN
        RETURN QUERY SELECT 'lease_expired', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::timestamptz, NULL::integer;
        RETURN;
    END IF;

    -- See claim_next_job's own comment on this exact race/fix. This
    -- row is already RUNNING (already claimed), so its existing
    -- updated_at is already >= submitted_at; this floor defends the
    -- same invariant against the same stale-p_now class, not a defect
    -- specific to renewal.
    v_effective_now := GREATEST(p_now, v_submitted_at);
    v_new_expires_at := v_effective_now + make_interval(secs => p_lease_seconds);

    UPDATE public.scan_jobs
    SET heartbeat_at = v_effective_now, lease_expires_at = v_new_expires_at, updated_at = v_effective_now, revision = v_revision + 1
    WHERE scan_jobs.job_id = p_job_id AND scan_jobs.state = 'running' AND scan_jobs.revision = v_revision
      AND scan_jobs.worker_id = v_trimmed_worker_id AND scan_jobs.lease_token = p_lease_token;
    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RETURN QUERY SELECT 'lease_lost', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::timestamptz, NULL::integer;
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        'ok', j.job_id, j.target, j.authorization_id, j.authorization_sha256, j.mode, j.state,
        j.revision, j.cancellation_requested, j.submitted_at, j.updated_at, j.started_at,
        j.completed_at, j.scan_id, j.result_status, j.report_ref, j.audit_ref, j.error_code,
        j.error_message, j.idempotency_key, j.worker_id, j.lease_token, j.lease_expires_at,
        j.attempt_count
    FROM public.scan_jobs AS j
    WHERE j.job_id = p_job_id;
END;
$$;

-- resolve_job_organization: current source is postgres_jobs.py's
-- organization_id_for_job() (a thin wrapper over get_scope()).
-- Deliberately minimal: the worker sometimes must discover which
-- tenant a job belongs to BEFORE tenant context can be established,
-- so this returns only the organization_id, nothing else -- no job
-- contents, no finding/report/target data.
CREATE OR REPLACE FUNCTION webguard_control.resolve_job_organization(
    p_job_id uuid
) RETURNS uuid
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT organization_id FROM public.scan_jobs WHERE job_id = p_job_id;
$$;

-- resolve_job_scope: current source is postgres_jobs.py's get_scope().
-- P1-2 Phase H gap closure: get_scope's own contract needs
-- submitted_by as well as organization_id, which resolve_job_organization
-- (above) deliberately never returned (Section 13: it exists only
-- for organization_id_for_job's own scalar need). Rather than widen
-- resolve_job_organization itself, a scalar-returning function
-- (RETURNS uuid), not RETURNS TABLE, so turning it into a two-column
-- table would be a return-type change breaking its five existing call
-- sites (organization_id_for_job itself, plus four direct callers
-- across test_postgres_control_functions.py and
-- test_postgres_rls_policies.py that all call it as a scalar) for no
-- benefit to organization_id_for_job, which still only ever needs the
-- scalar, this is a separate, purpose-built function, so
-- organization_id_for_job's own already-closed conversion (2026-09-16)
-- is untouched. Exact-match on job_id (scan_jobs' own primary key).
CREATE OR REPLACE FUNCTION webguard_control.resolve_job_scope(
    p_job_id uuid
) RETURNS TABLE (
    organization_id uuid,
    submitted_by uuid
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT organization_id, submitted_by FROM public.scan_jobs WHERE job_id = p_job_id;
$$;

-- resolve_job_cancellation_requested: current source is
-- postgres_jobs.py's is_cancellation_requested(), which previously
-- delegated to get(job_id): a full-row, unrestricted-connection
-- read, purely to check one boolean. get()'s own docstring already
-- rules out running its full-row query under any restricted role for
-- this caller (worker_tenant_data has no scan_jobs grant at all, and
-- api_tenant_data would misrepresent which process is asking). This
-- function returns ONLY cancellation_requested, nothing else. NULL
-- back means no such job_id (scan_jobs.cancellation_requested is
-- itself NOT NULL, migration 0004), which is how
-- is_cancellation_requested distinguishes "not found" from "found,
-- not cancelled": get()'s own job_not_found error is raised in
-- Python on that NULL, not inside this function.
CREATE OR REPLACE FUNCTION webguard_control.resolve_job_cancellation_requested(
    p_job_id uuid
) RETURNS boolean
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT cancellation_requested FROM public.scan_jobs WHERE job_id = p_job_id;
$$;

-- resolve_job_permit_binding: current source is postgres_jobs.py's
-- get_job_permit_binding(). job_permits carries no organization_id
-- column of its own (get_job_permit_binding_scoped's own docstring:
-- tenant scope can only be proven by a join to scan_jobs), but this
-- method's own real callers (both in executor.py, the worker) never
-- need that join: they already hold a job_id the worker legitimately
-- leased via claim_next_job's own SKIP LOCKED claim, the same
-- already-trusted-job_id shape get()/resolve_job_cancellation_requested
-- above rely on. Reuses worker_function_owner's EXISTING SELECT grant
-- on job_permits (Phase E, originally for claim_next_job's own
-- claimable-row query) rather than extending worker_tenant_data's own
-- ACL with a new grant, which also means no new RLS policy is
-- needed: worker_function_owner's job_permits SELECT already carries
-- an unconditional (`USING (true)`) policy, for the same reason
-- claim_next_job's own cross-tenant claim query needs one (job_permits
-- has no tenant column to predicate a policy on in the first place).
-- Exact-match on job_id.
CREATE OR REPLACE FUNCTION webguard_control.resolve_job_permit_binding(
    p_job_id uuid
) RETURNS TABLE (
    permit_id uuid,
    permit_sha256 text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT permit_id, permit_sha256 FROM public.job_permits WHERE job_id = p_job_id;
$$;

-- terminal_transition: current source is postgres_jobs.py's
-- _terminal_update(), called from finish_result_leased()/
-- fail_leased()/cancel_running_leased() for the FAILED/CANCELLED/
-- explicit-cancel paths. Preserves the exact atomic sequence traced
-- and reconfirmed in Phase E: (1) fetch the current job row, (2)
-- confirm it is RUNNING, (3) if a worker_id/lease_token pair was
-- supplied, require it to be the CURRENT active lease (matching
-- _require_active_lease exactly; if the job has no lease_token but a
-- worker_id was supplied anyway, that is 'lease_lost', matching the
-- current `elif effective_worker_id is not None` branch), (4) the CAS
-- UPDATE (state/revision[/worker_id/lease_token]-guarded), (5) only
-- when the new state is 'failed' or 'cancelled', the scan_records
-- reconciliation UPDATE, (6) only when a safety receipt reference was
-- supplied, the job_safety_receipts INSERT, (7) the final readback.
-- SUCCEEDED completion is explicitly NOT part of this function: the
-- comment inside _terminal_update itself says the executor's own
-- complete_scan() call already ran, in an earlier, separate, short
-- transaction, before _terminal_update is ever invoked -- reconfirmed
-- directly against the current source for this phase, nothing about
-- that separate path is collapsed in here. All of this runs inside
-- one PL/pgSQL function body with no internal exception handler that
-- could let a partial write commit: any failure aborts the whole
-- invocation.
--
-- Reproduces current code's safety-receipt STRING FORMAT validation
-- (rejecting a reference starting with "/" or containing a ".." path
-- segment, and requiring the digest to be exactly 64 lower-case hex
-- characters), in addition to the same-or-neither pairing check --
-- see the file header's Section 5 review for why this one, unlike
-- worker_id shape, is genuinely security-relevant (a persisted,
-- unsanitized path is a real path-traversal risk for a future
-- reader) rather than orthogonal.
CREATE OR REPLACE FUNCTION webguard_control.terminal_transition(
    p_job_id uuid,
    p_state text,
    p_now timestamptz,
    p_worker_id text,
    p_lease_token text,
    p_scan_id text,
    p_result_status text,
    p_report_ref text,
    p_audit_ref text,
    p_error_code text,
    p_error_message text,
    p_safety_receipt_ref text,
    p_safety_receipt_sha256 text
) RETURNS TABLE (
    outcome text,
    job_id uuid,
    target text,
    authorization_id text,
    authorization_sha256 text,
    mode text,
    state text,
    revision integer,
    cancellation_requested boolean,
    submitted_at timestamptz,
    updated_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    scan_id text,
    result_status text,
    report_ref text,
    audit_ref text,
    error_code text,
    error_message text,
    idempotency_key text
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_state text;
    v_worker_id text;
    v_lease_token text;
    v_lease_expires_at timestamptz;
    v_revision integer;
    v_submitted_at timestamptz;
    v_started_at timestamptz;
    v_effective_now timestamptz;
    v_updated integer;
    v_has_lease_predicate boolean := p_worker_id IS NOT NULL;
    v_trimmed_worker_id text;
BEGIN
    IF (p_safety_receipt_ref IS NULL) <> (p_safety_receipt_sha256 IS NULL) THEN
        RETURN QUERY SELECT 'receipt_metadata_invalid', p_job_id, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    -- Reproduces postgres_jobs.py's path-traversal/hex-digest safety-
    -- receipt validation (Section 5 review: genuinely security-
    -- relevant, since this value is persisted permanently and a
    -- future reader may trust it as already-validated). Checked here
    -- rather than immediately before the INSERT as current Python
    -- does; both orderings are observably identical since a failure
    -- either way aborts this whole invocation with zero writes.
    IF p_safety_receipt_ref IS NOT NULL THEN
        IF p_safety_receipt_ref = '' OR p_safety_receipt_ref LIKE '/%'
           OR '..' = ANY(string_to_array(p_safety_receipt_ref, '/')) THEN
            RETURN QUERY SELECT 'safety_receipt_reference_invalid', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
        IF length(p_safety_receipt_sha256) <> 64 OR p_safety_receipt_sha256 ~ '[^0-9a-f]' THEN
            RETURN QUERY SELECT 'safety_receipt_digest_invalid', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
    END IF;

    IF (p_worker_id IS NULL) <> (p_lease_token IS NULL) THEN
        RETURN QUERY SELECT 'lease_credentials_invalid', p_job_id, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    -- Reproduces postgres_jobs.py's _worker_id() (Section 5 review),
    -- only when a worker_id was actually supplied, matching current
    -- code's `None if worker_id is None else _worker_id(worker_id)`.
    IF p_worker_id IS NOT NULL THEN
        v_trimmed_worker_id := btrim(p_worker_id);
        IF length(v_trimmed_worker_id) < 1 OR length(v_trimmed_worker_id) > 128
           OR v_trimmed_worker_id ~ '[^\x21-\x7E]' THEN
            RETURN QUERY SELECT 'worker_id_invalid', p_job_id, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
    END IF;

    SELECT scan_jobs.state, scan_jobs.worker_id, scan_jobs.lease_token, scan_jobs.lease_expires_at,
           scan_jobs.revision, scan_jobs.submitted_at, scan_jobs.started_at
    INTO v_state, v_worker_id, v_lease_token, v_lease_expires_at, v_revision, v_submitted_at, v_started_at
    FROM public.scan_jobs
    WHERE scan_jobs.job_id = p_job_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    IF v_state <> 'running' THEN
        RETURN QUERY SELECT 'invalid_state', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    IF v_lease_token IS NOT NULL THEN
        IF p_worker_id IS NULL OR p_lease_token IS NULL THEN
            RETURN QUERY SELECT 'lease_required', p_job_id, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
        IF v_worker_id IS DISTINCT FROM v_trimmed_worker_id OR v_lease_token IS DISTINCT FROM p_lease_token THEN
            RETURN QUERY SELECT 'lease_lost', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
        IF v_lease_expires_at IS NULL OR v_lease_expires_at <= p_now THEN
            RETURN QUERY SELECT 'lease_expired', p_job_id, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
                NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                NULL::text, NULL::text, NULL::text;
            RETURN;
        END IF;
    ELSIF p_worker_id IS NOT NULL THEN
        RETURN QUERY SELECT 'lease_lost', p_job_id, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    -- See claim_next_job's own comment on this exact race/fix.
    -- ScanJobRecord also requires completed_at not precede the job's
    -- start boundary (started_at if set, else submitted_at); floor
    -- against whichever of the two is later, exactly mirroring
    -- store.py's _terminal_update.
    v_effective_now := GREATEST(p_now, COALESCE(v_started_at, v_submitted_at));

    IF v_has_lease_predicate THEN
        UPDATE public.scan_jobs
        SET state = p_state, completed_at = v_effective_now, updated_at = v_effective_now, revision = v_revision + 1,
            scan_id = p_scan_id, result_status = p_result_status, report_ref = p_report_ref,
            audit_ref = p_audit_ref, error_code = p_error_code, error_message = p_error_message,
            worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
        WHERE scan_jobs.job_id = p_job_id AND scan_jobs.state = 'running' AND scan_jobs.revision = v_revision
          AND scan_jobs.worker_id = v_trimmed_worker_id AND scan_jobs.lease_token = p_lease_token;
    ELSE
        UPDATE public.scan_jobs
        SET state = p_state, completed_at = v_effective_now, updated_at = v_effective_now, revision = v_revision + 1,
            scan_id = p_scan_id, result_status = p_result_status, report_ref = p_report_ref,
            audit_ref = p_audit_ref, error_code = p_error_code, error_message = p_error_message,
            worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
        WHERE scan_jobs.job_id = p_job_id AND scan_jobs.state = 'running' AND scan_jobs.revision = v_revision;
    END IF;
    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RETURN QUERY SELECT
            CASE WHEN v_has_lease_predicate THEN 'lease_lost' ELSE 'transition_conflict' END,
            p_job_id, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::boolean, NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;

    IF p_state IN ('failed', 'cancelled') THEN
        UPDATE public.scan_records
        SET status = p_state, completed_at = COALESCE(scan_records.completed_at, v_effective_now)
        WHERE scan_records.job_id = p_job_id AND scan_records.completed_at IS NULL;
    END IF;

    IF p_safety_receipt_ref IS NOT NULL THEN
        INSERT INTO public.job_safety_receipts (job_id, receipt_ref, receipt_sha256, created_at)
        VALUES (p_job_id, p_safety_receipt_ref, p_safety_receipt_sha256, v_effective_now);
    END IF;

    RETURN QUERY
    SELECT
        'ok', j.job_id, j.target, j.authorization_id, j.authorization_sha256, j.mode, j.state,
        j.revision, j.cancellation_requested, j.submitted_at, j.updated_at, j.started_at,
        j.completed_at, j.scan_id, j.result_status, j.report_ref, j.audit_ref, j.error_code,
        j.error_message, j.idempotency_key
    FROM public.scan_jobs AS j
    WHERE j.job_id = p_job_id;
END;
$$;

REVOKE ALL ON FUNCTION webguard_control.claim_next_job(text, numeric, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.recover_expired_leases(timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.renew_lease(uuid, text, text, timestamptz, numeric) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_job_organization(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_job_scope(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_job_cancellation_requested(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_job_permit_binding(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.terminal_transition(
    uuid, text, timestamptz, text, text, text, text, text, text, text, text, text, text
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION webguard_control.claim_next_job(text, numeric, timestamptz) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.recover_expired_leases(timestamptz, integer) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.renew_lease(uuid, text, text, timestamptz, numeric) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_job_organization(uuid) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_job_scope(uuid) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_job_cancellation_requested(uuid) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_job_permit_binding(uuid) TO worker_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.terminal_transition(
    uuid, text, timestamptz, text, text, text, text, text, text, text, text, text, text
) TO worker_tenant_data;

RESET ROLE;

-- Function-owner CREATE on webguard_control returns to FALSE; the
-- bootstrap actor loses standing ability to SET ROLE to this role
-- (it retains only the ADMIN OPTION PG16's CREATEROLE conferred
-- automatically in Phase C, which lets it re-claim SET again in a
-- future run if genuinely needed, but confers no privilege by
-- itself). A no-op for a superuser bootstrap actor.
REVOKE CREATE ON SCHEMA webguard_control FROM worker_function_owner;
REVOKE SET OPTION FOR worker_function_owner FROM CURRENT_USER;

-- Non-superuser, RDS-compatible ownership-transfer mechanics: see the
-- IDENTITY block above (and the file header) for the full explanation
-- of why WITH INHERIT FALSE must be claimed before WITH SET TRUE.
GRANT scheduler_function_owner TO CURRENT_USER WITH INHERIT FALSE;
GRANT scheduler_function_owner TO CURRENT_USER WITH SET TRUE;
GRANT CREATE ON SCHEMA webguard_control TO scheduler_function_owner;

SET ROLE scheduler_function_owner;

-- =========================================================================
-- SCHEDULER (scheduler_function_owner) -- due-schedule discovery and
-- materialization control plane.
-- =========================================================================

-- resolve_schedule_request_shape: new, P1-2 Phase H gap closure
-- support function for enqueue_due_schedule's own Python caller.
-- enqueue_due_schedule's SQL body (below) needs a caller-computed
-- p_request_fingerprint, exactly like its original design (Section on
-- request_fingerprint, below): Python owns the one canonical-JSON
-- algorithm ScanJobRequest.fingerprint implements, and reimplementing
-- it a second time in PL/pgSQL was already tried and reverted in an
-- earlier draft. Computing that fingerprint needs target,
-- authorization_id, and mode, immutable for a schedule's entire
-- lifetime (no method anywhere in this codebase ever updates them
-- after create_schedule), which postgres_schedules.py's
-- enqueue_due_schedule must read BEFORE it can call
-- webguard_control.enqueue_due_schedule, but scheduler_tenant_data has
-- no table-level grant on scan_schedules at all. Reuses
-- scheduler_function_owner's existing SELECT grant on scan_schedules
-- (Phase E) and its existing unconditional RLS policy, so no ACL or
-- RLS file needs touching. Exact-match on schedule_id; returns nothing
-- else, not even organization_id (the caller never needs it for
-- this specific purpose, Section 13 output minimization).
CREATE OR REPLACE FUNCTION webguard_control.resolve_schedule_request_shape(
    p_schedule_id uuid
) RETURNS TABLE (
    target text,
    authorization_id text,
    mode text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT target, authorization_id, mode FROM public.scan_schedules WHERE schedule_id = p_schedule_id;
$$;

-- resolve_schedule_permit_binding: current source is
-- postgres_schedules.py's get_schedule_permit_binding(). Same shape as
-- worker_function_owner's resolve_job_permit_binding above:
-- schedule_permits carries no organization_id column of its own
-- (get_schedule_permit_binding_scoped's own docstring: tenant scope is
-- proven by joining to scan_schedules), but this method's only caller
-- anywhere in this codebase (scheduler.py) never needs that join --
-- schedule_id here is a value the scheduler process already reads off
-- its own list_due_schedules()/enqueue_due_schedule() results, not an
-- unverified caller input. Reuses scheduler_function_owner's EXISTING
-- SELECT grant on schedule_permits (Phase E, originally for
-- enqueue_due_schedule's own binding check) rather than a new
-- scheduler_tenant_data ACL grant, so no new RLS policy is needed
-- either: that SELECT already carries an unconditional (`USING
-- (true)`) policy, for the same reason enqueue_due_schedule's own
-- binding check needs one (schedule_permits has no tenant column to
-- predicate a policy on). Exact-match on schedule_id.
CREATE OR REPLACE FUNCTION webguard_control.resolve_schedule_permit_binding(
    p_schedule_id uuid
) RETURNS TABLE (
    permit_id uuid,
    permit_sha256 text
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT permit_id, permit_sha256 FROM public.schedule_permits WHERE schedule_id = p_schedule_id;
$$;

-- list_due_schedules: current source is postgres_schedules.py's own
-- method of that name. Preserves the exact eligibility (state =
-- 'active', next_run_at <= now), ordering (next_run_at, schedule_id),
-- and LIMIT. p_limit's current [1, 1000] range validation is Python-
-- side input-shape validation and is not reproduced here (file
-- header); an out-of-range LIMIT simply behaves as PostgreSQL's own
-- LIMIT clause would.
CREATE OR REPLACE FUNCTION webguard_control.list_due_schedules(
    p_now timestamptz,
    p_limit integer
) RETURNS TABLE (
    schedule_id uuid,
    organization_id uuid,
    created_by uuid,
    name text,
    target text,
    authorization_id text,
    authorization_sha256 text,
    mode text,
    interval_seconds integer,
    state text,
    created_at timestamptz,
    updated_at timestamptz,
    next_run_at timestamptz,
    revision integer,
    last_enqueued_at timestamptz,
    last_job_id uuid,
    last_error_code text,
    last_error_at timestamptz
)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
    SELECT
        schedule_id, organization_id, created_by, name, target, authorization_id,
        authorization_sha256, mode, interval_seconds, state, created_at, updated_at,
        next_run_at, revision, last_enqueued_at, last_job_id, last_error_code, last_error_at
    FROM public.scan_schedules
    WHERE state = 'active' AND next_run_at <= p_now
    ORDER BY next_run_at, schedule_id
    LIMIT p_limit;
$$;

-- enqueue_due_schedule: current source is postgres_schedules.py's own
-- method of that name. Preserves the exact sequence: (1) SELECT ...
-- FOR UPDATE of the schedule row, (2) confirm ACTIVE/expected
-- revision/due, (3) confirm the authorization is still assigned, (4)
-- confirm the permit binding matches exactly, raising the same
-- 'schedule_binding_changed' condition current code raises for (as an
-- outcome value here, since a SQL function cannot raise an
-- application-level JobStoreError a future caller pattern-matches
-- on), (5) confirm the permit itself is still valid, (6) INSERT the
-- new scan_jobs row (job_id generated internally via
-- gen_random_uuid(), matching current code's own str(uuid4())),
-- catching a unique-idempotency-key violation as 'raced' exactly like
-- current code's DatabaseIntegrityError handling, (7) INSERT the
-- job_permits row, (8) the schedule-advancement UPDATE, (9) the
-- scan_jobs readback -- Phase E's own finding, reconfirmed here: this
-- SEPARATE post-INSERT SELECT (not INSERT ... RETURNING) is preserved
-- deliberately rather than silently converted, since
-- scheduler_function_owner's ACL was specifically built around this
-- exact shape. Returns 'ok' with both schedule and job fields, or one
-- of 'not_due' / 'authorization_not_assigned' / 'binding_changed' /
-- 'permit_invalid' / 'raced' / 'schedule_conflict' with every field
-- NULL, mirroring current code's None-return and exception cases.
--
-- request_fingerprint: current Python computes this as
-- hashlib.sha256(_canonical_json({target, authorization_id,
-- authorization_sha256, mode})).hexdigest() (webguard_contracts'
-- ScanJobRequest.fingerprint property), a specific canonical-JSON key
-- ordering and separator convention that would be fragile and
-- non-obviously-correct to reimplement in PL/pgSQL. Rather than
-- maintain two divergent algorithms for the same stored field (a
-- correction from an earlier draft that did exactly that), this
-- function accepts the fingerprint as an explicit typed parameter,
-- computed by whichever caller already has the current Python
-- algorithm available, and stores it unchanged. A future repository-
-- conversion phase continues using ScanJobRequest.fingerprint exactly
-- as it does today; this function never computes or approximates it.
-- P1-2 Phase H gap closure, 2026-09-17: RETURNS TABLE widened from the
-- original 8-column outcome summary (outcome, schedule_id,
-- schedule_state, schedule_revision, schedule_next_run_at, job_id,
-- job_state, job_submitted_at, kept as the first 8 columns, in the
-- same order, so every existing caller that reads them positionally
-- keeps working unchanged) to every column postgres_schedules.py's
-- ScanScheduleRecord/ScanJobRecord reconstruction needs. Chosen over
-- the alternative (narrowing enqueue_due_schedule's own Python
-- contract to the one field scheduler.py's run_once actually reads,
-- job_id) after reading run_once in full: this repository method's
-- return type is shared across the SQLite and PostgreSQL backends of
-- the same repository_contracts.py interface, and
-- tests/unit/test_schedule_store.py, test_phase3_revocation_cancellation_races.py,
-- test_phase3_transaction_schedule_safety.py, and
-- test_phase4_scheduler_authority_toc.py all exercise the full
-- ScanScheduleRecord/ScanJobRecord pair this method promises against
-- the SQLite backend, and narrowing only the Postgres backend's return
-- shape would make the two backends silently diverge on a method nothing
-- currently forces them to keep in lockstep except convention. Widening
-- the SQL function's own output, leaving its transactional logic
-- (the FOR UPDATE read, the revision CAS, the idempotency-key INSERT
-- race handling, the schedule-advancement UPDATE) completely
-- unchanged, keeps both backends' contracts identical instead.
--
-- Like resolve_identity_token above, this is DROP FUNCTION then CREATE
-- FUNCTION, not CREATE OR REPLACE: PostgreSQL does not allow
-- CREATE OR REPLACE FUNCTION to change an existing function's result
-- type, including appending a RETURNS TABLE column (confirmed directly
-- against this project's own disposable Postgres 16). The REVOKE/GRANT
-- EXECUTE below re-establishes the exact same grant DROP FUNCTION
-- removes.
DROP FUNCTION IF EXISTS webguard_control.enqueue_due_schedule(uuid, integer, text, uuid, text, timestamptz, text);
CREATE FUNCTION webguard_control.enqueue_due_schedule(
    p_schedule_id uuid,
    p_expected_revision integer,
    p_authorization_sha256 text,
    p_permit_id uuid,
    p_permit_sha256 text,
    p_now timestamptz,
    p_request_fingerprint text
) RETURNS TABLE (
    outcome text,
    schedule_id uuid,
    schedule_state text,
    schedule_revision integer,
    schedule_next_run_at timestamptz,
    job_id uuid,
    job_state text,
    job_submitted_at timestamptz,
    schedule_organization_id uuid,
    schedule_created_by uuid,
    schedule_name text,
    schedule_target text,
    schedule_authorization_id text,
    schedule_authorization_sha256 text,
    schedule_mode text,
    schedule_interval_seconds integer,
    schedule_created_at timestamptz,
    schedule_updated_at timestamptz,
    schedule_last_enqueued_at timestamptz,
    schedule_last_job_id uuid,
    schedule_last_error_code text,
    schedule_last_error_at timestamptz,
    job_target text,
    job_authorization_id text,
    job_authorization_sha256 text,
    job_mode text,
    job_revision integer,
    job_cancellation_requested boolean,
    job_updated_at timestamptz,
    job_started_at timestamptz,
    job_completed_at timestamptz,
    job_scan_id text,
    job_result_status text,
    job_report_ref text,
    job_audit_ref text,
    job_error_code text,
    job_error_message text,
    job_idempotency_key text
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_organization_id uuid;
    v_created_by uuid;
    v_target text;
    v_authorization_id text;
    v_mode text;
    v_state text;
    v_revision integer;
    v_next_run_at timestamptz;
    v_interval_seconds integer;
    v_binding_permit_id uuid;
    v_binding_permit_sha256 text;
    v_permit_ok boolean;
    v_idempotency_key text;
    v_scheduled_for_key text;
    v_new_next_run_at timestamptz;
    v_new_job_id uuid := gen_random_uuid();
    v_updated integer;
BEGIN
    SELECT organization_id, created_by, target, authorization_id, mode, state, revision,
           next_run_at, interval_seconds
    INTO v_organization_id, v_created_by, v_target, v_authorization_id, v_mode, v_state,
         v_revision, v_next_run_at, v_interval_seconds
    FROM public.scan_schedules
    WHERE scan_schedules.schedule_id = p_schedule_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_due', p_schedule_id, NULL::text, NULL::integer, NULL::timestamptz,
            NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    IF v_state <> 'active' OR v_revision <> p_expected_revision OR v_next_run_at > p_now THEN
        RETURN QUERY SELECT 'not_due', p_schedule_id, NULL::text, NULL::integer, NULL::timestamptz,
            NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.organization_authorizations
        WHERE organization_id = v_organization_id AND authorization_id = v_authorization_id
    ) THEN
        RETURN QUERY SELECT 'authorization_not_assigned', p_schedule_id, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    SELECT permit_id, permit_sha256 INTO v_binding_permit_id, v_binding_permit_sha256
    FROM public.schedule_permits WHERE schedule_permits.schedule_id = p_schedule_id;

    IF v_binding_permit_id IS NULL
       OR v_binding_permit_id <> p_permit_id OR v_binding_permit_sha256 <> p_permit_sha256 THEN
        RETURN QUERY SELECT 'binding_changed', p_schedule_id, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    SELECT TRUE INTO v_permit_ok
    FROM public.scan_permits
    WHERE permit_id = p_permit_id AND organization_id = v_organization_id
      AND permit_sha256 = p_permit_sha256 AND revoked_at IS NULL
      AND not_before <= p_now AND p_now < expires_at;

    IF v_permit_ok IS NOT TRUE THEN
        RETURN QUERY SELECT 'permit_invalid', p_schedule_id, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    v_scheduled_for_key := to_char(v_next_run_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    v_idempotency_key := 'schedule:' || p_schedule_id::text || ':' || v_scheduled_for_key;

    BEGIN
        INSERT INTO public.scan_jobs (
            job_id, organization_id, submitted_by, idempotency_key,
            request_fingerprint, target, authorization_id, authorization_sha256,
            mode, submitted_at, state, updated_at, revision, cancellation_requested
        ) VALUES (
            v_new_job_id, v_organization_id, v_created_by, v_idempotency_key,
            p_request_fingerprint, v_target, v_authorization_id, p_authorization_sha256,
            v_mode, p_now, 'queued', p_now, 0, FALSE
        );
    EXCEPTION WHEN unique_violation THEN
        RETURN QUERY SELECT 'raced', p_schedule_id, NULL::text, NULL::integer, NULL::timestamptz,
            NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END;

    INSERT INTO public.job_permits (job_id, permit_id, permit_sha256)
    VALUES (v_new_job_id, p_permit_id, p_permit_sha256);

    v_new_next_run_at := v_next_run_at + make_interval(secs => v_interval_seconds);
    IF v_new_next_run_at <= p_now THEN
        v_new_next_run_at := v_next_run_at
            + (make_interval(secs => v_interval_seconds)
               * (((extract(epoch FROM (p_now - v_next_run_at)) / v_interval_seconds)::integer) + 1));
    END IF;

    UPDATE public.scan_schedules
    SET authorization_sha256 = p_authorization_sha256, updated_at = p_now, next_run_at = v_new_next_run_at,
        revision = revision + 1, last_enqueued_at = p_now, last_job_id = v_new_job_id,
        last_error_code = NULL, last_error_at = NULL
    WHERE scan_schedules.schedule_id = p_schedule_id AND revision = p_expected_revision AND state = 'active';
    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RETURN QUERY SELECT 'schedule_conflict', p_schedule_id, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::uuid, NULL::uuid, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer,
            NULL::timestamptz, NULL::timestamptz, NULL::timestamptz, NULL::uuid, NULL::text, NULL::timestamptz,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer, NULL::boolean, NULL::timestamptz,
            NULL::timestamptz, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
            NULL::text, NULL::text;
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        'ok', s.schedule_id, s.state, s.revision, s.next_run_at, j.job_id, j.state, j.submitted_at,
        s.organization_id, s.created_by, s.name, s.target, s.authorization_id, s.authorization_sha256,
        s.mode, s.interval_seconds, s.created_at, s.updated_at, s.last_enqueued_at, s.last_job_id,
        s.last_error_code, s.last_error_at,
        j.target, j.authorization_id, j.authorization_sha256, j.mode, j.revision, j.cancellation_requested,
        j.updated_at, j.started_at, j.completed_at, j.scan_id, j.result_status, j.report_ref, j.audit_ref,
        j.error_code, j.error_message, j.idempotency_key
    FROM public.scan_schedules AS s
    JOIN public.scan_jobs AS j ON j.job_id = v_new_job_id
    WHERE s.schedule_id = p_schedule_id;
END;
$$;

-- block_due_schedule: current source is postgres_schedules.py's own
-- method of that name. Preserves the exact CAS UPDATE (revision/state
-- guarded, transitioning ACTIVE -> PAUSED with a fixed error_code and
-- timestamp) and the exact readback. Returns zero rows when the CAS
-- lost the race, exactly matching current code's `if updated.rowcount
-- != 1: return None`.
CREATE OR REPLACE FUNCTION webguard_control.block_due_schedule(
    p_schedule_id uuid,
    p_expected_revision integer,
    p_error_code text,
    p_now timestamptz
) RETURNS TABLE (
    schedule_id uuid,
    organization_id uuid,
    created_by uuid,
    name text,
    target text,
    authorization_id text,
    authorization_sha256 text,
    mode text,
    interval_seconds integer,
    state text,
    created_at timestamptz,
    updated_at timestamptz,
    next_run_at timestamptz,
    revision integer,
    last_enqueued_at timestamptz,
    last_job_id uuid,
    last_error_code text,
    last_error_at timestamptz
)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_updated integer;
BEGIN
    UPDATE public.scan_schedules
    SET state = 'paused', updated_at = p_now, revision = scan_schedules.revision + 1,
        last_error_code = p_error_code, last_error_at = p_now
    WHERE scan_schedules.schedule_id = p_schedule_id AND scan_schedules.revision = p_expected_revision
      AND scan_schedules.state = 'active';
    GET DIAGNOSTICS v_updated = ROW_COUNT;

    IF v_updated <> 1 THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        s.schedule_id, s.organization_id, s.created_by, s.name, s.target, s.authorization_id,
        s.authorization_sha256, s.mode, s.interval_seconds, s.state, s.created_at, s.updated_at,
        s.next_run_at, s.revision, s.last_enqueued_at, s.last_job_id, s.last_error_code, s.last_error_at
    FROM public.scan_schedules AS s
    WHERE s.schedule_id = p_schedule_id;
END;
$$;

REVOKE ALL ON FUNCTION webguard_control.resolve_schedule_request_shape(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.resolve_schedule_permit_binding(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.list_due_schedules(timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.enqueue_due_schedule(
    uuid, integer, text, uuid, text, timestamptz, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION webguard_control.block_due_schedule(uuid, integer, text, timestamptz) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION webguard_control.resolve_schedule_request_shape(uuid) TO scheduler_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.resolve_schedule_permit_binding(uuid) TO scheduler_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.list_due_schedules(timestamptz, integer) TO scheduler_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.enqueue_due_schedule(
    uuid, integer, text, uuid, text, timestamptz, text
) TO scheduler_tenant_data;
GRANT EXECUTE ON FUNCTION webguard_control.block_due_schedule(uuid, integer, text, timestamptz) TO scheduler_tenant_data;

RESET ROLE;

-- Function-owner CREATE on webguard_control returns to FALSE; the
-- bootstrap actor loses standing ability to SET ROLE to this role
-- (it retains only the ADMIN OPTION PG16's CREATEROLE conferred
-- automatically in Phase C, which lets it re-claim SET again in a
-- future run if genuinely needed, but confers no privilege by
-- itself). A no-op for a superuser bootstrap actor.
REVOKE CREATE ON SCHEMA webguard_control FROM scheduler_function_owner;
REVOKE SET OPTION FOR scheduler_function_owner FROM CURRENT_USER;

-- Non-superuser, RDS-compatible ownership-transfer mechanics: see the
-- IDENTITY block above (and the file header) for the full explanation
-- of why WITH INHERIT FALSE must be claimed before WITH SET TRUE.
GRANT callback_function_owner TO CURRENT_USER WITH INHERIT FALSE;
GRANT callback_function_owner TO CURRENT_USER WITH SET TRUE;
GRANT CREATE ON SCHEMA webguard_control TO callback_function_owner;

SET ROLE callback_function_owner;

-- =========================================================================
-- CALLBACK (callback_function_owner) -- public, pre-authentication
-- ingress. One atomic function only.
-- =========================================================================

-- resolve_and_record_callback_observation: current source is
-- postgres_callback_service.py's PostgresCallbackRegistrationRepository
-- .record_observation(). Deliberately kept as ONE atomic function
-- (Section 22): resolving the registration and recording the
-- observation in two separate privileged functions would reopen the
-- TOCTOU window between "is this token still valid" and "record that
-- it was used" that the current single-transaction Python method
-- already closes. Preserves the exact eligibility check (registration
-- exists, not revoked, not expired as of the given observed_at) and
-- the exact INSERT shape. Returns boolean, matching current code's
-- bool return, with no distinct signal for "unknown token" vs "valid-
-- but-expired" vs "valid-but-revoked" -- current code already
-- collapses all three into the same `False`/generic-204 response
-- (Section 23), so this function does not introduce a new oracle.
-- observed_at is accepted as a parameter, not computed via now()/
-- clock_timestamp() inside the function: current code (P1-12)
-- captures it exactly once, before any persistence attempt, in the
-- callback receiver itself, and this function must use that same
-- trusted value rather than silently substituting its own clock read
-- (Section 23).
CREATE OR REPLACE FUNCTION webguard_control.resolve_and_record_callback_observation(
    p_token_value text,
    p_method text,
    p_source_class text,
    p_observed_at timestamptz
) RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    v_revoked_at timestamptz;
    v_expires_at timestamptz;
BEGIN
    SELECT revoked_at, expires_at INTO v_revoked_at, v_expires_at
    FROM public.callback_registrations
    WHERE token_value = p_token_value;

    IF NOT FOUND OR v_revoked_at IS NOT NULL OR v_expires_at <= p_observed_at THEN
        RETURN FALSE;
    END IF;

    INSERT INTO public.callback_observations (observation_id, token_value, method, source_class, observed_at)
    VALUES (gen_random_uuid(), p_token_value, p_method, p_source_class, p_observed_at);

    RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION webguard_control.resolve_and_record_callback_observation(
    text, text, text, timestamptz
) FROM PUBLIC;

-- CALLBACK IS SPECIAL (Section 9), gap closed 2026-09-17: the future
-- deployment phase this section originally deferred to has arrived.
-- callback_receiver (tenant_isolation_roles.sql) is that new,
-- execution-only, directly-connectable LOGIN identity, distinct from
-- callback_function_owner (the function's own privileged SECURITY
-- DEFINER owner, still not a caller-facing role: nothing is, or should
-- be, a member of it) and distinct from the three NOLOGIN tenant-data
-- roles (each already carries ordinary tenant-scoped table privileges
-- this pre-authentication path has no business holding, per this
-- section's own original reasoning, which is unchanged). EXECUTE on
-- this one function is the ONLY privilege callback_receiver is ever
-- granted, here or anywhere else in this bootstrap chain: no table
-- grant, no other function, no membership in any other role, no
-- BYPASSRLS. The public callback-service process authenticates
-- directly as this role (its own dedicated DSN, not
-- WEBGUARD_DATABASE_URL's "webguard" identity), so even a bug that
-- reused its connection for some other query would hit "permission
-- denied," never an ambient "webguard" privilege. See
-- postgres_callback_service.py's own docstring and postgres_pool.py's
-- CALLBACK_RECEIVER_ROLE for the Python side of this wiring.
GRANT EXECUTE ON FUNCTION webguard_control.resolve_and_record_callback_observation(
    text, text, text, timestamptz
) TO callback_receiver;

RESET ROLE;

-- Function-owner CREATE on webguard_control returns to FALSE; the
-- bootstrap actor loses standing ability to SET ROLE to this role
-- (it retains only the ADMIN OPTION PG16's CREATEROLE conferred
-- automatically in Phase C, which lets it re-claim SET again in a
-- future run if genuinely needed, but confers no privilege by
-- itself). A no-op for a superuser bootstrap actor.
REVOKE CREATE ON SCHEMA webguard_control FROM callback_function_owner;
REVOKE SET OPTION FOR callback_function_owner FROM CURRENT_USER;

COMMIT;
