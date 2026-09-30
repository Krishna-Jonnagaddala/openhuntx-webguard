-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): Phase C of
-- the tenant-isolation plumbing -- creates the NOLOGIN privilege
-- identities a later phase's row-level-security policies and
-- SECURITY DEFINER functions will target. This is cluster-level role
-- administration, not ordinary tenant-schema DDL, which is why it
-- lives here rather than in infra/postgres/migrations/:
-- scripts/run-postgres-migrations.py discovers only that directory,
-- by design (it is an immutable, checksum-tracked schema-migration
-- sequence), and database roles are cluster objects, not schema
-- objects, so they do not belong in it.
--
-- Every role created here is inert: no table grant, no schema CREATE
-- privilege, and no function EXECUTE grant. Running this file does not
-- change how the existing application connects to or uses the
-- database in any way -- WEBGUARD_DATABASE_URL, the existing
-- development/application role, and every current table's ownership
-- are all untouched.
--
-- Deliberately flat: no role created here is a member of any other
-- role created here, and none inherits from an existing role. A
-- later phase will grant exactly the specific table/function
-- privileges each of these needs; Phase C's only job is to make the
-- identities exist, safely.
--
-- One later addition to this file (P1-2 Phase H gap closure,
-- callback_receiver, below) is deliberately LOGIN, unlike the seven
-- roles this section creates -- see its own block for why the public
-- callback-ingress path needs a directly-connectable identity rather
-- than another NOLOGIN-plus-membership role. It is still just as
-- inert on creation (no table grant, no schema CREATE, no function
-- EXECUTE, no membership) until a later file grants it exactly one
-- EXECUTE privilege.
--
-- BYPASSRLS is not, and must never be, granted to any of these
-- roles -- deliberately not even written as an explicit NOBYPASSRLS
-- clause below, so that word never appears in this file at all. Every
-- role instead relies on CREATE ROLE's own default (a freshly created
-- role is NOBYPASSRLS unless a caller with BYPASSRLS or superuser
-- privilege explicitly grants it, which this script never does).
--
-- Safe to run more than once: a role that already exists with the
-- expected safe attribute profile is left completely untouched. A
-- role that already exists under one of these names with an unsafe
-- attribute (LOGIN, SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, or
-- BYPASSRLS) makes this script fail outright, in one atomic
-- transaction (CREATE ROLE is transactional in PostgreSQL, so a
-- failure partway through this block leaves none of the roles it
-- already created in this same run behind either) -- it never
-- silently proceeds past, or alters, an unexpectedly privileged
-- pre-existing role of one of these names.
DO $$
DECLARE
    role_name text;
    existing pg_roles%ROWTYPE;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'api_tenant_data',
        'worker_tenant_data',
        'scheduler_tenant_data',
        'identity_function_owner',
        'worker_function_owner',
        'scheduler_function_owner',
        'callback_function_owner'
    ]
    LOOP
        SELECT * INTO existing FROM pg_roles WHERE rolname = role_name;

        IF NOT FOUND THEN
            -- role_name is drawn only from the fixed literal array
            -- above, never from external input; %I safely quotes it
            -- as an identifier. CREATE ROLE has no parameterized form,
            -- so EXECUTE format(...) is the standard way to create
            -- several identically-attributed roles from one block
            -- without repeating this statement seven times.
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION',
                role_name
            );
        ELSE
            IF existing.rolcanlogin
                OR existing.rolsuper
                OR existing.rolbypassrls
                OR existing.rolcreaterole
                OR existing.rolcreatedb
                OR existing.rolreplication
            THEN
                RAISE EXCEPTION
                    'role % already exists with an unsafe attribute '
                    '(login=%, superuser=%, bypassrls=%, createrole=%, createdb=%, replication=%) '
                    '-- refusing to proceed',
                    role_name, existing.rolcanlogin, existing.rolsuper, existing.rolbypassrls,
                    existing.rolcreaterole, existing.rolcreatedb, existing.rolreplication;
            END IF;
        END IF;
    END LOOP;
END;
$$;

-- P1-2 Phase H gap closure (record_observation, the callback-service
-- ingress path): callback_receiver is the one deliberate exception to
-- every claim in the file header above -- it is the only role this
-- file ever creates WITH LOGIN. Every other role here is reached only
-- through role-membership-plus-SET-ROLE from "webguard" (see
-- tenant_isolation_runtime_grant.sql), which means a session that
-- somehow forgets to narrow its role still runs as "webguard" itself,
-- broadly trusted by definition. The callback-service process is
-- different in kind, not degree: it is the one WebGuard component a
-- pre-authentication, unauthenticated network caller (a scanned
-- target's own outbound SSRF probe) reaches directly, with no session,
-- no API token, and no organization_id established yet. Giving it a
-- genuinely separate LOGIN identity, authenticated with its own
-- credential and never a member of "webguard" or of any other role
-- here, means a bug in that one process's connection wiring cannot
-- fall back to "webguard"'s own ambient privileges the way a bug in
-- the api-serve/worker/scheduler processes theoretically could -- the
-- TCP-level Postgres authentication itself never establishes a
-- "webguard" session for this process at all. See
-- tenant_isolation_control_functions.sql's own CALLBACK section for
-- the one privilege this role is ever granted (EXECUTE on exactly one
-- function, nothing else -- no table grant, no schema CREATE, no
-- membership in any other role).
--
-- Deliberately created with NO PASSWORD here: CREATE ROLE ... LOGIN
-- with no PASSWORD clause leaves rolpassword NULL, meaning password
-- authentication as this role always fails until a separate,
-- non-source-controlled step (an operator's ALTER ROLE, or a
-- secrets-manager-driven deployment script -- never this checked-in
-- SQL file) sets one. This mirrors how "webguard" itself already gets
-- its own password (POSTGRES_PASSWORD in the disposable dev/CI
-- container, the RDS master-password mechanism in a real deployment),
-- never from bootstrap SQL. A disposable integration test sets a
-- test-only password directly, the same way it already does for its
-- own synthetic test_api_caller/test_worker_caller/test_scheduler_caller
-- roles.
--
-- Same restrictive attribute profile as the seven roles above, LOGIN
-- aside: NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION, and (per
-- the file header's own reasoning) no explicit NOBYPASSRLS clause --
-- CREATE ROLE's own default already leaves it BYPASSRLS false. Not a
-- member of any other role, and no other role is ever made a member of
-- it. Idempotent like the loop above, but with its own safe-attribute
-- check: LOGIN is this role's REQUIRED, expected state, not an unsafe
-- surprise, so unlike the flat loop's check, a pre-existing
-- "callback_receiver" failing this check is one that is NOT LOGIN (or
-- carries any of the other five unsafe attributes) -- proof someone or
-- something other than this file created a role by this name.
DO $$
DECLARE
    existing pg_roles%ROWTYPE;
BEGIN
    SELECT * INTO existing FROM pg_roles WHERE rolname = 'callback_receiver';

    IF NOT FOUND THEN
        CREATE ROLE callback_receiver LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    ELSE
        IF NOT existing.rolcanlogin
            OR existing.rolsuper
            OR existing.rolbypassrls
            OR existing.rolcreaterole
            OR existing.rolcreatedb
            OR existing.rolreplication
        THEN
            RAISE EXCEPTION
                'role callback_receiver already exists with an unsafe attribute '
                '(login=%, superuser=%, bypassrls=%, createrole=%, createdb=%, replication=%) '
                '-- refusing to proceed',
                existing.rolcanlogin, existing.rolsuper, existing.rolbypassrls,
                existing.rolcreaterole, existing.rolcreatedb, existing.rolreplication;
        END IF;
    END IF;
END;
$$;
