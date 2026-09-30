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
-- privilege, no function EXECUTE grant, and no LOGIN capability.
-- Running this file does not change how the existing application
-- connects to or uses the database in any way -- WEBGUARD_DATABASE_URL,
-- the existing development/application role, and every current
-- table's ownership are all untouched.
--
-- Deliberately flat: no role created here is a member of any other
-- role created here, and none inherits from an existing role. A
-- later phase will grant exactly the specific table/function
-- privileges each of these needs; Phase C's only job is to make the
-- identities exist, safely.
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
