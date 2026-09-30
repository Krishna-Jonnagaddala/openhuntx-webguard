-- P1-2 (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md): the
-- database-side half of the tenant-context plumbing Phase A
-- (postgres_pool.py's tenant_connection()/set_tenant_context()) added
-- on the Python side. This migration creates exactly one inert
-- helper function -- no table, no role, no policy, no privilege
-- change, and nothing in this schema or in application code calls it
-- yet. A future migration will reference it from row-level-security
-- policies; that phase does not exist yet.
--
-- public.webguard_current_tenant() reads the same transaction-local
-- GUC set_tenant_context() writes (webguard.current_organization_id)
-- and returns it as a uuid, or NULL if the setting is absent, empty,
-- or not a syntactically valid UUID. Never SECURITY DEFINER -- this
-- function needs no elevated privilege at all, it only reads ordinary
-- session state any connected role can already read for itself via
-- current_setting(). Deliberately named webguard_current_tenant()
-- rather than the more generic current_tenant(): this project has no
-- other schema than public today (no CREATE SCHEMA exists anywhere in
-- this migration history), and a generic name in a shared schema
-- risks an unrelated future object colliding with it; a future RLS
-- policy can still schema-qualify this exactly (public.webguard_current_tenant())
-- without this migration having to invent a dedicated schema first.
--
-- Fail-closed by construction, not by a catch-all handler: a
-- malformed value only ever reaches the ::uuid cast below, and only
-- PostgreSQL's own invalid_text_representation exception (raised by
-- that cast for anything that isn't a syntactically valid UUID) is
-- caught -- any other, genuinely unexpected database error remains
-- visible rather than being silently absorbed into "no tenant."
--
-- This is deliberately the opposite failure mode from the Python-side
-- tenant_connection()/set_tenant_context(), which reject a malformed
-- organization_id loudly, as a ValueError, before anything reaches
-- Postgres at all -- that is where an application bug is meant to be
-- caught. This function is the database's own defense-in-depth
-- backstop for a case that should never occur in normal operation (a
-- future caller that somehow bypasses that Python-side validation),
-- where the safe default is "behave exactly as if no tenant context
-- were set" rather than raising and aborting whatever transaction
-- happens to touch a policy that calls this.
CREATE FUNCTION public.webguard_current_tenant() RETURNS uuid
    LANGUAGE plpgsql
    STABLE
    SECURITY INVOKER
    SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    raw_value text;
BEGIN
    raw_value := current_setting('webguard.current_organization_id', true);
    IF raw_value IS NULL OR raw_value = '' THEN
        RETURN NULL;
    END IF;
    RETURN raw_value::uuid;
EXCEPTION
    WHEN invalid_text_representation THEN
        RETURN NULL;
END;
$$;
