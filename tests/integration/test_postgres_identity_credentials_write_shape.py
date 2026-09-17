"""P1-2 Phase-D correction (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
proves the real ``PostgresIdentityRepository`` write paths this
correction touches -- ``set_password_hash``'s rewritten two-statement
upsert, and ``consume_identity_token``/``invalidate_identity_tokens``'s
own ``UPDATE`` statements -- actually execute under ``api_tenant_data``'s
corrected column-level ACL (tenant_isolation_acl.sql), end to end,
through a disposable LOGIN role that inherits nothing beyond that
role's own privileges.

One thing is deliberately still out of scope here, left to a later,
not-yet-scoped repository-conversion phase:

* the read half of ``consume_identity_token`` (its own initial
  8-column ``SELECT`` by ``token_id``) is a pre-authentication read
  that belongs to ``identity_function_owner``'s
  ``webguard_control.resolve_identity_token``, not this ordinary
  tenant-scoped role, and this correction never grants direct table
  access for it, so ``IdentityTokensWriteShapeTests`` below only ever
  reproduces the method's own post-resolution ``UPDATE``.
* Row-level security is a separate phase (P1-C2-G); every test here
  runs with RLS never enabled at all, so nothing here is a tenant-
  isolation claim.

``get_password_hash`` WAS in the list above until P1-2 Phase H's
method-level gap closure (2026-09-17): it now succeeds through
``webguard_control.resolve_password_hash``, a new principal_id-keyed
SECURITY DEFINER function. See
``PasswordCredentialsWriteShapeTests.test_get_password_hash_now_succeeds_via_resolver``,
whose ``setUpClass`` applies ``tenant_isolation_function_acl.sql`` and
``tenant_isolation_control_functions.sql`` in addition to the two files
below, specifically to prove this end to end. api_tenant_data still
has no direct table-level SELECT on ``password_credentials``: the
function is the only path.

The rollback tests reproduce the exact production SQL statement text
over a raw psycopg connection under the same restricted role, rather
than modifying ``postgres_identity.py`` to allow failure injection --
the same test-only technique already used in this repository's Phase F
and Phase G proofs.

Requires a real database (`WEBGUARD_RUN_INTEGRATION=1` and a reachable
`WEBGUARD_POSTGRES_TEST_DSN`) with the schema migrations, tenant roles,
and corrected tenant ACL applied by this test's own setUpClass.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from webguard_contracts import OrganizationRole, PrincipalType

RUN_INTEGRATION = os.environ.get("WEBGUARD_RUN_INTEGRATION") == "1"
POSTGRES_TEST_DSN = os.environ.get("WEBGUARD_POSTGRES_TEST_DSN")
RUN_POSTGRES_TESTS = RUN_INTEGRATION and bool(POSTGRES_TEST_DSN)

_BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent.parent / "infra" / "postgres" / "bootstrap"
ROLES_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_roles.sql"
ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_acl.sql"
# P1-2 Phase H gap closure, 2026-09-17: PasswordCredentialsWriteShapeTests
# now also applies these two so its get_password_hash test can prove
# the closed gap (see that test's own docstring). IdentityTokensWriteShapeTests
# below does not need them, since its own consume_identity_token test
# only ever reproduces the method's raw post-resolution UPDATE text,
# never calls webguard_control.resolve_identity_token at all.
FUNCTION_ACL_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_function_acl.sql"
CONTROL_FUNCTIONS_SQL_PATH = _BOOTSTRAP_DIR / "tenant_isolation_control_functions.sql"

ALL_BOOTSTRAP_ROLES = [
    "api_tenant_data",
    "worker_tenant_data",
    "scheduler_tenant_data",
    "identity_function_owner",
    "worker_function_owner",
    "scheduler_function_owner",
    "callback_function_owner",
]


def _run_migrations(dsn: str) -> None:
    repo_root = Path(__file__).resolve().parent.parent.parent
    env = dict(os.environ)
    env["WEBGUARD_DATABASE_URL"] = dsn
    result = subprocess.run(
        [sys.executable, str(repo_root / "scripts" / "run-postgres-migrations.py")],
        env=env, capture_output=True, text=True, cwd=repo_root,
    )
    assert result.returncode == 0, result.stderr


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class PasswordCredentialsWriteShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._db_name = "test_identity_write_shape_db"
        cls._caller_user = "test_identity_write_caller"
        cls._caller_password = "test-caller-password"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._caller_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')
            admin.execute(f'CREATE DATABASE "{cls._db_name}"')

        admin_parts = urlsplit(cls._admin_dsn)
        cls._db_dsn = urlunsplit((admin_parts.scheme, admin_parts.netloc, f"/{cls._db_name}", "", ""))
        _run_migrations(cls._db_dsn)

        with psycopg.connect(cls._db_dsn) as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            # P1-2 Phase H gap closure, 2026-09-17: needed for
            # test_get_password_hash_now_succeeds_via_resolver below.
            connection.execute(FUNCTION_ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(CONTROL_FUNCTIONS_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()

        with psycopg.connect(cls._db_dsn, autocommit=True) as connection:
            connection.execute(
                f'CREATE ROLE "{cls._caller_user}" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                f'IN ROLE "api_tenant_data" PASSWORD \'{cls._caller_password}\''
            )

        cls._caller_dsn = urlunsplit(
            ("postgresql", f"{cls._caller_user}:{cls._caller_password}@{cls._host_port}", f"/{cls._db_name}", "", "")
        )

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._caller_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self.pool = WebGuardPostgresPool(self._caller_dsn, minimum_connections=2, maximum_connections=8)
        self.addCleanup(self.pool.close)
        self.identity = PostgresIdentityRepository(self.pool)

        now = datetime.now(timezone.utc)
        # api_tenant_data has no TRUNCATE/DELETE on organizations under
        # the real production ACL (unlike test_postgres_sessions.py's
        # superuser-based TRUNCATE fixture), so nothing resets
        # organizations_name_key_unique between test methods -- each
        # needs its own name.
        organization = self.identity.create_organization(f"Write Shape Test Org {uuid.uuid4()}", now=now)
        principal = self.identity.create_principal(
            organization.organization_id, "Write Shape Principal", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        self.organization_id = organization.organization_id
        self.principal_id = principal.principal_id

    def _connect(self):
        import psycopg

        return psycopg.connect(self._caller_dsn)

    def _admin_connect(self):
        """Verification-only connection as the unrestricted admin
        actor, for assertions that need to read a column
        api_tenant_data correctly has no SELECT on (password_hash,
        created_at) -- never used to exercise the write path under
        test, only to check its result."""

        import psycopg

        return psycopg.connect(self._db_dsn)

    # -- fresh vs. existing credential -------------------------------------

    def test_fresh_credential_uses_insert_path(self) -> None:
        now = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-1", now=now)

        with self._connect() as connection:
            row = connection.execute(
                "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchone()
        self.assertIsNotNone(row, "the fresh-credential INSERT path must create exactly one row")

    def test_existing_credential_uses_conditional_update_path(self) -> None:
        created = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-1", now=created)

        updated = created + timedelta(hours=1)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-2", now=updated)

        with self._connect() as connection:
            row = connection.execute(
                "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchone()
        self.assertIsNotNone(row, "the conditional UPDATE path must not create a second row")

    def test_caller_visible_behavior_unchanged(self) -> None:
        now = datetime.now(timezone.utc)
        result = self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-1", now=now)
        self.assertIsNone(result, "set_password_hash's own return value is unchanged by the write-shape rewrite")

    def test_get_password_hash_now_succeeds_via_resolver(self) -> None:
        """P1-2 Phase H gap closed, 2026-09-17: get_password_hash used
        to be correctly denied here (api_tenant_data never held direct
        SELECT on password_credentials, and this correction's own ACL
        never granted it, per Section 13/Phase D's own output-minimization
        principle). It now succeeds through
        webguard_control.resolve_password_hash, a new principal_id-keyed
        SECURITY DEFINER function owned by identity_function_owner,
        granted EXECUTE to api_tenant_data (this class's setUpClass now
        also applies tenant_isolation_function_acl.sql and
        tenant_isolation_control_functions.sql to prove it end to end
        under the real disposable LOGIN caller, not just a superuser
        connection). Still no direct table-level SELECT on
        password_credentials for api_tenant_data: the function is the
        only path, and it returns only password_hash."""

        now = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-1", now=now)
        self.assertEqual(self.identity.get_password_hash(self.principal_id), "hash-1")
        self.assertIsNone(self.identity.get_password_hash(str(uuid.uuid4())))

        import psycopg

        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self._connect() as connection:
                connection.execute(
                    "SELECT password_hash FROM password_credentials WHERE principal_id = %s",
                    (self.principal_id,),
                )

    # -- concurrency ---------------------------------------------------------

    def test_concurrent_first_write_race(self) -> None:
        writer_count = 6
        barrier = threading.Barrier(writer_count)
        errors: list[BaseException] = []

        def _write(index: int) -> None:
            try:
                barrier.wait(timeout=10)
                now = datetime.now(timezone.utc).replace(microsecond=0)
                self.identity.set_password_hash(
                    self.principal_id, algorithm="scrypt", password_hash=f"writer-{now.hour}", now=now
                )
            except BaseException as exc:  # noqa: BLE001 - collected and re-raised on the main thread
                errors.append(exc)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(writer_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        self.assertEqual(errors, [], f"no writer should raise under the corrected ACL: {errors}")
        with self._admin_connect() as connection:
            rows = connection.execute(
                "SELECT password_hash FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchall()
        self.assertEqual(len(rows), 1, "exactly one row must exist after a concurrent first-write race")
        password_hash = rows[0][0]
        self.assertTrue(
            password_hash.startswith("writer-") and password_hash.split("-", 1)[1].isdigit(),
            f"the surviving value must be one writer's whole value, never a torn write: {password_hash!r}",
        )

    def test_concurrent_existing_row_write_race(self) -> None:
        created = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="seed", now=created)

        writer_count = 6
        barrier = threading.Barrier(writer_count)
        errors: list[BaseException] = []

        def _write(index: int) -> None:
            try:
                barrier.wait(timeout=10)
                now = datetime.now(timezone.utc).replace(microsecond=0)
                self.identity.set_password_hash(
                    self.principal_id, algorithm="scrypt", password_hash=f"writer-{now.hour}", now=now
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(writer_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        self.assertEqual(errors, [], f"no writer should raise under the corrected ACL: {errors}")
        with self._admin_connect() as connection:
            rows = connection.execute(
                "SELECT password_hash, created_at FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchall()
        self.assertEqual(len(rows), 1, "the race must never create a second row against an existing credential")
        password_hash, created_at = rows[0]
        self.assertTrue(password_hash.startswith("writer-"), "one of the racing writers' values must win, not the seed")
        self.assertEqual(
            created_at.astimezone(timezone.utc).replace(microsecond=0), created.replace(microsecond=0),
            "the conditional UPDATE path must preserve the original created_at, never touch it",
        )

    # -- transaction rollback -------------------------------------------------

    def test_rollback_fresh_insert_path_leaves_no_row(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (principal_id) DO NOTHING
                """,
                (self.principal_id, "scrypt", "rollback-fresh", datetime.now(timezone.utc), datetime.now(timezone.utc)),
            )
            with self.assertRaises(Exception):
                connection.execute("SELECT 1/0")
            connection.rollback()

        with self._connect() as connection:
            row = connection.execute(
                "SELECT principal_id FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchone()
        self.assertIsNone(row, "a rolled-back fresh insert must leave no row behind")

    def test_rollback_existing_row_update_path_restores_original(self) -> None:
        created = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="original", now=created)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (principal_id) DO NOTHING
                """,
                (self.principal_id, "scrypt", "should-not-apply", created, created),
            )
            connection.execute(
                """
                UPDATE password_credentials
                SET algorithm = %s, password_hash = %s, updated_at = %s
                WHERE principal_id = %s
                """,
                ("scrypt", "rollback-update", datetime.now(timezone.utc), self.principal_id),
            )
            with self.assertRaises(Exception):
                connection.execute("SELECT 1/0")
            connection.rollback()

        with self._admin_connect() as connection:
            row = connection.execute(
                "SELECT password_hash FROM password_credentials WHERE principal_id = %s",
                (self.principal_id,),
            ).fetchone()
        self.assertEqual(row[0], "original", "a rolled-back update must restore the pre-transaction value")

    # -- direct-read denial ---------------------------------------------------

    def test_password_hash_not_directly_selectable_by_caller_role(self) -> None:
        import psycopg

        now = datetime.now(timezone.utc)
        self.identity.set_password_hash(self.principal_id, algorithm="scrypt", password_hash="hash-1", now=now)

        with self._connect() as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT password_hash FROM password_credentials WHERE principal_id = %s",
                    (self.principal_id,),
                )


@unittest.skipUnless(
    RUN_POSTGRES_TESTS,
    "Set WEBGUARD_RUN_INTEGRATION=1 and WEBGUARD_POSTGRES_TEST_DSN to run this PostgreSQL integration test.",
)
class IdentityTokensWriteShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg

        cls._admin_dsn = POSTGRES_TEST_DSN
        parts = urlsplit(POSTGRES_TEST_DSN)
        cls._host_port = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        cls._db_name = "test_identity_tokens_write_shape_db"
        cls._caller_user = "test_identity_tokens_write_caller"
        cls._caller_password = "test-caller-password"

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._caller_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')
            admin.execute(f'CREATE DATABASE "{cls._db_name}"')

        admin_parts = urlsplit(cls._admin_dsn)
        cls._db_dsn = urlunsplit((admin_parts.scheme, admin_parts.netloc, f"/{cls._db_name}", "", ""))
        _run_migrations(cls._db_dsn)

        with psycopg.connect(cls._db_dsn) as connection:
            connection.execute(ROLES_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()
            connection.execute(ACL_SQL_PATH.read_text(encoding="utf-8"))
            connection.commit()

        with psycopg.connect(cls._db_dsn, autocommit=True) as connection:
            connection.execute(
                f'CREATE ROLE "{cls._caller_user}" LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB '
                f'IN ROLE "api_tenant_data" PASSWORD \'{cls._caller_password}\''
            )

        cls._caller_dsn = urlunsplit(
            ("postgresql", f"{cls._caller_user}:{cls._caller_password}@{cls._host_port}", f"/{cls._db_name}", "", "")
        )

    @classmethod
    def tearDownClass(cls) -> None:
        import psycopg

        with psycopg.connect(cls._admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls._db_name}"')
            admin.execute(f'DROP ROLE IF EXISTS "{cls._caller_user}"')
            for role in ALL_BOOTSTRAP_ROLES:
                admin.execute(f'DROP ROLE IF EXISTS "{role}"')

    def setUp(self) -> None:
        from webguard_api.postgres_identity import PostgresIdentityRepository
        from webguard_api.postgres_pool import WebGuardPostgresPool

        self.pool = WebGuardPostgresPool(self._caller_dsn, minimum_connections=2, maximum_connections=8)
        self.addCleanup(self.pool.close)
        self.identity = PostgresIdentityRepository(self.pool)

        now = datetime.now(timezone.utc)
        organization = self.identity.create_organization(f"Token Write Shape Test Org {uuid.uuid4()}", now=now)
        principal = self.identity.create_principal(
            organization.organization_id, "Token Write Shape Principal", principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=now,
        )
        self.organization_id = organization.organization_id
        self.principal_id = principal.principal_id

    def _connect(self):
        import psycopg

        return psycopg.connect(self._caller_dsn)

    def test_consume_identity_token_post_resolution_update_succeeds_under_corrected_acl(self) -> None:
        """consume_identity_token's own initial SELECT reads four
        columns (organization_id, secret_hash, created_at, expires_at)
        this correction does not grant -- that resolver split is a
        later repository-conversion phase's scope, not this one's. This
        test reproduces only the method's own post-resolution
        ``UPDATE identity_tokens SET used_at = %s WHERE token_id = %s``,
        against a token created through the real
        ``create_identity_token`` (a pure INSERT, unaffected by this
        correction's SELECT grant, since it references no conflict
        target and no WHERE clause)."""

        from webguard_api.identity import IdentityTokenPurpose

        now = datetime.now(timezone.utc)
        issued = self.identity.create_identity_token(
            self.principal_id, self.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET, ttl=timedelta(hours=1), now=now,
        )

        with self._connect() as connection:
            connection.execute(
                "UPDATE identity_tokens SET used_at = %s WHERE token_id = %s",
                (now, issued.record.token_id),
            )
            row = connection.execute(
                "SELECT used_at FROM identity_tokens WHERE token_id = %s", (issued.record.token_id,)
            ).fetchone()
        self.assertIsNotNone(row[0], "the post-resolution UPDATE must succeed and set used_at")

    def test_invalidate_identity_tokens_succeeds_under_corrected_acl(self) -> None:
        """invalidate_identity_tokens has no internal SELECT of its
        own -- it is exercised directly, unlike
        consume_identity_token above."""

        from webguard_api.identity import IdentityTokenPurpose

        now = datetime.now(timezone.utc)
        issued = self.identity.create_identity_token(
            self.principal_id, self.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET, ttl=timedelta(hours=1), now=now,
        )

        self.identity.invalidate_identity_tokens(
            self.principal_id, purpose=IdentityTokenPurpose.PASSWORD_RESET, now=now
        )

        with self._connect() as connection:
            row = connection.execute(
                "SELECT used_at FROM identity_tokens WHERE token_id = %s", (issued.record.token_id,)
            ).fetchone()
        self.assertIsNotNone(row[0], "invalidate_identity_tokens must mark the token used")

    def test_identity_tokens_secret_hash_not_directly_selectable(self) -> None:
        import psycopg

        from webguard_api.identity import IdentityTokenPurpose

        now = datetime.now(timezone.utc)
        self.identity.create_identity_token(
            self.principal_id, self.organization_id,
            purpose=IdentityTokenPurpose.PASSWORD_RESET, ttl=timedelta(hours=1), now=now,
        )

        with self._connect() as connection:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                connection.execute("SELECT secret_hash FROM identity_tokens LIMIT 1")


if __name__ == "__main__":
    unittest.main()
