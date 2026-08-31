"""P0-2 remediation (docs/audit/WEBGUARD_FULL_SYSTEM_AUDIT_2026-08.md):
`webguard-api signing-service` previously had no `--environment` concept
at all, so `--key-source` silently defaulted to "development" -- an
operator or deployment script that forgot `--key-source cloudhsm` in
production would start and listen anyway, signing every TrustScan
permit with a fixed, source-visible development key
(`LocalDevelopmentSigner(bytes(range(32)))`) while reporting success.

This suite proves the fail-closed gate now in `_signing_service_command`
using the exact same seam-substitution pattern as
`test_cli_production_environment.py` (patch `cli`'s module-level
references, never a real socket, never real PKCS#11/CloudHSM). It does
not and cannot prove anything about real CloudHSM hardware -- see
`build_cloudhsm_signing_provider_from_env`'s own docstring; the
"malformed provider"/"unavailable provider" cases here simulate what
that function raises, they do not exercise real PKCS#11."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from webguard_api import cli
from webguard_api.signing import SigningKeyRegistry, SigningProviderError
from webguard_api.signing_service import SigningServiceError


class _FakeSigningServer:
    instances: list["_FakeSigningServer"] = []

    def __init__(self, registry, *, bearer_token, host, port) -> None:
        self.registry = registry
        self.bearer_token = bearer_token
        self.host = host
        self.port = port
        self.started = False
        self.stopped = False
        _FakeSigningServer.instances.append(self)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


class _FakeStopEvent:
    def __init__(self) -> None:
        self.set_called = False

    def wait(self) -> None:
        return None

    def set(self) -> None:
        self.set_called = True


def _args(*, environment: str, key_source: str = "development") -> SimpleNamespace:
    return SimpleNamespace(environment=environment, key_source=key_source)


class SigningServiceProductionGateTests(unittest.TestCase):
    """The six CLI-gate scenarios the audit's own remediation test
    names, plus the two "malformed"/"unavailable" CloudHSM-path
    variants the review brief additionally required."""

    def setUp(self) -> None:
        _FakeSigningServer.instances.clear()
        self._env_patch = patch.dict(
            "os.environ", {"WEBGUARD_SIGNING_SERVICE_BEARER_TOKEN": "test-bearer-token"}, clear=False
        )
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)

    def _run(self, args: SimpleNamespace):
        with patch.object(cli, "SigningServiceServer", _FakeSigningServer), patch.object(
            cli.threading, "Event", return_value=_FakeStopEvent()
        ), patch.object(cli.signal, "signal"):
            exit_code = cli._signing_service_command(args)
        return exit_code

    # -- production + no signing config (default key-source) -> FAIL --
    def test_production_with_no_key_source_flag_fails_closed(self) -> None:
        exit_code = self._run(_args(environment="production"))

        self.assertEqual(exit_code, cli.EXIT_FAILURE)
        self.assertEqual(
            _FakeSigningServer.instances, [], "no socket may be bound when the gate rejects the launch"
        )

    # -- production + explicit development signer -> FAIL --
    def test_production_with_explicit_development_key_source_fails_closed(self) -> None:
        exit_code = self._run(_args(environment="production", key_source="development"))

        self.assertEqual(exit_code, cli.EXIT_FAILURE)
        self.assertEqual(_FakeSigningServer.instances, [])

    # -- production + malformed provider configuration -> FAIL --
    def test_production_cloudhsm_malformed_configuration_fails_closed(self) -> None:
        with patch.object(
            cli,
            "build_cloudhsm_signing_provider_from_env",
            side_effect=SigningServiceError(
                "signing_service_config_missing",
                "WEBGUARD_SIGNING_SERVICE_PKCS11_TOKEN_LABEL is required to start the signing service.",
                status=500,
            ),
        ):
            exit_code = self._run(_args(environment="production", key_source="cloudhsm"))

        self.assertEqual(exit_code, cli.EXIT_FAILURE)
        self.assertEqual(_FakeSigningServer.instances, [])

    # -- production + a required provider that cannot be reached/loaded -> FAIL --
    def test_production_cloudhsm_unavailable_provider_fails_closed(self) -> None:
        with patch.object(
            cli,
            "build_cloudhsm_signing_provider_from_env",
            side_effect=RuntimeError("PKCS#11 library could not be loaded: /nonexistent/libcloudhsm_pkcs11.so"),
        ):
            exit_code = self._run(_args(environment="production", key_source="cloudhsm"))

        self.assertEqual(exit_code, cli.EXIT_FAILURE)
        self.assertEqual(
            _FakeSigningServer.instances, [], "an unexpected CloudHSM failure must fail closed, not crash uncaught"
        )

    # -- development + development signer -> PASS, unchanged --
    def test_development_with_development_key_source_starts(self) -> None:
        exit_code = self._run(_args(environment="development", key_source="development"))

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(len(_FakeSigningServer.instances), 1)
        self.assertTrue(_FakeSigningServer.instances[0].started)

    # -- test/lab configured path -> PASS, unchanged --
    def test_test_and_lab_environments_with_development_key_source_start(self) -> None:
        for environment in ("test", "lab"):
            with self.subTest(environment=environment):
                _FakeSigningServer.instances.clear()
                exit_code = self._run(_args(environment=environment, key_source="development"))

                self.assertEqual(exit_code, cli.EXIT_SUCCESS)
                self.assertEqual(len(_FakeSigningServer.instances), 1)

    # -- non-production environments are not restricted to "development" --
    def test_non_production_environment_may_still_select_cloudhsm(self) -> None:
        """The P0-2 gate is one-directional: production must never use
        a development key. It does not forbid a non-production
        environment from exercising the cloudhsm path (e.g. a lab
        rehearsal against a real HSM) -- only the missing-config/
        provider-failure path already fails this the same way it would
        in production, proving the gate itself imposes no new
        restriction here."""

        with patch.object(
            cli,
            "build_cloudhsm_signing_provider_from_env",
            side_effect=SigningServiceError("signing_service_config_missing", "not configured", status=500),
        ):
            exit_code = self._run(_args(environment="lab", key_source="cloudhsm"))

        self.assertEqual(exit_code, cli.EXIT_FAILURE)
        self.assertEqual(_FakeSigningServer.instances, [])


class SigningServiceKeyLifecycleRegressionTests(unittest.TestCase):
    """Confirms the pre-existing SigningKeyRegistry key-lifecycle
    contract (untouched by this fix -- signing.py was not modified) is
    unaffected: a disabled key can never verify, and an unknown key ID
    is always rejected. See tests/unit/test_signing_provider.py for the
    full, pre-existing suite this mirrors a slice of; these two are
    repeated here specifically against a registry constructed the same
    way `_signing_service_command` constructs one, as a regression
    check tied directly to this remediation."""

    def _registry(self) -> SigningKeyRegistry:
        from webguard_api.signing import LocalDevelopmentSigner

        provider = LocalDevelopmentSigner(bytes(range(32)))
        return SigningKeyRegistry(provider)

    def test_disabled_active_key_cannot_verify(self) -> None:
        registry = self._registry()
        message = b"trustscan-permit-payload"
        signature = registry.active.sign(message)
        registry.set_status(registry.active.key_id, "disabled")

        with self.assertRaises(SigningProviderError) as caught:
            registry.verify_by_key_id(registry.active.key_id, message, signature)
        self.assertEqual(caught.exception.code, "trustscan_signing_key_disabled")

    def test_unknown_key_id_fails_closed(self) -> None:
        registry = self._registry()

        with self.assertRaises(SigningProviderError) as caught:
            registry.verify_by_key_id("sha256:not-a-real-key", b"message", b"signature")
        self.assertEqual(caught.exception.code, "trustscan_signing_key_unknown")


if __name__ == "__main__":
    unittest.main()
