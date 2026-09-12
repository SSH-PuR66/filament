"""Configured-identity handoff tests. No signing, Apple calls, or device access."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import filament as F
import sideload as S


class AppBundlePreflightTests(unittest.TestCase):
    def test_unprovisioned_directory_is_blocked_just_like_an_ipa(self):
        with tempfile.TemporaryDirectory(suffix=".app") as app:
            fatal, info = S.check_app(app)
            self.assertTrue(fatal)
            self.assertIs(info["profile"], False)
            fatal, info = S.check_app(app, will_sign=True)
            self.assertEqual(fatal, [])
            self.assertEqual(info["profile"], "none yet - signing will embed one")

    def test_profile_must_be_a_file_in_an_app_bundle(self):
        with tempfile.TemporaryDirectory(suffix=".app") as app:
            Path(app, "embedded.mobileprovision").mkdir()
            self.assertTrue(S.check_app(app)[0])


class ConfiguredIdentityTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for variable, filename in {
            "SIGNING_PYTHON": "python.exe", "SIDELOAD_PY": "sideload.py",
            "SIGNING_P12": "identity.p12", "SIGNING_PROFILE": "identity.mobileprovision",
            "SIGNING_PEM_KEY": "key.pem", "SIGNING_PEM_CERT": "cert.pem",
        }.items():
            path = root / filename
            path.write_bytes(b"fixture")
            self.stack.enter_context(patch.object(F, variable, str(path)))
        self.stack.enter_context(patch.object(F, "SIGNING_P12_PASSWORD", "configured-test-secret"))
        self.app = root / "fixture.ipa"
        self.app.write_bytes(b"not an executable; subprocess is mocked")
        self.run = self.stack.enter_context(patch.object(
            F.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="checked", stderr="")))

    def test_configured_identity_uses_signing_runtime_and_secret_stdin(self):
        result = F.sideload_check(app=str(self.app), use_identity=True)
        self.assertTrue(result["ok"])
        argv = self.run.call_args.args[0]
        opts = self.run.call_args.kwargs
        self.assertEqual(argv[:3], [F.SIGNING_PYTHON, F.SIDELOAD_PY, "check"])
        self.assertEqual(argv[argv.index("--p12") + 1], F.SIGNING_P12)
        self.assertEqual(argv[argv.index("--profile") + 1], F.SIGNING_PROFILE)
        self.assertEqual(opts["input"], "configured-test-secret\n")
        self.assertNotIn("configured-test-secret", json.dumps(argv))
        self.assertNotIn("configured-test-secret", json.dumps(result))
        self.assertNotIn("P12_PASSWORD", opts["env"])
        self.assertNotIn("FILAMENT_P12_PASSWORD", opts["env"])

    def test_pem_identity_is_supported_when_p12_is_absent(self):
        Path(F.SIGNING_P12).unlink()
        self.assertTrue(F.sideload_check(app=str(self.app), use_identity=True)["ok"])
        argv = self.run.call_args.args[0]
        self.assertIn("--pem-key", argv)
        self.assertIn("--pem-cert", argv)
        self.assertNotIn("--p12", argv)

    def test_incomplete_pem_identity_never_launches_child(self):
        Path(F.SIGNING_P12).unlink()
        Path(F.SIGNING_PEM_KEY).unlink()
        self.assertFalse(F.sideload_check(app=str(self.app), use_identity=True)["ok"])
        self.run.assert_not_called()

    def test_configured_and_custom_material_cannot_mix(self):
        for name in ("profile", "p12", "p12password"):
            with self.subTest(field=name):
                result = F.sideload_check(app=str(self.app), use_identity=True, **{name: "custom"})
                self.assertFalse(result["ok"])
        self.run.assert_not_called()

    def test_custom_mode_retains_the_previous_runtime_and_arguments(self):
        self.assertTrue(F.sideload_check(app=str(self.app))["ok"])
        self.assertEqual(self.run.call_args.args[0], [F.PYTHON, F.SIDELOAD_PY, "check", str(self.app)])

    def test_install_keeps_the_existing_revalidating_child_command(self):
        self.assertTrue(F.sideload_check(app=str(self.app), use_identity=True, install=True)["ok"])
        self.assertEqual(self.run.call_args.args[0][2], "install")

    def test_missing_runtime_or_app_fails_before_subprocess(self):
        Path(F.SIGNING_PYTHON).unlink()
        self.assertFalse(F.sideload_check(app=str(self.app), use_identity=True)["ok"])
        self.assertFalse(F.sideload_check(install=True)["ok"])
        self.run.assert_not_called()

    def test_child_failure_never_reports_success(self):
        self.run.return_value = SimpleNamespace(returncode=1, stdout="profile expired", stderr="")
        self.assertFalse(F.sideload_check(app=str(self.app), use_identity=True)["ok"])

    def test_request_types_and_conflicts_fail_closed(self):
        for value in ("true", 1, [], None):
            self.assertIsNotNone(F._parse_sideload_request({"use_identity": value})[1])
        self.assertIsNotNone(F._parse_sideload_request({"use_identity": True, "p12": "x.p12"})[1])
        parsed, error = F._parse_sideload_request({"app": " app.ipa ", "use_identity": True})
        self.assertIsNone(error)
        self.assertTrue(parsed["use_identity"])
        self.assertEqual(parsed["app"], "app.ipa")
        self.assertFalse(parsed["install"])

    def test_ui_contains_model_without_private_identity_values(self):
        page = F.UI.replace("__TOKEN__", "fixture-token").replace("__INSTALL_FLOW__", F.INSTALL_FLOW)
        self.assertNotIn("__INSTALL_FLOW__", page)
        self.assertNotIn("configured-test-secret", page)
        self.assertNotIn(F.SIGNING_PEM_KEY, page)
        self.assertNotIn("class=\"st st-shut\">absent", page)


class PackagePreflightTests(unittest.TestCase):
    def test_unsigned_bundle_and_archive_both_require_resigning(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Fixture.app"
            app.mkdir()
            ipa = Path(folder) / "Fixture.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Fixture.app/Info.plist", b"fixture")
            for path in (app, ipa):
                with self.subTest(path=path.suffix):
                    self.assertTrue(S.check_app(str(path))[0])
                    errors, info = S.check_app(str(path), will_sign=True)
                    self.assertEqual(errors, [])
                    self.assertIn("signing will embed", info["profile"])

if __name__ == "__main__":
    unittest.main()
