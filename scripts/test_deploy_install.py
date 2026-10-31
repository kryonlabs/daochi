"""Exercise installation and rollback using disposable files and fake services."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
STAMP = "20261031T000000Z"


class InstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = dict(os.environ, TEST_ROOT=str(self.root))
        self.environment["PATH"] = str(self.root / "bin") + os.pathsep + os.environ["PATH"]
        for name in ("opt/daochi", "opt/daochi-src/deploy", "opt/daochi-src/scripts", "opt/daochi-src/build",
                     "var/lib/daochi", "etc/daochi", "etc/systemd/system/daochi.service.d", "bin"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        for script in ("install.sh", "rollback.sh"):
            text = (REPOSITORY / "deploy" / script).read_text()
            for prefix in ("/opt/daochi", "/var/lib/daochi", "/etc/daochi", "/etc/systemd"):
                text = text.replace(prefix, str(self.root) + prefix)
            (self.root / "opt/daochi-src/deploy" / script).write_text(text)
        for name, value in {
            "opt/daochi/daochi": "old binary", "opt/daochi/daochi.manifest.json": "old manifest",
            "opt/daochi-src/daochi": "new binary", "opt/daochi-src/build/daochi.manifest.json": "new manifest",
            "var/lib/daochi/daochi.db": "paid data", "etc/daochi/daochi.env": "old environment",
            "etc/systemd/system/daochi.service.d/20-daochi-mesh.conf": "old mesh setting",
        }.items():
            (self.root / name).write_text(value)
        for name in ("daochi-backup-prune.service", "daochi-backup-prune.timer", "node.env", "dew-ratio.env"):
            (self.root / "opt/daochi-src/deploy" / name).write_text("fixture")
        self.executable("bin/systemctl", '''
import os, pathlib, sys
command = " ".join(sys.argv[1:])
with (pathlib.Path(os.environ["TEST_ROOT"]) / "services.log").open("a") as output:
    output.write(command + "\\n")
sys.exit(1 if command == os.environ.get("FAIL_SERVICE") else 0)
''')
        self.executable("bin/sqlite3", '''
import os, pathlib, shlex, shutil, sys
assert "stop daochi.service" in (pathlib.Path(os.environ["TEST_ROOT"]) / "services.log").read_text()
shutil.copyfile(sys.argv[1], shlex.split(sys.argv[2])[1])
''')
        self.executable("bin/sleep", "")
        self.executable("opt/daochi-src/scripts/verify_deployment_inputs.py", '''
import os, sys
sys.exit(1 if os.environ.get("FAIL_VERIFY") else 0)
''')
        self.executable("opt/daochi-src/scripts/migrate-legacy-env.py", '''
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text("new environment")
''')
        (self.root / "opt/daochi-src/deploy/set-environment.sh").write_text("exit 0\n")
        (self.root / "opt/daochi-src/deploy/apply-dew-ratio.sh").write_text('[ -z "${FAIL_MIGRATION:-}" ]\n')

    def executable(self, name, body):
        path = self.root / name
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o755)

    def run_install(self, token="node:secret"):
        return subprocess.run(
            ["sh", str(self.root / "opt/daochi-src/deploy/install.sh"), STAMP, "a" * 40, "b" * 40],
            input=token.encode(), env=self.environment, capture_output=True, timeout=10,
        )

    def assert_old_install(self):
        self.assertEqual((self.root / "opt/daochi/daochi").read_text(), "old binary")
        self.assertEqual((self.root / "var/lib/daochi/daochi.db").read_text(), "paid data")
        self.assertEqual((self.root / "etc/daochi/daochi.env").read_text(), "old environment")

    def test_success_backs_up_data_and_treats_secret_as_data(self):
        token = 'node:quote\"$()\\percent%'
        result = self.run_install(token)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.root / "opt/daochi/daochi").read_text(), "new binary")
        self.assertEqual((self.root / f"var/lib/daochi/backups/daochi.db.{STAMP}").read_text(), "paid data")
        setting = self.root / "etc/systemd/system/daochi.service.d/20-daochi-mesh.conf"
        self.assertIn('$()', setting.read_text())
        self.assertIn('percent%%', setting.read_text())
        self.assertEqual(setting.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(token.encode(), result.stdout + result.stderr)

    def test_failed_migration_restores_binary_database_environment_and_mesh(self):
        self.environment["FAIL_MIGRATION"] = "1"
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assert_old_install()
        self.assertEqual((self.root / "opt/daochi/daochi.manifest.json").read_text(), "old manifest")
        self.assertEqual((self.root / "etc/systemd/system/daochi.service.d/20-daochi-mesh.conf").read_text(), "old mesh setting")

    def test_failed_health_restores_absent_old_manifest_and_mesh(self):
        (self.root / "opt/daochi/daochi.manifest.json").unlink()
        mesh = self.root / "etc/systemd/system/daochi.service.d/20-daochi-mesh.conf"
        mesh.unlink()
        self.environment["FAIL_SERVICE"] = "is-active --quiet daochi.service"
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assert_old_install()
        self.assertFalse((self.root / "opt/daochi/daochi.manifest.json").exists())
        self.assertFalse(mesh.exists())

    def test_bad_provenance_does_not_swap_or_restart(self):
        self.environment["FAIL_VERIFY"] = "1"
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assert_old_install()
        self.assertFalse((self.root / "services.log").exists())

    def test_json_entry_keeps_credentials_out_of_arguments(self):
        spec = importlib.util.spec_from_file_location("deploy_install", REPOSITORY / "deploy/install.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        request = {"stamp": STAMP, "source_commit": "a" * 40, "native_commit": "b" * 40, "mesh_token": "private credential"}
        with mock.patch.object(module.subprocess, "run") as run:
            module.install(request)
            self.assertNotIn(request["mesh_token"], run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["input"], b"private credential")
            self.assertTrue(run.call_args.kwargs["check"])
        with self.assertRaises(ValueError):
            module.install({"stamp": []})


if __name__ == "__main__":
    unittest.main()
