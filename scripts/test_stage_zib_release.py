import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app_release import signing_message

SCRIPT = Path(__file__).with_name('stage-zib-release.py')


class StageReleaseTest(unittest.TestCase):
    def test_component_versions_variants_and_dependencies(self):
        with tempfile.TemporaryDirectory(prefix='stage-app-') as temporary:
            root = Path(temporary)
            key = Ed25519PrivateKey.generate()
            private = root / 'publisher.pem'
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            module = root / 'module.zib'
            standalone = root / 'standalone.zib'
            module.write_bytes(b'ZIB\0thin module')
            standalone.write_bytes(b'ZIB\0complete standalone')
            store = root / 'packages'

            def stage(app, sequence, version='1.0.0', dependencies=(), expected=0):
                command = [sys.executable, SCRIPT, '--store', store, '--app', app,
                    '--key-id', 'release', '--key', private, '--format-version', '2',
                    '--version', version, '--sequence', str(sequence),
                    '--standalone', standalone]
                for dependency in dependencies:
                    command.extend(['--dependency', dependency])
                result = subprocess.run([*command, module], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                return store / app / 'latest-v2.json'

            common = stage('common', 1)
            harness = stage('inbe', 1, dependencies=[common])
            diary = stage('diary', 1, dependencies=[common])
            original_harness = harness.read_bytes()
            release = json.loads(diary.read_bytes())
            key.public_key().verify(bytes.fromhex(release['signature']), signing_message(release))
            self.assertEqual([a['variant'] for a in release['artifacts']], ['module', 'standalone'])
            self.assertEqual(release['dependencies'][0]['app_id'], 'common')
            stage('diary', 2, '1.0.1', [common])
            self.assertEqual(harness.read_bytes(), original_harness)
            second = diary.read_bytes()
            stage('diary', 2, '1.0.1', [common])
            self.assertEqual(diary.read_bytes(), second)
            stage('diary', 1, dependencies=[common], expected=2)
            self.assertEqual(diary.read_bytes(), second)
            stage('diary', 3, '1.0.2', [diary], expected=2)
            stage('diary', 3, '01.0.0', expected=2)
            self.assertEqual(diary.read_bytes(), second)

    def test_signed_immutable_release_and_monotonic_publication(self):
        with tempfile.TemporaryDirectory(prefix='stage-zib-') as temporary:
            root = Path(temporary)
            key = Ed25519PrivateKey.generate()
            private = root / 'publisher.pem'
            private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            private.chmod(0o600)
            bundle = root / 'app.zib'
            bundle.write_bytes(b'ZIB\0signed test payload')
            command = [sys.executable, SCRIPT, '--store', root / 'packages', '--app', 'portable',
                       '--key-id', 'release', '--key', private, '--version', '1.0.0']

            def stage(sequence, expected=0):
                result = subprocess.run([*command, '--sequence', str(sequence), bundle],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
                self.assertNotIn(private.read_bytes(), result.stdout + result.stderr)

            stage(1)
            directory = root / 'packages/portable'
            latest = directory / 'latest.json'
            release = json.loads(latest.read_bytes())
            fields = ('app_id', 'sequence', 'version', 'runtime', 'sha256', 'size', 'key_id')
            message = 'daochi-zib-release-v1\n' + ''.join(f'{release[name]}\n' for name in fields)
            key.public_key().verify(bytes.fromhex(release['signature']), message.encode())
            first = directory / (release['sha256'] + '.zib')
            self.assertEqual(first.read_bytes(), bundle.read_bytes())
            self.assertEqual(json.loads((directory / (first.name + '.json')).read_text()), release)
            baseline = latest.read_bytes()
            stage(1)
            self.assertEqual(latest.read_bytes(), baseline)
            bundle.write_bytes(b'ZIB\0updated test payload')
            stage(1, 2)
            self.assertEqual(latest.read_bytes(), baseline)
            stage(2)
            self.assertEqual(json.loads(latest.read_bytes())['sequence'], 2)
            self.assertTrue(first.exists())
            stage(1, 2)
            self.assertFalse(list(directory.glob('.stage-*')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
