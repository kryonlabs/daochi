import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("mirror", Path(__file__).with_name("mirror.py"))
mirror = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mirror
spec.loader.exec_module(mirror)


class MirrorTests(unittest.TestCase):
    def artifact(self, root, data=b"ZX\0\0published fixture", suffix=".zx"):
        app = root / "inbe.practices"
        app.mkdir(exist_ok=True)
        name = hashlib.sha256(data).hexdigest() + suffix
        path = app / name
        path.write_bytes(data)
        return path

    def test_verified_bytes_have_an_immutable_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.artifact(root)
            artifacts = mirror.collect_artifacts(root)
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].key, "inbe.practices/" + path.name)

    def test_legacy_bundles_stay_mirrored_beside_portable_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            portable = self.artifact(root)
            legacy = self.artifact(root, b"ZIB\0legacy fixture", ".zib")
            keys = {artifact.key for artifact in mirror.collect_artifacts(root)}
            self.assertEqual(keys, {"inbe.practices/" + portable.name, "inbe.practices/" + legacy.name})

    def test_corruption_is_rejected_before_any_upload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.artifact(root)
            path.write_bytes(b"ZIB\0changed bytes")
            with self.assertRaisesRegex(ValueError, "hash does not match"):
                mirror.collect_artifacts(root)

    def test_symlinks_are_not_uploaded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.artifact(root)
            target = root / "private-file"
            target.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "invalid immutable artifact"):
                mirror.collect_artifacts(root)

    def test_storage_budget_counts_previous_and_interrupted_uploads(self):
        keys = {f"app/{index:064x}.zib": mirror.MAX_ARTIFACT_BYTES for index in range(16)}
        previous = {"schema": 1, "objects": keys}
        artifact = mirror.Artifact("app/" + "f" * 64 + ".zib", Path("unused"), 1)
        with self.assertRaisesRegex(ValueError, "8 GiB"):
            mirror.reserve_inventory(previous, [artifact])
        self.assertEqual(len(previous["objects"]), 16)

    def test_retries_reserve_each_hash_once(self):
        artifact = mirror.Artifact("app/" + "a" * 64 + ".zib", Path("unused"), 123)
        initial = mirror.reserve_inventory({"schema": 1, "objects": {}}, [artifact])
        retried = mirror.reserve_inventory(initial, [artifact])
        self.assertEqual(sum(retried["objects"].values()), 123)


if __name__ == "__main__":
    unittest.main()
