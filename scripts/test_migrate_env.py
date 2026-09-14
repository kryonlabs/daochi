import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "migration", Path(__file__).with_name("migrate-legacy-env.py")
)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class MigrationTest(unittest.TestCase):
    def test_preserves_credentials_and_database_and_is_idempotent(self):
        original = "# production\nKSYNC_TOKEN_SECRET_HEX=example\nKSYNC_DB=/data/existing.db\n"
        updated = migration.migrate(original)
        self.assertTrue(updated.startswith(original))
        self.assertIn("DAOCHI_TOKEN_SECRET_HEX=example\n", updated)
        self.assertIn("DAOCHI_DB=/data/existing.db\n", updated)
        self.assertEqual(migration.migrate(updated), updated)

    def test_conflict_does_not_silently_switch_database(self):
        with self.assertRaises(ValueError):
            migration.migrate("KSYNC_DB=/data/old.db\nDAOCHI_DB=/data/new.db\n")

    def test_canonical_only_is_unchanged(self):
        original = "DAOCHI_DB=/data/existing.db\nMONERO_NETWORK=mainnet\n"
        self.assertEqual(migration.migrate(original), original)


if __name__ == "__main__":
    unittest.main()
