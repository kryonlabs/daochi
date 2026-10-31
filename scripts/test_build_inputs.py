#!/usr/bin/env python3
"""Tests for immutable Daochi build inputs."""

from pathlib import Path
import tempfile
import unittest

from verify_build_inputs import BuildInputError, verify_build_inputs


REPOSITORY = Path(__file__).resolve().parents[1]


class BuildInputTests(unittest.TestCase):
    def copy_repository_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        dockerfile = root / "Dockerfile"
        workflow = root / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        dockerfile.write_bytes((REPOSITORY / "Dockerfile").read_bytes())
        workflow.write_bytes((REPOSITORY / ".github/workflows/ci.yml").read_bytes())
        return dockerfile, workflow

    def test_accepts_verified_docker_and_linter_identities(self):
        dockerfile, _ = self.copy_repository_fixture()
        verify_build_inputs(dockerfile.parent)

    def test_rejects_each_changed_base_image_digest(self):
        positions = (0, 1, 2)
        for position in positions:
            with self.subTest(position=position):
                dockerfile, _ = self.copy_repository_fixture()
                text = dockerfile.read_text()
                digest_pattern = "@sha256:"
                occurrence = -1
                cursor = 0
                while occurrence < position:
                    cursor = text.index(digest_pattern, cursor) + len(digest_pattern)
                    occurrence += 1
                text = text[:cursor] + "0" + text[cursor + 1 :]
                dockerfile.write_text(text)
                with self.assertRaises(BuildInputError):
                    verify_build_inputs(dockerfile.parent)

    def test_rejects_changed_golangci_lint_checksum(self):
        _, workflow = self.copy_repository_fixture()
        text = workflow.read_text()
        text = text.replace(
            "GOLANGCI_LINT_SHA256: \"ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab\"",
            "GOLANGCI_LINT_SHA256: \"0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        workflow.write_text(text)
        with self.assertRaises(BuildInputError):
            verify_build_inputs(workflow.parents[2])

    def test_rejects_unpinned_base_image(self):
        dockerfile, _ = self.copy_repository_fixture()
        text = dockerfile.read_text().replace("@sha256:13e0a2e78aa0554ad5ff66e4e260c6dbcdff807eb1f39d43b9fb0288aae88b04", "")
        dockerfile.write_text(text)
        with self.assertRaises(BuildInputError):
            verify_build_inputs(dockerfile.parent)


if __name__ == "__main__":
    unittest.main()
