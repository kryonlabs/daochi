#!/usr/bin/env python3
"""Verify immutable Daochi build-tool and base-image inputs.

To update a pin, resolve the new official registry index digest or upstream
release checksum, update the corresponding expected identity here, verify the
new artifact against its authoritative source, and run this helper plus its
unit tests. Do not weaken digest or checksum validation to make an update pass.
"""

import argparse
from pathlib import Path
import re
import sys


EXPECTED_BASE_IMAGES = (
    "debian:stable-slim@sha256:13e0a2e78aa0554ad5ff66e4e260c6dbcdff807eb1f39d43b9fb0288aae88b04",
    "golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb",
    "gcr.io/distroless/base-nossl-debian13:nonroot@sha256:6a2a3346335b94d3be0732472245f42ca3ce3cc1135a9521a2bda4b677f2ef0d",
)

EXPECTED_GOLANGCI_LINT_VERSION = "2.14.0"
EXPECTED_GOLANGCI_LINT_SHA256 = "ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab"
EXPECTED_GOLANGCI_LINT_INSTALL = "\n".join([
    "        env:",
    f'          GOLANGCI_LINT_VERSION: "{EXPECTED_GOLANGCI_LINT_VERSION}"',
    f'          GOLANGCI_LINT_SHA256: "{EXPECTED_GOLANGCI_LINT_SHA256}"',
    "        run: |",
    "          curl --fail --location --silent --show-error \\",
    '            --output "$RUNNER_TEMP/golangci-lint.tar.gz" \\',
    '            "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz"',
    """          printf '%s  %s\\n' "$GOLANGCI_LINT_SHA256" "$RUNNER_TEMP/golangci-lint.tar.gz" | sha256sum --check --strict""",
    '          tar --extract --gzip --file "$RUNNER_TEMP/golangci-lint.tar.gz" --directory "$RUNNER_TEMP"',
    '          install -m 0755 "$RUNNER_TEMP/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64/golangci-lint" /usr/local/bin/golangci-lint',
])


class BuildInputError(ValueError):
    pass


def dockerfile_references(dockerfile_text):
    pattern = re.compile(r"^FROM\s+(?P<reference>\S+)(?:\s+AS\s+\S+)?\s*$", re.MULTILINE)
    references = [match.group("reference") for match in pattern.finditer(dockerfile_text)]
    if not references:
        raise BuildInputError("Dockerfile contains no FROM instructions")
    return references


def verify_build_inputs(root):
    root_path = Path(root)
    dockerfile_path = root_path / "Dockerfile"
    workflow_path = root_path / ".github/workflows/ci.yml"
    if not dockerfile_path.is_file() or not workflow_path.is_file():
        raise BuildInputError("Dockerfile and .github/workflows/ci.yml must exist")

    references = dockerfile_references(dockerfile_path.read_text())
    if tuple(references) != EXPECTED_BASE_IMAGES:
        differences = [
            f"position {position}: expected {expected}, found {observed}"
            for position, (expected, observed) in enumerate(zip(EXPECTED_BASE_IMAGES, references), start=1)
        ]
        if len(references) != len(EXPECTED_BASE_IMAGES):
            differences.append(f"expected {len(EXPECTED_BASE_IMAGES)} FROM references, found {len(references)}")
        raise BuildInputError("; ".join(differences))

    workflow_text = workflow_path.read_text()
    match = re.search(
        r"^      - name: Install golangci-lint\n(?P<section>.*?)(?=^      - name: Lint\n)",
        workflow_text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise BuildInputError("golangci-lint installation step is missing")
    if match.group("section") != EXPECTED_GOLANGCI_LINT_INSTALL + "\n\n":
        raise BuildInputError("golangci-lint installation does not match the verified immutable input")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        verify_build_inputs(arguments.root)
    except (BuildInputError, OSError) as failure:
        print(f"build-input verification failed: {failure}", file=sys.stderr)
        return 1
    print("build inputs match verified immutable identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
