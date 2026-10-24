#!/usr/bin/env python3
"""Mirror an already published node package store into a private R2 bucket."""

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_MIRROR_BYTES = 8 * 1024 * 1024 * 1024
APP_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}\Z")
# ZX portable executables, and legacy .zib bundles for hosts from before ZX.
ARTIFACT_NAME = re.compile(r"([a-f0-9]{64})\.(?:zx|zib)\Z")
INVENTORY = ".mirror.json"


@dataclass(frozen=True)
class Artifact:
    key: str
    path: Path
    size: int


def collect_artifacts(store):
    artifacts = []
    for directory in sorted(store.iterdir()):
        if directory.is_symlink():
            raise ValueError("package directories must not be symlinks")
        if not directory.is_dir() or not APP_ID.fullmatch(directory.name):
            continue
        for path in sorted([*directory.glob("*.zx"), *directory.glob("*.zib")]):
            match = ARTIFACT_NAME.fullmatch(path.name)
            if not match or path.is_symlink() or not path.is_file():
                raise ValueError(f"invalid immutable artifact: {path}")
            size = path.stat().st_size
            if not 0 < size <= MAX_ARTIFACT_BYTES:
                raise ValueError(f"artifact exceeds the cache limit: {path}")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != match[1]:
                raise ValueError(f"artifact hash does not match its filename: {path}")
            artifacts.append(Artifact(f"{directory.name}/{path.name}", path, size))
    if not artifacts:
        raise ValueError("the published package store contains no immutable artifacts")
    return artifacts


def reserve_inventory(previous, artifacts):
    if not isinstance(previous, dict) or previous.get("schema") != 1 or not isinstance(previous.get("objects"), dict):
        raise ValueError("invalid remote mirror inventory")
    objects = previous["objects"].copy()
    for key, size in objects.items():
        parts = key.split("/")
        if len(parts) != 2 or not APP_ID.fullmatch(parts[0]) or not ARTIFACT_NAME.fullmatch(parts[1]):
            raise ValueError("invalid artifact in remote mirror inventory")
        if type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES:
            raise ValueError("invalid artifact size in remote mirror inventory")
    for artifact in artifacts:
        if artifact.key in objects and objects[artifact.key] != artifact.size:
            raise ValueError("an immutable artifact changed size")
        objects[artifact.key] = artifact.size
    if sum(objects.values()) > MAX_MIRROR_BYTES:
        raise ValueError("the mirror would exceed its 8 GiB storage budget")
    return {"schema": 1, "objects": objects}


def wrangler(command, arguments):
    environment = os.environ | {"WRANGLER_SEND_METRICS": "false"}
    return subprocess.run([*command, "r2", "object", *arguments], env=environment,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def upload(command, bucket, key, path, content_type):
    result = wrangler(command, ["put", f"{bucket}/{key}", "--file", str(path),
                               "--content-type", content_type, "--cache-control", "private, no-store",
                               "--remote"])
    if result.returncode:
        raise RuntimeError(f"R2 upload failed for {key}:\n{result.stdout}")


def mirror(artifacts, bucket, command, directory):
    inventory_path = directory / INVENTORY
    result = wrangler(command, ["get", f"{bucket}/{INVENTORY}", "--file", str(inventory_path), "--remote"])
    if result.returncode:
        missing = any(message in result.stdout.lower() for message in (
            "object does not exist", "object not found", "no such object", "[code: 10007]", "404"))
        if not missing:
            raise RuntimeError(f"Could not read the R2 mirror inventory:\n{result.stdout}")
        previous = {"schema": 1, "objects": {}}
    else:
        if inventory_path.stat().st_size > 1024 * 1024:
            raise ValueError("remote mirror inventory is too large")
        previous = json.loads(inventory_path.read_text())
    inventory = reserve_inventory(previous, artifacts)
    inventory_path.write_text(json.dumps(inventory, sort_keys=True) + "\n")
    # Reserve space first. An interrupted upload therefore cannot leave
    # uncounted objects that a later attempt could push over the budget.
    upload(command, bucket, INVENTORY, inventory_path, "application/json")
    for artifact in artifacts:
        upload(command, bucket, artifact.key, artifact.path, "application/octet-stream")
    return sum(inventory["objects"].values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True, type=Path,
                        help="The node's already published APP_ID/SHA256.zx store; never an unreviewed build")
    parser.add_argument("--bucket", default="daochi-packages")
    parser.add_argument("--wrangler", default="npx --yes wrangler@4.141.0")
    parser.add_argument("--execute", action="store_true", help="Upload verified bytes into the private bucket")
    options = parser.parse_args()
    artifacts = collect_artifacts(options.store.resolve(strict=True))
    inventory = reserve_inventory({"schema": 1, "objects": {}}, artifacts)
    size = sum(inventory["objects"].values())
    if options.execute:
        if not APP_ID.fullmatch(options.bucket):
            parser.error("invalid bucket name")
        private = Path(__file__).resolve().parents[1] / "backup/cdn"
        private.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("WRANGLER_LOG_PATH", str(private / "wrangler.log"))
        with (private / f"{options.bucket}.lock").open("a") as lock, \
                tempfile.TemporaryDirectory(prefix="daochi-r2-mirror-") as temporary:
            fcntl.flock(lock, fcntl.LOCK_EX)
            size = mirror(artifacts, options.bucket, shlex.split(options.wrangler), Path(temporary))
    print(json.dumps({"uploaded": options.execute, "artifacts": len(artifacts), "reserved_bytes": size}))


if __name__ == "__main__":
    main()
