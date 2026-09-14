#!/usr/bin/env python3
"""Preserve deployed settings when migrating Ksync environment names to Daochi."""

import argparse
import os
from pathlib import Path
import shutil
import tempfile
import time


def migrate(text):
    lines = text.splitlines(keepends=True)
    settings = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.startswith(("KSYNC_", "DAOCHI_")):
            settings[key] = value.rstrip("\r\n")
    additions = []
    for key, value in settings.items():
        if not key.startswith("KSYNC_"):
            continue
        canonical = "DAOCHI_" + key[len("KSYNC_"):]
        if canonical in settings:
            if settings[canonical] != value:
                raise ValueError("conflicting settings: " + key + " and " + canonical)
            continue
        additions.append(canonical + "=" + value + "\n")
    if not additions:
        return text
    return text.rstrip("\n") + "\n" + "".join(additions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    original = args.path.read_text()
    updated = migrate(original)
    if updated == original:
        print("Environment already migrated")
        return
    if not args.apply:
        print("Legacy environment settings need migration; use --apply")
        return
    backup = args.path.with_name(args.path.name + ".before-daochi-" + str(time.time_ns()))
    shutil.copy2(args.path, backup)
    os.chmod(backup, 0o600)
    descriptor, temporary = tempfile.mkstemp(dir=args.path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(updated)
        stat = args.path.stat()
        os.chown(temporary, stat.st_uid, stat.st_gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, args.path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Environment migrated; original settings retained in a private backup")


if __name__ == "__main__":
    main()
