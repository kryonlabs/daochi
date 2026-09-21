#!/usr/bin/env python3
"""Preserve deployed settings when migrating Ksync environment names to Daochi."""

import argparse
import os
from pathlib import Path
import shutil
import tempfile
import time


RENAMED_SETTINGS = {
    "DAOCHI_WAOZI_ISSUER_PRIVATE_KEY_HEX_FILE": "DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE",
    "DAOCHI_WAOZI_ISSUER_PUBLIC_KEY_HEX_FILE": "DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE",
    "DAOCHI_MONERO_WALLET_RPC_URL": "MONERO_WALLET_RPC_URL",
}


def migrate(text, canonical_only=False):
    lines = text.splitlines(keepends=True)
    settings = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.startswith(("KSYNC_", "DAOCHI_")):
            settings[key] = value.rstrip("\r\n")
    canonical = dict(settings)
    for key, value in settings.items():
        if not key.startswith("KSYNC_"):
            continue
        replacement = "DAOCHI_" + key[len("KSYNC_"):]
        if replacement in canonical:
            if canonical[replacement] != value:
                raise ValueError("conflicting settings: " + key + " and " + replacement)
            continue
        canonical[replacement] = value
    for key, replacement in RENAMED_SETTINGS.items():
        if key not in canonical:
            continue
        if replacement in canonical and canonical[replacement] != canonical[key]:
            raise ValueError("conflicting settings: " + key + " and " + replacement)
        canonical[replacement] = canonical[key]
    if canonical_only:
        output = []
        emitted = set()
        for line in lines:
            key, separator, _ = line.partition("=")
            if not separator or key not in settings:
                output.append(line)
                continue
            replacement = key
            if key.startswith("KSYNC_"):
                replacement = "DAOCHI_" + key[len("KSYNC_"):]
            replacement = RENAMED_SETTINGS.get(replacement, replacement)
            if replacement in emitted:
                continue
            output.append(replacement + "=" + canonical[replacement] + "\n")
            emitted.add(replacement)
        for key, value in canonical.items():
            replacement = RENAMED_SETTINGS.get(key, key)
            if replacement.startswith("KSYNC_") or replacement in emitted:
                continue
            output.append(replacement + "=" + value + "\n")
            emitted.add(replacement)
        return "".join(output)
    additions = []
    for key, value in canonical.items():
        if key not in settings:
            additions.append(key + "=" + value + "\n")
    if not additions:
        return text
    return text.rstrip("\n") + "\n" + "".join(additions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--canonical-only", action="store_true")
    args = parser.parse_args()
    original = args.path.read_text()
    updated = migrate(original, canonical_only=args.canonical_only)
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
