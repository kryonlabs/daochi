#!/usr/bin/env python3
"""Sign a portable release into a node's package directory without touching its DB."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import app_release


def atomic_write(path, data):
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True, type=Path, help='DAOCHI_DB followed by .packages')
    parser.add_argument('--app', required=True)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--key', required=True, type=Path, help='private Ed25519 PEM file; never printed')
    parser.add_argument('--sequence', required=True, type=int)
    parser.add_argument('--version', required=True)
    parser.add_argument('--format-version', type=int, choices=(1, 2), default=1)
    parser.add_argument('--standalone', type=Path)
    parser.add_argument('--dependency', action='append', type=Path, default=[])
    parser.add_argument('--host-api', type=int, default=1)
    parser.add_argument('--module-api', type=int, default=1)
    parser.add_argument('--data-schema', type=int, default=0)
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    for value in (args.app, args.key_id):
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', value) or value in ('.', '..'):
            parser.error('app and key IDs must be valid registry identifiers')
    if args.sequence <= 0 or args.sequence > 2**63 - 1 or not args.version or any(
            c in args.version for c in '\r\n'):
        parser.error('release needs a positive sequence and version')
    data = args.bundle.read_bytes()
    if len(data) < 8 or not data.startswith(b'ZIB\0'):
        parser.error('input is not a ZIB bundle')
    key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        parser.error('publisher key must be Ed25519')
    if args.format_version == 2:
        try:
            release = app_release.stage(args, key)
        except (ValueError, KeyError, StopIteration, OSError) as error:
            parser.error(str(error))
        print(f"Staged {release['app_id']} {release['version']} (module and standalone release v2)")
        return
    if args.standalone or args.dependency:
        parser.error('standalone variants and dependencies require --format-version 2')
    release = dict(app_id=args.app, sequence=args.sequence, version=args.version,
                   runtime='kryon-desktop-v1', sha256=sha256(data).hexdigest(),
                   size=len(data), key_id=args.key_id)
    fields = ('app_id', 'sequence', 'version', 'runtime', 'sha256', 'size', 'key_id')
    message = 'daochi-zib-release-v1\n' + ''.join(f'{release[name]}\n' for name in fields)
    release['signature'] = key.sign(message.encode()).hex()
    encoded = (json.dumps(release, separators=(',', ':')) + '\n').encode()
    root = args.store / args.app
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    latest = root / 'latest.json'
    if latest.exists():
        previous = json.loads(latest.read_bytes())
        if previous == release:
            print('Release already staged')
            return
        if args.sequence <= previous['sequence']:
            parser.error('sequence must advance the existing release')
    bundle = root / (release['sha256'] + '.zib')
    if bundle.exists() and bundle.read_bytes() != data:
        parser.error('existing immutable package does not match its filename')
    atomic_write(bundle, data)
    atomic_write(root / (bundle.name + '.json'), encoded)
    atomic_write(latest, encoded)
    print(f'Staged {args.app} {args.version}; the node verifies its registered publisher key')


if __name__ == '__main__':
    main()
