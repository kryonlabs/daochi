"""Retain three release choices and every blob referenced by retained apps.

Called under the store publication lock. Unknown files and malformed metadata
are never deletion candidates. No live store is modified by importing this.
"""
import json
from pathlib import Path
import re

HASH = re.compile(r'[0-9a-f]{64}\Z')
IDENTIFIER = re.compile(r'[a-z0-9][a-z0-9_.-]*\Z')
RETAINED_RELEASES = 3


def read_release(path, app):
    try:
        if path.is_symlink():
            return None
        if path.stat().st_size > 65536:
            return None
        value = json.loads(path.read_bytes())
        if (value.get('app_id') != app or type(value.get('sequence')) is not int
                or value['sequence'] < 1 or not isinstance(value.get('artifacts'), list)):
            return None
        if not value['artifacts'] or any(not isinstance(a, dict) or
                not isinstance(a.get('sha256'), str) or not HASH.fullmatch(a['sha256'])
                for a in value['artifacts']):
            return None
        dependencies = value.get('dependencies', [])
        if not isinstance(dependencies, list) or any(not isinstance(d, dict) or
                not isinstance(d.get('app_id'), str) or not IDENTIFIER.fullmatch(d['app_id']) or
                not isinstance(d.get('sha256'), str) or not HASH.fullmatch(d['sha256'])
                for d in dependencies):
            return None
        return value
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def retain(store, write):
    store = Path(store)
    releases = {}
    protected = {}
    candidates = []
    can_prune = True
    for root in store.iterdir():
        if not root.is_dir() or root.is_symlink() or not IDENTIFIER.fullmatch(root.name):
            continue
        values = []
        for path in root.glob('release-*.json'):
            value = read_release(path, root.name)
            if value is not None and path.name == f"release-{value['sequence']}.json":
                values.append((path, value))
            else:
                # Unknown metadata may reference a blob in another app.
                # Preserve the store until its references can be understood.
                can_prune = False
        values.sort(key=lambda item: item[1]['sequence'], reverse=True)
        releases[root.name] = values[:RETAINED_RELEASES]
        history = [value for _, value in values[:RETAINED_RELEASES]]
        candidates.extend(values[RETAINED_RELEASES:])
        # Keep the latest pointer's bytes even if an old store has no archive.
        latest = read_release(root / 'latest-v2.json', root.name)
        if (root / 'latest-v2.json').exists() and latest is None:
            can_prune = False
        if latest is not None:
            releases[root.name].append((root / 'latest-v2.json', latest))
            if not history:
                history = [latest]
        if history:
            write(root / 'history-v2.json', (json.dumps({'versions': history}, separators=(',', ':')) + '\n').encode())
        # A legacy v1 pointer may still be served alongside the v2 store.
        try:
            legacy = json.loads((root / 'latest.json').read_bytes())
            digest = legacy.get('sha256', '')
            if legacy.get('app_id') == root.name and HASH.fullmatch(digest):
                protected.setdefault(root.name, set()).add(digest)
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    for app, values in releases.items():
        for _, value in values:
            protected.setdefault(app, set()).update(a['sha256'] for a in value['artifacts'])
            for dependency in value.get('dependencies', []):
                owner, digest = dependency.get('app_id', ''), dependency.get('sha256', '')
                if IDENTIFIER.fullmatch(owner) and HASH.fullmatch(digest):
                    protected.setdefault(owner, set()).add(digest)
    if not can_prune:
        return
    for path, value in candidates:
        # Retired archive choices disappear, but a blob still needed by any
        # retained parent collection/dependency remains fetchable by hash.
        path.unlink()
        root = path.parent
        for artifact in value['artifacts']:
            digest = artifact['sha256']
            if digest in protected.get(root.name, set()):
                continue
            for suffix in ('.zib', '.zib.release-v2.json'):
                candidate = root / (digest + suffix)
                if candidate.is_file() and not candidate.is_symlink():
                    candidate.unlink()
