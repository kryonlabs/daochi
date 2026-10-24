"""Portable release v2 serialization and atomic publication."""
from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
# This module is also imported directly by consumer signature fixtures.
# Resolve its sibling without depending on the caller's Python search path.
import importlib.util
_retention_spec = importlib.util.spec_from_file_location(
    "package_retention", Path(__file__).with_name("package_retention.py"))
_retention_module = importlib.util.module_from_spec(_retention_spec)
_retention_spec.loader.exec_module(_retention_module)
retain = _retention_module.retain

IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_.-]*\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


def valid_id(value):
    return bool(IDENTIFIER.fullmatch(value)) and value not in (".", "..")


def signing_message(release):
    fields = ("app_id", "sequence", "version", "runtime", "host_api",
              "module_api", "data_schema", "key_id")
    lines = ["daochi-zib-release-v2", *(str(release[name]) for name in fields),
             str(len(release["artifacts"]))]
    for artifact in release["artifacts"]:
        lines.extend(str(artifact[name]) for name in ("variant", "sha256", "size"))
    lines.append(str(len(release["dependencies"])))
    for dependency in release["dependencies"]:
        lines.extend(str(dependency[name]) for name in
                     ("app_id", "version", "sha256", "size"))
    return ("\n".join(lines) + "\n").encode("ascii")


def atomic_write(path, data):
    fd, name = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
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


@contextmanager
def publication_lock(root):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / ".publish.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


# Portable executables are .zx files. Hosts released before the ZX format
# keep reading .zib bundles through 2027-10-23.
SUFFIXES = ((b"ZX\0\0", ".zx"), (b"ZIB\0", ".zib"))


def bundle_suffix(data):
    for signature, suffix in SUFFIXES:
        if len(data) >= 8 and data.startswith(signature):
            return suffix
    return None


def read_bundle(path):
    data = path.read_bytes()
    if bundle_suffix(data) is None:
        raise ValueError(f"{path.name} is not a ZX portable executable")
    return data


def stored_bundle(root, digest):
    for _, suffix in SUFFIXES:
        path = root / (digest + suffix)
        if path.is_file():
            return path
    return root / (digest + ".zx")


def artifact(path, variant):
    data = read_bundle(path)
    return dict(variant=variant, sha256=sha256(data).hexdigest(), size=len(data)), data


def stage(args, key):
    if not VERSION.fullmatch(args.version):
        raise ValueError("version must be numeric major.minor.patch")
    if args.host_api <= 0 or args.module_api <= 0 or args.data_schema < 0:
        raise ValueError("invalid host API, module API or data schema")
    module, module_bytes = artifact(args.bundle, "module")
    artifacts = [module]
    payloads = [module_bytes]
    if args.standalone:
        standalone, standalone_bytes = artifact(args.standalone, "standalone")
        if bundle_suffix(standalone_bytes) != bundle_suffix(module_bytes):
            raise ValueError("both variants must use the same portable format")
        artifacts.append(standalone)
        payloads.append(standalone_bytes)
    dependencies = []
    for path in args.dependency:
        value = json.loads(path.read_bytes())
        if not valid_id(value["app_id"]) or value["app_id"] == args.app:
            raise ValueError("invalid or self-referencing dependency")
        if not VERSION.fullmatch(value["version"]):
            raise ValueError("invalid dependency version")
        module_artifact = next(a for a in value["artifacts"] if a["variant"] == "module")
        digest = module_artifact["sha256"]
        if not HASH.fullmatch(digest):
            raise ValueError("invalid dependency hash")
        installed = stored_bundle(args.store / value["app_id"], digest)
        data = read_bundle(installed)
        if len(data) != module_artifact["size"] or sha256(data).hexdigest() != digest:
            raise ValueError("dependency must be completely staged first")
        if bundle_suffix(data) != bundle_suffix(module_bytes):
            raise ValueError("a dependency must use the same portable format as the app")
        dependencies.append(dict(app_id=value["app_id"], version=value["version"],
                                 sha256=digest, size=len(data)))
    dependencies.sort(key=lambda dependency: dependency["app_id"])
    if len(dependencies) > 64 or len({d["app_id"] for d in dependencies}) != len(dependencies):
        raise ValueError("too many or duplicate dependencies")
    release = dict(app_id=args.app, sequence=args.sequence, version=args.version,
                   runtime="kryon-app-v1", host_api=args.host_api,
                   module_api=args.module_api, data_schema=args.data_schema,
                   key_id=args.key_id, artifacts=artifacts, dependencies=dependencies)
    release["signature"] = key.sign(signing_message(release)).hex()
    encoded = (json.dumps(release, separators=(",", ":")) + "\n").encode()
    if len(encoded) > 65536:
        raise ValueError("release descriptor is too large")
    root = args.store / args.app
    with publication_lock(args.store), publication_lock(root):
        # A concurrent publication may have pruned a dependency after it was
        # inspected above. Recheck under the same lock used by retention.
        for dependency in dependencies:
            path = stored_bundle(args.store / dependency['app_id'], dependency['sha256'])
            data = read_bundle(path)
            if len(data) != dependency['size'] or sha256(data).hexdigest() != dependency['sha256']:
                raise ValueError('dependency changed before publication')
        latest = root / "latest-v2.json"
        if latest.exists():
            previous = json.loads(latest.read_bytes())
            if previous != release and args.sequence <= previous["sequence"]:
                raise ValueError("sequence must advance the existing component release")
        for descriptor, data in zip(artifacts, payloads):
            path = root / (descriptor['sha256'] + bundle_suffix(data))
            if path.exists():
                if path.read_bytes() != data:
                    raise ValueError("existing immutable package differs from its hash")
            else:
                atomic_write(path, data)
            archived = path.with_name(path.name + ".release-v2.json")
            if not archived.exists():
                atomic_write(archived, encoded)
        sequence = root / f"release-{args.sequence}.json"
        if sequence.exists() and sequence.read_bytes() != encoded:
            raise ValueError("release sequence is already occupied")
        atomic_write(sequence, encoded)
        atomic_write(latest, encoded)
        retain(args.store, atomic_write)
    return release
