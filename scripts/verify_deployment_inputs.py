#!/usr/bin/env python3
"""Verify native build and SSH inputs before a Daochi deployment."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from shutil import which


class VerificationError(Exception):
    pass


def run_command(arguments, error):
    try:
        result = subprocess.run(
            arguments,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as failure:
        raise VerificationError(f"{error}: {failure}") from failure
    return result.stdout.strip()


def atomic_write(path, data, mode):
    descriptor, temporary_name = tempfile.mkstemp(prefix=".daochi-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def source_identity(source_directory):
    directory = source_directory.resolve()
    if not directory.is_dir():
        raise VerificationError(f"source directory does not exist: {source_directory}")

    entries = []
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            entries.append((relative, "symlink", 0, os.readlink(path)))
        elif path.is_file():
            mode = path.stat().st_mode & 0o111
            entries.append((relative, "file", mode, sha256(path.read_bytes()).hexdigest()))
        elif not path.is_dir():
            raise VerificationError(f"unsupported source entry: {relative}")

    digest = sha256()
    for relative, entry_type, executable, value in entries:
        encoded_type = "1" if executable else "0"
        digest.update(f"{entry_type}{encoded_type}{relative}\0{value}\0".encode())
    return {
        "algorithm": "sha256-path-type-mode-content-v1",
        "digest": digest.hexdigest(),
        "entries": len(entries),
    }


def pinned_source(repository, submodule_path):
    repository_path = repository.resolve()
    submodule = (repository_path / submodule_path).resolve()
    if not repository_path.is_dir() or not submodule.is_dir():
        raise VerificationError("repository and submodule directories must exist")

    expected_commit = run_command(
        ["git", "-C", str(repository_path), "rev-parse", f"HEAD:{submodule_path}"],
        "cannot read the pinned submodule gitlink",
    )
    actual_commit = run_command(
        ["git", "-C", str(submodule), "rev-parse", "HEAD"],
        "cannot read the checked-out submodule commit",
    )
    dirty = run_command(
        ["git", "-C", str(submodule), "status", "--porcelain", "--untracked-files=all"],
        "cannot inspect the submodule worktree",
    )
    if expected_commit != actual_commit:
        raise VerificationError(
            f"liboqs gitlink is {expected_commit} but checkout is {actual_commit}"
        )
    if dirty:
        raise VerificationError("liboqs submodule worktree is not clean")

    identity = source_identity(submodule)
    identity["commit"] = actual_commit
    return identity


def verify_source(source_directory, expected_commit, expected_digest, expected_entries):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise VerificationError("invalid expected liboqs commit")
    identity = source_identity(source_directory)
    identity["commit"] = expected_commit
    observed = (
        identity["digest"],
        identity["entries"],
    )
    expected = (expected_digest, expected_entries)
    if observed != expected:
        raise VerificationError(
            f"liboqs source identity mismatch: expected {expected}, observed {observed}"
        )
    return identity


def tool_identity(executable_name):
    executable = Path(which(executable_name) or executable_name).resolve()
    if not executable.is_file():
        raise VerificationError(f"build tool must be a regular file: {executable_name}")

    version = run_command([str(executable), "--version"], f"cannot identify {executable_name}")
    return {
        "path": str(executable.resolve()),
        "sha256": sha256(executable.read_bytes()).hexdigest(),
        "version": version.splitlines()[0],
    }


def compiler_identity(name):
    executable = os.environ.get(name, "cc" if name == "CC" else "c++")
    identity = tool_identity(executable)
    identity["environment_name"] = name
    return identity


def native_build_identity(source_directory, cmake, cmake_options):
    identity = {
        "schema": 1,
        "platform": run_command(["uname", "-sm"], "cannot identify the build platform"),
        "source": source_identity(source_directory),
        "cmake": tool_identity(cmake),
        "cmake_options": cmake_options.split(),
        "compilers": [compiler_identity("CC"), compiler_identity("CXX")],
        "environment_flags": {
            name: os.environ.get(name, "")
            for name in ("CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS")
        },
    }
    return {
        "schema": 1,
        "identity": identity,
        "identity_sha256": sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def validate_native_paths(source_directory, build_directory):
    repository = Path(__file__).resolve().parents[1]
    source = source_directory.resolve()
    build = build_directory.resolve()
    expected_source = (repository / "vendor" / "liboqs").resolve()
    expected_build_root = (repository / "build").resolve()
    if source != expected_source:
        raise VerificationError("native source must be vendor/liboqs in this repository")
    if build == Path("/") or build == repository or build == source:
        raise VerificationError("unsafe native build directory")
    if expected_build_root not in build.parents:
        raise VerificationError("native build directory must be inside build/")
    if source in build.parents or build in source.parents:
        raise VerificationError("native source and build directories must not overlap")


def native_metadata_path(build_directory):
    return build_directory / ".daochi-native-build.json"


def check_native_build(source_directory, build_directory, artifact, cmake, cmake_options):
    validate_native_paths(source_directory, build_directory)
    expected = native_build_identity(source_directory, cmake, cmake_options)
    metadata_path = native_metadata_path(build_directory)
    if not metadata_path.is_file() or not artifact.is_file():
        return False
    try:
        recorded = json.loads(metadata_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return recorded == expected and artifact.stat().st_size > 0


def record_native_build(source_directory, build_directory, artifact, cmake, cmake_options):
    validate_native_paths(source_directory, build_directory)
    if not artifact.is_file() or artifact.stat().st_size == 0:
        raise VerificationError(f"native artifact is empty or missing: {artifact}")
    artifact_bytes = artifact.read_bytes()
    identity = native_build_identity(source_directory, cmake, cmake_options)
    metadata = {
        **identity,
        "artifact": {
            "sha256": sha256(artifact_bytes).hexdigest(),
            "size": len(artifact_bytes),
        },
    }
    encoded = (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()
    atomic_write(native_metadata_path(build_directory), encoded, 0o600)
    return identity


def record_artifact_manifest(
    output, manifest, source_commit, liboqs_commit, native_metadata
):
    if not output.is_file():
        raise VerificationError(f"artifact does not exist: {output}")
    for label, commit in (
        ("source", source_commit),
        ("liboqs", liboqs_commit),
    ):
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise VerificationError(f"invalid {label} commit")
    try:
        native = json.loads(native_metadata.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid native build metadata: {error}") from error

    go_version = run_command(["go", "version"], "cannot identify the Go compiler")
    go_version_m = run_command(
        ["go", "version", "-m", str(output)], "cannot inspect the Go build"
    )
    artifact_bytes = output.read_bytes()
    repository = Path(__file__).resolve().parents[1]
    source_inputs = {}
    for input_name in ("go.mod", "go.sum", "ziran.lock"):
        input_path = repository / input_name
        if input_path.is_file():
            source_inputs[input_name] = sha256(input_path.read_bytes()).hexdigest()
    provenance = {
        "schema": 1,
        "source_commit": source_commit,
        "liboqs_commit": liboqs_commit,
        "liboqs_source": native["identity"]["source"],
        "source_inputs": source_inputs,
        "native_build": native,
        "go": {
            "version": go_version,
            "version_m": go_version_m,
            "cgo_cflags": os.environ.get("CGO_CFLAGS", ""),
            "cgo_ldflags": os.environ.get("CGO_LDFLAGS", ""),
            "goflags": os.environ.get("GOFLAGS", ""),
        },
        "artifact": {
            "path": output.name,
            "sha256": sha256(artifact_bytes).hexdigest(),
            "size": len(artifact_bytes),
        },
    }
    encoded = (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode()
    manifest.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(manifest, encoded, 0o644)
    return provenance


def verify_artifact_manifest(output, manifest, expected_source_commit, expected_liboqs_commit):
    try:
        recorded = json.loads(manifest.read_text())
        native = recorded["native_build"]
        artifact = recorded["artifact"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise VerificationError(f"invalid artifact manifest: {error}") from error
    if recorded.get("source_commit") != expected_source_commit:
        raise VerificationError("artifact manifest source commit mismatch")
    if recorded.get("liboqs_commit") != expected_liboqs_commit:
        raise VerificationError("artifact manifest liboqs commit mismatch")
    canonical_identity = json.dumps(
        native.get("identity"), sort_keys=True, separators=(",", ":")
    ).encode()
    if native.get("identity_sha256") != sha256(canonical_identity).hexdigest():
        raise VerificationError("native identity digest mismatch")
    artifact_bytes = output.read_bytes()
    if artifact.get("sha256") != sha256(artifact_bytes).hexdigest():
        raise VerificationError("artifact digest mismatch")
    if artifact.get("size") != len(artifact_bytes):
        raise VerificationError("artifact size mismatch")


def validate_host_name(host):
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
        raise VerificationError("SSH host contains invalid characters")


def validate_user_name(user):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", user):
        raise VerificationError("SSH user contains invalid characters")


def known_host_entries(host, lines):
    if not lines:
        raise VerificationError("trusted SSH host key is empty")
    for line in lines:
        if line.lstrip().startswith("@"):
            raise VerificationError("trusted SSH host key entries must be literal host keys")
    with tempfile.TemporaryDirectory(prefix="daochi-known-hosts-") as temporary:
        known_hosts = Path(temporary) / "trusted"
        known_hosts.write_text("\n".join(lines) + "\n")
        output = run_command(
            ["ssh-keygen", "-F", host, "-f", str(known_hosts)],
            "trusted SSH host key does not match the deployment host",
        )
    matches = []
    for line in output.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            raise VerificationError("invalid trusted SSH host key line")
        matches.append((fields[1], fields[2]))
    if not matches:
        raise VerificationError("trusted SSH host key does not match the deployment host")
    return matches


def verify_presented_key(host, trusted_lines, presented_lines):
    trusted = set(known_host_entries(host, trusted_lines))
    presented = set(known_host_entries(host, presented_lines))
    if trusted.isdisjoint(presented):
        raise VerificationError("presented SSH host key does not match the trusted key")


def configure_ssh(host, user, trusted_lines, ssh_directory):
    validate_host_name(host)
    validate_user_name(user)
    known_host_entries(host, trusted_lines)

    ssh_directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    ssh_directory.chmod(0o700)
    known_hosts = ssh_directory / "known_hosts"
    atomic_write(known_hosts, ("\n".join(trusted_lines) + "\n").encode(), 0o600)
    configuration = "\n".join(
        (
            "Host daochi-origin",
            f"  HostName {host}",
            f"  User {user}",
            "  IdentityFile ~/.ssh/id_ed25519",
            "  IdentitiesOnly yes",
            "  StrictHostKeyChecking yes",
            "  UserKnownHostsFile ~/.ssh/known_hosts",
            "  GlobalKnownHostsFile /dev/null",
            "  BatchMode yes",
            "",
        )
    )
    atomic_write(ssh_directory / "config", configuration.encode(), 0o600)


def emit_github_output(name, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def add_common_arguments(parser):
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--cmake-options", required=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    pinned = commands.add_parser("pinned-source")
    pinned.add_argument("--repository", default=Path.cwd(), type=Path)
    pinned.add_argument("--submodule", default="vendor/liboqs")

    verify = commands.add_parser("verify-source")
    verify.add_argument("--source-dir", required=True, type=Path)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--expected-digest", required=True)
    verify.add_argument("--expected-entries", required=True, type=int)

    native_check = commands.add_parser("check-native-build")
    add_common_arguments(native_check)

    native_record = commands.add_parser("record-native-build")
    add_common_arguments(native_record)

    artifact = commands.add_parser("record-artifact-manifest")
    artifact.add_argument("--output", required=True, type=Path)
    artifact.add_argument("--manifest", required=True, type=Path)
    artifact.add_argument("--source-commit", required=True)
    artifact.add_argument("--liboqs-commit", required=True)
    artifact.add_argument("--native-metadata", required=True, type=Path)

    verify_artifact = commands.add_parser("verify-artifact-manifest")
    verify_artifact.add_argument("--output", required=True, type=Path)
    verify_artifact.add_argument("--manifest", required=True, type=Path)
    verify_artifact.add_argument("--expected-source-commit", required=True)
    verify_artifact.add_argument("--expected-liboqs-commit", required=True)

    presented = commands.add_parser("verify-presented-key")
    presented.add_argument("--host", required=True)
    presented.add_argument("--trusted-key", required=True)
    presented.add_argument("--presented-key", required=True)

    configure = commands.add_parser("configure-ssh")
    configure.add_argument("--host", required=True)
    configure.add_argument("--user", required=True)
    configure.add_argument("--trusted-key", required=True)
    configure.add_argument("--ssh-dir", default=Path("~/.ssh").expanduser(), type=Path)

    arguments = parser.parse_args()
    try:
        if arguments.command == "pinned-source":
            identity = pinned_source(arguments.repository, arguments.submodule)
            emit_github_output("liboqs_commit", identity["commit"])
            emit_github_output("liboqs_digest", identity["digest"])
            emit_github_output("liboqs_entries", str(identity["entries"]))
            print(json.dumps(identity, sort_keys=True))
        elif arguments.command == "verify-source":
            verify_source(
                arguments.source_dir,
                arguments.expected_commit,
                arguments.expected_digest,
                arguments.expected_entries,
            )
            print("liboqs source identity verified")
        elif arguments.command == "check-native-build":
            if check_native_build(
                arguments.source_dir,
                arguments.build_dir,
                arguments.artifact,
                arguments.cmake,
                arguments.cmake_options,
            ):
                print("native build inputs verified")
            else:
                print("native build inputs changed; rebuild required", flush=True)
                raise SystemExit(2)
        elif arguments.command == "record-native-build":
            record_native_build(
                arguments.source_dir,
                arguments.build_dir,
                arguments.artifact,
                arguments.cmake,
                arguments.cmake_options,
            )
            print("native build identity recorded")
        elif arguments.command == "record-artifact-manifest":
            provenance = record_artifact_manifest(
                arguments.output,
                arguments.manifest,
                arguments.source_commit,
                arguments.liboqs_commit,
                arguments.native_metadata,
            )
            print(json.dumps(provenance["artifact"], sort_keys=True))
        elif arguments.command == "verify-artifact-manifest":
            verify_artifact_manifest(
                arguments.output,
                arguments.manifest,
                arguments.expected_source_commit,
                arguments.expected_liboqs_commit,
            )
            print("artifact manifest verified")
        elif arguments.command == "verify-presented-key":
            verify_presented_key(
                arguments.host,
                [line for line in arguments.trusted_key.splitlines() if line],
                [line for line in arguments.presented_key.splitlines() if line],
            )
            print("presented SSH host key verified")
        elif arguments.command == "configure-ssh":
            configure_ssh(
                arguments.host,
                arguments.user,
                [line for line in arguments.trusted_key.splitlines() if line],
                arguments.ssh_dir,
            )
            print("strict SSH configuration written")
    except VerificationError as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
