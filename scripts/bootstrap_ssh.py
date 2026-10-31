#!/usr/bin/env python3
"""Verify an SSH candidate against the HTTPS node identity, then encrypt its pin."""

import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import subprocess
import tempfile

from origin_attestation import message, openssl_with_key
from verify_deployment_inputs import known_host_entries, validate_host_name, validate_user_name


def bounded_command(arguments, *, data=None):
    def output_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))

    with tempfile.TemporaryFile() as output:
        subprocess.run(arguments, input=data, stdout=output, stderr=subprocess.DEVNULL,
                       check=True, timeout=45, preexec_fn=output_limit)
        output.seek(0)
        value = output.read(65537)
    if len(value) > 65536:
        raise ValueError("command output exceeds limit")
    return value


def verify_proof(proof, nonce, host_key, node_public_key, directory):
    if proof.get("nonce") != nonce or proof.get("host_key") != host_key:
        raise ValueError("origin proof does not match this SSH connection")
    if proof.get("public_key") != node_public_key:
        raise ValueError("origin identity does not match the authenticated HTTPS API")
    public = bytes.fromhex(node_public_key)
    signature = bytes.fromhex(proof["signature"])
    if len(public) != 32 or len(signature) != 64:
        raise ValueError("invalid identity proof size")
    signature_path = directory / "signature"
    signature_path.write_bytes(signature)
    public_der = bytes.fromhex("302a300506032b6570032100") + public
    openssl_with_key(["pkeyutl", "-verify", "-rawin", "-pubin", "-sigfile", str(signature_path)],
                     public_der, message(nonce, host_key))


def main():
    host = os.environ["DAOCHI_HOST"]
    user = os.environ["DAOCHI_USER"]
    validate_host_name(host)
    validate_user_name(user)
    # HTTPS certificate verification remains enabled. This public identity is
    # the independent trust anchor; ssh-keyscan supplies only an untrusted candidate.
    node = json.loads(bounded_command(["curl", "--fail", "--silent", "--show-error", "--proto", "=https",
                                       "--max-time", "20", "https://api.waozi.xyz/api/v1/node"]))
    public_key = node["node_public_key"]
    if len(bytes.fromhex(public_key)) != 32 or hashlib.sha256(bytes.fromhex(public_key)).hexdigest() != node["node_id"]:
        raise ValueError("invalid public API node identity")
    output_directory = Path(os.environ["RUNNER_TEMP"]) / "daochi-origin-proof"
    output_directory.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="daochi-ssh-proof-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        directory = Path(temporary)
        candidates = bounded_command(["ssh-keyscan", "-T", "10", "-t", "ed25519", host]).decode().splitlines()
        entries = set(known_host_entries(host, candidates))
        if len(entries) != 1:
            raise ValueError("expected one SSH Ed25519 host key")
        key_type, key_body = entries.pop()
        host_key = key_type + " " + key_body
        candidate = directory / "candidate"
        candidate.write_text("\n".join(candidates) + "\n")
        key_file = directory / "identity"
        key_file.touch(mode=0o600)
        key_file.write_text(os.environ["DAOCHI_SSH_KEY"].strip() + "\n")
        nonce = secrets.token_hex(32)
        remote_source = Path(__file__).with_name("origin_attestation.py").read_bytes()
        # The candidate is pinned for this read-only proof request. It is never
        # accepted as a deployment trust anchor unless the independent signature verifies.
        proof = json.loads(bounded_command([
            "ssh", "-F", "/dev/null", "-i", str(key_file), "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(candidate), "-o", "GlobalKnownHostsFile=/dev/null",
            user + "@" + host, "python3", "-", nonce,
        ], data=remote_source))
        verify_proof(proof, nonce, host_key, public_key, directory)
        recipient = directory / "recipient.pem"
        recipient.write_text(os.environ["DAOCHI_SSH_BOOTSTRAP_RECIPIENT"])
        # Encrypt the address as well as the pin so the artifact reveals no secret destination.
        pin = (host + " " + host_key + "\n").encode()
        encrypted = bounded_command([
            "openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(recipient),
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
        ], data=pin)
        (output_directory / "trusted-host.enc").write_bytes(encrypted)
        # Only public attestation fields survive the remote boundary.
        verified = {key: proof[key] for key in ("nonce", "host_key", "public_key", "signature")}
        verified["node_id"] = node["node_id"]
        verified["source_commit"] = os.environ["GITHUB_SHA"]
        (output_directory / "proof.json").write_text(json.dumps(verified, indent=2) + "\n")
    print("SSH host key verified against the HTTPS node identity; encrypted pin produced")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("SSH identity bootstrap failed; no deployment trust was installed")
