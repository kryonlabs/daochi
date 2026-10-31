#!/usr/bin/env python3
"""Read-only proof binding this node's identity to its SSH host key."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


DOMAIN = b"daochi-ssh-origin-attestation-v1\n"


def message(nonce, host_key):
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("invalid attestation nonce")
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", host_key):
        raise ValueError("invalid SSH public key")
    return DOMAIN + nonce.encode() + b"\n" + host_key.encode() + b"\n"


def openssl_with_key(arguments, key, payload=None):
    descriptors = []
    try:
        for name, data in (("node-signing-key", key), ("attestation", payload)):
            if data is None:
                continue
            descriptor = os.memfd_create(name)
            descriptors.append(descriptor)
            os.write(descriptor, data)
            os.lseek(descriptor, 0, os.SEEK_SET)
        key_option = "-in" if arguments[0] == "pkey" else "-inkey"
        format_option = "-inform" if arguments[0] == "pkey" else "-keyform"
        command = ["openssl", *arguments, key_option, f"/proc/self/fd/{descriptors[0]}", format_option, "DER"]
        if payload is not None:
            command.extend(["-in", f"/proc/self/fd/{descriptors[1]}"])
        return subprocess.run(command, pass_fds=descriptors, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10).stdout
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def attest(nonce):
    pid = subprocess.check_output(["systemctl", "show", "daochi.service", "-p", "MainPID", "--value"], timeout=10).strip().decode()
    if not pid.isdecimal() or int(pid) <= 1:
        raise ValueError("Daochi service is not running")
    process = Path("/proc") / pid
    with (process / "environ").open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("service environment exceeds limit")
    wanted = {"DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", "DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE",
              "DAOCHI_NODE_IDENTITY_KEY_FILE", "DAOCHI_DB"}
    environment = {}
    for entry in raw.split(b"\0"):
        name, separator, value = entry.partition(b"=")
        if separator and name.decode(errors="replace") in wanted:
            environment[name.decode()] = value.decode()
    del raw
    working = (process / "cwd").resolve(strict=True)
    encoded = environment.get("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", "")
    if not encoded:
        path = environment.get("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE")
        if not path:
            path = environment.get("DAOCHI_NODE_IDENTITY_KEY_FILE") or environment.get("DAOCHI_DB", "daochi.db") + ".node-key"
        with (working / path).open() as stream:
            encoded = stream.read(257).strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128})", encoded):
        raise ValueError("invalid node identity key")
    private = bytes.fromhex(encoded)
    der = bytes.fromhex("302e020100300506032b657004220420") + private[:32]
    public = openssl_with_key(["pkey", "-pubout", "-outform", "DER"], der)[-32:]
    if len(private) == 64 and private[32:] != public:
        raise ValueError("node identity key mismatch")
    with Path("/etc/ssh/ssh_host_ed25519_key.pub").open() as stream:
        fields = stream.read(1025).split()
    host_key = " ".join(fields[:2])
    payload = message(nonce, host_key)
    signature = openssl_with_key(["pkeyutl", "-sign", "-rawin"], der, payload)
    return {"nonce": nonce, "host_key": host_key, "public_key": public.hex(), "signature": signature.hex()}


if __name__ == "__main__":
    try:
        print(json.dumps(attest(sys.argv[1])))
    except Exception:
        sys.exit("origin identity attestation failed")
