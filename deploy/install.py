#!/usr/bin/env python3
"""Pass deployment metadata and credentials as data, never remote shell text."""

import json
import subprocess
import sys


def install(request):
    names = ("stamp", "source_commit", "native_commit", "mesh_token")
    if not isinstance(request, dict) or any(not isinstance(request.get(name), str) for name in names):
        raise ValueError("invalid deployment request")
    subprocess.run(
        ["sh", "/opt/daochi-src/deploy/install.sh", request["stamp"], request["source_commit"], request["native_commit"]],
        input=request["mesh_token"].encode(),
        check=True,
    )


if __name__ == "__main__":
    body = sys.stdin.read(16385)
    if len(body) > 16384:
        raise SystemExit("deployment request exceeds limit")
    install(json.loads(body))
