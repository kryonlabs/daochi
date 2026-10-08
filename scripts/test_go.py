#!/usr/bin/env python3
"""Test every maintained Go package without treating ignored backups as code."""

import os
from pathlib import Path
import subprocess


root = Path(__file__).resolve().parent.parent
files = subprocess.check_output(
    ["git", "ls-files", "-z", "--", "*.go"], cwd=root
).decode().split("\0")
packages = {"."}
for name in files:
    if name:
        parent = Path(name).parent.as_posix()
        if parent != ".":
            packages.add("./" + parent)
subprocess.run(
    [os.environ.get("GO", "go"), "test", *sorted(packages)],
    cwd=root,
    check=True,
)
