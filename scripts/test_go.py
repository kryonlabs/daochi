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
            # Experimental tools can own a separate Go module. They are not
            # packages of the application module and cannot be passed to its
            # go test invocation (the compression benchmark is one example).
            directory = root / parent
            nested_module = False
            while directory != root:
                if (directory / "go.mod").is_file():
                    nested_module = True
                    break
                directory = directory.parent
            if nested_module:
                continue
            packages.add("./" + parent)
subprocess.run(
    [os.environ.get("GO", "go"), "test", *sorted(packages)],
    cwd=root,
    check=True,
)
