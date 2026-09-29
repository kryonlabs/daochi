#!/usr/bin/env python3
"""Run the real server suite against Go regenerated from saved Ziran IR."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    repo = Path(__file__).resolve().parent.parent
    compiler = Path(os.environ.get("ZI2GO", "../ziran/build/bin/zi2go"))
    zi2zir = os.environ.get("ZI2ZIR", str(compiler.with_name("zi2zir")))
    standard = os.environ.get("ZIRAN_STD", "../ziran/std")
    sources = sorted(path.name for path in repo.glob("*.zi"))
    env = os.environ.copy()
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    build = repo / "build"
    build.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="saved-ir-", dir=build) as output:
        work = Path(output)
        ir = work / "ir"
        generated = work / "go"
        subprocess.run([zi2zir, "--root", ".", "--module-path", standard,
                        "-o", str(ir), *sources], cwd=repo, env=env, check=True)
        entries = [str(ir / Path(source).with_suffix(".zir")) for source in sources]
        subprocess.run([str(compiler), "--no-main", "--pkg", "main", "--root", str(ir),
                        "-o", str(generated), *entries], cwd=repo, env=env, check=True)
        replacement = {str(repo / path.name): str(path)
                       for path in generated.glob("*.go")}
        overlay = work / "overlay.json"
        overlay.write_text(json.dumps({"Replace": replacement}))
        subprocess.run([os.environ.get("GO", "go"), "test", "-count=1", "-overlay", str(overlay), "."],
                       cwd=repo, env=env, check=True)
    print("Server tests against saved Ziran IR: passed")


if __name__ == "__main__":
    main()
