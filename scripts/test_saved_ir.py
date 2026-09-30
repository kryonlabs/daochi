#!/usr/bin/env python3
"""Run the real server suite against Go regenerated from saved Ziran IR."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from generate_go import project_flags


def main():
    repo = Path(__file__).resolve().parent.parent
    ziran = os.environ.get("ZIRAN", "ziran")
    sources = sorted(path.name for path in repo.glob("*.zi"))
    env = os.environ.copy()
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    build = repo / "build"
    build.mkdir(exist_ok=True)
    env.setdefault("XDG_CACHE_HOME", str(build / "package-cache"))
    with tempfile.TemporaryDirectory(prefix="saved-ir-", dir=build) as output:
        work = Path(output)
        ir = work / "ir"
        generated = work / "go"
        subprocess.run([ziran, "ir", *project_flags(repo),
                        "-o", str(ir), *sources], cwd=repo, env=env, check=True)
        entries = [str(ir / Path(source).with_suffix(".zir")) for source in sources]
        subprocess.run([ziran, "build", *project_flags(repo), "--target=go",
                        "--no-main", "--pkg", "main", "--root", str(ir),
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
