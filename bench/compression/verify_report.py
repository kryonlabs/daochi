#!/usr/bin/env python3
"""Smoke-test the saved report in a disposable Chromium on a private Xvfb."""
import os
from pathlib import Path
import re
import subprocess
import sys


root = Path(__file__).resolve().parents[2]
out = root / "build/scratch/compression-2026-10-26/report-verification"
out.mkdir(parents=True, exist_ok=True)
page = root / "docs/benchmarks/2026-10-26-compression.html"
environment = os.environ.copy()
for key in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "SESSION_MANAGER"):
    environment.pop(key, None)
environment["YUE_DESKTOP_RECOVERY"] = "0"
for label, size in (("desktop", "1440,1100"), ("mobile", "390,844")):
    command = ["xvfb-run", "-a", "chromium", "--headless=new", "--no-sandbox",
               "--disable-gpu", "--disable-background-networking", "--disable-sync",
               "--disable-component-update", "--no-first-run", "--no-default-browser-check",
               "--disable-crash-reporter", f"--user-data-dir={out/(label+'-profile')}",
               f"--window-size={size}", "--virtual-time-budget=2000",
               f"--screenshot={out/(label+'.png')}", "--dump-dom", page.as_uri()]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=40)
    (out/(label+".dom.html")).write_text(result.stdout)
    (out/(label+".stderr.log")).write_text(result.stderr)
    if result.returncode:
        print(result.stderr[-1600:], file=sys.stderr)
        raise SystemExit(f"Chromium failed: {label}, code={result.returncode}")
    assert '<strong id="case-count">735</strong>' in result.stdout, label+" metric script failed"
    for section, expected in (("codec-rows",30),("network-rows",30),("http-rows",8),("memory-rows",8)):
        match = re.search(r'<tbody id="'+section+r'">(.*?)</tbody>',result.stdout,re.S)
        assert match and match.group(1).count('<tr>') == expected, label+" "+section
    assert (out/(label+".png")).is_file(), label+" screenshot missing"
    print(f"{label}: metrics and all initial tables rendered; private screenshot saved")
