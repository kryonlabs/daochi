#!/usr/bin/env python3
"""Read or reply to app feedback from the owner's developer harness over SSH."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys


REMOTE = r'''
import json, sys, urllib.request, urllib.error
from pathlib import Path
operation = json.load(sys.stdin)
values = {}
for line in Path("/etc/daochi/daochi.env").read_text().splitlines():
    name, separator, value = line.partition("=")
    if separator:
        values[name.strip()] = value.strip().strip("\"'")
token = values.get("DAOCHI_FEEDBACK_TOKEN", "")
if not token and values.get("DAOCHI_FEEDBACK_TOKEN_FILE"):
    token = Path(values["DAOCHI_FEEDBACK_TOKEN_FILE"]).read_text().strip()
if not token:
    token = values.get("DAOCHI_ADMIN_TOKEN", "")
if not token:
    print("Developer inbox is disabled: configure DAOCHI_ADMIN_TOKEN.", file=sys.stderr)
    sys.exit(1)
base = "http://127.0.0.1:8080/api/v1/admin/feedback"
payload = None
if operation["action"] == "reply":
    base += "/reply"
    payload = json.dumps(operation["reply"]).encode()
request = urllib.request.Request(base, data=payload, headers={"X-Daochi-Admin": token, "Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
except urllib.error.HTTPError as error:
    print("Developer inbox: HTTP", error.code, file=sys.stderr)
    sys.exit(1)
except Exception as error:
    print("Developer inbox:", type(error).__name__, file=sys.stderr)
    sys.exit(1)
print(json.dumps(result, ensure_ascii=False, indent=2))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("inbox")
    reply = commands.add_parser("reply")
    reply.add_argument("--account-id", required=True)
    reply.add_argument("--report-id", required=True)
    reply.add_argument("--reply-file", required=True, type=Path)
    args = parser.parse_args()
    operation = {"action": args.action}
    if args.action == "reply":
        message = args.reply_file.read_text()
        if not message.strip() or len(message.encode()) > 4096:
            parser.error("reply must contain 1 to 4096 bytes")
        operation["reply"] = {"account_id": args.account_id, "id": args.report_id,
                              "reply": message}
    result = subprocess.run(
        ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         args.host, "python3 -c " + shlex.quote(REMOTE)],
        input=json.dumps(operation), text=True, capture_output=True,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
