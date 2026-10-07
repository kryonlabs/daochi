#!/usr/bin/env python3
"""Probe the selected Z.ai API on the node and optionally install it privately."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess


REMOTE = r'''
import json, sys, urllib.request, urllib.error
from pathlib import Path
configuration = json.load(sys.stdin)
key = configuration["key"]
thinking = configuration["model"].startswith("glm-5")
payload = {"model": configuration["model"], "messages": [{"role": "user", "content": "Reply with just OK."}], "max_tokens": 2048 if thinking else 16, "thinking": {"type": "enabled" if thinking else "disabled"}}
if thinking:
    payload["reasoning_effort"] = "low"
request = urllib.request.Request(configuration["endpoint"], data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
try:
    with urllib.request.urlopen(request, timeout=35) as response:
        result = json.load(response)
        success = bool(result.get("choices", [{}])[0].get("message", {}).get("content"))
        print("GLM API:", configuration["provider"], response.status, "valid reply:", success)
except urllib.error.HTTPError as error:
    details = json.loads(error.read())
    problem = details.get("error", {})
    print("GLM API:", configuration["provider"], "HTTP", error.code, "code:", problem.get("code"), "message:", str(problem.get("message", "")).replace(key, "[redacted]"))
    sys.exit(1)
except Exception as error:
    print("GLM API:", type(error).__name__)
    sys.exit(1)
if not success:
    sys.exit(1)
if configuration["install"]:
    directory = Path("/etc/daochi")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = directory / "chat-api-key"
    descriptor = __import__("os").open(secret, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_TRUNC, 0o600)
    with __import__("os").fdopen(descriptor, "w") as output:
        output.write(key + "\n")
    secret.chmod(0o600)
    env_path = directory / "daochi.env"
    original = env_path.read_text() if env_path.exists() else ""
    lines = [line for line in original.splitlines() if not line.startswith(("DAOCHI_CHAT_API_KEY=", "DAOCHI_CHAT_API_KEY_FILE=", "DAOCHI_CHAT_ENDPOINT=", "DAOCHI_CHAT_MODEL=", "DAOCHI_CHAT_DAILY_LIMIT=", "DAOCHI_CHAT_GLOBAL_DAILY_LIMIT="))]
    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))
    if not any(values.get(name) for name in ("DAOCHI_FEEDBACK_TOKEN", "DAOCHI_FEEDBACK_TOKEN_FILE", "DAOCHI_ADMIN_TOKEN", "KSYNC_ADMIN_TOKEN")):
        feedback_secret = directory / "feedback-token"
        descriptor = __import__("os").open(feedback_secret, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_TRUNC, 0o600)
        with __import__("os").fdopen(descriptor, "w") as output:
            output.write(__import__("secrets").token_hex(32) + "\n")
        lines.append("DAOCHI_FEEDBACK_TOKEN_FILE=/etc/daochi/feedback-token")
    lines += ["DAOCHI_CHAT_API_KEY_FILE=/etc/daochi/chat-api-key", "DAOCHI_CHAT_ENDPOINT=" + configuration["endpoint"], "DAOCHI_CHAT_MODEL=" + configuration["model"], "DAOCHI_CHAT_DAILY_LIMIT=20", "DAOCHI_CHAT_GLOBAL_DAILY_LIMIT=1000"]
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)
    print("Installed private chat configuration; service restart is separate.")
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--install-key", action="store_true")
    parser.add_argument("--key-name", choices=("ZAI_API_KEY", "GLM_API_KEY"), default="ZAI_API_KEY")
    parser.add_argument("--provider", choices=("standard", "coding"), default="standard")
    parser.add_argument("--model", choices=("glm-4.7-flash", "glm-4.5-flash", "glm-5.3", "glm-5.3-flash"), default="glm-4.7-flash")
    args = parser.parse_args()
    key = ""
    for line in args.env_file.read_text().splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name == args.key_name:
            key = value.strip().strip("\"'")
    if not key:
        parser.error("the environment file has no " + args.key_name)
    process = subprocess.run(
        ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         args.host, "python3 -c " + shlex.quote(REMOTE)],
        input=json.dumps({"key": key, "install": args.install_key, "model": args.model,
                         "provider": args.provider, "endpoint": "https://api.z.ai/api/" + ("coding/" if args.provider == "coding" else "") + "paas/v4/chat/completions"}),
        text=True, capture_output=True,
    )
    print(process.stdout.replace(key, "[redacted]"), end="")
    print(process.stderr.replace(key, "[redacted]"), end="")
    raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
