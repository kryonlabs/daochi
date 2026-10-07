#!/usr/bin/env python3
"""Check or apply Lumi's Telegram command menu and profile without exposing its token."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request


USERNAME = "inlumi_bot"
DESCRIPTION = (
    "Lumi is your companion in Inner Breeze. Chat, reflect on your day, "
    "track habits and tasks, and find a little space to breathe. "
    "Link your account from Lumi in Inner Breeze, then use /help to get started. "
    "Keep Inner Breeze open for replies and app actions."
)
SHORT_DESCRIPTION = "Your Inner Breeze companion for journaling, habits, tasks and breathing. Use /help to get started."


def catalogue(source):
    match = re.search(r"Document :: #string JSON\n(.*?)\nJSON;", source, re.S)
    if not match:
        raise ValueError("Lumi command catalogue is missing")
    commands = json.loads(match[1])
    validate(commands)
    return commands


def validate(commands):
    if not isinstance(commands, list) or not 1 <= len(commands) <= 100:
        raise ValueError("Invalid command count")
    names = set()
    for item in commands:
        name = item.get("command", "")
        description = item.get("description", "")
        if not re.fullmatch(r"[a-z_]{1,32}", name) or name in names:
            raise ValueError("Invalid or duplicate command name")
        if not isinstance(description, str) or not 1 <= len(description) <= 256:
            raise ValueError("Invalid command description")
        names.add(name)


def token_from_configuration(env_file, token_file):
    if token_file:
        return token_file.read_text().strip()
    values = dict(os.environ)
    if env_file:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name, separator, value = line.partition("=")
                if separator:
                    values[name] = value.strip().strip("\"'")
    token = values.get("DAOCHI_LUMI_BOT_TOKEN", "").strip()
    if not token and values.get("DAOCHI_LUMI_BOT_TOKEN_FILE"):
        token = Path(values["DAOCHI_LUMI_BOT_TOKEN_FILE"]).read_text().strip()
    if not token:
        raise ValueError("Lumi bot token is not configured")
    return token


class Telegram:
    def __init__(self, token):
        self.token = token

    def call(self, method, payload):
        request = urllib.request.Request(
            "https://api.telegram.org/bot" + self.token + "/" + method,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(65537)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Telegram {method} returned HTTP {error.code}") from None
        except Exception:
            # Network exceptions can contain the credential-bearing URL.
            raise RuntimeError(f"Telegram {method} request failed") from None
        if len(raw) > 65536:
            raise RuntimeError(f"Telegram {method} response is too large")
        answer = json.loads(raw)
        if not answer.get("ok"):
            raise RuntimeError(f"Telegram {method} did not succeed")
        return answer.get("result")


def configure(api, commands, apply):
    validate(commands)
    identity = api.call("getMe", {})
    if not identity.get("is_bot") or identity.get("username", "").lower() != USERNAME:
        raise ValueError("Configured token does not belong to @inlumi_bot; nothing changed")
    scopes = ({"type": "default"}, {"type": "all_private_chats"})
    before = [api.call("getMyCommands", {"scope": scope}) for scope in scopes]
    description = api.call("getMyDescription", {})
    short = api.call("getMyShortDescription", {})
    button = api.call("getChatMenuButton", {})
    matches = (
        all(menu == commands for menu in before)
        and description.get("description") == DESCRIPTION
        and short.get("short_description") == SHORT_DESCRIPTION
        and button.get("type") == "commands"
    )
    if apply:
        for scope, menu in zip(scopes, before):
            if menu != commands:
                api.call("setMyCommands", {"scope": scope, "commands": commands})
        if description.get("description") != DESCRIPTION:
            api.call("setMyDescription", {"description": DESCRIPTION})
        if short.get("short_description") != SHORT_DESCRIPTION:
            api.call("setMyShortDescription", {"short_description": SHORT_DESCRIPTION})
        if button.get("type") != "commands":
            api.call("setChatMenuButton", {"menu_button": {"type": "commands"}})
        matches = (
            all(api.call("getMyCommands", {"scope": scope}) == commands for scope in scopes)
            and api.call("getMyDescription", {}).get("description") == DESCRIPTION
            and api.call("getMyShortDescription", {}).get("short_description") == SHORT_DESCRIPTION
            and api.call("getChatMenuButton", {}).get("type") == "commands"
        )
        if not matches:
            raise RuntimeError("Lumi bot profile verification failed")
    return {"bot": "@" + USERNAME, "applied": apply, "verified": matches,
            "commands": commands, "description": DESCRIPTION,
            "short_description": SHORT_DESCRIPTION}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--host", help="Existing SSH node holding the bot token")
    parser.add_argument("--apply", action="store_true", help="Apply and verify the menu and profile")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--from-stdin", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        commands = (json.load(sys.stdin) if args.from_stdin else catalogue(
            (Path(__file__).resolve().parent.parent / "lumi_commands.zi").read_text()))
        if args.host:
            arguments = ["python3", "-c", Path(__file__).read_text(), "--from-stdin",
                         "--env-file", str(args.env_file or "/etc/daochi/daochi.env")]
            if args.apply:
                arguments.append("--apply")
            completed = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", args.host,
                 shlex.join(arguments)], input=json.dumps(commands), text=True,
                capture_output=True, timeout=180,
            )
            if completed.returncode:
                # Print only our controlled JSON error, never raw SSH output.
                try:
                    problem = json.loads(completed.stdout)["error"]
                except (ValueError, KeyError):
                    problem = "Remote Lumi configuration could not be read"
                raise RuntimeError(problem)
            result = json.loads(completed.stdout)
        else:
            token = token_from_configuration(args.env_file, args.token_file)
            result = configure(Telegram(token), commands, args.apply)
        if args.receipt:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        # File and transport errors do not include token values in this code.
        message = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        print(json.dumps({"error": message}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
