import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("configure_lumi_bot", Path(__file__).with_name("configure-lumi-bot.py"))
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class API:
    def __init__(self, username="inlumi_bot"):
        self.username = username
        self.calls = []
        self.menus = {}
        self.description = ""
        self.short = ""
        self.button = {"type": "default"}

    def call(self, method, payload):
        self.calls.append((method, payload))
        if method == "getMe":
            return {"is_bot": True, "username": self.username}
        if method == "getMyCommands":
            return self.menus.get(payload["scope"]["type"], [])
        if method == "setMyCommands":
            self.menus[payload["scope"]["type"]] = payload["commands"]
        if method == "getMyDescription":
            return {"description": self.description}
        if method == "setMyDescription":
            self.description = payload["description"]
        if method == "getMyShortDescription":
            return {"short_description": self.short}
        if method == "setMyShortDescription":
            self.short = payload["short_description"]
        if method == "getChatMenuButton":
            return self.button
        if method == "setChatMenuButton":
            self.button = payload["menu_button"]
        return True


class ConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.commands = bot.catalogue((Path(__file__).resolve().parent.parent / "lumi_commands.zi").read_text())

    def test_wrong_bot_is_never_modified(self):
        api = API("another_bot")
        with self.assertRaises(ValueError):
            bot.configure(api, self.commands, True)
        self.assertEqual([method for method, _ in api.calls], ["getMe"])

    def test_read_only_and_apply_verification(self):
        api = API()
        self.assertFalse(bot.configure(api, self.commands, False)["verified"])
        self.assertFalse(any(method.startswith("set") for method, _ in api.calls))
        self.assertTrue(bot.configure(api, self.commands, True)["verified"])
        self.assertEqual(api.menus["all_private_chats"], self.commands)
        api.calls.clear()
        self.assertTrue(bot.configure(api, self.commands, True)["verified"])
        self.assertFalse(any(method.startswith("set") for method, _ in api.calls))

    def test_catalogue_validation(self):
        for commands in [[], [{"command": "Bad", "description": "bad"}], self.commands + [self.commands[0]]]:
            with self.assertRaises(ValueError):
                bot.validate(commands)
        self.assertLessEqual(len(bot.DESCRIPTION), 512)
        self.assertLessEqual(len(bot.SHORT_DESCRIPTION), 120)

    def test_transport_never_exposes_secret_url(self):
        secret = "fixture-private-token"
        with patch.object(bot.urllib.request, "urlopen", side_effect=OSError("https://api.telegram.org/bot" + secret)):
            with self.assertRaises(RuntimeError) as caught:
                bot.Telegram(secret).call("getMe", {})
        self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
