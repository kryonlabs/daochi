package main

import "testing"

func TestLumiCommandAddressAndArguments(t *testing.T) {
	for _, input := range []string{
		"/journal@inlumi_bot  A calm morning\n水を飲む  ",
		"/JOURNAL@INLUMI_BOT  A calm morning\n水を飲む  ",
	} {
		got := LumiCommands_Parse(input)
		if got.Foreign || got.Name != "journal" || got.Message != "/journal  A calm morning\n水を飲む  " || !got.HasArgument {
			t.Fatalf("command changed its arguments: %#v", got)
		}
	}
	for _, input := range []string{"/todo@other_bot text", "/todo@inlumi_bot.evil text", "/todo@ text"} {
		if !LumiCommands_Parse(input).Foreign {
			t.Fatalf("accepted foreign bot command %q", input)
		}
	}
	if got := LumiCommands_Parse("/todo \t\n"); got.HasArgument {
		t.Fatal("whitespace counted as a task title")
	}
	if got := LumiCommands_Parse("hello @inlumi_bot\n/journal private text"); got.Name != "" || got.Message != "hello @inlumi_bot\n/journal private text" {
		t.Fatal("ordinary chat was interpreted as a command")
	}
}
