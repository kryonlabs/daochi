package native

import "testing"

func TestPathComponentRejectsNavigationAndAliases(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../other", "a/../b", "/absolute", `a\b`, "app\x00"} {
		if _, err := PathComponent(value); err == nil {
			t.Errorf("unsafe path component accepted: %q", value)
		}
	}
	for _, value := range []string{"shovey.classic", "app_name", "0123456789abcdef", "release-v2.json"} {
		got, err := PathComponent(value)
		if err != nil || got != value {
			t.Errorf("valid component changed: %q became %q (%v)", value, got, err)
		}
	}
}
