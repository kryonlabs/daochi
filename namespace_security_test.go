package main

import "testing"

func TestNamespacesRejectFilesystemNavigation(t *testing.T) {
	for _, value := range []string{".", "..", "../app", "app/..", `app\..`, "/app", "app\x00"} {
		if Identity_ValidNamespace(value) {
			t.Errorf("filesystem navigation accepted as namespace: %q", value)
		}
	}
	for _, value := range []string{"app", "shovey.classic", "org.example.app", "app-1", "app_name"} {
		if !Identity_ValidNamespace(value) {
			t.Errorf("valid application namespace rejected: %q", value)
		}
	}
}
