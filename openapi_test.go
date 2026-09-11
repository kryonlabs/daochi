package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestOpenAPIServedFromCache(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("openapi status = %d/%d, want 200", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatal("openapi responses differ between requests")
	}
	var spec map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &spec); err != nil {
		t.Fatalf("openapi payload is not valid JSON: %v", err)
	}
	if spec["openapi"] != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", spec["openapi"])
	}
}

// undocumentedRoutes are registered but intentionally absent from the
// OpenAPI spec today: infra endpoints and in-flight features. When a
// feature ships, document its paths and remove them here — the test then
// guards against future drift in both directions.
var undocumentedRoutes = map[string]bool{
	"/":             true,
	"/openapi.json": true,
}

func TestOpenAPISpecCoversRegisteredRoutes(t *testing.T) {
	spec := openAPISpec()
	paths, _ := spec["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("openapi spec has no paths")
	}
	source, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	registered := regexp.MustCompile(`HandleFunc\("([A-Z]+) (/[^"]*)"`).FindAllStringSubmatch(string(source), -1)
	if len(registered) == 0 {
		t.Fatal("no HandleFunc registrations found in server.go")
	}
	for _, match := range registered {
		route := match[2]
		if undocumentedRoutes[route] {
			continue
		}
		// Subtree handlers (trailing "/") are documented by any
		// parameterized path beneath them.
		prefix := strings.TrimSuffix(route, "/") + "/"
		if strings.HasSuffix(route, "/") {
			documented := false
			for specPath := range paths {
				if strings.HasPrefix(specPath, prefix) {
					documented = true
					break
				}
			}
			if !documented {
				t.Errorf("route %s is registered but no spec path starts with %s", route, prefix)
			}
			continue
		}
		if _, ok := paths[route]; !ok {
			t.Errorf("route %s is registered but missing from OpenAPI spec", route)
		}
	}
}
