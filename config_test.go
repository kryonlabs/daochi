package main

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigPrefersDaochiEnv(t *testing.T) {
	daochiSecret := strings.Repeat("11", 32)
	legacySecret := strings.Repeat("22", 32)

	t.Setenv("DAOCHI_TOKEN_SECRET_HEX", daochiSecret)
	t.Setenv("KSYNC_TOKEN_SECRET_HEX", legacySecret)
	t.Setenv("DAOCHI_ADDR", "0.0.0.0:18080")
	t.Setenv("KSYNC_ADDR", "0.0.0.0:8080")
	t.Setenv("DAOCHI_BASE_URL", "http://192.168.100.97:18080")
	t.Setenv("KSYNC_BASE_URL", "https://api.legacy.example")
	t.Setenv("DAOCHI_DB", "/data/daochi.db")
	t.Setenv("KSYNC_DB", "/data/ksync.db")
	t.Setenv("DAOCHI_KNOWN_NODES", "Waozi=https://api.waozi.xyz")
	t.Setenv("KSYNC_KNOWN_NODES", "Legacy=https://legacy.example")
	t.Setenv("DAOCHI_TOKEN_TTL_SECONDS", "90")
	t.Setenv("KSYNC_TOKEN_TTL_SECONDS", "45")

	cfg := loadConfig()
	if got := hex.EncodeToString(cfg.TokenSecret); got != daochiSecret {
		t.Fatalf("TokenSecret=%q, want DAOCHI secret", got)
	}
	if cfg.Addr != "0.0.0.0:18080" || cfg.BaseURL != "http://192.168.100.97:18080" || cfg.DBPath != "/data/daochi.db" {
		t.Fatalf("config did not prefer DAOCHI env: %+v", cfg)
	}
	if cfg.TokenTTL != 90*time.Second {
		t.Fatalf("TokenTTL=%s, want 90s", cfg.TokenTTL)
	}
	if len(cfg.KnownNodes) != 1 || cfg.KnownNodes[0].Name != "Waozi" || cfg.KnownNodes[0].URL != "https://api.waozi.xyz" {
		t.Fatalf("KnownNodes=%+v, want DAOCHI_KNOWN_NODES", cfg.KnownNodes)
	}
}

func TestLoadConfigAcceptsLegacyKsyncEnvFallback(t *testing.T) {
	legacySecret := strings.Repeat("33", 32)

	t.Setenv("DAOCHI_TOKEN_SECRET_HEX", "")
	t.Setenv("DAOCHI_ADDR", "")
	t.Setenv("DAOCHI_BASE_URL", "")
	t.Setenv("DAOCHI_DB", "")
	t.Setenv("DAOCHI_TOKEN_TTL_SECONDS", "")
	t.Setenv("KSYNC_TOKEN_SECRET_HEX", legacySecret)
	t.Setenv("KSYNC_ADDR", "0.0.0.0:8081")
	t.Setenv("KSYNC_BASE_URL", "https://api.legacy.example")
	t.Setenv("KSYNC_DB", "/data/legacy.db")
	t.Setenv("KSYNC_TOKEN_TTL_SECONDS", "120")

	cfg := loadConfig()
	if got := hex.EncodeToString(cfg.TokenSecret); got != legacySecret {
		t.Fatalf("TokenSecret=%q, want legacy KSYNC secret", got)
	}
	if cfg.Addr != "0.0.0.0:8081" || cfg.BaseURL != "https://api.legacy.example" || cfg.DBPath != "/data/legacy.db" {
		t.Fatalf("config did not accept legacy KSYNC env: %+v", cfg)
	}
	if cfg.TokenTTL != 120*time.Second {
		t.Fatalf("TokenTTL=%s, want 120s", cfg.TokenTTL)
	}
}
