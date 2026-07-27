package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr         string
	BaseURL      string
	DBPath       string
	ChallengeTTL time.Duration
	TokenTTL     time.Duration
	TokenSecret  []byte
	MaxBodyBytes int64
}

func loadConfig() Config {
	secret := envBytesHex("KSYNC_TOKEN_SECRET_HEX", nil)
	if len(secret) < 32 {
		if !envBool("KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET", false) {
			log.Fatal("KSYNC_TOKEN_SECRET_HEX must be at least 32 bytes; set KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET=1 only for local development")
		}
		slog.Warn("KSYNC_TOKEN_SECRET_HEX is missing or too short; using an ephemeral token secret suitable only for local development")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
	}
	return Config{
		Addr:         envString("KSYNC_ADDR", "127.0.0.1:8080"),
		BaseURL:      envString("KSYNC_BASE_URL", "https://api.waozi.xyz"),
		DBPath:       envString("KSYNC_DB", "ksync.db"),
		ChallengeTTL: envDurationSeconds("KSYNC_CHALLENGE_TTL_SECONDS", 60*time.Second),
		TokenTTL:     envDurationSeconds("KSYNC_TOKEN_TTL_SECONDS", 3600*time.Second),
		TokenSecret:  secret,
		MaxBodyBytes: envInt64("KSYNC_MAX_BODY_BYTES", 1<<20),
	}
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envDurationSeconds(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		seconds, err := strconv.Atoi(value)
		if err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if value := os.Getenv(key); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if value := strings.ToLower(strings.TrimSpace(os.Getenv(key))); value != "" {
		return value == "1" || value == "true" || value == "yes" || value == "on"
	}
	return fallback
}

func envBytesHex(key string, fallback []byte) []byte {
	if value := os.Getenv(key); value != "" {
		decoded, err := hex.DecodeString(value)
		if err == nil {
			return decoded
		}
	}
	return fallback
}
