package main

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
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
	secret := envBytesHex("LYRA_TOKEN_SECRET_HEX", nil)
	if len(secret) < 32 {
		slog.Warn("LYRA_TOKEN_SECRET_HEX is missing or too short; using an ephemeral token secret suitable only for local development")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
	}
	return Config{
		Addr:         envString("LYRA_ADDR", "127.0.0.1:8080"),
		BaseURL:      envString("LYRA_BASE_URL", "https://api.waozi.xyz"),
		DBPath:       envString("LYRA_DB", "lyra.db"),
		ChallengeTTL: envDurationSeconds("LYRA_CHALLENGE_TTL_SECONDS", 60*time.Second),
		TokenTTL:     envDurationSeconds("LYRA_TOKEN_TTL_SECONDS", 3600*time.Second),
		TokenSecret:  secret,
		MaxBodyBytes: envInt64("LYRA_MAX_BODY_BYTES", 1<<20),
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

func envBytesHex(key string, fallback []byte) []byte {
	if value := os.Getenv(key); value != "" {
		decoded, err := hex.DecodeString(value)
		if err == nil {
			return decoded
		}
	}
	return fallback
}
