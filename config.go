package main

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr         string
	BaseURL      string
	DBPath       string
	ChallengeTTL time.Duration
	MaxBodyBytes int64
}

func loadConfig() Config {
	return Config{
		Addr:         envString("LYRA_ADDR", "127.0.0.1:8080"),
		BaseURL:      envString("LYRA_BASE_URL", "https://api.waozi.xyz"),
		DBPath:       envString("LYRA_DB", "lyra.db"),
		ChallengeTTL: envDurationSeconds("LYRA_CHALLENGE_TTL_SECONDS", 60*time.Second),
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
