package main

import (
	"crypto/ed25519"
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
	Addr                            string
	BaseURL                         string
	DBPath                          string
	AdminToken                      string
	ChallengeTTL                    time.Duration
	TokenTTL                        time.Duration
	TokenSecret                     []byte
	TokenSecretEphemeral            bool
	MaxBodyBytes                    int64
	EncryptedPayloadMaxReturn       int
	EncryptedPayloadMaxAccountBytes int64
	EncryptedPayloadRetention       time.Duration
	NodeRegistryPublicKey           ed25519.PublicKey
	WaoziIssuerPublicKey            ed25519.PublicKey
	WaoziIssuerPrivateKey           ed25519.PrivateKey
	TokenProducts                   map[string]TokenProduct
	GooglePackageNames              map[string]bool
	GoogleServiceAccountJSON        string
	GoogleOAuthClientJSON           string
	GoogleOAuthRefreshToken         string
	MoneroWalletRPCURL              string
	MoneroWalletRPCUser             string
	MoneroWalletRPCPassword         string
	TokenDirectPurchasesEnabled     bool
}

func loadConfig() Config {
	secret := envBytesHex("KSYNC_TOKEN_SECRET_HEX", nil)
	ephemeralSecret := false
	if len(secret) < 32 {
		if !envBool("KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET", false) {
			log.Fatal("KSYNC_TOKEN_SECRET_HEX must be at least 32 bytes; set KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET=1 only for local development")
		}
		slog.Warn("KSYNC_TOKEN_SECRET_HEX is missing or too short; using an ephemeral token secret suitable only for local development")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
		ephemeralSecret = true
	}
	nodeRegistryPublic := ed25519.PublicKey(envBytesHexOrFile("KSYNC_NODE_REGISTRY_PUBLIC_KEY_HEX", "KSYNC_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE", nil))
	issuerPublic := envBytesHexOrFile("KSYNC_TOKEN_ISSUER_PUBLIC_KEY_HEX", "KSYNC_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	if len(issuerPublic) == 0 {
		issuerPublic = envBytesHexOrFile("KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX", "KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	}
	issuerPrivateBytes := envBytesHexOrFile("KSYNC_TOKEN_ISSUER_PRIVATE_KEY_HEX", "KSYNC_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
	if len(issuerPrivateBytes) == 0 {
		issuerPrivateBytes = envBytesHexOrFile("KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX", "KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
	}
	var issuerPrivate ed25519.PrivateKey
	if len(issuerPrivateBytes) == ed25519.SeedSize {
		issuerPrivate = ed25519.NewKeyFromSeed(issuerPrivateBytes)
	} else if len(issuerPrivateBytes) == ed25519.PrivateKeySize {
		issuerPrivate = ed25519.PrivateKey(issuerPrivateBytes)
	}
	if len(issuerPrivate) == ed25519.PrivateKeySize && len(issuerPublic) == 0 {
		issuerPublic = issuerPrivate.Public().(ed25519.PublicKey)
	}
	return Config{
		Addr:                            envString("KSYNC_ADDR", "127.0.0.1:8080"),
		BaseURL:                         envString("KSYNC_BASE_URL", "https://api.example.com"),
		DBPath:                          envString("KSYNC_DB", "ksync.db"),
		AdminToken:                      envString("KSYNC_ADMIN_TOKEN", ""),
		ChallengeTTL:                    envDurationSeconds("KSYNC_CHALLENGE_TTL_SECONDS", 60*time.Second),
		TokenTTL:                        envDurationSeconds("KSYNC_TOKEN_TTL_SECONDS", 3600*time.Second),
		TokenSecret:                     secret,
		TokenSecretEphemeral:            ephemeralSecret,
		MaxBodyBytes:                    envInt64("KSYNC_MAX_BODY_BYTES", 1<<20),
		EncryptedPayloadMaxReturn:       envInt("KSYNC_ENCRYPTED_PAYLOAD_MAX_RETURN", 0),
		EncryptedPayloadMaxAccountBytes: envInt64("KSYNC_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES", 0),
		EncryptedPayloadRetention:       envDurationDays("KSYNC_ENCRYPTED_PAYLOAD_RETENTION_DAYS", 0),
		NodeRegistryPublicKey:           nodeRegistryPublic,
		WaoziIssuerPublicKey:            issuerPublic,
		WaoziIssuerPrivateKey:           issuerPrivate,
		TokenProducts:                   envTokenProducts("KSYNC_TOKEN_PRODUCTS"),
		GooglePackageNames:              envStringSet("KSYNC_GOOGLE_PACKAGE_NAMES"),
		GoogleServiceAccountJSON:        envStringOrFile("KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON", "KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", ""),
		GoogleOAuthClientJSON:           envStringOrFile("KSYNC_GOOGLE_OAUTH_CLIENT_JSON", "KSYNC_GOOGLE_OAUTH_CLIENT_JSON_FILE", ""),
		GoogleOAuthRefreshToken:         envStringOrFile("KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN", "KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", ""),
		MoneroWalletRPCURL:              envString("KSYNC_MONERO_WALLET_RPC_URL", ""),
		MoneroWalletRPCUser:             envString("KSYNC_MONERO_WALLET_RPC_USER", ""),
		MoneroWalletRPCPassword:         envString("KSYNC_MONERO_WALLET_RPC_PASSWORD", ""),
		TokenDirectPurchasesEnabled:     envBool("KSYNC_TOKEN_DIRECT_PURCHASES_ENABLED", false),
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

func envDurationDays(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		days, err := strconv.Atoi(value)
		if err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		n, err := strconv.Atoi(value)
		if err == nil && n > 0 {
			return n
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

func envStringOrFile(key, fileKey, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	if path := strings.TrimSpace(os.Getenv(fileKey)); path != "" {
		bytes, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(bytes))
		}
		slog.Warn("failed to read config file", "env", fileKey, "path", path, "error", err)
	}
	return fallback
}

func envBytesHexOrFile(key, fileKey string, fallback []byte) []byte {
	if value := os.Getenv(key); value != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(value))
		if err == nil {
			return decoded
		}
	}
	if value := envStringOrFile("", fileKey, ""); value != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(value))
		if err == nil {
			return decoded
		}
	}
	return fallback
}

func envStringSet(key string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(os.Getenv(key), ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func envTokenProducts(key string) map[string]TokenProduct {
	out := map[string]TokenProduct{}
	for _, item := range strings.Split(os.Getenv(key), ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" {
			continue
		}
		units, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || units <= 0 {
			continue
		}
		product := TokenProduct{ProductID: parts[0], TokenUnits: units}
		if len(parts) == 3 {
			atomic, err := strconv.ParseInt(parts[2], 10, 64)
			if err == nil && atomic > 0 {
				product.MoneroAtomicAmount = atomic
			}
		}
		out[product.ProductID] = product
	}
	return out
}
