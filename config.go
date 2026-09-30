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
	KnownNodes                      []NodePeer
	NodeSyncToken                   string
	NodeSyncInterval                time.Duration
	NodeSyncBatchLimit              int
	NodeIdentityKeyFile             string
	NodeIdentityPrivateKey          ed25519.PrivateKey
	NodeDisplayName                 string
	LANDiscovery                    bool
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
	MoneroNetwork                   string
	MoneroRateAtomicAmount          int64
	MoneroRateTokenUnits            int64
	MoneroMinimumAtomicAmount       int64
	MoneroConfirmationsRequired     int64
	TokenDirectPurchasesEnabled     bool
}

func loadConfig() Config {
	secret := envBytesHex("DAOCHI_TOKEN_SECRET_HEX", nil)
	ephemeralSecret := false
	if len(secret) < 32 {
		if !ConfigValues_Bool(os.Getenv("DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET"), false) {
			log.Fatal("DAOCHI_TOKEN_SECRET_HEX must be at least 32 bytes; set DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET=1 only for local development")
		}
		slog.Warn("DAOCHI_TOKEN_SECRET_HEX is missing or too short; using an ephemeral token secret suitable only for local development")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
		ephemeralSecret = true
	}
	nodeRegistryPublic := ed25519.PublicKey(envBytesHexOrFile("DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX", "DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE", nil))
	issuerPublic := envBytesHexOrFile("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	issuerPrivateBytes := envBytesHexOrFile("DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
	var issuerPrivate ed25519.PrivateKey
	if len(issuerPrivateBytes) == ed25519.SeedSize {
		issuerPrivate = ed25519.NewKeyFromSeed(issuerPrivateBytes)
	} else if len(issuerPrivateBytes) == ed25519.PrivateKeySize {
		issuerPrivate = ed25519.PrivateKey(issuerPrivateBytes)
	}
	if len(issuerPrivate) == ed25519.PrivateKeySize && len(issuerPublic) == 0 {
		issuerPublic = issuerPrivate.Public().(ed25519.PublicKey)
	}
	baseURL := envString("DAOCHI_BASE_URL", "https://api.example.com")
	nodeKeyBytes := envBytesHexOrFile("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", "DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE", nil)
	var nodePrivateKey ed25519.PrivateKey
	if len(nodeKeyBytes) == ed25519.SeedSize {
		nodePrivateKey = ed25519.NewKeyFromSeed(nodeKeyBytes)
	} else if len(nodeKeyBytes) == ed25519.PrivateKeySize {
		nodePrivateKey = ed25519.PrivateKey(nodeKeyBytes)
	} else if len(nodeKeyBytes) != 0 {
		log.Fatal("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX must contain a 32-byte Ed25519 seed or 64-byte private key")
	}
	return Config{
		Addr:                            envString("DAOCHI_ADDR", "127.0.0.1:8080"),
		BaseURL:                         baseURL,
		DBPath:                          envString("DAOCHI_DB", "daochi.db"),
		AdminToken:                      envString("DAOCHI_ADMIN_TOKEN", ""),
		ChallengeTTL:                    envDurationSeconds("DAOCHI_CHALLENGE_TTL_SECONDS", 60*time.Second),
		TokenTTL:                        envDurationSeconds("DAOCHI_TOKEN_TTL_SECONDS", 3600*time.Second),
		TokenSecret:                     secret,
		TokenSecretEphemeral:            ephemeralSecret,
		MaxBodyBytes:                    envInt64("DAOCHI_MAX_BODY_BYTES", 1<<20),
		EncryptedPayloadMaxReturn:       envInt("DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN", 0),
		EncryptedPayloadMaxAccountBytes: envInt64("DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES", 0),
		EncryptedPayloadRetention:       envDurationDays("DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS", 0),
		NodeRegistryPublicKey:           nodeRegistryPublic,
		KnownNodes:                      ConfigValues_Peers(envString("DAOCHI_KNOWN_NODES", "")),
		NodeSyncToken:                   envString("DAOCHI_NODE_SYNC_TOKEN", ""),
		NodeSyncInterval:                envDurationSeconds("DAOCHI_NODE_SYNC_INTERVAL_SECONDS", 0),
		NodeSyncBatchLimit:              envInt("DAOCHI_NODE_SYNC_BATCH_LIMIT", 500),
		NodeIdentityKeyFile:             envString("DAOCHI_NODE_IDENTITY_KEY_FILE", envString("DAOCHI_DB", "daochi.db")+".node-key"),
		NodeIdentityPrivateKey:          nodePrivateKey,
		NodeDisplayName:                 envString("DAOCHI_NODE_NAME", "Daochi Node"),
		LANDiscovery:                    ConfigValues_Bool(os.Getenv("DAOCHI_LAN_DISCOVERY"), true),
		WaoziIssuerPublicKey:            issuerPublic,
		WaoziIssuerPrivateKey:           issuerPrivate,
		TokenProducts:                   ConfigValues_Products(envString("DAOCHI_TOKEN_PRODUCTS", "")),
		GooglePackageNames:              Sets_FromEnvironment(envString("DAOCHI_GOOGLE_PACKAGE_NAMES", "")),
		GoogleServiceAccountJSON:        envStringOrFile("DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON", "DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", ""),
		GoogleOAuthClientJSON:           envStringOrFile("DAOCHI_GOOGLE_OAUTH_CLIENT_JSON", "DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE", ""),
		GoogleOAuthRefreshToken:         envStringOrFile("DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN", "DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", ""),
		MoneroWalletRPCURL:              envString("MONERO_WALLET_RPC_URL", ""),
		MoneroWalletRPCUser:             envString("MONERO_WALLET_RPC_USER", ""),
		MoneroWalletRPCPassword:         envStringOrFile("MONERO_WALLET_RPC_PASSWORD", "MONERO_WALLET_RPC_PASSWORD_FILE", ""),
		MoneroNetwork:                   envString("MONERO_NETWORK", "mainnet"),
		MoneroRateAtomicAmount:          envInt64("MONERO_RATE_ATOMIC_AMOUNT", 0),
		MoneroRateTokenUnits:            envInt64("MONERO_RATE_TOKEN_UNITS", 0),
		MoneroMinimumAtomicAmount:       envInt64("MONERO_MINIMUM_ATOMIC_AMOUNT", 1),
		MoneroConfirmationsRequired:     envInt64("MONERO_CONFIRMATIONS_REQUIRED", 10),
		TokenDirectPurchasesEnabled:     ConfigValues_Bool(os.Getenv("DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED"), false),
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
		if err != nil {
			log.Fatalf("invalid %s: not an integer: %q", key, value)
		}
		if seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return fallback
}

func envDurationDays(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil {
			log.Fatalf("invalid %s: not an integer: %q", key, value)
		}
		if days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			log.Fatalf("invalid %s: not an integer: %q", key, value)
		}
		if n > 0 {
			return n
		}
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if value := os.Getenv(key); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			log.Fatalf("invalid %s: not an integer: %q", key, value)
		}
		if n > 0 {
			return n
		}
	}
	return fallback
}

func envBytesHex(key string, fallback []byte) []byte {
	if value := os.Getenv(key); value != "" {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			// A malformed secret must abort startup, not silently fall
			// back (e.g. to an ephemeral token secret).
			log.Fatalf("invalid %s: not valid hex: %q", key, value)
		}
		return decoded
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
