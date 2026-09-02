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
	secret := envBytesHex("DAOCHI_TOKEN_SECRET_HEX", envBytesHex("KSYNC_TOKEN_SECRET_HEX", nil))
	ephemeralSecret := false
	if len(secret) < 32 {
		if !envBool("DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET", envBool("KSYNC_ALLOW_EPHEMERAL_TOKEN_SECRET", false)) {
			log.Fatal("DAOCHI_TOKEN_SECRET_HEX must be at least 32 bytes; set DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET=1 only for local development")
		}
		slog.Warn("DAOCHI_TOKEN_SECRET_HEX is missing or too short; using an ephemeral token secret suitable only for local development")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
		ephemeralSecret = true
	}
	nodeRegistryPublic := ed25519.PublicKey(envBytesHexOrFileFallback("DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX", "DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE", "KSYNC_NODE_REGISTRY_PUBLIC_KEY_HEX", "KSYNC_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE", nil))
	issuerPublic := envBytesHexOrFileFallback("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", "KSYNC_TOKEN_ISSUER_PUBLIC_KEY_HEX", "KSYNC_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	if len(issuerPublic) == 0 {
		issuerPublic = envBytesHexOrFileFallback("DAOCHI_WAOZI_ISSUER_PUBLIC_KEY_HEX", "DAOCHI_WAOZI_ISSUER_PUBLIC_KEY_HEX_FILE", "KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX", "KSYNC_WAOZI_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	}
	issuerPrivateBytes := envBytesHexOrFileFallback("DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE", "KSYNC_TOKEN_ISSUER_PRIVATE_KEY_HEX", "KSYNC_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
	if len(issuerPrivateBytes) == 0 {
		issuerPrivateBytes = envBytesHexOrFileFallback("DAOCHI_WAOZI_ISSUER_PRIVATE_KEY_HEX", "DAOCHI_WAOZI_ISSUER_PRIVATE_KEY_HEX_FILE", "KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX", "KSYNC_WAOZI_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
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
	baseURL := envString("DAOCHI_BASE_URL", envString("KSYNC_BASE_URL", "https://api.example.com"))
	return Config{
		Addr:                            envString("DAOCHI_ADDR", envString("KSYNC_ADDR", "127.0.0.1:8080")),
		BaseURL:                         baseURL,
		DBPath:                          envString("DAOCHI_DB", envString("KSYNC_DB", "daochi.db")),
		AdminToken:                      envString("DAOCHI_ADMIN_TOKEN", envString("KSYNC_ADMIN_TOKEN", "")),
		ChallengeTTL:                    envDurationSeconds("DAOCHI_CHALLENGE_TTL_SECONDS", envDurationSeconds("KSYNC_CHALLENGE_TTL_SECONDS", 60*time.Second)),
		TokenTTL:                        envDurationSeconds("DAOCHI_TOKEN_TTL_SECONDS", envDurationSeconds("KSYNC_TOKEN_TTL_SECONDS", 3600*time.Second)),
		TokenSecret:                     secret,
		TokenSecretEphemeral:            ephemeralSecret,
		MaxBodyBytes:                    envInt64("DAOCHI_MAX_BODY_BYTES", envInt64("KSYNC_MAX_BODY_BYTES", 1<<20)),
		EncryptedPayloadMaxReturn:       envInt("DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN", envInt("KSYNC_ENCRYPTED_PAYLOAD_MAX_RETURN", 0)),
		EncryptedPayloadMaxAccountBytes: envInt64("DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES", envInt64("KSYNC_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES", 0)),
		EncryptedPayloadRetention:       envDurationDays("DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS", envDurationDays("KSYNC_ENCRYPTED_PAYLOAD_RETENTION_DAYS", 0)),
		NodeRegistryPublicKey:           nodeRegistryPublic,
		KnownNodes:                      envNodePeersValue(envString("DAOCHI_KNOWN_NODES", envString("KSYNC_KNOWN_NODES", ""))),
		NodeSyncToken:                   envString("DAOCHI_NODE_SYNC_TOKEN", envString("KSYNC_NODE_SYNC_TOKEN", "")),
		NodeSyncInterval:                envDurationSeconds("DAOCHI_NODE_SYNC_INTERVAL_SECONDS", envDurationSeconds("KSYNC_NODE_SYNC_INTERVAL_SECONDS", 0)),
		NodeSyncBatchLimit:              envInt("DAOCHI_NODE_SYNC_BATCH_LIMIT", envInt("KSYNC_NODE_SYNC_BATCH_LIMIT", 500)),
		WaoziIssuerPublicKey:            issuerPublic,
		WaoziIssuerPrivateKey:           issuerPrivate,
		TokenProducts:                   envTokenProductsValue(envString("DAOCHI_TOKEN_PRODUCTS", envString("KSYNC_TOKEN_PRODUCTS", ""))),
		GooglePackageNames:              envStringSetValue(envString("DAOCHI_GOOGLE_PACKAGE_NAMES", envString("KSYNC_GOOGLE_PACKAGE_NAMES", ""))),
		GoogleServiceAccountJSON:        envStringOrFileFallback("DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON", "DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", "KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON", "KSYNC_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", ""),
		GoogleOAuthClientJSON:           envStringOrFileFallback("DAOCHI_GOOGLE_OAUTH_CLIENT_JSON", "DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE", "KSYNC_GOOGLE_OAUTH_CLIENT_JSON", "KSYNC_GOOGLE_OAUTH_CLIENT_JSON_FILE", ""),
		GoogleOAuthRefreshToken:         envStringOrFileFallback("DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN", "DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", "KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN", "KSYNC_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", ""),
		MoneroWalletRPCURL:              envString("DAOCHI_MONERO_WALLET_RPC_URL", envString("KSYNC_MONERO_WALLET_RPC_URL", "")),
		MoneroWalletRPCUser:             envString("DAOCHI_MONERO_WALLET_RPC_USER", envString("KSYNC_MONERO_WALLET_RPC_USER", "")),
		MoneroWalletRPCPassword:         envString("DAOCHI_MONERO_WALLET_RPC_PASSWORD", envString("KSYNC_MONERO_WALLET_RPC_PASSWORD", "")),
		TokenDirectPurchasesEnabled:     envBool("DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED", envBool("KSYNC_TOKEN_DIRECT_PURCHASES_ENABLED", false)),
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

func envStringOrFileFallback(key, fileKey, legacyKey, legacyFileKey, fallback string) string {
	if value := envStringOrFile(key, fileKey, ""); value != "" {
		return value
	}
	return envStringOrFile(legacyKey, legacyFileKey, fallback)
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

func envBytesHexOrFileFallback(key, fileKey, legacyKey, legacyFileKey string, fallback []byte) []byte {
	if value := envBytesHexOrFile(key, fileKey, nil); len(value) != 0 {
		return value
	}
	return envBytesHexOrFile(legacyKey, legacyFileKey, fallback)
}

func envStringSet(key string) map[string]bool {
	return envStringSetValue(os.Getenv(key))
}

func envStringSetValue(raw string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func envNodePeers(key string) []NodePeer {
	return envNodePeersValue(os.Getenv(key))
}

func envNodePeersValue(raw string) []NodePeer {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var peers []NodePeer
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name := ""
		urlValue := item
		policyFields := []string{}
		if fields := strings.Split(item, ";"); len(fields) > 1 {
			urlValue = strings.TrimSpace(fields[0])
			policyFields = fields[1:]
		}
		if before, after, ok := strings.Cut(urlValue, "="); ok {
			name = strings.TrimSpace(before)
			urlValue = after
		} else if before, after, ok := strings.Cut(urlValue, "|"); ok {
			name = strings.TrimSpace(before)
			urlValue = after
		}
		urlValue = strings.TrimRight(strings.TrimSpace(urlValue), "/")
		if urlValue == "" || seen[urlValue] {
			continue
		}
		seen[urlValue] = true
		peers = append(peers, NodePeer{Name: name, URL: urlValue, Sync: envNodeSyncPolicyValue(policyFields)})
	}
	return peers
}

func envNodeSyncPolicyValue(fields []string) *NodeSyncPolicy {
	var policy NodeSyncPolicy
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "sync", "mode", "direction":
			policy.Direction = normalizeNodeSyncDirection(value)
		case "app", "apps", "app_id", "app_ids":
			policy.Apps = splitNodeSyncList(value)
		case "collection", "collections":
			policy.Collections = splitNodeSyncList(value)
		case "data", "type", "types":
			policy.Data = splitNodeSyncList(value)
		case "enabled":
			if !envBoolValue(value, true) {
				policy.Direction = "none"
			}
		}
	}
	if policy.Direction == "" && len(policy.Apps) == 0 && len(policy.Collections) == 0 && len(policy.Data) == 0 {
		return nil
	}
	if policy.Direction == "" {
		policy.Direction = "bidirectional"
	}
	return &policy
}

func normalizeNodeSyncDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pull", "receive", "from_peer", "from-peer":
		return "pull"
	case "push", "send", "to_peer", "to-peer":
		return "push"
	case "bidirectional", "both", "mirror", "readwrite", "read-write":
		return "bidirectional"
	case "none", "off", "disabled", "false", "0", "no":
		return "none"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func splitNodeSyncList(value string) []string {
	value = strings.NewReplacer("|", "+", " ", "+").Replace(value)
	seen := map[string]bool{}
	var out []string
	for _, item := range strings.Split(value, "+") {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func envBoolValue(value string, fallback bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envTokenProducts(key string) map[string]TokenProduct {
	return envTokenProductsValue(os.Getenv(key))
}

func envTokenProductsValue(raw string) map[string]TokenProduct {
	out := map[string]TokenProduct{}
	for _, item := range strings.Split(raw, ",") {
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
