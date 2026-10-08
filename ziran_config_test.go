package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Configuration implementation from bf780b1, retained only as a regression oracle.
type BaselineConfig struct {
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
	ChatAPIKey                      string
	ChatAPIEndpoint                 string
	LumiBotToken                    string
	LumiWebhookSecret               string
	LumiOwnerID                     string
	LumiCanvasURL                   string
	FeedbackToken                   string
	ChatModel                       string
	ChatDailyLimit                  int64
	ChatGlobalDailyLimit            int64
}

func baselineLoadConfig() BaselineConfig {
	secret := baselineEnvBytesHex("DAOCHI_TOKEN_SECRET_HEX", nil)
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
	nodeRegistryPublic := ed25519.PublicKey(baselineEnvBytesHexOrFile("DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX", "DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE", nil))
	issuerPublic := baselineEnvBytesHexOrFile("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", nil)
	issuerPrivateBytes := baselineEnvBytesHexOrFile("DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX", "DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE", nil)
	var issuerPrivate ed25519.PrivateKey
	if len(issuerPrivateBytes) == ed25519.SeedSize {
		issuerPrivate = ed25519.NewKeyFromSeed(issuerPrivateBytes)
	} else if len(issuerPrivateBytes) == ed25519.PrivateKeySize {
		issuerPrivate = ed25519.PrivateKey(issuerPrivateBytes)
	}
	if len(issuerPrivate) == ed25519.PrivateKeySize && len(issuerPublic) == 0 {
		issuerPublic = issuerPrivate.Public().(ed25519.PublicKey)
	}
	baseURL := baselineEnvString("DAOCHI_BASE_URL", "https://api.example.com")
	nodeKeyBytes := baselineEnvBytesHexOrFile("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", "DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE", nil)
	var nodePrivateKey ed25519.PrivateKey
	if len(nodeKeyBytes) == ed25519.SeedSize {
		nodePrivateKey = ed25519.NewKeyFromSeed(nodeKeyBytes)
	} else if len(nodeKeyBytes) == ed25519.PrivateKeySize {
		nodePrivateKey = ed25519.PrivateKey(nodeKeyBytes)
	} else if len(nodeKeyBytes) != 0 {
		log.Fatal("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX must contain a 32-byte Ed25519 seed or 64-byte private key")
	}
	return BaselineConfig{
		Addr:                            baselineEnvString("DAOCHI_ADDR", "127.0.0.1:8080"),
		BaseURL:                         baseURL,
		DBPath:                          baselineEnvString("DAOCHI_DB", "daochi.db"),
		AdminToken:                      baselineEnvString("DAOCHI_ADMIN_TOKEN", ""),
		ChallengeTTL:                    baselineEnvDurationSeconds("DAOCHI_CHALLENGE_TTL_SECONDS", 60*time.Second),
		TokenTTL:                        baselineEnvDurationSeconds("DAOCHI_TOKEN_TTL_SECONDS", 3600*time.Second),
		TokenSecret:                     secret,
		TokenSecretEphemeral:            ephemeralSecret,
		MaxBodyBytes:                    baselineEnvInt64("DAOCHI_MAX_BODY_BYTES", 1<<20),
		EncryptedPayloadMaxReturn:       baselineEnvInt("DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN", 0),
		EncryptedPayloadMaxAccountBytes: baselineEnvInt64("DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES", 0),
		EncryptedPayloadRetention:       baselineEnvDurationDays("DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS", 0),
		NodeRegistryPublicKey:           nodeRegistryPublic,
		KnownNodes:                      ConfigValues_Peers(baselineEnvString("DAOCHI_KNOWN_NODES", "")),
		NodeSyncToken:                   baselineEnvString("DAOCHI_NODE_SYNC_TOKEN", ""),
		NodeSyncInterval:                baselineEnvDurationSeconds("DAOCHI_NODE_SYNC_INTERVAL_SECONDS", 0),
		NodeSyncBatchLimit:              baselineEnvInt("DAOCHI_NODE_SYNC_BATCH_LIMIT", 500),
		NodeIdentityKeyFile:             baselineEnvString("DAOCHI_NODE_IDENTITY_KEY_FILE", baselineEnvString("DAOCHI_DB", "daochi.db")+".node-key"),
		NodeIdentityPrivateKey:          nodePrivateKey,
		NodeDisplayName:                 baselineEnvString("DAOCHI_NODE_NAME", "Daochi Node"),
		LANDiscovery:                    ConfigValues_Bool(os.Getenv("DAOCHI_LAN_DISCOVERY"), true),
		WaoziIssuerPublicKey:            issuerPublic,
		WaoziIssuerPrivateKey:           issuerPrivate,
		TokenProducts:                   ConfigValues_Products(baselineEnvString("DAOCHI_TOKEN_PRODUCTS", "")),
		GooglePackageNames:              Sets_FromEnvironment(baselineEnvString("DAOCHI_GOOGLE_PACKAGE_NAMES", "")),
		GoogleServiceAccountJSON:        baselineEnvStringOrFile("DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON", "DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", ""),
		GoogleOAuthClientJSON:           baselineEnvStringOrFile("DAOCHI_GOOGLE_OAUTH_CLIENT_JSON", "DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE", ""),
		GoogleOAuthRefreshToken:         baselineEnvStringOrFile("DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN", "DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", ""),
		MoneroWalletRPCURL:              baselineEnvString("MONERO_WALLET_RPC_URL", ""),
		MoneroWalletRPCUser:             baselineEnvString("MONERO_WALLET_RPC_USER", ""),
		MoneroWalletRPCPassword:         baselineEnvStringOrFile("MONERO_WALLET_RPC_PASSWORD", "MONERO_WALLET_RPC_PASSWORD_FILE", ""),
		MoneroNetwork:                   baselineEnvString("MONERO_NETWORK", "mainnet"),
		MoneroRateAtomicAmount:          baselineEnvInt64("MONERO_RATE_ATOMIC_AMOUNT", 0),
		MoneroRateTokenUnits:            baselineEnvInt64("MONERO_RATE_TOKEN_UNITS", 0),
		MoneroMinimumAtomicAmount:       baselineEnvInt64("MONERO_MINIMUM_ATOMIC_AMOUNT", 1),
		MoneroConfirmationsRequired:     baselineEnvInt64("MONERO_CONFIRMATIONS_REQUIRED", 10),
		TokenDirectPurchasesEnabled:     ConfigValues_Bool(os.Getenv("DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED"), false),
		ChatAPIKey:                      baselineEnvStringOrFile("DAOCHI_CHAT_API_KEY", "DAOCHI_CHAT_API_KEY_FILE", ""),
		ChatAPIEndpoint:                 baselineEnvString("DAOCHI_CHAT_ENDPOINT", ""),
		FeedbackToken:                   baselineEnvStringOrFile("DAOCHI_FEEDBACK_TOKEN", "DAOCHI_FEEDBACK_TOKEN_FILE", ""),
		LumiBotToken:                    baselineEnvStringOrFile("DAOCHI_LUMI_BOT_TOKEN", "DAOCHI_LUMI_BOT_TOKEN_FILE", ""),
		LumiWebhookSecret:               baselineEnvStringOrFile("DAOCHI_LUMI_WEBHOOK_SECRET", "DAOCHI_LUMI_WEBHOOK_SECRET_FILE", ""),
		LumiOwnerID:                     baselineEnvString("DAOCHI_LUMI_OWNER_ID", ""),
		LumiCanvasURL:                   baselineEnvString("DAOCHI_LUMI_CANVAS_URL", "https://inbe.waozi.xyz/build/telegram/index.html"),
		ChatModel:                       baselineEnvString("DAOCHI_CHAT_MODEL", "glm-4.7-flash"),
		ChatDailyLimit:                  baselineEnvInt64("DAOCHI_CHAT_DAILY_LIMIT", 20),
		ChatGlobalDailyLimit:            baselineEnvInt64("DAOCHI_CHAT_GLOBAL_DAILY_LIMIT", 1000),
	}
}

func baselineEnvString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func baselineEnvDurationSeconds(key string, fallback time.Duration) time.Duration {
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

func baselineEnvDurationDays(key string, fallback time.Duration) time.Duration {
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

func baselineEnvInt(key string, fallback int) int {
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

func baselineEnvInt64(key string, fallback int64) int64 {
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

func baselineEnvBytesHex(key string, fallback []byte) []byte {
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

func baselineEnvStringOrFile(key, fileKey, fallback string) string {
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

func baselineEnvBytesHexOrFile(key, fileKey string, fallback []byte) []byte {
	if value := os.Getenv(key); value != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(value))
		if err == nil {
			return decoded
		}
	}
	if value := baselineEnvStringOrFile("", fileKey, ""); value != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(value))
		if err == nil {
			return decoded
		}
	}
	return fallback
}

var configEnvironmentKeys = []string{
	"DAOCHI_LUMI_BOT_TOKEN",
	"DAOCHI_LUMI_BOT_TOKEN_FILE",
	"DAOCHI_LUMI_WEBHOOK_SECRET",
	"DAOCHI_LUMI_WEBHOOK_SECRET_FILE",
	"DAOCHI_LUMI_OWNER_ID",
	"DAOCHI_LUMI_CANVAS_URL",
	"DAOCHI_ADDR",
	"DAOCHI_ADMIN_TOKEN",
	"DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET",
	"DAOCHI_BASE_URL",
	"DAOCHI_CHALLENGE_TTL_SECONDS",
	"DAOCHI_CHAT_API_KEY",
	"DAOCHI_CHAT_API_KEY_FILE",
	"DAOCHI_CHAT_ENDPOINT",
	"DAOCHI_CHAT_MODEL",
	"DAOCHI_CHAT_DAILY_LIMIT",
	"DAOCHI_CHAT_GLOBAL_DAILY_LIMIT",
	"DAOCHI_FEEDBACK_TOKEN",
	"DAOCHI_FEEDBACK_TOKEN_FILE",
	"DAOCHI_DB",
	"DAOCHI_ENCRYPTED_PAYLOAD_MAX_ACCOUNT_BYTES",
	"DAOCHI_ENCRYPTED_PAYLOAD_MAX_RETURN",
	"DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS",
	"DAOCHI_GOOGLE_OAUTH_CLIENT_JSON",
	"DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE",
	"DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN",
	"DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE",
	"DAOCHI_GOOGLE_PACKAGE_NAMES",
	"DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON",
	"DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE",
	"DAOCHI_KNOWN_NODES",
	"DAOCHI_LAN_DISCOVERY",
	"DAOCHI_MAX_BODY_BYTES",
	"DAOCHI_NODE_IDENTITY_KEY_FILE",
	"DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX",
	"DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX_FILE",
	"DAOCHI_NODE_NAME",
	"DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX",
	"DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX_FILE",
	"DAOCHI_NODE_SYNC_BATCH_LIMIT",
	"DAOCHI_NODE_SYNC_INTERVAL_SECONDS",
	"DAOCHI_NODE_SYNC_TOKEN",
	"DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED",
	"DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX",
	"DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX_FILE",
	"DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX",
	"DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE",
	"DAOCHI_TOKEN_PRODUCTS",
	"DAOCHI_TOKEN_SECRET_HEX",
	"DAOCHI_TOKEN_TTL_SECONDS",
	"MONERO_CONFIRMATIONS_REQUIRED",
	"MONERO_MINIMUM_ATOMIC_AMOUNT",
	"MONERO_NETWORK",
	"MONERO_RATE_ATOMIC_AMOUNT",
	"MONERO_RATE_TOKEN_UNITS",
	"MONERO_WALLET_RPC_PASSWORD",
	"MONERO_WALLET_RPC_PASSWORD_FILE",
	"MONERO_WALLET_RPC_URL",
	"MONERO_WALLET_RPC_USER",
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range configEnvironmentKeys {
		t.Setenv(key, "")
	}
	t.Setenv("DAOCHI_TOKEN_SECRET_HEX", strings.Repeat("11", 32))
}

func assertConfigurationMatchesBaseline(t *testing.T) Config {
	t.Helper()
	actual := Config_Load()
	expected := baselineLoadConfig()
	actualType := reflect.TypeOf(actual)
	expectedType := reflect.TypeOf(expected)
	if actualType.NumField() != expectedType.NumField() {
		t.Fatal("configuration fields changed")
	}
	for i := 0; i < actualType.NumField(); i++ {
		got := actualType.Field(i)
		want := expectedType.Field(i)
		if got.Name != want.Name || got.Type != want.Type || got.Tag != want.Tag {
			t.Fatalf("configuration field %d: got %#v, want %#v", i, got, want)
		}
		if !reflect.DeepEqual(reflect.ValueOf(actual).Field(i).Interface(), reflect.ValueOf(expected).Field(i).Interface()) {
			t.Fatalf("configuration field %s differs", got.Name)
		}
	}
	return actual
}

func TestZiranConfigDefaultsAndKeyIdentity(t *testing.T) {
	clearConfigEnvironment(t)
	assertConfigurationMatchesBaseline(t)
	for _, privateKeySize := range []int{1, 31, 32, 33, 64, 65} {
		t.Setenv("DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX", strings.Repeat("22", privateKeySize))
		actual := assertConfigurationMatchesBaseline(t)
		if len(actual.WaoziIssuerPrivateKey) == ed25519.PrivateKeySize {
			before := append([]byte(nil), actual.WaoziIssuerPrivateKey...)
			if cap(actual.WaoziIssuerPublicKey) != ed25519.PublicKeySize {
				t.Fatal("derived public key has excess capacity")
			}
			actual.WaoziIssuerPublicKey[0] ^= 0xff
			if !bytes.Equal(before, actual.WaoziIssuerPrivateKey) {
				t.Fatal("derived public key aliases private key storage")
			}
		}
	}
	t.Setenv("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX", "abcdef")
	t.Setenv("DAOCHI_NODE_REGISTRY_PUBLIC_KEY_HEX", "111213")
	for _, nodeKeySize := range []int{0, 32, 64} {
		t.Setenv("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", strings.Repeat("33", nodeKeySize))
		assertConfigurationMatchesBaseline(t)
	}
	t.Setenv("DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX", "")
	t.Setenv("DAOCHI_TOKEN_ISSUER_PRIVATE_KEY_HEX", "malformed")
	assertConfigurationMatchesBaseline(t)
}

func TestZiranConfigEnvironmentAndFiles(t *testing.T) {
	clearConfigEnvironment(t)
	file := filepath.Join(t.TempDir(), "configuration")
	if err := os.WriteFile(file, []byte(" \u2000\nabcdef\n\t"), 0600); err != nil {
		t.Fatal(err)
	}
	fallback := []byte{7, 8, 9}
	for _, path := range []string{"", " \u2000" + file + "\t", file + ".missing"} {
		t.Setenv("CONFIG_FILE_PATH", path)
		for _, value := range []string{"", " ", "direct", " abcdef ", "00", "badhex", "\xff"} {
			t.Setenv("CONFIG_TEST_VALUE", value)
			if got, want := Config_EnvString("CONFIG_TEST_VALUE", "fallback"), baselineEnvString("CONFIG_TEST_VALUE", "fallback"); got != want {
				t.Fatalf("environment string: got %q, want %q", got, want)
			}
			if got, want := Config_EnvStringOrFile("CONFIG_TEST_VALUE", "CONFIG_FILE_PATH", "fallback"), baselineEnvStringOrFile("CONFIG_TEST_VALUE", "CONFIG_FILE_PATH", "fallback"); got != want {
				t.Fatalf("file string: got %q, want %q", got, want)
			}
			got := Config_EnvBytesHexOrFile("CONFIG_TEST_VALUE", "CONFIG_FILE_PATH", fallback)
			want := baselineEnvBytesHexOrFile("CONFIG_TEST_VALUE", "CONFIG_FILE_PATH", fallback)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("file bytes: got %#v, want %#v", got, want)
			}
		}
	}
	t.Setenv("CONFIG_TEST_VALUE", "")
	got := Config_EnvBytesHex("CONFIG_TEST_VALUE", fallback)
	if &got[0] != &fallback[0] {
		t.Fatal("byte fallback storage was copied")
	}
	for _, value := range []string{"00", "AbCdEf", "1122334455"} {
		t.Setenv("CONFIG_TEST_VALUE", value)
		if got, want := Config_EnvBytesHex("CONFIG_TEST_VALUE", fallback), baselineEnvBytesHex("CONFIG_TEST_VALUE", fallback); !reflect.DeepEqual(got, want) {
			t.Fatalf("strict hexadecimal decoding: got %#v, want %#v", got, want)
		}
	}
	t.Setenv("DAOCHI_GOOGLE_SERVICE_ACCOUNT_JSON_FILE", file)
	t.Setenv("DAOCHI_GOOGLE_OAUTH_CLIENT_JSON_FILE", file)
	t.Setenv("DAOCHI_GOOGLE_OAUTH_REFRESH_TOKEN_FILE", file)
	t.Setenv("MONERO_WALLET_RPC_PASSWORD_FILE", file)
	t.Setenv("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX", "malformed")
	t.Setenv("DAOCHI_TOKEN_ISSUER_PUBLIC_KEY_HEX_FILE", file)
	t.Setenv("DAOCHI_DB", "database\nname")
	t.Setenv("DAOCHI_NODE_NAME", "node😀")
	t.Setenv("DAOCHI_ADDR", "[::1]:8090")
	t.Setenv("DAOCHI_BASE_URL", " https://example.test ")
	t.Setenv("DAOCHI_KNOWN_NODES", "Node=https://peer.test;mode=pull;apps=a+b")
	t.Setenv("DAOCHI_TOKEN_PRODUCTS", "coins:100:999")
	t.Setenv("DAOCHI_GOOGLE_PACKAGE_NAMES", " com.a , com.b ")
	t.Setenv("DAOCHI_LAN_DISCOVERY", "OFF")
	t.Setenv("DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED", "yes")
	assertConfigurationMatchesBaseline(t)
}

func TestZiranConfigIntegerAndDurationBoundaries(t *testing.T) {
	clearConfigEnvironment(t)
	for _, value := range []string{"", "+1", "0", "-1", "0002", "9223372036854775807", "-9223372036854775808"} {
		t.Setenv("CONFIG_TEST_VALUE", value)
		if got, want := Config_EnvInt("CONFIG_TEST_VALUE", 17), baselineEnvInt("CONFIG_TEST_VALUE", 17); got != want {
			t.Fatalf("integer %q: got %d, want %d", value, got, want)
		}
		if got, want := Config_EnvInt64("CONFIG_TEST_VALUE", 19), baselineEnvInt64("CONFIG_TEST_VALUE", 19); got != want {
			t.Fatalf("wide integer %q: got %d, want %d", value, got, want)
		}
		if got, want := Config_EnvDurationSeconds("CONFIG_TEST_VALUE", 23*time.Second), baselineEnvDurationSeconds("CONFIG_TEST_VALUE", 23*time.Second); got != want {
			t.Fatalf("seconds %q: got %d, want %d", value, got, want)
		}
		if got, want := Config_EnvDurationDays("CONFIG_TEST_VALUE", 29*time.Second), baselineEnvDurationDays("CONFIG_TEST_VALUE", 29*time.Second); got != want {
			t.Fatalf("days %q: got %d, want %d", value, got, want)
		}
	}
	t.Setenv("DAOCHI_TOKEN_TTL_SECONDS", "9223372036854775807")
	t.Setenv("DAOCHI_ENCRYPTED_PAYLOAD_RETENTION_DAYS", "9223372036854775807")
	t.Setenv("MONERO_CONFIRMATIONS_REQUIRED", "9223372036854775807")
	actual := assertConfigurationMatchesBaseline(t)
	if actual.MoneroConfirmationsRequired != math.MaxInt64 {
		t.Fatal("maximum integer changed")
	}
}

func TestZiranConfigEphemeralSecret(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("DAOCHI_TOKEN_SECRET_HEX", "11")
	t.Setenv("DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET", "true")
	first := Config_Load()
	second := Config_Load()
	if !first.TokenSecretEphemeral || len(first.TokenSecret) != 32 || bytes.Equal(first.TokenSecret, second.TokenSecret) {
		t.Fatal("ephemeral secret must contain fresh random bytes")
	}
}

func TestZiranConfigFatalHelper(t *testing.T) {
	operation := os.Getenv("CONFIG_PORT_CASE")
	if operation == "" {
		t.Skip("subprocess helper")
	}
	log.SetFlags(0)
	baseline := os.Getenv("CONFIG_PORT_BASELINE") == "1"
	switch operation {
	case "load":
		if baseline {
			baselineLoadConfig()
		} else {
			Config_Load()
		}
	case "seconds":
		if baseline {
			baselineEnvDurationSeconds("CONFIG_TEST_VALUE", 0)
		} else {
			Config_EnvDurationSeconds("CONFIG_TEST_VALUE", 0)
		}
	case "days":
		if baseline {
			baselineEnvDurationDays("CONFIG_TEST_VALUE", 0)
		} else {
			Config_EnvDurationDays("CONFIG_TEST_VALUE", 0)
		}
	case "integer":
		if baseline {
			baselineEnvInt("CONFIG_TEST_VALUE", 0)
		} else {
			Config_EnvInt("CONFIG_TEST_VALUE", 0)
		}
	case "wide":
		if baseline {
			baselineEnvInt64("CONFIG_TEST_VALUE", 0)
		} else {
			Config_EnvInt64("CONFIG_TEST_VALUE", 0)
		}
	case "hex":
		if baseline {
			baselineEnvBytesHex("CONFIG_TEST_VALUE", nil)
		} else {
			Config_EnvBytesHex("CONFIG_TEST_VALUE", nil)
		}
	default:
		t.Fatal("unknown subprocess operation")
	}
	t.Fatal("invalid configuration did not abort startup")
}

func TestZiranConfigFatalMessagesAgainstBaseline(t *testing.T) {
	clearConfigEnvironment(t)
	cases := []struct {
		operation string
		settings  map[string]string
	}{
		{"load", map[string]string{"DAOCHI_TOKEN_SECRET_HEX": ""}},
		{"load", map[string]string{"DAOCHI_TOKEN_SECRET_HEX": "11"}},
		{"load", map[string]string{"DAOCHI_TOKEN_SECRET_HEX": "malformed", "DAOCHI_ALLOW_EPHEMERAL_TOKEN_SECRET": "1"}},
		{"load", map[string]string{"DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX": "11"}},
		{"seconds", map[string]string{"CONFIG_TEST_VALUE": " 1"}},
		{"days", map[string]string{"CONFIG_TEST_VALUE": "1.5"}},
		{"integer", map[string]string{"CONFIG_TEST_VALUE": "9223372036854775808"}},
		{"wide", map[string]string{"CONFIG_TEST_VALUE": "-9223372036854775809"}},
		{"hex", map[string]string{"CONFIG_TEST_VALUE": " abcdef "}},
	}
	for _, test := range cases {
		var outputs [2][]byte
		for implementation := range outputs {
			command := exec.Command(os.Args[0], "-test.run=^TestZiranConfigFatalHelper$")
			command.Env = append([]string{}, os.Environ()...)
			command.Env = append(command.Env, "CONFIG_PORT_CASE="+test.operation, fmt.Sprintf("CONFIG_PORT_BASELINE=%d", implementation))
			for key, value := range test.settings {
				command.Env = append(command.Env, key+"="+value)
			}
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("invalid %s must exit 1: error=%v output=%s", test.operation, err, output)
			}
			outputs[implementation] = output
		}
		if !bytes.Equal(outputs[0], outputs[1]) {
			t.Fatalf("fatal %s message differs: got %s, want %s", test.operation, outputs[0], outputs[1])
		}
	}
}
