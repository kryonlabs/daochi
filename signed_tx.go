package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	daochiTxContext          = "daochi-tx-v1"
	daochiAppManifestContext = "daochi-app-manifest-v1"
	daochiAppApprovalContext = "daochi-app-approval-v1"
	daochiTxMaxFutureSkew    = 15 * time.Minute
)

type SignedTxEnvelope struct {
	ProtocolVersion  int    `json:"protocol_version"`
	TxID             string `json:"tx_id"`
	AccountID        string `json:"account_id"`
	AppID            string `json:"app_id"`
	AppKeyID         string `json:"app_key_id"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	BodySHA256       string `json:"body_sha256"`
	Nonce            string `json:"nonce"`
	ExpiresAt        int64  `json:"expires_at"`
	SignatureContext string `json:"signature_context,omitempty"`
	Signature        string `json:"signature"`
	AppSignature     string `json:"app_signature"`
}

type SignedAppGrantRequest struct {
	Tx    SignedTxEnvelope `json:"tx"`
	Grant AppGrantRequest  `json:"grant"`
}

type SignedAppRegistrationRequest struct {
	Manifest          AppManifest `json:"manifest"`
	ManifestSignature string      `json:"manifest_signature"`
	ApprovalSignature string      `json:"approval_signature"`
}

type AppManifest struct {
	ManifestVersion    int              `json:"manifest_version"`
	AppID              string           `json:"app_id"`
	DisplayName        string           `json:"display_name"`
	Description        string           `json:"description,omitempty"`
	HomepageURL        string           `json:"homepage_url,omitempty"`
	SourceURL          string           `json:"source_url,omitempty"`
	Status             string           `json:"status,omitempty"`
	ExpiresAt          int64            `json:"expires_at,omitempty"`
	AppSchemaVersion   int              `json:"app_schema_version,omitempty"`
	MinClientVersion   string           `json:"min_supported_client_version,omitempty"`
	CurrentVersion     string           `json:"current_client_version,omitempty"`
	CompatibilityUntil string           `json:"compatibility_until,omitempty"`
	Keys               []AppKey         `json:"keys"`
	Collections        []AppCollection  `json:"collections,omitempty"`
	Capabilities       []string         `json:"capabilities,omitempty"`
	Features           []AppFeature     `json:"features,omitempty"`
	LegacyProtocols    []LegacyProtocol `json:"legacy_protocols,omitempty"`
	TokenPolicies      []TokenPolicy    `json:"token_policies,omitempty"`
}

type AppKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Purpose   string `json:"purpose,omitempty"`
	Status    string `json:"status,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

type TokenPolicy struct {
	AssetID    string `json:"asset_id"`
	Permission string `json:"permission"`
	Status     string `json:"status,omitempty"`
}

func readSignedTxHeader(r *http.Request) (SignedTxEnvelope, error) {
	value := strings.TrimSpace(r.Header.Get("X-Daochi-Tx"))
	if value == "" {
		return SignedTxEnvelope{}, authError{status: http.StatusUnauthorized, message: "signed transaction required"}
	}
	var raw []byte
	if strings.HasPrefix(value, "{") {
		raw = []byte(value)
	} else if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		raw = decoded
	} else if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		raw = decoded
	} else {
		return SignedTxEnvelope{}, authError{status: http.StatusBadRequest, message: "invalid signed transaction"}
	}
	var tx SignedTxEnvelope
	if err := json.Unmarshal(raw, &tx); err != nil {
		return SignedTxEnvelope{}, authError{status: http.StatusBadRequest, message: "invalid signed transaction"}
	}
	normalizeSignedTx(&tx)
	return tx, nil
}

func normalizeSignedTx(tx *SignedTxEnvelope) {
	tx.TxID = strings.TrimSpace(tx.TxID)
	tx.AccountID = strings.ToLower(strings.TrimSpace(tx.AccountID))
	tx.AppID = strings.TrimSpace(tx.AppID)
	tx.AppKeyID = strings.TrimSpace(tx.AppKeyID)
	tx.Method = strings.ToUpper(strings.TrimSpace(tx.Method))
	tx.Path = strings.TrimSpace(tx.Path)
	tx.BodySHA256 = strings.ToLower(strings.TrimSpace(tx.BodySHA256))
	tx.Nonce = strings.TrimSpace(tx.Nonce)
	tx.SignatureContext = strings.TrimSpace(tx.SignatureContext)
	tx.Signature = strings.TrimSpace(tx.Signature)
	tx.AppSignature = strings.TrimSpace(tx.AppSignature)
}

func (s *Server) verifySignedTx(ctx context.Context, r *http.Request, body []byte, tx SignedTxEnvelope, accountID, appID string) error {
	accountID = strings.ToLower(strings.TrimSpace(accountID))
	appID = strings.TrimSpace(appID)
	if tx.ProtocolVersion < 6 {
		return authError{status: http.StatusBadRequest, message: "signed transaction protocol too old"}
	}
	if !validClientID(tx.TxID) || !validClientID(tx.Nonce) {
		return authError{status: http.StatusBadRequest, message: "invalid signed transaction id"}
	}
	if !validUserID(tx.AccountID) || tx.AccountID != accountID {
		return authError{status: http.StatusUnauthorized, message: "signed transaction account mismatch"}
	}
	if !validNamespace(tx.AppID) || tx.AppID != appID {
		return authError{status: http.StatusUnauthorized, message: "signed transaction app mismatch"}
	}
	if tx.Method != r.Method || tx.Path != r.URL.Path {
		return authError{status: http.StatusUnauthorized, message: "signed transaction route mismatch"}
	}
	sum := sha256.Sum256(body)
	if tx.BodySHA256 != hex.EncodeToString(sum[:]) {
		return authError{status: http.StatusUnauthorized, message: "signed transaction body mismatch"}
	}
	now := time.Now()
	if tx.ExpiresAt <= now.Unix() || time.Unix(tx.ExpiresAt, 0).After(now.Add(daochiTxMaxFutureSkew)) {
		return authError{status: http.StatusUnauthorized, message: "signed transaction expired"}
	}
	publicKey, found, err := s.store.PublicKey(ctx, tx.AccountID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	signature, err := decodeBinaryField(tx.Signature)
	if err != nil || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid signed transaction signature"}
	}
	message := canonicalSignedTxMessage(tx)
	if !s.verifier.Verify(publicKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "signed transaction rejected"}
	}
	if err := s.verifyAppSignedTx(ctx, tx, message); err != nil {
		return err
	}
	if err := s.store.RecordSignedTx(ctx, tx); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			return authError{status: http.StatusConflict, message: "signed transaction replay"}
		}
		return err
	}
	return nil
}

func (s *Server) verifyAppSignedTx(ctx context.Context, tx SignedTxEnvelope, message []byte) error {
	if !validClientID(tx.AppKeyID) {
		return authError{status: http.StatusBadRequest, message: "invalid app key id"}
	}
	appKey, found, err := s.store.ActiveAppKey(ctx, tx.AppID, tx.AppKeyID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "app key not registered"}
	}
	if !strings.EqualFold(appKey.Algorithm, "Ed25519") {
		return authError{status: http.StatusUnauthorized, message: "unsupported app key algorithm"}
	}
	publicKey, err := decodeBinaryField(appKey.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return authError{status: http.StatusUnauthorized, message: "invalid app public key"}
	}
	signature, err := decodeBinaryField(tx.AppSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid app signature"}
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "app signature rejected"}
	}
	return nil
}

func canonicalSignedTxMessage(tx SignedTxEnvelope) []byte {
	context := tx.SignatureContext
	if context == "" {
		context = daochiTxContext
	}
	var b strings.Builder
	b.WriteString(context)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(tx.ProtocolVersion))
	b.WriteByte('\n')
	b.WriteString(tx.TxID)
	b.WriteByte('\n')
	b.WriteString(tx.AccountID)
	b.WriteByte('\n')
	b.WriteString(tx.AppID)
	b.WriteByte('\n')
	b.WriteString(tx.AppKeyID)
	b.WriteByte('\n')
	b.WriteString(tx.Method)
	b.WriteByte('\n')
	b.WriteString(tx.Path)
	b.WriteByte('\n')
	b.WriteString(tx.BodySHA256)
	b.WriteByte('\n')
	b.WriteString(tx.Nonce)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(tx.ExpiresAt, 10))
	b.WriteByte('\n')
	return []byte(b.String())
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
