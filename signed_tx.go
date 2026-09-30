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
	"strings"
	"time"
)

const (
	daochiTxContext          = "daochi-tx-v1"
	daochiAppManifestContext = "daochi-app-manifest-v1"
	daochiAppApprovalContext = "daochi-app-approval-v1"
	daochiTxMaxFutureSkew    = 15 * time.Minute
)

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
	Transaction_Normalize(&tx)
	return tx, nil
}

func (s *Server) verifySignedTx(ctx context.Context, r *http.Request, body []byte, tx SignedTxEnvelope, accountID, appID string) error {
	accountID = strings.ToLower(strings.TrimSpace(accountID))
	appID = strings.TrimSpace(appID)
	if tx.ProtocolVersion < 6 {
		return authError{status: http.StatusBadRequest, message: "signed transaction protocol too old"}
	}
	if tx.SignatureContext != "" && tx.SignatureContext != daochiTxContext {
		return authError{status: http.StatusBadRequest, message: "invalid signed transaction context"}
	}
	if !Identity_ValidClientID(tx.TxID) || !Identity_ValidClientID(tx.Nonce) {
		return authError{status: http.StatusBadRequest, message: "invalid signed transaction id"}
	}
	if !Identity_ValidUserID(tx.AccountID) || tx.AccountID != accountID {
		return authError{status: http.StatusUnauthorized, message: "signed transaction account mismatch"}
	}
	if !Identity_ValidNamespace(tx.AppID) || tx.AppID != appID {
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
	signatureField := Codec_DecodeBinaryField(tx.Signature)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid signed transaction signature"}
	}
	message := []byte(Transaction_CanonicalMessage(daochiTxContext, tx))
	if !s.verifier.Verify(publicKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "signed transaction rejected"}
	}
	if err := s.verifyDeviceSignedTx(ctx, tx, message); err != nil {
		return err
	}
	if err := s.store.RecordSignedTx(ctx, tx); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			return authError{status: http.StatusConflict, message: "signed transaction replay"}
		}
		return err
	}
	if err := DeviceKeys_Touch(s.store.db, ctx, tx.AccountID, tx.AppID, tx.DeviceKeyID); err != nil {
		return err
	}
	return nil
}

func (s *Server) verifyDeviceSignedTx(ctx context.Context, tx SignedTxEnvelope, message []byte) error {
	if !Identity_ValidClientID(tx.DeviceKeyID) {
		return authError{status: http.StatusBadRequest, message: "invalid device key id"}
	}
	active := DeviceKeys_Active(s.store.db, ctx, tx.AccountID, tx.AppID, tx.DeviceKeyID)
	deviceKey, found, err := active.Value, active.Found, active.Error
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "device key not registered"}
	}
	publicKeyField := Codec_DecodeBinaryField(deviceKey.PublicKey)
	publicKey := []byte(publicKeyField.Value)
	if publicKeyField.Error != "" || len(publicKey) != ed25519.PublicKeySize {
		return authError{status: http.StatusUnauthorized, message: "invalid app public key"}
	}
	signatureField := Codec_DecodeBinaryField(tx.DeviceSignature)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" || len(signature) != ed25519.SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid device signature"}
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "device signature rejected"}
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}
