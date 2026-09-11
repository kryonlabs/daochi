package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	deviceRegistrationContext = "daochi-device-registration-v1"
	deviceRevocationContext   = "daochi-device-revocation-v1"
)

type DeviceKey struct {
	AccountID  string `json:"account_id,omitempty"`
	AppID      string `json:"app_id"`
	KeyID      string `json:"device_key_id"`
	ClientID   string `json:"client_id"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

type DeviceRegistrationRequest struct {
	AppID     string `json:"app_id"`
	KeyID     string `json:"device_key_id"`
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

type DeviceRevocationRequest struct {
	AppID     string `json:"app_id"`
	KeyID     string `json:"device_key_id"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

func canonicalDeviceRegistrationMessage(accountID string, request DeviceRegistrationRequest) []byte {
	var message strings.Builder

	message.WriteString(deviceRegistrationContext)
	message.WriteByte('\n')
	message.WriteString(accountID)
	message.WriteByte('\n')
	message.WriteString(request.AppID)
	message.WriteByte('\n')
	message.WriteString(request.KeyID)
	message.WriteByte('\n')
	message.WriteString(request.ClientID)
	message.WriteByte('\n')
	message.WriteString(request.PublicKey)
	message.WriteByte('\n')
	message.WriteString(request.Nonce)
	message.WriteByte('\n')
	message.WriteString(strconv.FormatInt(request.ExpiresAt, 10))
	message.WriteByte('\n')
	return []byte(message.String())
}

func normalizeDeviceRegistration(request *DeviceRegistrationRequest) {
	request.AppID = strings.TrimSpace(request.AppID)
	request.KeyID = strings.TrimSpace(request.KeyID)
	request.ClientID = strings.TrimSpace(request.ClientID)
	request.PublicKey = strings.ToLower(strings.TrimSpace(request.PublicKey))
	request.Nonce = strings.TrimSpace(request.Nonce)
	request.Signature = strings.TrimSpace(request.Signature)
}

func canonicalDeviceRevocationMessage(accountID string, request DeviceRevocationRequest) []byte {
	var message strings.Builder

	message.WriteString(deviceRevocationContext)
	message.WriteByte('\n')
	message.WriteString(accountID)
	message.WriteByte('\n')
	message.WriteString(request.AppID)
	message.WriteByte('\n')
	message.WriteString(request.KeyID)
	message.WriteByte('\n')
	message.WriteString(request.Nonce)
	message.WriteByte('\n')
	message.WriteString(strconv.FormatInt(request.ExpiresAt, 10))
	message.WriteByte('\n')
	return []byte(message.String())
}

func normalizeDeviceRevocation(request *DeviceRevocationRequest) {
	request.AppID = strings.TrimSpace(request.AppID)
	request.KeyID = strings.TrimSpace(request.KeyID)
	request.Nonce = strings.TrimSpace(request.Nonce)
	request.Signature = strings.TrimSpace(request.Signature)
}

func validDeviceRequestExpiry(expiresAt int64) bool {
	now := time.Now()
	return expiresAt > now.Unix() &&
		!time.Unix(expiresAt, 0).After(now.Add(daochiTxMaxFutureSkew))
}

func validDeviceRegistration(request DeviceRegistrationRequest) bool {
	if !validNamespace(request.AppID) || !validClientID(request.KeyID) ||
		!validClientID(request.ClientID) || !validClientID(request.Nonce) {
		return false
	}
	publicKey, err := hex.DecodeString(request.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return validDeviceRequestExpiry(request.ExpiresAt)
}

func (s *Server) verifyDeviceRegistration(ctx context.Context, accountID string, request DeviceRegistrationRequest) error {
	if !validDeviceRegistration(request) {
		return authError{status: http.StatusBadRequest, message: "invalid device registration"}
	}
	accountKey, found, err := s.store.PublicKey(ctx, accountID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	signature, err := decodeBinaryField(request.Signature)
	if err != nil || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid device registration signature"}
	}
	message := canonicalDeviceRegistrationMessage(accountID, request)
	if !s.verifier.Verify(accountKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "device registration rejected"}
	}
	return nil
}

func (s *Server) verifyDeviceRevocation(ctx context.Context, accountID string, request DeviceRevocationRequest) error {
	if !validNamespace(request.AppID) || !validClientID(request.KeyID) ||
		!validClientID(request.Nonce) || !validDeviceRequestExpiry(request.ExpiresAt) {
		return authError{status: http.StatusBadRequest, message: "invalid device revocation"}
	}
	accountKey, found, err := s.store.PublicKey(ctx, accountID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	signature, err := decodeBinaryField(request.Signature)
	if err != nil || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid device revocation signature"}
	}
	if !s.verifier.Verify(accountKey, canonicalDeviceRevocationMessage(accountID, request), signature) {
		return authError{status: http.StatusUnauthorized, message: "device revocation rejected"}
	}
	return nil
}

func (s *Server) handleAccountDevices(w http.ResponseWriter, r *http.Request) {
	accountID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		devices, err := s.store.ListDeviceKeys(r.Context(), accountID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "device list failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
		return
	case http.MethodDelete:
		s.handleDeviceRevocation(w, r, accountID)
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var request DeviceRegistrationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid device registration")
		return
	}
	normalizeDeviceRegistration(&request)
	if err := s.verifyDeviceRegistration(r.Context(), accountID, request); err != nil {
		s.writeAuthError(w, err)
		return
	}
	device := DeviceKey{
		AccountID: accountID,
		AppID:     request.AppID,
		KeyID:     request.KeyID,
		ClientID:  request.ClientID,
		PublicKey: request.PublicKey,
	}
	if err := s.store.RegisterDeviceKey(r.Context(), device, request.Nonce); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			writeError(w, http.StatusConflict, "device registration replay")
			return
		}
		writeError(w, http.StatusInternalServerError, "device registration failed")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) handleDeviceRevocation(w http.ResponseWriter, r *http.Request, accountID string) {
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var request DeviceRevocationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid device revocation")
		return
	}
	normalizeDeviceRevocation(&request)
	if err := s.verifyDeviceRevocation(r.Context(), accountID, request); err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.RevokeDeviceKey(r.Context(), accountID, request); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			writeError(w, http.StatusConflict, "device revocation replay")
			return
		}
		writeError(w, http.StatusInternalServerError, "device revocation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Store) RegisterDeviceKey(ctx context.Context, device DeviceKey, nonce string) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := recordDeviceNonce(ctx, transaction, device.AccountID, nonce); err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO server_device_keys(account_id,app_id,device_key_id,client_id,public_key,created_at,last_used_at,revoked_at)
VALUES(?1,?2,?3,?4,?5,?6,?6,'')
ON CONFLICT(account_id,app_id,device_key_id) DO UPDATE SET
 client_id=excluded.client_id,
 public_key=excluded.public_key,
 last_used_at=excluded.last_used_at,
 revoked_at=''`, device.AccountID, device.AppID, device.KeyID, device.ClientID,
		device.PublicKey, canonicalNow())
	if err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) RevokeDeviceKey(ctx context.Context, accountID string, request DeviceRevocationRequest) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := recordDeviceNonce(ctx, transaction, accountID, request.Nonce); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE server_device_keys SET revoked_at=?4
WHERE account_id=?1 AND app_id=?2 AND device_key_id=?3 AND revoked_at=''`,
		accountID, request.AppID, request.KeyID, canonicalNow())
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return sql.ErrNoRows
	}
	return transaction.Commit()
}

func recordDeviceNonce(ctx context.Context, transaction *sql.Tx,
	accountID, nonce string) error {
	cutoff := canonicalTimestamp(time.Now().Add(-2 * daochiTxMaxFutureSkew))
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM server_device_registration_nonces WHERE created_at<?1`, cutoff); err != nil {
		return err
	}
	_, err := transaction.ExecContext(ctx, `
INSERT INTO server_device_registration_nonces(account_id,nonce,created_at)
VALUES(?1,?2,?3)`, accountID, nonce, canonicalNow())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errSignedTxReplay
	}
	return err
}

func (s *Store) ActiveDeviceKey(ctx context.Context, accountID, appID, keyID string) (DeviceKey, bool, error) {
	var device DeviceKey
	err := s.db.QueryRowContext(ctx, `
SELECT account_id,app_id,device_key_id,client_id,public_key,created_at,last_used_at,revoked_at
FROM server_device_keys
WHERE account_id=?1 AND app_id=?2 AND device_key_id=?3 AND revoked_at=''`,
		accountID, appID, keyID).Scan(&device.AccountID, &device.AppID, &device.KeyID,
		&device.ClientID, &device.PublicKey, &device.CreatedAt, &device.LastUsedAt,
		&device.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceKey{}, false, nil
	}
	return device, err == nil, err
}

func (s *Store) TouchDeviceKey(ctx context.Context, accountID, appID, keyID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE server_device_keys SET last_used_at=?4
WHERE account_id=?1 AND app_id=?2 AND device_key_id=?3 AND revoked_at=''`,
		accountID, appID, keyID, canonicalNow())
	return err
}

func (s *Store) ListDeviceKeys(ctx context.Context, accountID string) ([]DeviceKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT account_id,app_id,device_key_id,client_id,public_key,created_at,last_used_at,revoked_at
FROM server_device_keys WHERE account_id=?1 ORDER BY app_id,device_key_id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []DeviceKey
	for rows.Next() {
		var device DeviceKey
		if err := rows.Scan(&device.AccountID, &device.AppID, &device.KeyID,
			&device.ClientID, &device.PublicKey, &device.CreatedAt,
			&device.LastUsedAt, &device.RevokedAt); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}
