package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// These fixtures preserve the handwritten request boundary at be7f3a0.
// They remain independent regression oracles for the canonical Ziran module.
func baselineBoundaryReadJSON(w http.ResponseWriter, r *http.Request, maxBody int64) JSONResult {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return JSONResult{Error: errors.New("request body too large")}
	}
	if !json.Valid(body) {
		return JSONResult{Error: errors.New("invalid json")}
	}
	return JSONResult{Value: body}
}

func baselineBoundaryEncryptedPayloadLimit(r *http.Request, configuredMax int) (int, error) {
	limit := configuredMax
	if text := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Limit", "X-Ksync-Limit"}); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed <= 0 {
			return 0, errors.New("invalid X-Daochi-Limit")
		}
		limit = parsed
	}
	if configuredMax > 0 && (limit == 0 || limit > configuredMax) {
		limit = configuredMax
	}
	return limit, nil
}

func baselineBoundarySyncTransitionMode(req SyncRequest) string {
	if req.ProtocolVersion >= 5 {
		return "encrypted_primary"
	}
	if req.ProtocolVersion >= 4 {
		return "dual_write"
	}
	return ""
}

func baselineBoundaryIncludeLegacyPrivateData(req SyncRequest) bool {
	return req.ProtocolVersion < 5 || req.IncludeLegacyData
}

func baselineBoundarySyncRequestHasLocalChanges(req SyncRequest) bool {
	return req.FullSyncRequested ||
		len(req.MeditationLogs) > 0 ||
		len(req.Habits) > 0 ||
		len(req.HabitDays) > 0 ||
		len(req.Sessions) > 0 ||
		len(req.EncryptedRecords) > 0 ||
		len(req.Ops) > 0
}

func baselineBoundarySyncRequestPublicKey(req SyncRequest) ([]byte, error) {
	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, nil
	}
	publicKeyField, decodeError := referenceBinaryField(req.PublicKey)
	publicKey := publicKeyField
	if decodeError != nil {
		return nil, errors.New("invalid public_key")
	}
	if len(publicKey) != mlDSA44PublicKeySize {
		return nil, errors.New("wrong public_key size")
	}
	if err := EncryptedRecord_ValidateAccountKey(req.UserIDHash, publicKey); err != nil {
		return nil, errors.New("public_key does not match user_id_hash")
	}
	return publicKey, nil
}

func baselineBoundaryApplyHeaderUser(r *http.Request, bodyUser *string) error {
	userHeader := HttpAuth_UserHeader(r)
	headerUser, headerName := userHeader.Value, userHeader.Name
	if headerUser == "" {
		return errors.New("missing X-Daochi-User")
	}
	if *bodyUser == "" {
		*bodyUser = headerUser
		return nil
	}
	*bodyUser = strings.ToLower(strings.TrimSpace(*bodyUser))
	if *bodyUser != headerUser {
		return errors.New(headerName + " does not match user_id_hash")
	}
	return nil
}

func baselineBoundaryRequestSignatureHeader(r *http.Request) (string, string) {
	if value := strings.TrimSpace(r.Header.Get("X-Daochi-Signature")); value != "" {
		return value, daochiSignatureContext
	}
	if value := strings.TrimSpace(r.Header.Get("X-Ksync-Signature")); value != "" {
		return value, legacySyncSignatureContext
	}
	if value := strings.TrimSpace(r.Header.Get("X-Inbe-Signature")); value != "" {
		return value, legacyInbeSignatureContext
	}
	return "", legacySyncSignatureContext
}

func baselineBoundaryReadSyncRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, SyncRequest, error) {
	bodyResult := baselineBoundaryReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, SyncRequest{}, err
	}
	req, err := baselineBoundaryParseSyncRequestBody(body)
	return body, req, err
}

func baselineBoundaryParseSyncRequestBody(body []byte) (SyncRequest, error) {
	var req SyncRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.AppID = strings.TrimSpace(req.AppID)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.ClientID = strings.TrimSpace(req.ClientID)
	for i := range req.EncryptedRecords {
		req.EncryptedRecords[i].Collection = strings.TrimSpace(req.EncryptedRecords[i].Collection)
		req.EncryptedRecords[i].ID = strings.TrimSpace(req.EncryptedRecords[i].ID)
		req.EncryptedRecords[i].KeyID = strings.TrimSpace(req.EncryptedRecords[i].KeyID)
		req.EncryptedRecords[i].Nonce = strings.TrimSpace(req.EncryptedRecords[i].Nonce)
		req.EncryptedRecords[i].UpdatedAt = strings.TrimSpace(req.EncryptedRecords[i].UpdatedAt)
		req.EncryptedRecords[i].ContentHash = strings.ToLower(strings.TrimSpace(req.EncryptedRecords[i].ContentHash))
		req.EncryptedRecords[i].ParentID = strings.TrimSpace(req.EncryptedRecords[i].ParentID)
	}
	return req, nil
}

func baselineBoundaryIsEncryptedSyncEnvelope(body []byte) bool {
	var envelope struct {
		V          int    `json:"v"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if !json.Valid(body) || json.Unmarshal(body, &envelope) != nil {
		return false
	}
	return (envelope.V == 1 || envelope.V == 2) &&
		strings.TrimSpace(envelope.Nonce) != "" &&
		strings.TrimSpace(envelope.Ciphertext) != ""
}

func baselineBoundaryEmptySyncChanges() SyncChanges {
	return SyncChanges{
		Habits:           []Habit{},
		HabitDays:        []HabitDay{},
		Sessions:         []Session{},
		MeditationLogs:   []MeditationLog{},
		SocialCache:      []SocialSnapshot{},
		EncryptedRecords: []EncryptedRecord{},
	}
}

func baselineBoundaryReadLoginRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, LoginRequest, error) {
	var req LoginRequest
	bodyResult := baselineBoundaryReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.ClientID = strings.TrimSpace(req.ClientID)
	return body, req, nil
}

func baselineBoundaryReadDeleteRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, DeleteRequest, error) {
	var req DeleteRequest
	bodyResult := baselineBoundaryReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	return body, req, nil
}

func baselineBoundaryReadDeleteWithKeyRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (DeleteWithKeyRequest, error) {
	var req DeleteWithKeyRequest
	bodyResult := baselineBoundaryReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.ExportedKey = strings.TrimSpace(req.ExportedKey)
	if !Identity_ValidUserID(req.UserIDHash) {
		return req, errors.New("invalid user_id_hash")
	}
	if req.ExportedKey == "" {
		return req, errors.New("exported_key required")
	}
	return req, nil
}

func baselineBoundaryNormalizeMeditationDurations(logs []MeditationLog) {
	for i := range logs {
		if logs[i].DurationSeconds == 0 && logs[i].Duration != 0 {
			logs[i].DurationSeconds = logs[i].Duration
		}
	}
}

const (
	accountKeyHeader       = "ksync-account-key-v1"
	legacyAccountKeyHeader = "lyra-account-key-v1"
	legacyUkuKeyHeader     = "account-key-v1"
	legacyInbeKeyHeader    = "inbe-sync-key-v1"
)

func baselineBoundaryParseExportedSyncKey(text string) (ExportedAccountKey, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return ExportedAccountKey{}, errors.New("invalid account key file")
	}
	header := strings.TrimSpace(lines[0])
	if header != accountKeyHeader && header != legacyAccountKeyHeader &&
		header != legacyUkuKeyHeader && header != legacyInbeKeyHeader {
		return ExportedAccountKey{}, errors.New("invalid account key file")
	}
	algorithmOK := false
	publicID := ""
	privateKeyText := ""
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "algorithm":
			algorithmOK = strings.TrimSpace(value) == "ML-DSA-44"
		case "public_id":
			publicID = strings.ToLower(strings.TrimSpace(value))
		case "private_key":
			privateKeyText = strings.TrimSpace(value)
		}
	}
	if !algorithmOK {
		return ExportedAccountKey{}, errors.New("account key algorithm must be ML-DSA-44")
	}
	if publicID != "" && !Identity_ValidUserID(publicID) {
		return ExportedAccountKey{}, errors.New("invalid public_id")
	}
	privateKey, decodeError := referenceBinaryField(privateKeyText)
	if decodeError != nil {
		return ExportedAccountKey{}, errors.New("invalid private_key")
	}
	if len(privateKey) != mlDSA44PrivateKeySize {
		return ExportedAccountKey{}, errors.New("wrong private_key size")
	}
	return ExportedAccountKey{PublicID: publicID, PrivateKey: privateKey}, nil
}
