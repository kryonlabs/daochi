package main

// Original account access and signature orchestration at 10e14c2.
import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func (s *Server) baselineAccessHandleChallenge(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user_id")))
	if !Identity_ValidUserID(userID) {
		Response_Error(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if !s.baselineAccessAllowRequest(r, "challenge:ip:"+ClientAddress_FromRequest(r), 60, time.Minute) ||
		!s.baselineAccessAllowRequest(r, "challenge:user:"+userID, 20, time.Minute) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	issued := Challenge_Issue(s.challenges, userID)
	nonce, err := issued.Nonce, issued.Error
	if err != nil {
		slog.Error("issue challenge", "error", err)
		Response_Error(w, http.StatusInternalServerError, "challenge failed")
		return
	}
	Response_JSON(w, http.StatusOK, ChallengeResponse{
		UserIDHash: userID,
		Nonce:      hex.EncodeToString(nonce),
		ExpiresIn:  int64(s.cfg.ChallengeTTL.Seconds()),
	})
}

func (s *Server) baselineAccessHandleLogin(w http.ResponseWriter, r *http.Request) {
	read := SyncRequest_ReadLogin(w, r, s.cfg.MaxBodyBytes)
	body, req, err := read.Body, read.Value, read.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := SyncRequest_ApplyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !Identity_ValidClientID(req.ClientID) {
		Response_Error(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	if !s.baselineAccessAllowRequest(r, "login:ip:"+ClientAddress_FromRequest(r), 40, time.Minute) ||
		!s.baselineAccessAllowRequest(r, "login:user:"+req.UserIDHash, 20, time.Minute) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	signed := SyncRequest_SignatureHeader(r)
	signature, context := signed.Value, signed.Context
	publicKey, err := s.baselineAccessAuthenticateSignature(r.Context(), req.UserIDHash, req.PublicKey, signature, context, r.Method, r.URL.Path, body)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.RegisterUser(r.Context(), req.UserIDHash, publicKey); err != nil {
		slog.Error("register sync user", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	if err := s.store.RecordClientLogin(r.Context(), req.UserIDHash, req.ClientID); err != nil {
		slog.Error("record login client", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	token := Token_IssueAuthToken(s.cfg.TokenSecret, req.UserIDHash, time.Now().Add(s.cfg.TokenTTL).Unix())
	if token.Error != "" {
		slog.Error("issue auth token", "user", LogSafety_LogText(req.UserIDHash), "error", token.Error)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	profileIcon, err := s.store.AccountProfileIcon(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	Response_JSON(w, http.StatusOK, LoginResponse{
		Status:       "ok",
		AuthToken:    token.Value,
		ExpiresIn:    int64(s.cfg.TokenTTL.Seconds()),
		ServerTime:   time.Now().Unix(),
		AccountAlias: accountAlias,
		ProfileIcon:  profileIcon,
	})
}

func (s *Server) baselineAccessHandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	read := SyncRequest_ReadDelete(w, r, s.cfg.MaxBodyBytes)
	body, req, err := read.Body, read.Value, read.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := SyncRequest_ApplyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	signed := SyncRequest_SignatureHeader(r)
	signature, context := signed.Value, signed.Context
	_, err = s.baselineAccessAuthenticateSignature(r.Context(), req.UserIDHash, "", signature, context, r.Method, r.URL.Path, body)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) baselineAccessHandleDeleteAccountWithKey(w http.ResponseWriter, r *http.Request, sign func([]byte, []byte) ([]byte, error)) {
	read := SyncRequest_ReadDeleteWithKey(w, r, s.cfg.MaxBodyBytes)
	req, err := read.Value, read.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.baselineAccessAllowRequest(r, "delete-key:ip:"+ClientAddress_FromRequest(r), 8, time.Hour) ||
		!s.baselineAccessAllowRequest(r, "delete-key:user:"+req.UserIDHash, 4, time.Hour) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	account := AccountKeys_PublicKey(s.store.db, r.Context(), req.UserIDHash)
	publicKey, found, err := account.Value, account.Found, account.Error
	if err != nil {
		slog.Error("load account key", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "sync account not found")
		return
	}
	parsed := SyncRequest_ParseExportedKey(req.ExportedKey)
	exportedKey, err := parsed.Value, parsed.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if exportedKey.PublicID != "" && exportedKey.PublicID != req.UserIDHash {
		Response_Error(w, http.StatusBadRequest, "exported key public_id does not match user_id_hash")
		return
	}
	message := []byte("inbe-delete-account-v1\n" + req.UserIDHash + "\n")
	signature, err := sign(message, exportedKey.PrivateKey)
	if err != nil || !s.verifier.Verify(publicKey, []byte(message), signature) {
		Response_Error(w, http.StatusUnauthorized, "exported key does not match sync account")
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account with key", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) baselineAccessAuthenticateSignature(ctx context.Context, userID, publicKeyText, signatureText, signatureContext, method, path string, signedPayload []byte) ([]byte, error) {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !Identity_ValidUserID(userID) {
		return nil, authError{status: http.StatusBadRequest, message: "invalid user_id_hash"}
	}
	consumed := Challenge_Consume(s.challenges, userID)
	nonce, ok := consumed.Nonce, consumed.Found
	if !ok {
		return nil, authError{status: http.StatusBadRequest, message: "missing or expired challenge"}
	}
	account := AccountKeys_PublicKey(s.store.db, ctx, userID)
	publicKey, found, err := account.Value, account.Found, account.Error
	if err != nil {
		return nil, err
	}
	if !found {
		if publicKeyText == "" {
			return nil, authError{status: http.StatusBadRequest, message: "public_key required for first sync"}
		}
		publicKeyField := Codec_DecodeBinaryField(publicKeyText)
		publicKey = []byte(publicKeyField.Value)
		if publicKeyField.Error != "" {
			return nil, authError{status: http.StatusBadRequest, message: "invalid public_key"}
		}
		if len(publicKey) != mlDSA44PublicKeySize {
			return nil, authError{status: http.StatusBadRequest, message: "wrong public_key size"}
		}
		if err := EncryptedRecord_ValidateAccountKey(userID, publicKey); err != nil {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match user_id_hash"}
		}
	} else if publicKeyText != "" {
		suppliedField := Codec_DecodeBinaryField(publicKeyText)
		supplied := []byte(suppliedField.Value)
		if suppliedField.Error != "" || subtle.ConstantTimeCompare(supplied, publicKey) != 1 {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match registered user"}
		}
	}
	signatureField := Codec_DecodeBinaryField(signatureText)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" {
		return nil, authError{status: http.StatusBadRequest, message: "invalid signature"}
	}
	if len(signature) != mlDSA44SignatureSize {
		return nil, authError{status: http.StatusBadRequest, message: "wrong signature size"}
	}
	message := Signing_CanonicalMessageWithContext(signatureContext, nonce, method, path, signedPayload)
	if !s.verifier.Verify(publicKey, []byte(message), signature) {
		return nil, authError{status: http.StatusUnauthorized, message: "signature rejected"}
	}
	return publicKey, nil
}

func (s *Server) baselineAccessAllowRequest(r *http.Request, key string, limit int, window time.Duration) bool {
	if s.limiter == nil {
		return true
	}
	allowed := RateLimit_Allow(s.limiter, key, limit, window)
	if !allowed {
		s.metrics.RateLimitedRequests.Add(1)
	}
	return allowed
}
