package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

func (s *Server) verifyDeviceRegistration(ctx context.Context, accountID string, request DeviceRegistrationRequest) error {
	if !DeviceKeys_ValidRegistration(request) {
		return authError{status: http.StatusBadRequest, message: "invalid device registration"}
	}
	accountKey, found, err := s.store.PublicKey(ctx, accountID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	signatureField := Codec_DecodeBinaryField(request.Signature)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid device registration signature"}
	}
	message := DeviceKeys_RegistrationMessage(accountID, request)
	if !s.verifier.Verify(accountKey, message, signature) {
		return authError{status: http.StatusUnauthorized, message: "device registration rejected"}
	}
	return nil
}

func (s *Server) verifyDeviceRevocation(ctx context.Context, accountID string, request DeviceRevocationRequest) error {
	if !Identity_ValidNamespace(request.AppID) || !Identity_ValidClientID(request.KeyID) ||
		!Identity_ValidClientID(request.Nonce) || !DeviceKeys_ValidExpiry(request.ExpiresAt) {
		return authError{status: http.StatusBadRequest, message: "invalid device revocation"}
	}
	accountKey, found, err := s.store.PublicKey(ctx, accountID)
	if err != nil {
		return err
	}
	if !found {
		return authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	signatureField := Codec_DecodeBinaryField(request.Signature)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" || len(signature) != mlDSA44SignatureSize {
		return authError{status: http.StatusBadRequest, message: "invalid device revocation signature"}
	}
	if !s.verifier.Verify(accountKey, DeviceKeys_RevocationMessage(accountID, request), signature) {
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
		listed := DeviceKeys_List(s.store.db, r.Context(), accountID)
		devices, err := listed.Value, listed.Error
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
	DeviceKeys_NormalizeRegistration(&request)
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
	if err := DeviceKeys_Register(s.store.db, r.Context(), device, request.Nonce, errSignedTxReplay); err != nil {
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
	DeviceKeys_NormalizeRevocation(&request)
	if err := s.verifyDeviceRevocation(r.Context(), accountID, request); err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := DeviceKeys_Revoke(s.store.db, r.Context(), accountID, request, errSignedTxReplay); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			writeError(w, http.StatusConflict, "device revocation replay")
			return
		}
		writeError(w, http.StatusInternalServerError, "device revocation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
