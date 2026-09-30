package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

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
	if err := authenticationError(DeviceKeys_VerifyRegistration(s.store.db, r.Context(), accountID, request, s.verifier.Verify)); err != nil {
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
	if err := authenticationError(DeviceKeys_VerifyRevocation(s.store.db, r.Context(), accountID, request, s.verifier.Verify)); err != nil {
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
