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
			Response_Error(w, http.StatusInternalServerError, "device list failed")
			return
		}
		Response_JSON(w, http.StatusOK, map[string]any{"devices": devices})
		return
	case http.MethodDelete:
		s.handleDeviceRevocation(w, r, accountID)
		return
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var request DeviceRegistrationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid device registration")
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
			Response_Error(w, http.StatusConflict, "device registration replay")
			return
		}
		Response_Error(w, http.StatusInternalServerError, "device registration failed")
		return
	}
	Response_JSON(w, http.StatusOK, device)
}

func (s *Server) handleDeviceRevocation(w http.ResponseWriter, r *http.Request, accountID string) {
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var request DeviceRevocationRequest
	if err := json.Unmarshal(body, &request); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid device revocation")
		return
	}
	DeviceKeys_NormalizeRevocation(&request)
	if err := authenticationError(DeviceKeys_VerifyRevocation(s.store.db, r.Context(), accountID, request, s.verifier.Verify)); err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := DeviceKeys_Revoke(s.store.db, r.Context(), accountID, request, errSignedTxReplay); err != nil {
		if errors.Is(err, errSignedTxReplay) {
			Response_Error(w, http.StatusConflict, "device revocation replay")
			return
		}
		Response_Error(w, http.StatusInternalServerError, "device revocation failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
