package main

import (
	"errors"
	"log/slog"
	"net/http"
)

var errSignedTxReplay = errors.New("signed transaction replay")

func (s *Server) handleSignedAppRegister(w http.ResponseWriter, r *http.Request) {
	req, err := readSignedAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	verified := AppRegistration_Verify(req, s.cfg.NodeRegistryPublicKey)
	manifestBytes, manifestHash, err := verified.Value, verified.Hash, authenticationError(verified.Authentication)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := AppStore_UpsertSignedManifest(s.store.db, r.Context(), req.Manifest, manifestBytes, manifestHash, req.ManifestSignature, req.ApprovalSignature); err != nil {
		slog.Error("register signed app manifest", "app", LogSafety_LogText(req.Manifest.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), req.Manifest.AppID)
	app, _, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load signed app manifest", "app", LogSafety_LogText(req.Manifest.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func readSignedAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppRegistrationRequest, error) {
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return SignedAppRegistrationRequest{}, err
	}
	decoded := AppRegistration_DecodeSigned(body)
	return decoded.Value, decoded.Error
}
