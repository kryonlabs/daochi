package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var errSignedTxReplay = errors.New("signed transaction replay")

func (s *Server) handleSignedAppRegister(w http.ResponseWriter, r *http.Request) {
	req, err := readSignedAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	manifestBytes, manifestHash, err := validateSignedAppRegistration(req, s.cfg.NodeRegistryPublicKey)
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
	var req SignedAppRegistrationRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	Manifest_Normalize(&req.Manifest)
	req.ManifestSignature = strings.TrimSpace(req.ManifestSignature)
	req.ApprovalSignature = strings.TrimSpace(req.ApprovalSignature)
	if problem := Manifest_Validate(req.Manifest, time.Now().Unix()); problem != "" {
		return req, errors.New(problem)
	}
	return req, nil
}

func validateSignedAppRegistration(req SignedAppRegistrationRequest, nodePublicKey ed25519.PublicKey) ([]byte, string, error) {
	if len(nodePublicKey) != ed25519.PublicKeySize {
		return nil, "", authError{status: http.StatusForbidden, message: "node registry approval unavailable"}
	}
	serialized := JsonGo_Marshal(req.Manifest)
	manifestBytes, err := serialized.Value, serialized.Error
	if err != nil {
		return nil, "", err
	}
	manifestHash := Signing_SHA256Hex(manifestBytes)
	manifestSigField := Codec_DecodeBinaryField(req.ManifestSignature)
	manifestSig := []byte(manifestSigField.Value)
	if manifestSigField.Error != "" || len(manifestSig) != ed25519.SignatureSize {
		return nil, "", authError{status: http.StatusBadRequest, message: "invalid manifest signature"}
	}
	manifestMsg := append([]byte(AppManifestContext+"\n"), manifestBytes...)
	if !Manifest_SignedByActiveKey(req.Manifest, manifestMsg, manifestSig, time.Now().Unix()) {
		return nil, "", authError{status: http.StatusUnauthorized, message: "manifest signature rejected"}
	}
	approvalSigField := Codec_DecodeBinaryField(req.ApprovalSignature)
	approvalSig := []byte(approvalSigField.Value)
	if approvalSigField.Error != "" || len(approvalSig) != ed25519.SignatureSize {
		return nil, "", authError{status: http.StatusBadRequest, message: "invalid approval signature"}
	}
	if !ed25519.Verify(nodePublicKey, []byte(Signing_AppApprovalMessage(AppApprovalContext, req.Manifest.AppID, manifestHash)), approvalSig) {
		return nil, "", authError{status: http.StatusUnauthorized, message: "node approval rejected"}
	}
	return manifestBytes, manifestHash, nil
}

func manifestDigest(manifest AppManifest) (string, error) {
	serialized := JsonGo_Marshal(manifest)
	data, err := serialized.Value, serialized.Error
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func formatAppManifestForTest(manifest AppManifest) ([]byte, string, error) {
	Manifest_Normalize(&manifest)
	if problem := Manifest_Validate(manifest, time.Now().Unix()); problem != "" {
		return nil, "", errors.New(problem)
	}
	serialized := JsonGo_Marshal(manifest)
	data, err := serialized.Value, serialized.Error
	if err != nil {
		return nil, "", err
	}
	return data, Signing_SHA256Hex(data), nil
}

func (p TokenPolicy) String() string {
	return fmt.Sprintf("%s:%s", p.AssetID, p.Permission)
}
