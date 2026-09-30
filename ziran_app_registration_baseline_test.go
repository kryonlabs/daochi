package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func baselineDecodeSignedRegistration(body []byte) (SignedAppRegistrationRequest, error) {
	var req SignedAppRegistrationRequest
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

func baselineValidateSignedAppRegistration(req SignedAppRegistrationRequest, nodePublicKey ed25519.PublicKey) ([]byte, string, error) {
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

func baselineDecodeAppRegistration(body []byte) (AppRegistration, error) {
	var req AppRegistration
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Description = strings.TrimSpace(req.Description)
	req.HomepageURL = strings.TrimSpace(req.HomepageURL)
	req.SourceURL = strings.TrimSpace(req.SourceURL)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.Status = strings.TrimSpace(req.Status)
	req.MinClientVersion = strings.TrimSpace(req.MinClientVersion)
	req.CurrentVersion = strings.TrimSpace(req.CurrentVersion)
	req.CompatibilityUntil = strings.TrimSpace(req.CompatibilityUntil)
	if req.Status == "" {
		req.Status = appStatusActive
	}
	if !Identity_ValidNamespace(req.AppID) {
		return req, errors.New("invalid app_id")
	}
	if req.DisplayName == "" || len(req.DisplayName) > 80 {
		return req, errors.New("invalid display_name")
	}
	if req.Status != appStatusActive && req.Status != appStatusSuspended {
		return req, errors.New("invalid status")
	}
	if req.AppSchemaVersion < 0 || req.AppSchemaVersion > 65535 {
		return req, errors.New("invalid app_schema_version")
	}
	if req.CompatibilityUntil != "" && !Manifest_ValidDate(req.CompatibilityUntil) {
		return req, errors.New("invalid compatibility_until")
	}
	if len(req.Collections) > 64 || len(req.Capabilities) > 64 ||
		len(req.Features) > 128 || len(req.LegacyProtocols) > 64 ||
		len(req.TokenPolicies) > 64 {
		return req, errors.New("too many app fields")
	}
	for i := range req.Collections {
		req.Collections[i].AppID = req.AppID
		req.Collections[i].CollectionPrefix = strings.TrimSpace(req.Collections[i].CollectionPrefix)
		req.Collections[i].Visibility = strings.TrimSpace(req.Collections[i].Visibility)
		req.Collections[i].Description = strings.TrimSpace(req.Collections[i].Description)
		if req.Collections[i].SchemaVersion < 0 {
			return req, errors.New("invalid schema_version")
		}
		if !Scope_ValidCollectionPrefix(req.Collections[i].CollectionPrefix) ||
			!Scope_ValidAppVisibility(req.Collections[i].Visibility) ||
			!Scope_AppOwnsDeclaredScope(req.AppID, req.Collections[i]) {
			return req, errors.New("invalid app collection")
		}
	}
	for i := range req.Capabilities {
		req.Capabilities[i] = strings.TrimSpace(req.Capabilities[i])
		if !Identity_ValidNamespace(req.Capabilities[i]) {
			return req, errors.New("invalid capability")
		}
	}
	for i := range req.Features {
		req.Features[i].ID = strings.TrimSpace(req.Features[i].ID)
		req.Features[i].Description = strings.TrimSpace(req.Features[i].Description)
		if !Identity_ValidNamespace(req.Features[i].ID) || len(req.Features[i].Collections) > 16 {
			return req, errors.New("invalid app feature")
		}
		for j := range req.Features[i].Collections {
			req.Features[i].Collections[j] = strings.TrimSpace(req.Features[i].Collections[j])
			if !Scope_DeclaresCollection(req.Collections, req.Features[i].Collections[j]) {
				return req, errors.New("invalid app feature collection")
			}
		}
	}
	for i := range req.LegacyProtocols {
		req.LegacyProtocols[i].Name = strings.TrimSpace(req.LegacyProtocols[i].Name)
		req.LegacyProtocols[i].Status = strings.TrimSpace(req.LegacyProtocols[i].Status)
		req.LegacyProtocols[i].ValidUntil = strings.TrimSpace(req.LegacyProtocols[i].ValidUntil)
		if !Identity_ValidNamespace(req.LegacyProtocols[i].Name) ||
			req.LegacyProtocols[i].Version < 0 ||
			!Scope_ValidLegacyProtocolStatus(req.LegacyProtocols[i].Status) ||
			!Manifest_ValidDate(req.LegacyProtocols[i].ValidUntil) {
			return req, errors.New("invalid legacy protocol")
		}
	}
	for i := range req.TokenPolicies {
		policy := &req.TokenPolicies[i]
		policy.AssetID = strings.TrimSpace(policy.AssetID)
		policy.Permission = strings.TrimSpace(policy.Permission)
		policy.Status = Manifest_DefaultString(strings.TrimSpace(policy.Status), appStatusActive)
		if policy.AssetID == "" || !Scope_ValidTokenPolicyPermission(policy.Permission) ||
			(policy.Status != appStatusActive && policy.Status != appStatusSuspended) ||
			policy.LegacyUnsignedUntil < 0 ||
			policy.LegacyUnsignedUntil > time.Now().Add(365*24*time.Hour).Unix() {
			return req, errors.New("invalid token policy")
		}
	}
	return req, nil
}

func baselineDecodeAppGrant(body []byte) (AppGrantRequest, error) {
	var req AppGrantRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.SourceAppID = strings.TrimSpace(req.SourceAppID)
	req.TargetAppID = strings.TrimSpace(req.TargetAppID)
	req.CollectionPrefix = strings.TrimSpace(req.CollectionPrefix)
	req.Permission = strings.TrimSpace(req.Permission)
	if req.Permission == "" {
		req.Permission = appGrantRead
	}
	if !Identity_ValidNamespace(req.SourceAppID) || !Identity_ValidNamespace(req.TargetAppID) ||
		!Scope_ValidCollectionPrefix(req.CollectionPrefix) || req.Permission != appGrantRead {
		return req, errors.New("invalid app grant")
	}
	return req, nil
}

func baselineDecodeSignedAppGrant(body []byte) (SignedAppGrantRequest, []byte, error) {
	var req SignedAppGrantRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	Transaction_Normalize(&req.Tx)
	req.Grant.SourceAppID = strings.TrimSpace(req.Grant.SourceAppID)
	req.Grant.TargetAppID = strings.TrimSpace(req.Grant.TargetAppID)
	req.Grant.CollectionPrefix = strings.TrimSpace(req.Grant.CollectionPrefix)
	req.Grant.Permission = strings.TrimSpace(req.Grant.Permission)
	if req.Grant.Permission == "" {
		req.Grant.Permission = appGrantRead
	}
	if !Identity_ValidNamespace(req.Grant.SourceAppID) || !Identity_ValidNamespace(req.Grant.TargetAppID) ||
		!Scope_ValidCollectionPrefix(req.Grant.CollectionPrefix) || req.Grant.Permission != appGrantRead {
		return req, nil, errors.New("invalid app grant")
	}
	return req, body, nil
}
