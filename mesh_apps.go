package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type storedManifestVersion struct {
	Version int
	Hash    string
}

func (s *Store) ExportMeshApps(
	ctx context.Context,
	policy NodeSyncPolicy,
) ([]SignedAppRegistrationRequest, error) {
	if !nodePolicyIncludesData(&policy, "app_registry") || len(policy.Apps) == 0 {
		return []SignedAppRegistrationRequest{}, nil
	}

	allowedApps := normalizedStringSet(policy.Apps)
	rows, err := s.db.QueryContext(ctx, `
SELECT app_id,manifest_json,manifest_signature,approval_signature
FROM server_app_manifests
ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	registrations := make([]SignedAppRegistrationRequest, 0, len(allowedApps))
	for rows.Next() {
		var appID string
		var manifestJSON string
		var manifestSignature string
		var approvalSignature string
		if err := rows.Scan(
			&appID,
			&manifestJSON,
			&manifestSignature,
			&approvalSignature,
		); err != nil {
			return nil, err
		}
		if !allowedApps[strings.ToLower(appID)] {
			continue
		}

		var manifest AppManifest
		if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
			return nil, fmt.Errorf("decode stored manifest %q: %w", appID, err)
		}
		registrations = append(registrations, SignedAppRegistrationRequest{
			Manifest:          manifest,
			ManifestSignature: manifestSignature,
			ApprovalSignature: approvalSignature,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return registrations, nil
}

func (s *Server) ImportMeshApps(
	ctx context.Context,
	policy NodeSyncPolicy,
	registrations []SignedAppRegistrationRequest,
) (int, error) {
	if !nodePolicyIncludesData(&policy, "app_registry") {
		return 0, nil
	}

	allowedApps := normalizedStringSet(policy.Apps)
	applied := 0
	for _, registration := range registrations {
		normalizeAppManifest(&registration.Manifest)
		if !allowedApps[strings.ToLower(registration.Manifest.AppID)] {
			return 0, fmt.Errorf("app %q exceeds mesh policy", registration.Manifest.AppID)
		}
		if err := validateAppManifest(registration.Manifest); err != nil {
			return 0, fmt.Errorf("invalid mesh app %q: %w", registration.Manifest.AppID, err)
		}

		manifestBytes, manifestHash, err := validateSignedAppRegistration(
			registration,
			s.cfg.NodeRegistryPublicKey,
		)
		if err != nil {
			return 0, fmt.Errorf("verify mesh app %q: %w", registration.Manifest.AppID, err)
		}

		current, found, err := s.store.loadManifestVersion(ctx, registration.Manifest.AppID)
		if err != nil {
			return 0, err
		}
		if found && registration.Manifest.ManifestVersion < current.Version {
			continue
		}
		if found && registration.Manifest.ManifestVersion == current.Version {
			if manifestHash != current.Hash {
				return 0, fmt.Errorf(
					"conflicting app manifest %q at version %d",
					registration.Manifest.AppID,
					current.Version,
				)
			}
			continue
		}

		if err := s.store.UpsertSignedAppManifest(
			ctx,
			registration.Manifest,
			manifestBytes,
			manifestHash,
			registration.ManifestSignature,
			registration.ApprovalSignature,
		); err != nil {
			return 0, err
		}
		applied++
	}
	return applied, nil
}

func (s *Store) loadManifestVersion(
	ctx context.Context,
	appID string,
) (storedManifestVersion, bool, error) {
	var current storedManifestVersion
	err := s.db.QueryRowContext(ctx, `
SELECT manifest_version,manifest_hash
FROM server_app_manifests
WHERE app_id=?1`, appID).Scan(&current.Version, &current.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return storedManifestVersion{}, false, nil
	}
	if err != nil {
		return storedManifestVersion{}, false, err
	}
	return current, true, nil
}

func normalizedStringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized != "" {
			set[normalized] = true
		}
	}
	return set
}
