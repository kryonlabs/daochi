// Original mesh app replication from d0f286e, retained as a regression oracle.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type baselineStoredManifestVersion struct {
	Version int
	Hash    string
}

func (s *Store) baselineExportMeshApps(
	ctx context.Context,
	policy NodeSyncPolicy,
) ([]SignedAppRegistrationRequest, error) {
	if !MeshPolicy_IncludesData(&policy, "app_registry") || len(policy.Apps) == 0 {
		return []SignedAppRegistrationRequest{}, nil
	}

	allowedApps := Sets_Normalize(policy.Apps)
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Server) baselineImportMeshApps(
	ctx context.Context,
	policy NodeSyncPolicy,
	registrations []SignedAppRegistrationRequest,
) (int, error) {
	if !MeshPolicy_IncludesData(&policy, "app_registry") {
		return 0, nil
	}

	allowedApps := Sets_Normalize(policy.Apps)
	applied := 0
	for _, registration := range registrations {
		Manifest_Normalize(&registration.Manifest)
		if !allowedApps[strings.ToLower(registration.Manifest.AppID)] {
			return 0, fmt.Errorf("app %q exceeds mesh policy", registration.Manifest.AppID)
		}
		if problem := Manifest_Validate(registration.Manifest, time.Now().Unix()); problem != "" {
			return 0, fmt.Errorf("invalid mesh app %q: %w", registration.Manifest.AppID, errors.New(problem))
		}

		verified := AppRegistration_Verify(registration, s.cfg.NodeRegistryPublicKey)
		manifestBytes, manifestHash, err := verified.Value, verified.Hash, authenticationError(verified.Authentication)
		if err != nil {
			return 0, fmt.Errorf("verify mesh app %q: %w", registration.Manifest.AppID, err)
		}

		current, found, err := s.store.baselineLoadManifestVersion(ctx, registration.Manifest.AppID)
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

		if err := AppStore_UpsertSignedManifest(s.store.Database,
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

func (s *Store) baselineLoadManifestVersion(
	ctx context.Context,
	appID string,
) (baselineStoredManifestVersion, bool, error) {
	var current baselineStoredManifestVersion
	err := s.Database.QueryRowContext(ctx, `
SELECT manifest_version,manifest_hash
FROM server_app_manifests
WHERE app_id=?1`, appID).Scan(&current.Version, &current.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return baselineStoredManifestVersion{}, false, nil
	}
	if err != nil {
		return baselineStoredManifestVersion{}, false, err
	}
	return current, true, nil
}
