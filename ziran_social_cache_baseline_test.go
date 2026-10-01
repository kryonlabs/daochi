// Original social snapshot writes retained as a regression oracle.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

func baselineSnapshotUpsert(ctx context.Context, tx *sql.Tx, userID string, item SocialSnapshot) (int, error) {
	kind := strings.TrimSpace(item.Kind)
	payload := item.JSON
	var same int

	if kind == "" || len(kind) > 96 {
		return 0, fmt.Errorf("invalid social_cache kind")
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return 0, fmt.Errorf("invalid social_cache json")
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_social_snapshots WHERE user_id_hash=?1 AND kind=?2 AND json=?3)`,
		userID, kind, string(payload)).Scan(&same); err != nil {
		return 0, err
	}
	if same != 0 {
		return 0, nil
	}
	version, err := nextUserVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO server_social_snapshots(user_id_hash,kind,json,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(user_id_hash,kind) DO UPDATE SET
	json=excluded.json,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.json != server_social_snapshots.json`,
		userID, kind, string(payload), Timestamp_NormalizeTime(item.UpdatedAt, ""), version)
	if err != nil {
		return 0, err
	}
	return AccountState_Affected(res), nil
}

func (s *Store) baselineSnapshotSet(ctx context.Context, userID, kind string, payload []byte) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	applied, err := baselineSnapshotUpsert(ctx, tx, userID, SocialSnapshot{
		Kind: kind,
		JSON: json.RawMessage(payload),
	})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return applied, nil
}
