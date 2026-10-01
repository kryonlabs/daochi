// Original account export from f851e0f, retained as an independent regression oracle.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

func (s *Store) baselineExportAccount(ctx context.Context, userID string) (AccountExportResponse, error) {
	var alias sql.NullString
	var profileIcon int
	response := AccountExportResponse{
		Status:     "ok",
		UserIDHash: userID,
		Tables:     make(map[string][]map[string]any),
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT alias,profile_icon
FROM server_users
WHERE user_id_hash=?1`, userID).Scan(&alias, &profileIcon); err != nil {
		return AccountExportResponse{}, err
	}
	if alias.Valid {
		response.AccountAlias = alias.String
	}
	response.ProfileIcon = profileIcon

	queries := []struct {
		name       string
		query      string
		jsonFields map[string]bool
	}{
		{
			name:  "users",
			query: `SELECT user_id_hash, alias, profile_icon, created_at, last_seen_at FROM server_users WHERE user_id_hash=?1`,
		},
		{
			name:  "clients",
			query: `SELECT client_id, created_at, last_seen_at, last_login_at, last_sync_at, last_since_server_version, last_seen_server_version, protocol_version, last_client_clock FROM server_clients WHERE user_id_hash=?1 ORDER BY last_seen_at DESC, client_id`,
		},
		{
			name:  "sync_state",
			query: `SELECT server_version FROM server_sync_state WHERE user_id_hash=?1`,
		},
		{
			name:  "sync_compaction",
			query: `SELECT compacted_through_version, updated_at FROM server_sync_compaction WHERE user_id_hash=?1`,
		},
		{
			name:  "habits",
			query: `SELECT id, name, color_r, color_g, color_b, sync_mode, sync_activity, counter_enabled, sort_order, deleted_at, updated_at, server_version FROM server_habits WHERE user_id_hash=?1 ORDER BY sort_order, id`,
		},
		{
			name:  "habit_days",
			query: `SELECT habit_id, local_date, completed, count, updated_at, server_version FROM server_habit_days WHERE user_id_hash=?1 ORDER BY local_date DESC, habit_id`,
		},
		{
			name:  "sessions",
			query: `SELECT id, started_at, local_date, topic, activity, source, rounds_hash, mood_before, mood_after, energy, stress, note, tags, deleted_at, updated_at, server_version FROM server_sessions WHERE user_id_hash=?1 ORDER BY started_at DESC, id`,
		},
		{
			name:  "session_rounds",
			query: `SELECT session_id, round_index, breaths, hold_seconds FROM server_session_rounds WHERE user_id_hash=?1 ORDER BY session_id, round_index`,
		},
		{
			name:  "meditation_logs",
			query: `SELECT id, session_id, duration_seconds, completed_at, server_version, created_at FROM server_meditation_logs WHERE user_id_hash=?1 ORDER BY completed_at DESC, id`,
		},
		{
			name:       "social_snapshots",
			query:      `SELECT kind, json, updated_at, server_version FROM server_social_snapshots WHERE user_id_hash=?1 ORDER BY kind`,
			jsonFields: map[string]bool{"json": true},
		},
		{
			name:  "encrypted_records",
			query: `SELECT collection, id, key_id, nonce, ciphertext, updated_at, deleted_at, content_hash, schema_version, parent_id, server_version FROM server_encrypted_records WHERE user_id_hash=?1 ORDER BY collection, id`,
		},
		{
			name:       "sync_ops",
			query:      `SELECT op_id, client_id, seq, entity_type, entity_id, local_date, op_type, payload_json, created_at, server_version FROM server_sync_ops WHERE user_id_hash=?1 ORDER BY server_version, client_id, seq`,
			jsonFields: map[string]bool{"payload_json": true},
		},
		{
			name:       "encrypted_payloads",
			query:      `SELECT id, client_id, payload_json, created_at, server_version FROM server_encrypted_payloads WHERE user_id_hash=?1 ORDER BY server_version, id`,
			jsonFields: map[string]bool{"payload_json": true},
		},
		{
			name:       "sync_audit",
			query:      `SELECT id, client_id, app_id, protocol_version, since_server_version, client_clock, server_version, applied_json, remote_ops, full_snapshot_required, snapshot_reason, encrypted_payload, encrypted_payload_bytes, created_at FROM server_sync_audit WHERE user_id_hash=?1 ORDER BY id DESC LIMIT 200`,
			jsonFields: map[string]bool{"applied_json": true},
		},
		{
			name:  "friend_requests",
			query: `SELECT id, requester_user_id_hash, target_user_id_hash, status, created_at, updated_at FROM server_friend_requests WHERE requester_user_id_hash=?1 OR target_user_id_hash=?1 ORDER BY updated_at DESC, id`,
		},
		{
			name:  "friendships",
			query: `SELECT user_id_a, user_id_b, created_at FROM server_friendships WHERE user_id_a=?1 OR user_id_b=?1 ORDER BY created_at DESC, user_id_a, user_id_b`,
		},
		{
			name:  "profile_stats",
			query: `SELECT app, practice, metric, value, label, local_date, updated_at FROM server_profile_stats WHERE user_id_hash=?1 ORDER BY app, practice, metric`,
		},
		{
			name:  "leaderboard_stats",
			query: `SELECT app, practice, metric, source_version, calc_version, value, label, local_date, updated_at FROM server_leaderboard_stats WHERE user_id_hash=?1 ORDER BY app, practice, metric`,
		},
		{
			name:  "app_grants",
			query: `SELECT id, source_app_id, target_app_id, collection_prefix, permission, status, created_at, updated_at, revoked_at FROM server_app_grants WHERE user_id_hash=?1 ORDER BY updated_at DESC, id`,
		},
	}
	for _, item := range queries {
		rows, err := s.baselineQueryAccountRows(ctx, item.query, userID, item.jsonFields)
		if err != nil {
			return AccountExportResponse{}, err
		}
		response.Tables[item.name] = rows
	}
	return response, nil
}

func (s *Store) baselineQueryAccountRows(ctx context.Context, query string, userID string, jsonFields map[string]bool) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		item := make(map[string]any, len(columns))
		for i, column := range columns {
			item[column] = baselineExportRowValue(column, values[i], jsonFields)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func baselineExportRowValue(column string, value any, jsonFields map[string]bool) any {
	if value == nil {
		return nil
	}
	if bytes, ok := value.([]byte); ok {
		text := string(bytes)
		if jsonFields[column] {
			var raw any
			if err := json.Unmarshal(bytes, &raw); err == nil {
				return raw
			}
		}
		return text
	}
	return value
}

func (s *Server) baselineHandleAccountExport(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	response, err := s.store.baselineExportAccount(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("export account", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "export failed")
		return
	}
	Response_JSON(w, http.StatusOK, response)
}
