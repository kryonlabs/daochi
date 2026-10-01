package main

// Original sync transaction, operation and identifier implementation at 2c6bd4d.
import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) baselineApplicationApplySyncDetailed(ctx context.Context, req SyncRequest, publicKey []byte) (SyncResult, []string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SyncResult{}, nil, err
	}
	defer tx.Rollback()

	if publicKey != nil {
		if err := AccountState_Upsert(tx, ctx, req.UserIDHash, publicKey); err != nil {
			return SyncResult{}, nil, err
		}
	} else if err := AccountState_Touch(tx, ctx, req.UserIDHash, ErrSyncUserNotFound); err != nil {
		return SyncResult{}, nil, err
	}
	if req.FullSyncRequested {
		if err := baselineWritesReplaceUserData(ctx, tx, req.UserIDHash); err != nil {
			return SyncResult{}, nil, err
		}
	}
	if len(req.SocialCache) > 0 {
		return SyncResult{}, nil, fmt.Errorf("social_cache is server-owned")
	}
	for _, item := range req.EncryptedRecords {
		if !EncryptedRecord_ValidForProtocol(item, req.ProtocolVersion) {
			return SyncResult{}, nil, fmt.Errorf("invalid encrypted record")
		}
	}

	result := SyncResult{}
	deletedHabitIDs := map[string]bool{}
	for _, item := range req.MeditationLogs {
		version, err := baselineLifecycleNextVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_meditation_logs(user_id_hash,id,session_id,duration_seconds,completed_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6)
ON CONFLICT(user_id_hash,id) DO NOTHING`, req.UserIDHash, item.ID, item.SessionID, item.DurationSeconds, Timestamp_NormalizeTime(item.CompletedAt, item.Timestamp), version)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.MeditationLogs += AccountState_Affected(res)
	}
	for _, habit := range req.Habits {
		originalID := habit.ID
		canonicalID, _, err := baselineApplicationCanonicalHabitIDForWrite(ctx, tx, req.UserIDHash, habit.ID, "legacy-write")
		if err != nil {
			return SyncResult{}, nil, err
		}
		habit.ID = canonicalID
		if req.Bootstrap && habit.DeletedAt > 0 {
			deletedHabitIDs[habit.ID] = true
			deletedHabitIDs[originalID] = true
			continue
		}
		if habit.DeletedAt > 0 {
			deletedHabitIDs[habit.ID] = true
			deletedHabitIDs[originalID] = true
			applied, err := baselineWritesDeleteHabit(ctx, tx, req.UserIDHash, habit)
			if err != nil {
				return SyncResult{}, nil, err
			}
			result.Habits += applied
			continue
		}
		version, err := baselineLifecycleNextVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	name=excluded.name,
	color_r=excluded.color_r,
	color_g=excluded.color_g,
	color_b=excluded.color_b,
	sync_mode=excluded.sync_mode,
	sync_activity=excluded.sync_activity,
	counter_enabled=excluded.counter_enabled,
	sort_order=excluded.sort_order,
	deleted_at=excluded.deleted_at,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_habits.updated_at`,
			req.UserIDHash, habit.ID, habit.Name, habit.ColorR, habit.ColorG, habit.ColorB,
			habit.SyncMode, habit.SyncActivity, habit.CounterEnabled, habit.SortOrder,
			habit.DeletedAt, Timestamp_NormalizeTime(habit.UpdatedAt, ""), version)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.Habits += AccountState_Affected(res)
	}
	for _, day := range req.HabitDays {
		originalID := day.HabitID
		if deletedHabitIDs[originalID] {
			continue
		}
		canonicalID, _, err := baselineApplicationCanonicalHabitIDForWrite(ctx, tx, req.UserIDHash, day.HabitID, "legacy-day-write")
		if err != nil {
			return SyncResult{}, nil, err
		}
		day.HabitID = canonicalID
		if deletedHabitIDs[day.HabitID] {
			continue
		}
		version, err := baselineLifecycleNextVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=excluded.completed,
	count=excluded.count,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_habit_days.updated_at`,
			req.UserIDHash, day.HabitID, day.LocalDate, baselineApplicationBoolInt(day.Completed), baselineApplicationNormalizedHabitDayCount(day), Timestamp_NormalizeTime(day.UpdatedAt, ""), version)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.HabitDays += AccountState_Affected(res)
	}
	for _, session := range req.Sessions {
		if req.Bootstrap && session.DeletedAt > 0 {
			continue
		}
		if session.DeletedAt > 0 {
			applied, err := baselineWritesDeleteSession(ctx, tx, req.UserIDHash, session)
			if err != nil {
				return SyncResult{}, nil, err
			}
			result.Sessions += applied
			continue
		}
		applied, err := baselineWritesUpsertSession(ctx, tx, req.UserIDHash, session)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.Sessions += applied
	}
	for _, item := range req.EncryptedRecords {
		applied, err := baselineWritesUpsertEncryptedRecord(ctx, tx, req.UserIDHash, item)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.EncryptedRecords += applied
	}
	acceptedOps, err := baselineApplicationApplySyncOps(ctx, tx, req.UserIDHash, req.Ops, &result)
	if err != nil {
		return SyncResult{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return SyncResult{}, nil, err
	}
	return result, acceptedOps, nil
}

func baselineApplicationApplySyncOps(ctx context.Context, tx *sql.Tx, userID string, ops []SyncOp, result *SyncResult) ([]string, error) {
	accepted := []string{}
	for _, op := range ops {
		if op.OpID == "" || op.ClientID == "" || op.Seq <= 0 {
			return nil, fmt.Errorf("invalid sync op identity")
		}
		exists, err := baselineApplicationSyncOpExists(ctx, tx, userID, op.OpID)
		if err != nil {
			return nil, err
		}
		if exists {
			accepted = append(accepted, op.OpID)
			continue
		}
		if err := baselineApplicationCanonicalizeSyncOpHabitIDs(ctx, tx, userID, &op); err != nil {
			return nil, err
		}
		if err := baselineApplicationMaterializeSyncOp(ctx, tx, userID, op, result); err != nil {
			return nil, err
		}
		version, err := currentUserVersionTx(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		if version <= 0 {
			version, err = baselineLifecycleNextVersion(ctx, tx, userID)
			if err != nil {
				return nil, err
			}
		}
		payload := string(op.Payload)
		createdAt := Timestamp_NormalizeTime(op.CreatedAt, "")
		if _, err := tx.ExecContext(ctx, `
INSERT INTO server_sync_ops(user_id_hash,op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`,
			userID, op.OpID, op.ClientID, op.Seq, op.EntityType, op.EntityID,
			op.LocalDate, op.OpType, payload, createdAt, version); err != nil {
			return nil, err
		}
		accepted = append(accepted, op.OpID)
	}
	return accepted, nil
}

func baselineApplicationCanonicalizeSyncOpHabitIDs(ctx context.Context, tx *sql.Tx, userID string, op *SyncOp) error {
	if op == nil {
		return nil
	}
	if op.EntityType != "habit" && op.EntityType != "habit_day" {
		return nil
	}
	id := strings.TrimSpace(op.EntityID)
	if id == "" && len(op.Payload) > 0 {
		var obj struct {
			ID      string `json:"id"`
			HabitID string `json:"habit_id"`
		}
		if err := json.Unmarshal(op.Payload, &obj); err == nil {
			if obj.HabitID != "" {
				id = obj.HabitID
			} else {
				id = obj.ID
			}
		}
	}
	if id == "" {
		return fmt.Errorf("habit op missing id")
	}
	canonicalID, _, err := baselineApplicationCanonicalHabitIDForWrite(ctx, tx, userID, id, "legacy-op")
	if err != nil {
		return err
	}
	op.EntityID = canonicalID
	op.Payload = baselineApplicationRewriteHabitPayloadID(op.Payload, canonicalID)
	return nil
}

func baselineApplicationSyncOpExists(ctx context.Context, tx *sql.Tx, userID, opID string) (bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_sync_ops WHERE user_id_hash=?1 AND op_id=?2)`,
		userID, opID).Scan(&exists)
	return exists != 0, err
}

func baselineApplicationMaterializeSyncOp(ctx context.Context, tx *sql.Tx, userID string, op SyncOp, result *SyncResult) error {
	switch op.EntityType {
	case "habit":
		var habit Habit
		if len(op.Payload) == 0 {
			return fmt.Errorf("habit op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &habit); err != nil {
			return err
		}
		if habit.ID == "" {
			habit.ID = op.EntityID
		}
		if op.OpType == "delete" && habit.DeletedAt <= 0 {
			habit.DeletedAt = time.Now().Unix()
		}
		if habit.DeletedAt > 0 || op.OpType == "delete" {
			applied, err := baselineWritesDeleteHabit(ctx, tx, userID, habit)
			if err != nil {
				return err
			}
			result.Habits += applied
			return nil
		}
		version, err := baselineLifecycleNextVersion(ctx, tx, userID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	name=excluded.name,color_r=excluded.color_r,color_g=excluded.color_g,color_b=excluded.color_b,
	sync_mode=excluded.sync_mode,sync_activity=excluded.sync_activity,counter_enabled=excluded.counter_enabled,
	sort_order=excluded.sort_order,deleted_at=excluded.deleted_at,updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_habits.updated_at`,
			userID, habit.ID, habit.Name, habit.ColorR, habit.ColorG, habit.ColorB,
			habit.SyncMode, habit.SyncActivity, habit.CounterEnabled, habit.SortOrder,
			habit.DeletedAt, Timestamp_NormalizeTime(habit.UpdatedAt, ""), version)
		if err != nil {
			return err
		}
		result.Habits += AccountState_Affected(res)
	case "habit_day":
		var day HabitDay
		if len(op.Payload) == 0 {
			return fmt.Errorf("habit_day op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &day); err != nil {
			return err
		}
		if day.HabitID == "" {
			day.HabitID = op.EntityID
		}
		if day.LocalDate == 0 {
			day.LocalDate = op.LocalDate
		}
		if op.OpType == "delete" {
			applied, err := baselineWritesDeleteHabitDay(ctx, tx, userID, day)
			if err != nil {
				return err
			}
			result.HabitDays += applied
			return nil
		}
		version, err := baselineLifecycleNextVersion(ctx, tx, userID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=excluded.completed,count=excluded.count,updated_at=excluded.updated_at,server_version=excluded.server_version
WHERE excluded.updated_at >= server_habit_days.updated_at`,
			userID, day.HabitID, day.LocalDate, baselineApplicationBoolInt(day.Completed),
			baselineApplicationNormalizedHabitDayCount(day), Timestamp_NormalizeTime(day.UpdatedAt, ""), version)
		if err != nil {
			return err
		}
		result.HabitDays += AccountState_Affected(res)
	case "session":
		var session Session
		if len(op.Payload) == 0 {
			return fmt.Errorf("session op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &session); err != nil {
			return err
		}
		if session.ID == "" {
			session.ID = op.EntityID
		}
		if op.OpType == "delete" && session.DeletedAt <= 0 {
			session.DeletedAt = time.Now().Unix()
		}
		if session.DeletedAt > 0 || op.OpType == "delete" {
			applied, err := baselineWritesDeleteSession(ctx, tx, userID, session)
			if err != nil {
				return err
			}
			result.Sessions += applied
			return nil
		}
		applied, err := baselineWritesUpsertSession(ctx, tx, userID, session)
		if err != nil {
			return err
		}
		result.Sessions += applied
	case "social_snapshots":
		return fmt.Errorf("social_cache is server-owned")
	default:
		if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return nil
}

func baselineApplicationNewCanonicalHabitID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func baselineApplicationIsCanonicalHabitID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, ch := range id {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}
	return true
}

func baselineApplicationCanonicalHabitIDForWrite(ctx context.Context, tx *sql.Tx, userID, id, source string) (string, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false, fmt.Errorf("empty habit id")
	}
	if baselineApplicationIsCanonicalHabitID(id) {
		return strings.ToLower(id), false, nil
	}
	var mapped string
	err := tx.QueryRowContext(ctx, `
SELECT new_id
FROM server_habit_id_migrations
WHERE user_id_hash=?1 AND old_id=?2`, userID, id).Scan(&mapped)
	if err == nil && mapped != "" {
		return mapped, true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	canonical, err := baselineApplicationNewCanonicalHabitID()
	if err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,?4)`, userID, id, canonical, source); err != nil {
		return "", false, err
	}
	return canonical, true, nil
}

func baselineApplicationCanonicalHabitIDForRead(ctx context.Context, tx *sql.Tx, userID, id string) (string, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" || baselineApplicationIsCanonicalHabitID(id) {
		return strings.ToLower(id), false, nil
	}
	var mapped string
	err := tx.QueryRowContext(ctx, `
SELECT new_id
FROM server_habit_id_migrations
WHERE user_id_hash=?1 AND old_id=?2`, userID, id).Scan(&mapped)
	if errors.Is(err, sql.ErrNoRows) {
		return id, false, nil
	}
	if err != nil {
		return "", false, err
	}
	return mapped, mapped != id, nil
}

func baselineApplicationRewriteHabitPayloadID(payload json.RawMessage, canonicalID string) json.RawMessage {
	if len(payload) == 0 || canonicalID == "" {
		return payload
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		return payload
	}
	changed := false
	if _, ok := obj["id"]; ok {
		obj["id"] = canonicalID
		changed = true
	}
	if _, ok := obj["habit_id"]; ok {
		obj["habit_id"] = canonicalID
		changed = true
	}
	if !changed {
		return payload
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return json.RawMessage(out)
}

func baselineApplicationNormalizedHabitDayCount(day HabitDay) int {
	if !day.Completed {
		return 0
	}
	if day.Count > 0 {
		return day.Count
	}
	return 1
}

func baselineApplicationBoolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
