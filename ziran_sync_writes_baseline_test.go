package main

// Original transactional write implementation at 369c69f.
import (
	"context"
	"database/sql"
)

func baselineWritesReplaceUserData(ctx context.Context, tx *sql.Tx, userID string) error {
	for _, query := range []string{
		`DELETE FROM server_session_rounds WHERE user_id_hash=?1`,
		`DELETE FROM server_sessions WHERE user_id_hash=?1`,
		`DELETE FROM server_habit_days WHERE user_id_hash=?1`,
		`DELETE FROM server_habits WHERE user_id_hash=?1`,
		`DELETE FROM server_meditation_logs WHERE user_id_hash=?1`,
		`DELETE FROM server_social_snapshots WHERE user_id_hash=?1`,
		`DELETE FROM server_encrypted_records WHERE user_id_hash=?1`,
		`DELETE FROM server_encrypted_payloads WHERE user_id_hash=?1`,
	} {
		if _, err := tx.ExecContext(ctx, query, userID); err != nil {
			return err
		}
	}
	_, err := baselineLifecycleNextVersion(ctx, tx, userID)
	return err
}

func baselineWritesUpsertSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	version, err := baselineLifecycleNextVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
	INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,source,
		rounds_hash,mood_before,mood_after,energy,stress,note,tags,deleted_at,updated_at,server_version)
	VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
	ON CONFLICT(user_id_hash,id) DO UPDATE SET
		started_at=excluded.started_at,
		local_date=excluded.local_date,
		topic=excluded.topic,
		activity=excluded.activity,
		source=excluded.source,
		rounds_hash=excluded.rounds_hash,
		mood_before=excluded.mood_before,
		mood_after=excluded.mood_after,
		energy=excluded.energy,
		stress=excluded.stress,
		note=excluded.note,
		tags=excluded.tags,
		deleted_at=excluded.deleted_at,
		updated_at=excluded.updated_at,
		server_version=excluded.server_version
	WHERE excluded.updated_at >= server_sessions.updated_at`,
		userID, session.ID, Timestamp_NormalizeTime(session.StartedAt, ""), session.LocalDate, session.Topic,
		session.Activity, session.Source, session.RoundsHash, session.MoodBefore,
		session.MoodAfter, session.Energy, session.Stress, session.Note, session.Tags,
		session.DeletedAt, Timestamp_NormalizeTime(session.UpdatedAt, ""), version)
	if err != nil {
		return 0, err
	}
	applied := AccountState_Affected(res)
	if applied == 0 || len(session.Rounds) == 0 {
		return applied, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_session_rounds WHERE user_id_hash=?1 AND session_id=?2`, userID, session.ID); err != nil {
		return 0, err
	}
	for _, round := range session.Rounds {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_session_rounds(user_id_hash,session_id,round_index,breaths,hold_seconds)
VALUES(?1,?2,?3,?4,?5)`, userID, session.ID, round.RoundIndex, round.Breaths, round.HoldSeconds)
		if err != nil {
			return 0, err
		}
	}
	return applied, nil
}

func baselineWritesUpsertEncryptedRecord(ctx context.Context, tx *sql.Tx, userID string, item EncryptedRecord) (int, error) {
	version, err := baselineLifecycleNextVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
ON CONFLICT(user_id_hash,collection,id) DO UPDATE SET
	key_id=excluded.key_id,
	nonce=excluded.nonce,
	ciphertext=excluded.ciphertext,
	updated_at=excluded.updated_at,
	deleted_at=excluded.deleted_at,
	content_hash=excluded.content_hash,
	schema_version=excluded.schema_version,
	parent_id=excluded.parent_id,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_encrypted_records.updated_at`,
		userID, item.Collection, item.ID, item.KeyID, item.Nonce, item.Ciphertext,
		Timestamp_NormalizeTime(item.UpdatedAt, ""), item.DeletedAt, item.ContentHash,
		item.SchemaVersion, item.ParentID, version)
	if err != nil {
		return 0, err
	}
	return AccountState_Affected(res), nil
}

func baselineWritesDeleteHabit(ctx context.Context, tx *sql.Tx, userID string, habit Habit) (int, error) {
	updatedAt := Timestamp_NormalizeTime(habit.UpdatedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2 AND updated_at<=?3`, userID, habit.ID, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := AccountState_Affected(res)
	if applied == 0 {
		return 0, nil
	}
	res, err = tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, habit.ID)
	if err != nil {
		return 0, err
	}
	applied += AccountState_Affected(res)
	if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
		return 0, err
	}
	return applied, nil
}

func baselineWritesDeleteHabitDay(ctx context.Context, tx *sql.Tx, userID string, day HabitDay) (int, error) {
	updatedAt := Timestamp_NormalizeTime(day.UpdatedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2 AND local_date=?3 AND updated_at<=?4`,
		userID, day.HabitID, day.LocalDate, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := AccountState_Affected(res)
	if applied == 0 {
		return 0, nil
	}
	if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
		return 0, err
	}
	return applied, nil
}

func baselineWritesDeleteSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	updatedAt := Timestamp_NormalizeTime(session.UpdatedAt, session.StartedAt)
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_sessions
WHERE user_id_hash=?1 AND id=?2 AND updated_at<=?3`, userID, session.ID, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := AccountState_Affected(res)
	if applied == 0 {
		return 0, nil
	}
	res, err = tx.ExecContext(ctx, `
DELETE FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2`, userID, session.ID)
	if err != nil {
		return 0, err
	}
	applied += AccountState_Affected(res)
	if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
		return 0, err
	}
	return applied, nil
}
