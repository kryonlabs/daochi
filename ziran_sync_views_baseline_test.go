package main

// Independent regression oracle copied from store.go at 9af22d6.
// Keep these original queries and control flow separate from the Ziran source.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func (s *Store) baselineViewsChangesSince(ctx context.Context, userID string, sinceVersion int64) (SyncChanges, int64, error) {
	var changes SyncChanges
	var err error

	changes.Habits, err = s.baselineViewsSnapshotHabits(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.HabitDays, err = s.baselineViewsSnapshotHabitDays(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.Sessions, err = s.baselineViewsSnapshotSessions(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.MeditationLogs, err = s.baselineViewsSnapshotMeditationLogs(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.SocialCache, err = s.baselineViewsSnapshotSocialCache(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.EncryptedRecords, err = s.baselineViewsSnapshotEncryptedRecords(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	version, err := s.currentUserVersion(ctx, userID)
	if err != nil {
		return changes, 0, err
	}
	return changes, version, nil
}

func (s *Store) baselineViewsOpsSince(ctx context.Context, userID string, sinceVersion int64) ([]SyncOp, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at
FROM server_sync_ops
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,client_id,seq,op_id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ops := []SyncOp{}
	for rows.Next() {
		var op SyncOp
		var payload string
		if err := rows.Scan(&op.OpID, &op.ClientID, &op.Seq, &op.EntityType,
			&op.EntityID, &op.LocalDate, &op.OpType, &payload, &op.CreatedAt); err != nil {
			return nil, err
		}
		if payload != "" {
			op.Payload = json.RawMessage(payload)
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

func (s *Store) baselineViewsCleanData(ctx context.Context, userID string) (*CleanData, error) {
	habits, err := s.baselineViewsCleanHabits(ctx, userID)
	if err != nil {
		return nil, err
	}
	habitDays, err := s.baselineViewsCleanHabitDays(ctx, userID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.baselineViewsCleanSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	meditationLogs, err := s.baselineViewsCleanMeditationLogs(ctx, userID)
	if err != nil {
		return nil, err
	}
	social, err := s.AuthoritativeSocial(ctx, userID)
	if err != nil {
		return nil, err
	}
	encryptedRecords, err := s.baselineViewsSnapshotEncryptedRecords(ctx, userID, 0)
	if err != nil {
		return nil, err
	}
	friends := json.RawMessage(`{"friends":[]}`)
	friendRequests := json.RawMessage(`{"incoming":[],"outgoing":[]}`)
	for _, item := range social {
		switch item.Kind {
		case "friends.list":
			friends = item.JSON
		case "friends.requests":
			friendRequests = item.JSON
		}
	}
	return &CleanData{
		Habits:           habits,
		HabitDays:        habitDays,
		Sessions:         sessions,
		MeditationLogs:   meditationLogs,
		Social:           social,
		EncryptedRecords: encryptedRecords,
		Friends:          friends,
		FriendRequests:   friendRequests,
	}, nil
}

func (s *Store) baselineViewsCleanHabits(ctx context.Context, userID string) ([]Habit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at
FROM server_habits
WHERE user_id_hash=?1 AND deleted_at=0
ORDER BY sort_order,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Habit{}
	for rows.Next() {
		var item Habit
		if err := rows.Scan(&item.ID, &item.Name, &item.ColorR, &item.ColorG, &item.ColorB,
			&item.SyncMode, &item.SyncActivity, &item.CounterEnabled, &item.SortOrder,
			&item.DeletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsCleanHabitDays(ctx context.Context, userID string) ([]CleanHabitDay, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT hd.habit_id,h.name,hd.local_date,hd.completed,hd.count,hd.updated_at
FROM server_habit_days hd
JOIN server_habits h ON h.user_id_hash=hd.user_id_hash AND h.id=hd.habit_id
WHERE hd.user_id_hash=?1
  AND h.deleted_at=0
  AND (hd.completed!=0 OR hd.count>0)
ORDER BY hd.local_date DESC,h.sort_order,hd.habit_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []CleanHabitDay{}
	for rows.Next() {
		var item CleanHabitDay
		var completed int
		if err := rows.Scan(&item.HabitID, &item.HabitName, &item.LocalDate,
			&completed, &item.Count, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Completed = completed != 0
		if item.Count <= 0 && item.Completed {
			item.Count = 1
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsCleanSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT id,started_at,local_date,topic,activity,source,rounds_hash,
	       mood_before,mood_after,energy,stress,note,tags,deleted_at,updated_at
	FROM server_sessions
	WHERE user_id_hash=?1 AND deleted_at=0
	ORDER BY started_at DESC,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Session{}
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ID, &item.StartedAt, &item.LocalDate, &item.Topic,
			&item.Activity, &item.Source, &item.RoundsHash, &item.MoodBefore,
			&item.MoodAfter, &item.Energy, &item.Stress, &item.Note, &item.Tags,
			&item.DeletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range items {
		rounds, err := s.baselineViewsSnapshotSessionRounds(ctx, userID, items[i].ID)
		if err != nil {
			return nil, err
		}
		items[i].Rounds = rounds
	}
	return items, nil
}

func (s *Store) baselineViewsCleanMeditationLogs(ctx context.Context, userID string) ([]MeditationLog, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1
ORDER BY completed_at DESC,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []MeditationLog{}
	for rows.Next() {
		var item MeditationLog
		if err := rows.Scan(&item.ID, &item.SessionID, &item.DurationSeconds, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsCleanSocialCache(ctx context.Context, userID string) ([]SocialSnapshot, error) {
	return s.baselineViewsSnapshotSocialCache(ctx, userID, 0)
}

func (s *Store) baselineViewsStateHash(ctx context.Context, userID string) (string, error) {
	h := sha256.New()

	if err := s.baselineViewsHashHabits(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.baselineViewsHashHabitDays(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.baselineViewsHashSessions(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.baselineViewsHashMeditationLogs(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.baselineViewsHashSocialCache(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.baselineViewsHashEncryptedRecords(ctx, h, userID); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) baselineViewsHashHabits(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at
FROM server_habits
WHERE user_id_hash=?1
ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, updatedAt string
		var colorR, colorG, colorB, syncMode, syncActivity, counterEnabled, sortOrder int
		var deletedAt int64
		if err := rows.Scan(&id, &name, &colorR, &colorG, &colorB, &syncMode, &syncActivity,
			&counterEnabled, &sortOrder, &deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "habit\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			id, name, colorR, colorG, colorB, syncMode, syncActivity, counterEnabled,
			sortOrder, deletedAt, updatedAt)
	}
	return rows.Err()
}

func (s *Store) baselineViewsHashHabitDays(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT habit_id,local_date,completed,count,updated_at
FROM server_habit_days
WHERE user_id_hash=?1
ORDER BY habit_id,local_date`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var habitID, updatedAt string
		var localDate, completed, count int
		if err := rows.Scan(&habitID, &localDate, &completed, &count, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "habit_day\t%s\t%d\t%d\t%d\t%s\n",
			habitID, localDate, completed, count, updatedAt)
	}
	return rows.Err()
}

func (s *Store) baselineViewsHashSessions(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	sessionIDs := []string{}
	rows, err := s.db.QueryContext(ctx, `
	SELECT id,started_at,local_date,topic,activity,source,rounds_hash,
	       mood_before,mood_after,energy,stress,note,tags,deleted_at,updated_at
	FROM server_sessions
	WHERE user_id_hash=?1
	ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, startedAt, topic, source, roundsHash, note, tags, updatedAt string
		var localDate, activity, moodBefore, moodAfter, energy, stress int
		var deletedAt int64
		if err := rows.Scan(&id, &startedAt, &localDate, &topic, &activity, &source,
			&roundsHash, &moodBefore, &moodAfter, &energy, &stress, &note, &tags,
			&deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "session\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%s\n",
			id, startedAt, localDate, topic, activity, source, roundsHash,
			moodBefore, moodAfter, energy, stress, note, tags, deletedAt, updatedAt)
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range sessionIDs {
		if err := s.baselineViewsHashSessionRounds(ctx, h, userID, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) baselineViewsHashSessionRounds(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID, sessionID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT round_index,breaths,hold_seconds
FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2
ORDER BY round_index`, userID, sessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var roundIndex, breaths, holdSeconds int
		if err := rows.Scan(&roundIndex, &breaths, &holdSeconds); err != nil {
			return err
		}
		fmt.Fprintf(h, "round\t%s\t%d\t%d\t%d\n", sessionID, roundIndex, breaths, holdSeconds)
	}
	return rows.Err()
}

func (s *Store) baselineViewsHashMeditationLogs(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1
ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, sessionID, completedAt string
		var durationSeconds int
		if err := rows.Scan(&id, &sessionID, &durationSeconds, &completedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "meditation_log\t%s\t%s\t%d\t%s\n", id, sessionID, durationSeconds, completedAt)
	}
	return rows.Err()
}

func (s *Store) baselineViewsHashSocialCache(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT kind,json,updated_at
FROM server_social_snapshots
WHERE user_id_hash=?1
ORDER BY kind`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var kind, payload, updatedAt string
		if err := rows.Scan(&kind, &payload, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "social_cache\t%s\t%s\t%s\n", kind, payload, updatedAt)
	}
	return rows.Err()
}

func (s *Store) baselineViewsHashEncryptedRecords(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1
ORDER BY collection,id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var collection, id, keyID, nonce, ciphertext, updatedAt, contentHash, parentID string
		var deletedAt int64
		var schemaVersion int
		if err := rows.Scan(&collection, &id, &keyID, &nonce, &ciphertext, &updatedAt,
			&deletedAt, &contentHash, &schemaVersion, &parentID); err != nil {
			return err
		}
		fmt.Fprintf(h, "encrypted_record\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
			collection, id, keyID, nonce, ciphertext, updatedAt, deletedAt,
			contentHash, schemaVersion, parentID)
	}
	return rows.Err()
}

func (s *Store) baselineViewsSnapshotHabits(ctx context.Context, userID string, sinceVersion int64) ([]Habit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version
FROM (
	SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version
	FROM server_habits
	WHERE user_id_hash=?1 AND server_version>?2
	UNION ALL
	SELECT hd.habit_id,
	       'Recovered ' || hd.habit_id,
	       99,196,165,
	       0,0,0,
	       1000,
	       0,
	       MAX(hd.updated_at),
	       MAX(hd.server_version)
	FROM server_habit_days hd
	WHERE hd.user_id_hash=?1
	  AND hd.server_version>?2
	  AND NOT EXISTS (
		SELECT 1 FROM server_habits h
		WHERE h.user_id_hash=hd.user_id_hash AND h.id=hd.habit_id
	  )
	GROUP BY hd.habit_id
)
ORDER BY server_version,sort_order,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Habit{}
	for rows.Next() {
		var item Habit
		var serverVersion int64
		if err := rows.Scan(&item.ID, &item.Name, &item.ColorR, &item.ColorG, &item.ColorB,
			&item.SyncMode, &item.SyncActivity, &item.CounterEnabled, &item.SortOrder,
			&item.DeletedAt, &item.UpdatedAt, &serverVersion); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsSnapshotHabitDays(ctx context.Context, userID string, sinceVersion int64) ([]HabitDay, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT habit_id,local_date,completed,count,updated_at
FROM server_habit_days
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,habit_id,local_date`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []HabitDay{}
	for rows.Next() {
		var item HabitDay
		var completed int
		if err := rows.Scan(&item.HabitID, &item.LocalDate, &completed, &item.Count, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Completed = completed != 0
		if item.Count <= 0 && item.Completed {
			item.Count = 1
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsSnapshotSessions(ctx context.Context, userID string, sinceVersion int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT id,started_at,local_date,topic,activity,source,rounds_hash,
	       mood_before,mood_after,energy,stress,note,tags,deleted_at,updated_at
	FROM server_sessions
	WHERE user_id_hash=?1 AND server_version>?2
	ORDER BY server_version,started_at,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Session{}
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ID, &item.StartedAt, &item.LocalDate, &item.Topic,
			&item.Activity, &item.Source, &item.RoundsHash, &item.MoodBefore,
			&item.MoodAfter, &item.Energy, &item.Stress, &item.Note, &item.Tags,
			&item.DeletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range items {
		rounds, err := s.baselineViewsSnapshotSessionRounds(ctx, userID, items[i].ID)
		if err != nil {
			return nil, err
		}
		items[i].Rounds = rounds
	}
	return items, nil
}

func (s *Store) baselineViewsSnapshotSessionRounds(ctx context.Context, userID, sessionID string) ([]SessionRound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT round_index,breaths,hold_seconds
FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2
ORDER BY round_index`, userID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SessionRound{}
	for rows.Next() {
		var item SessionRound
		if err := rows.Scan(&item.RoundIndex, &item.Breaths, &item.HoldSeconds); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsSnapshotMeditationLogs(ctx context.Context, userID string, sinceVersion int64) ([]MeditationLog, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,completed_at,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []MeditationLog{}
	for rows.Next() {
		var item MeditationLog
		if err := rows.Scan(&item.ID, &item.SessionID, &item.DurationSeconds, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsSnapshotSocialCache(ctx context.Context, userID string, sinceVersion int64) ([]SocialSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT kind,json,updated_at
FROM server_social_snapshots
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,kind`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SocialSnapshot{}
	for rows.Next() {
		var item SocialSnapshot
		var payload string
		if err := rows.Scan(&item.Kind, &payload, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if payload == "" {
			payload = "{}"
		}
		item.JSON = json.RawMessage(payload)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineViewsSnapshotEncryptedRecords(ctx context.Context, userID string, sinceVersion int64) ([]EncryptedRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,collection,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []EncryptedRecord{}
	for rows.Next() {
		var item EncryptedRecord
		if err := rows.Scan(&item.Collection, &item.ID, &item.KeyID, &item.Nonce,
			&item.Ciphertext, &item.UpdatedAt, &item.DeletedAt, &item.ContentHash,
			&item.SchemaVersion, &item.ParentID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
