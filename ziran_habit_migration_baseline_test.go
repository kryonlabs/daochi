package main

// Original legacy habit migration at 44f0f91.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *Store) baselineMigrationCleanupOrphanHabitDays(ctx context.Context, userID string) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := baselineMigrationCleanupOrphanHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	if changed {
		if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func baselineMigrationCleanupOrphanHabitDays(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1
  AND NOT EXISTS (
	SELECT 1 FROM server_habits h
	WHERE h.user_id_hash=server_habit_days.user_id_hash
	  AND h.id=server_habit_days.habit_id
  )
  AND (
	(completed=0 AND count=0)
	OR EXISTS (
		SELECT 1 FROM server_sync_ops op
		WHERE op.user_id_hash=server_habit_days.user_id_hash
		  AND op.entity_type='habit'
		  AND op.entity_id=server_habit_days.habit_id
		  AND op.op_type='delete'
	)
  )`, userID)
	if err != nil {
		return false, err
	}
	return AccountState_Affected(res) > 0, nil
}

func (s *Store) baselineMigrationAutoMigrateAccountForProtocol(ctx context.Context, userID string, protocol int) error {
	if protocol < 3 {
		return nil
	}
	return s.baselineMigrationAutoMigrateAccount(ctx, userID)
}

func (s *Store) baselineMigrationAutoMigrateAllAccounts(ctx context.Context) error {
	rows, err := s.Database.QueryContext(ctx, `SELECT user_id_hash FROM server_users ORDER BY user_id_hash`)
	if err != nil {
		return err
	}
	users := []string{}
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			rows.Close()
			return err
		}
		users = append(users, userID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, userID := range users {
		if err := s.baselineMigrationAutoMigrateAccount(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) baselineMigrationAutoMigrateAccount(ctx context.Context, userID string) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := baselineMigrationMigrateAllHabitIDsToCanonicalUUIDs(ctx, tx, userID)
	if err != nil {
		return err
	}
	materialized, err := baselineMigrationMaterializeLegacyHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	cleaned, err := baselineMigrationCleanupOrphanHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	changed = changed || materialized || cleaned
	if changed {
		if _, err := baselineLifecycleNextVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func baselineMigrationMigrateAllHabitIDsToCanonicalUUIDs(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id
FROM server_habits
WHERE user_id_hash=?1
ORDER BY sort_order,id`, userID)
	if err != nil {
		return false, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()

	changed := false
	for _, oldID := range ids {
		if oldID == "" || baselineApplicationIsCanonicalHabitID(oldID) {
			continue
		}
		newID, mapped, err := baselineApplicationCanonicalHabitIDForWrite(ctx, tx, userID, oldID, "protocol-v3-canonical")
		if err != nil {
			return false, err
		}
		if newID == oldID {
			continue
		}
		if err := baselineMigrationMergeHabitRows(ctx, tx, userID, newID, oldID); err != nil {
			return false, err
		}
		changed = changed || mapped
	}
	opsChanged, err := baselineMigrationCanonicalizeExistingHabitOps(ctx, tx, userID)
	if err != nil {
		return false, err
	}
	changed = changed || opsChanged
	return changed, nil
}

func baselineMigrationCanonicalizeExistingHabitOps(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT op_id,entity_id,payload_json
FROM server_sync_ops
WHERE user_id_hash=?1
  AND entity_type IN ('habit','habit_day')
ORDER BY server_version,op_id`, userID)
	if err != nil {
		return false, err
	}
	type opRow struct {
		opID     string
		entityID string
		payload  string
	}
	items := []opRow{}
	for rows.Next() {
		var item opRow
		if err := rows.Scan(&item.opID, &item.entityID, &item.payload); err != nil {
			rows.Close()
			return false, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()

	changed := false
	for _, item := range items {
		canonicalID, mapped, err := baselineApplicationCanonicalHabitIDForRead(ctx, tx, userID, item.entityID)
		if err != nil {
			return false, err
		}
		if !mapped {
			continue
		}
		payload := baselineApplicationRewriteHabitPayloadID(json.RawMessage(item.payload), canonicalID)
		res, err := tx.ExecContext(ctx, `
UPDATE server_sync_ops
SET entity_id=?3,payload_json=?4
WHERE user_id_hash=?1 AND op_id=?2`, userID, item.opID, canonicalID, string(payload))
		if err != nil {
			return false, err
		}
		changed = changed || AccountState_Affected(res) > 0
	}
	return changed, nil
}

func baselineMigrationMergeHabitRows(ctx context.Context, tx *sql.Tx, userID, keeperID, duplicateID string) error {
	var keeperExists int
	var duplicateExists int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, keeperID).Scan(&keeperExists); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, duplicateID).Scan(&duplicateExists); err != nil {
		return err
	}
	if duplicateExists != 0 {
		if keeperExists == 0 {
			if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET id=?3
WHERE user_id_hash=?1 AND id=?2`, userID, duplicateID, keeperID); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET name=CASE WHEN name='' THEN (SELECT name FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE name END,
	color_r=CASE WHEN color_r=0 THEN (SELECT color_r FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_r END,
	color_g=CASE WHEN color_g=0 THEN (SELECT color_g FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_g END,
	color_b=CASE WHEN color_b=0 THEN (SELECT color_b FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_b END,
	sync_mode=MAX(sync_mode,(SELECT sync_mode FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	sync_activity=(sync_activity | (SELECT sync_activity FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	counter_enabled=MAX(counter_enabled,(SELECT counter_enabled FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	sort_order=MIN(sort_order,(SELECT sort_order FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	deleted_at=CASE WHEN deleted_at=0 THEN 0 ELSE MIN(deleted_at,(SELECT deleted_at FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)) END,
	updated_at=MAX(updated_at,(SELECT updated_at FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	server_version=MAX(server_version,(SELECT server_version FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2))
WHERE user_id_hash=?1 AND id=?3`, userID, duplicateID, keeperID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, duplicateID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
SELECT user_id_hash,?3,local_date,completed,count,updated_at,server_version
FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=MAX(server_habit_days.completed,excluded.completed),
	count=MAX(server_habit_days.count,excluded.count),
	updated_at=MAX(server_habit_days.updated_at,excluded.updated_at),
	server_version=MAX(server_habit_days.server_version,excluded.server_version)`,
		userID, duplicateID, keeperID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, duplicateID); err != nil {
		return err
	}
	return nil
}

func baselineMigrationMaterializeLegacyHabitDays(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT hd.habit_id, MAX(hd.updated_at), MAX(hd.server_version)
FROM server_habit_days hd
WHERE hd.user_id_hash=?1
  AND (hd.completed!=0 OR hd.count>0)
  AND NOT EXISTS (
	SELECT 1 FROM server_habits h
	WHERE h.user_id_hash=hd.user_id_hash
	  AND h.id=hd.habit_id
  )
  AND NOT EXISTS (
	SELECT 1 FROM server_sync_ops op
	WHERE op.user_id_hash=hd.user_id_hash
	  AND op.entity_type='habit'
	  AND op.entity_id=hd.habit_id
	  AND op.op_type='delete'
  )
GROUP BY hd.habit_id
ORDER BY hd.habit_id`, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	type legacyHabit struct {
		id            string
		updatedAt     string
		serverVersion int64
	}
	habits := []legacyHabit{}
	for rows.Next() {
		var item legacyHabit
		if err := rows.Scan(&item.id, &item.updatedAt, &item.serverVersion); err != nil {
			return false, err
		}
		habits = append(habits, item)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(habits) == 0 {
		return false, nil
	}

	changed := false
	for index, habit := range habits {
		updatedAt := Timestamp_NormalizeTime(habit.updatedAt, "")
		if updatedAt == "" {
			updatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		canonicalID, _, err := baselineApplicationCanonicalHabitIDForWrite(ctx, tx, userID, habit.id, "protocol-v3-orphan")
		if err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,99,196,165,0,0,0,?4,0,?5,?6)
ON CONFLICT(user_id_hash,id) DO NOTHING`,
			userID, canonicalID, baselineMigrationLegacyHabitDisplayName(habit.id), 1000+index, updatedAt, habit.serverVersion)
		if err != nil {
			return false, err
		}
		changed = changed || AccountState_Affected(res) > 0
		if err := baselineMigrationMergeHabitRows(ctx, tx, userID, canonicalID, habit.id); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func baselineMigrationLegacyHabitDisplayName(id string) string {
	switch id {
	case "sun-salutation":
		return "Sun Salutation"
	case "whm":
		return "Wim Hof"
	case "meditation":
		return "Meditation"
	case "yoga":
		return "Yoga"
	}
	name := strings.TrimSpace(strings.ReplaceAll(id, "-", " "))
	if name == "" {
		return "Habit"
	}
	parts := strings.Fields(name)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func baselineMigrationMigrateSunSalutationHabitID(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	const oldID = "yoga"
	const newID = "sun-salutation"
	const sunSalutationMask = 1 << 2
	var syncActivity int
	var deletedAt int64
	var oldExists int
	var newExists int

	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habit_id_migrations WHERE user_id_hash=?1 AND old_id=?2)`,
		userID, oldID).Scan(&oldExists); err != nil {
		return false, err
	}
	if oldExists != 0 {
		return false, nil
	}
	err := tx.QueryRowContext(ctx, `
SELECT sync_activity,deleted_at
FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, oldID).Scan(&syncActivity, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'not-present')`, userID, oldID, newID)
		return false, err
	}
	if err != nil {
		return false, err
	}
	if deletedAt != 0 || syncActivity&sunSalutationMask == 0 {
		_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'not-sun-salutation')`, userID, oldID, newID)
		return false, err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, newID).Scan(&newExists); err != nil {
		return false, err
	}
	if newExists == 0 {
		if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET id=?3
WHERE user_id_hash=?1 AND id=?2`, userID, oldID, newID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE server_habit_days
SET habit_id=?3
WHERE user_id_hash=?1 AND habit_id=?2`, userID, oldID, newID); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
SELECT user_id_hash,?3,local_date,completed,count,updated_at,server_version
FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=MAX(server_habit_days.completed,excluded.completed),
	count=MAX(server_habit_days.count,excluded.count),
	updated_at=MAX(server_habit_days.updated_at,excluded.updated_at),
	server_version=MAX(server_habit_days.server_version,excluded.server_version)`,
			userID, oldID, newID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, oldID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, oldID); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'protocol-v3')`, userID, oldID, newID); err != nil {
		return false, err
	}
	return true, nil
}
