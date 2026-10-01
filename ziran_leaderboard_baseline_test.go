// Original leaderboard storage retained as an independent regression oracle.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

type baselineLeaderboardVisibleStatsUser struct {
	UserIDHash    string
	Alias         string
	ProfileIcon   int
	SourceVersion int64
}

const baselineLeaderboardLeaderboardStatsCalcVersion = 4

func baselineLeaderboardLeaderboardActivity(practice string) int {
	switch practice {
	case "meditation":
		return 1
	case "sun_salutation":
		return 2
	default:
		return 0
	}
}

func baselineLeaderboardLeaderboardTimeLabel(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	return fmt.Sprintf("%d:%02d", seconds/3600, (seconds%3600)/60)
}

func baselineLeaderboardLeaderboardTodayDate() int {
	today := time.Now().UTC()
	return today.Year()*10000 + int(today.Month())*100 + today.Day()
}

func (s *Store) baselineLeaderboardVisibleStatsUsers(ctx context.Context, userID string) ([]baselineLeaderboardVisibleStatsUser, error) {
	rows, err := s.Database.QueryContext(ctx, `
WITH visible_users AS (
  SELECT u.user_id_hash, COALESCE(u.alias,'') AS alias, u.profile_icon
  FROM server_users u
  WHERE u.user_id_hash=?1
  UNION
  SELECT u.user_id_hash, COALESCE(u.alias,'') AS alias, u.profile_icon
  FROM server_friendships f
  JOIN server_users u ON u.user_id_hash=CASE
      WHEN f.user_id_a=?1 THEN f.user_id_b
      ELSE f.user_id_a
  END
  WHERE f.user_id_a=?1 OR f.user_id_b=?1
)
SELECT vu.user_id_hash, vu.alias, vu.profile_icon, COALESCE(ss.server_version,0)
FROM visible_users vu
LEFT JOIN server_sync_state ss ON ss.user_id_hash=vu.user_id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []baselineLeaderboardVisibleStatsUser{}
	for rows.Next() {
		var user baselineLeaderboardVisibleStatsUser
		if err := rows.Scan(&user.UserIDHash, &user.Alias, &user.ProfileIcon, &user.SourceVersion); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) baselineLeaderboardCachedLeaderboardStat(ctx context.Context, user baselineLeaderboardVisibleStatsUser, app, practice, metric string) (FriendStatRow, bool, error) {
	var row FriendStatRow
	var sourceVersion int64
	var calcVersion int
	err := s.Database.QueryRowContext(ctx, `
SELECT source_version,calc_version,value,label,local_date,updated_at
FROM server_leaderboard_stats
WHERE user_id_hash=?1 AND app=?2 AND practice=?3 AND metric=?4`,
		user.UserIDHash, app, practice, metric).Scan(&sourceVersion, &calcVersion, &row.Value, &row.Label, &row.LocalDate, &row.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, err
	}
	if sourceVersion != user.SourceVersion || calcVersion != baselineLeaderboardLeaderboardStatsCalcVersion {
		return row, false, nil
	}
	if metric == "streak" && row.LocalDate != baselineLeaderboardLeaderboardTodayDate() {
		return row, false, nil
	}
	row.UserIDHash = user.UserIDHash
	row.Alias = user.Alias
	row.ProfileIcon = user.ProfileIcon
	row.App = app
	row.Practice = practice
	row.Metric = metric
	return row, true, nil
}

func (s *Store) baselineLeaderboardActivityStreak(ctx context.Context, userID string, activity int) (int, int, string, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT local_date, updated_at FROM server_sessions
WHERE user_id_hash=?1 AND deleted_at=0 AND activity=?2 AND local_date>0
UNION
SELECT CAST(strftime('%Y%m%d', completed_at) AS INTEGER), completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1 AND ?2=1 AND duration_seconds>0`, userID, activity)
	if err != nil {
		return 0, 0, "", err
	}
	defer rows.Close()
	seen := map[int]bool{}
	updatedAt := ""
	for rows.Next() {
		var localDate int
		var updated string
		if err := rows.Scan(&localDate, &updated); err != nil {
			return 0, 0, "", err
		}
		if localDate > 0 {
			seen[localDate] = true
		}
		if updated > updatedAt {
			updatedAt = updated
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, "", err
	}
	today := time.Now().UTC()
	todayDate := baselineLeaderboardLeaderboardTodayDate()
	start := today
	streak := 0
	for ; streak <= 370; streak++ {
		day := start.AddDate(0, 0, -streak)
		localDate := day.Year()*10000 + int(day.Month())*100 + day.Day()
		if !seen[localDate] {
			break
		}
	}
	return streak, todayDate, updatedAt, nil
}

func (s *Store) baselineLeaderboardActivityAverage(ctx context.Context, userID string, practice, metric string) (float64, string, error) {
	switch metric {
	case "avg_hold":
		if practice != "whm" {
			return 0, "0", nil
		}
		var value float64
		err := s.Database.QueryRowContext(ctx, `
SELECT COALESCE(AVG(sr.hold_seconds),0)
FROM server_sessions s
JOIN server_session_rounds sr ON sr.user_id_hash=s.user_id_hash AND sr.session_id=s.id
WHERE s.user_id_hash=?1 AND s.deleted_at=0 AND s.activity=0 AND sr.hold_seconds>0`, userID).Scan(&value)
		return value, fmt.Sprintf("%.0f", value), err
	case "avg_time":
		if practice != "meditation" {
			return 0, baselineLeaderboardLeaderboardTimeLabel(0), nil
		}
		var value float64
		err := s.Database.QueryRowContext(ctx, `
WITH session_totals AS (
  SELECT s.id, SUM(sr.hold_seconds) AS seconds
  FROM server_sessions s
  JOIN server_session_rounds sr ON sr.user_id_hash=s.user_id_hash AND sr.session_id=s.id
  WHERE s.user_id_hash=?1 AND s.deleted_at=0 AND s.activity=1 AND sr.hold_seconds>0
  GROUP BY s.id
),
log_totals AS (
  SELECT ml.session_id AS id, ml.duration_seconds AS seconds
  FROM server_meditation_logs ml
  WHERE ml.user_id_hash=?1 AND ml.duration_seconds>0
    AND NOT EXISTS (SELECT 1 FROM session_totals st WHERE st.id=ml.session_id)
),
all_totals AS (
  SELECT seconds FROM session_totals
  UNION ALL
  SELECT seconds FROM log_totals
)
SELECT COALESCE(AVG(seconds),0) FROM all_totals`, userID).Scan(&value)
		return value, baselineLeaderboardLeaderboardTimeLabel(int(value + 0.5)), err
	default:
		return 0, "0", nil
	}
}

func (s *Store) baselineLeaderboardComputeLeaderboardStat(ctx context.Context, user baselineLeaderboardVisibleStatsUser, app, practice, metric string) (FriendStatRow, error) {
	activity := baselineLeaderboardLeaderboardActivity(practice)
	streak, todayDate, updatedAt, err := s.baselineLeaderboardActivityStreak(ctx, user.UserIDHash, activity)
	if err != nil {
		return FriendStatRow{}, err
	}
	row := FriendStatRow{
		UserIDHash:  user.UserIDHash,
		Alias:       user.Alias,
		ProfileIcon: user.ProfileIcon,
		App:         app,
		Practice:    practice,
		Metric:      metric,
		LocalDate:   todayDate,
		UpdatedAt:   updatedAt,
	}
	if metric == "streak" {
		row.Value = float64(streak)
		row.Label = fmt.Sprintf("%d", streak)
	} else {
		value, label, err := s.baselineLeaderboardActivityAverage(ctx, user.UserIDHash, practice, metric)
		if err != nil {
			return row, err
		}
		row.Value = value
		row.Label = label
	}
	_, err = s.Database.ExecContext(ctx, `
INSERT INTO server_leaderboard_stats(user_id_hash,app,practice,metric,source_version,calc_version,value,label,local_date,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
ON CONFLICT(user_id_hash,app,practice,metric) DO UPDATE SET
	source_version=excluded.source_version,
	calc_version=excluded.calc_version,
	value=excluded.value,
	label=excluded.label,
	local_date=excluded.local_date,
	updated_at=excluded.updated_at`,
		user.UserIDHash, app, practice, metric, user.SourceVersion, baselineLeaderboardLeaderboardStatsCalcVersion,
		row.Value, row.Label, row.LocalDate, row.UpdatedAt)
	return row, err
}

func (s *Store) baselineLeaderboardFriendStats(ctx context.Context, userID, app, practice, metric string) ([]FriendStatRow, error) {
	users, err := s.baselineLeaderboardVisibleStatsUsers(ctx, userID)
	if err != nil {
		return nil, err
	}
	items := make([]FriendStatRow, 0, len(users))
	for _, user := range users {
		row, ok, err := s.baselineLeaderboardCachedLeaderboardStat(ctx, user, app, practice, metric)
		if err != nil {
			return nil, err
		}
		if !ok {
			row, err = s.baselineLeaderboardComputeLeaderboardStat(ctx, user, app, practice, metric)
			if err != nil {
				return nil, err
			}
		}
		items = append(items, row)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		left := items[i].Alias
		if left == "" {
			left = items[i].UserIDHash
		}
		right := items[j].Alias
		if right == "" {
			right = items[j].UserIDHash
		}
		if left != right {
			return left < right
		}
		return items[i].UserIDHash < items[j].UserIDHash
	})
	return items, nil
}
