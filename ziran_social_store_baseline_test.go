// Original account and friendship storage retained as a regression oracle.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *Store) baselineSocialRegisterUser(ctx context.Context, userID string, publicKey []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_account_tombstones WHERE user_id_hash=?1`, userID); err != nil {
		return err
	}
	if err := baselineSocialUpsertUser(ctx, tx, userID, publicKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) baselineSocialAccountAlias(ctx context.Context, userID string) (string, error) {
	var alias sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT alias FROM server_users WHERE user_id_hash=?1`, userID).Scan(&alias)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !alias.Valid {
		return "", nil
	}
	return alias.String, nil
}

func (s *Store) baselineSocialSetAccountAlias(ctx context.Context, userID, alias string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE server_users
SET alias=?2,last_seen_at=?3
WHERE user_id_hash=?1`, userID, alias, Timestamp_CanonicalNow())
	if err != nil {
		return err
	}
	if AccountState_Affected(res) == 0 {
		return ErrSyncUserNotFound
	}
	return nil
}

func (s *Store) baselineSocialAccountProfileIcon(ctx context.Context, userID string) (int, error) {
	var profileIcon int
	err := s.db.QueryRowContext(ctx, `SELECT profile_icon FROM server_users WHERE user_id_hash=?1`, userID).Scan(&profileIcon)
	if errors.Is(err, sql.ErrNoRows) {
		return ProfileIconNone, nil
	}
	if err != nil {
		return ProfileIconNone, err
	}
	return profileIcon, nil
}

func (s *Store) baselineSocialSetAccountProfileIcon(ctx context.Context, userID string, profileIcon int) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE server_users
SET profile_icon=?2,last_seen_at=?3
WHERE user_id_hash=?1`, userID, profileIcon, Timestamp_CanonicalNow())
	if err != nil {
		return err
	}
	if AccountState_Affected(res) == 0 {
		return ErrSyncUserNotFound
	}
	return nil
}

func (s *Store) baselineSocialResolveAccountRef(ctx context.Context, ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "@") {
		ref = strings.TrimPrefix(ref, "@")
	}
	if Identity_ValidUserID(strings.ToLower(ref)) {
		userID := strings.ToLower(ref)
		var exists int
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_users WHERE user_id_hash=?1)`, userID).Scan(&exists)
		return userID, exists != 0, err
	}
	alias := strings.ToLower(ref)
	if !Identity_ValidAccountAlias(alias) {
		return "", false, nil
	}
	var userID string
	err := s.db.QueryRowContext(ctx, `SELECT user_id_hash FROM server_users WHERE alias=?1`, alias).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return userID, true, err
}

func baselineSocialFriendPair(a, b string) (string, string) {
	if a < b {
		return a, b
	}
	return b, a
}

func (s *Store) baselineSocialCreateFriendRequest(ctx context.Context, id, requester, target string) (FriendRequest, error) {
	if requester == target {
		return FriendRequest{}, errors.New("cannot friend self")
	}
	a, b := baselineSocialFriendPair(requester, target)
	var alreadyFriends int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_friendships WHERE user_id_a=?1 AND user_id_b=?2)`, a, b).Scan(&alreadyFriends); err != nil {
		return FriendRequest{}, err
	}
	if alreadyFriends != 0 {
		return FriendRequest{}, errors.New("already friends")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO server_friend_requests(id,requester_user_id_hash,target_user_id_hash,status,created_at,updated_at)
VALUES(?1,?2,?3,'pending',?4,?4)
ON CONFLICT(requester_user_id_hash,target_user_id_hash) DO UPDATE SET
	status=CASE WHEN server_friend_requests.status='declined' THEN 'pending' ELSE server_friend_requests.status END,
	updated_at=CASE WHEN server_friend_requests.status='declined' THEN excluded.updated_at ELSE server_friend_requests.updated_at END`,
		id, requester, target, now); err != nil {
		return FriendRequest{}, err
	}
	return s.baselineSocialFriendRequestByUsers(ctx, requester, target)
}

func (s *Store) baselineSocialFriendRequestByUsers(ctx context.Context, requester, target string) (FriendRequest, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.requester_user_id_hash=?1 AND fr.target_user_id_hash=?2`, requester, target)
	return baselineSocialScanFriendRequest(row)
}

func (s *Store) baselineSocialFriendRequest(ctx context.Context, id string) (FriendRequest, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.id=?1`, id)
	req, err := baselineSocialScanFriendRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FriendRequest{}, false, nil
	}
	return req, err == nil, err
}

func baselineSocialScanFriendRequest(row interface{ Scan(...any) error }) (FriendRequest, error) {
	var req FriendRequest
	err := row.Scan(&req.ID, &req.RequesterUserID, &req.RequesterAlias, &req.TargetUserID, &req.TargetAlias, &req.Status, &req.CreatedAt, &req.UpdatedAt)
	return req, err
}

func (s *Store) baselineSocialListFriendRequests(ctx context.Context, userID string) ([]FriendRequest, []FriendRequest, error) {
	query := func(where string) ([]FriendRequest, error) {
		rows, err := s.db.QueryContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE `+where+` AND fr.status='pending'
ORDER BY fr.updated_at DESC`, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []FriendRequest{}
		for rows.Next() {
			req, err := baselineSocialScanFriendRequest(rows)
			if err != nil {
				return nil, err
			}
			items = append(items, req)
		}
		return items, rows.Err()
	}
	incoming, err := query("fr.target_user_id_hash=?1")
	if err != nil {
		return nil, nil, err
	}
	outgoing, err := query("fr.requester_user_id_hash=?1")
	return incoming, outgoing, err
}

func (s *Store) baselineSocialAcceptFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FriendRequest{}, err
	}
	defer tx.Rollback()
	var req FriendRequest
	row := tx.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.id=?1`, id)
	if err := row.Scan(&req.ID, &req.RequesterUserID, &req.RequesterAlias, &req.TargetUserID, &req.TargetAlias, &req.Status, &req.CreatedAt, &req.UpdatedAt); err != nil {
		return FriendRequest{}, err
	}
	if req.TargetUserID != userID {
		return FriendRequest{}, ErrSyncUserNotFound
	}
	if req.Status != "pending" {
		return FriendRequest{}, errors.New("request not pending")
	}
	a, b := baselineSocialFriendPair(req.RequesterUserID, req.TargetUserID)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `UPDATE server_friend_requests SET status='accepted',updated_at=?2 WHERE id=?1`, id, now); err != nil {
		return FriendRequest{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_friendships(user_id_a,user_id_b,created_at)
VALUES(?1,?2,?3)`, a, b, now); err != nil {
		return FriendRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return FriendRequest{}, err
	}
	req.Status = "accepted"
	req.UpdatedAt = now
	return req, nil
}

func (s *Store) baselineSocialDeclineFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	req, found, err := s.baselineSocialFriendRequest(ctx, id)
	if err != nil {
		return FriendRequest{}, err
	}
	if !found {
		return FriendRequest{}, sql.ErrNoRows
	}
	if req.TargetUserID != userID && req.RequesterUserID != userID {
		return FriendRequest{}, ErrSyncUserNotFound
	}
	if req.Status != "pending" {
		return FriendRequest{}, errors.New("request not pending")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `UPDATE server_friend_requests SET status='declined',updated_at=?2 WHERE id=?1`, id, now); err != nil {
		return FriendRequest{}, err
	}
	req.Status = "declined"
	req.UpdatedAt = now
	return req, nil
}

func (s *Store) baselineSocialListFriends(ctx context.Context, userID string) ([]Friend, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT u.user_id_hash,COALESCE(u.alias,''),u.profile_icon,f.created_at
FROM server_friendships f
JOIN server_users u ON u.user_id_hash=CASE WHEN f.user_id_a=?1 THEN f.user_id_b ELSE f.user_id_a END
WHERE f.user_id_a=?1 OR f.user_id_b=?1
ORDER BY COALESCE(u.alias,u.user_id_hash),u.user_id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Friend{}
	for rows.Next() {
		var item Friend
		if err := rows.Scan(&item.UserIDHash, &item.Alias, &item.ProfileIcon, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// baselineSocialAuthoritativeSocial returns the current social state from the friendship
// tables. server_social_snapshots is only a cache populated by the standalone
// social endpoints, so it must not decide what a newly restored client sees.
func (s *Store) baselineSocialAuthoritativeSocial(ctx context.Context, userID string) ([]SocialSnapshot, error) {
	friends, err := s.baselineSocialListFriends(ctx, userID)
	if err != nil {
		return nil, err
	}
	incoming, outgoing, err := s.baselineSocialListFriendRequests(ctx, userID)
	if err != nil {
		return nil, err
	}
	friendsJSON, err := json.Marshal(FriendsResponse{Friends: friends})
	if err != nil {
		return nil, err
	}
	requestsJSON, err := json.Marshal(FriendRequestsResponse{Incoming: incoming, Outgoing: outgoing})
	if err != nil {
		return nil, err
	}
	now := Timestamp_CanonicalNow()
	return []SocialSnapshot{
		{Kind: "friends.list", JSON: friendsJSON, UpdatedAt: now},
		{Kind: "friends.requests", JSON: requestsJSON, UpdatedAt: now},
	}, nil
}

func (s *Store) baselineSocialRemoveFriend(ctx context.Context, userID, friendID string) error {
	a, b := baselineSocialFriendPair(userID, friendID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_friendships WHERE user_id_a=?1 AND user_id_b=?2`, a, b); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM server_friend_requests
WHERE (requester_user_id_hash=?1 AND target_user_id_hash=?2)
   OR (requester_user_id_hash=?2 AND target_user_id_hash=?1)`, userID, friendID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) baselineSocialUpsertProfileStats(ctx context.Context, userID, app string, metrics []ProfileMetric) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	applied := 0
	for _, metric := range metrics {
		practice := strings.TrimSpace(metric.Practice)
		name := strings.TrimSpace(metric.Metric)
		if practice == "" || name == "" {
			continue
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_profile_stats(user_id_hash,app,practice,metric,value,label,local_date,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(user_id_hash,app,practice,metric) DO UPDATE SET
	value=excluded.value,label=excluded.label,local_date=excluded.local_date,updated_at=excluded.updated_at
WHERE excluded.value != server_profile_stats.value
   OR excluded.label != server_profile_stats.label
   OR excluded.local_date != server_profile_stats.local_date`,
			userID, app, practice, name, metric.Value, metric.Label, metric.LocalDate, now)
		if err != nil {
			return 0, err
		}
		applied += AccountState_Affected(res)
	}
	return applied, tx.Commit()
}

func baselineSocialUpsertUser(ctx context.Context, tx *sql.Tx, userID string, publicKey []byte) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_users(user_id_hash,public_key)
VALUES(?1,?2)
ON CONFLICT(user_id_hash) DO UPDATE SET last_seen_at=?3`, userID, publicKey, Timestamp_CanonicalNow()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, userID)
	return err
}
