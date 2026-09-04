package main

// Shared boards: server-enforced membership and permissions for app data
// that several accounts edit together (krait kanban boards are the first
// client). Records are typed JSON rows like the legacy typed sync surface:
// the server can read them for relay and diagnostics, and access is gated
// by board membership. Private per-account data still belongs in
// encrypted_records; boards are for data the members choose to share.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	boardPermissionRead  = "read"
	boardPermissionWrite = "write"
	boardPermissionOwner = "owner"
	boardStatusActive    = "active"
	boardStatusArchived  = "archived"
	boardMaxRecords      = 4096
	boardMaxMembers      = 64
	boardMaxTitle        = 120
	boardMaxRecordID     = 128
	boardMaxPayload      = 32 * 1024
)

func validBoardPermission(permission string) bool {
	return permission == boardPermissionRead || permission == boardPermissionWrite
}

func validBoardID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func validBoardRecordID(id string) bool {
	if id == "" || len(id) > boardMaxRecordID {
		return false
	}
	for _, c := range id {
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func randomBoardID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

type Board struct {
	ID           string `json:"id"`
	OwnerUserID  string `json:"owner_user_id_hash"`
	AppID        string `json:"app_id,omitempty"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	MyPermission string `json:"my_permission,omitempty"`
	MemberCount  int    `json:"member_count"`
	RecordCount  int    `json:"record_count"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type BoardMember struct {
	UserIDHash string `json:"user_id_hash"`
	Alias      string `json:"alias,omitempty"`
	Permission string `json:"permission"`
	InvitedBy  string `json:"invited_by,omitempty"`
	CreatedAt  int64  `json:"created_at"`
}

type BoardRecord struct {
	ID            string          `json:"id"`
	AuthorUserID  string          `json:"author_user_id_hash"`
	Payload       json.RawMessage `json:"payload"`
	UpdatedAt     int64           `json:"updated_at"`
	DeletedAt     int64           `json:"deleted_at"`
}

type BoardDetailResponse struct {
	Status  string        `json:"status"`
	Board   Board         `json:"board"`
	Members []BoardMember `json:"members"`
}

type BoardsResponse struct {
	Status string  `json:"status"`
	Boards []Board `json:"boards"`
}

type BoardRecordsResponse struct {
	Status     string        `json:"status"`
	Records    []BoardRecord `json:"records"`
	Since      int64         `json:"since"`
	Truncated  bool          `json:"truncated"`
	NextSince  int64         `json:"next_since,omitempty"`
	ServerTime int64         `json:"server_time"`
}

type BoardCreateRequest struct {
	Title string `json:"title"`
	AppID string `json:"app_id,omitempty"`
}

type BoardPatchRequest struct {
	Title  *string `json:"title,omitempty"`
	Status *string `json:"status,omitempty"`
}

type BoardMemberInviteRequest struct {
	Target     string `json:"target"`
	Permission string `json:"permission"`
}

type BoardMemberPatchRequest struct {
	Permission string `json:"permission"`
}

type BoardRecordPutRequest struct {
	Payload json.RawMessage `json:"payload"`
}

/* ------------------------------------------------------------------ */
/* store                                                               */
/* ------------------------------------------------------------------ */

func (s *Store) AreFriends(ctx context.Context, a, b string) (bool, error) {
	pairA, pairB := friendPair(a, b)
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_friendships WHERE user_id_a=?1 AND user_id_b=?2)`,
		pairA, pairB).Scan(&exists)
	return exists != 0, err
}

func (s *Store) CreateBoard(ctx context.Context, id, ownerUserID, appID, title string) (Board, error) {
	now := time.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Board{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_boards(id,owner_user_id_hash,app_id,title,status,created_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?6)`,
		id, ownerUserID, appID, title, boardStatusActive, now); err != nil {
		return Board{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_board_members(board_id,user_id_hash,permission,invited_by,created_at)
VALUES(?1,?2,?3,?4,?5)`,
		id, ownerUserID, boardPermissionOwner, ownerUserID, now); err != nil {
		return Board{}, err
	}
	if err := tx.Commit(); err != nil {
		return Board{}, err
	}
	return Board{
		ID: id, OwnerUserID: ownerUserID, AppID: appID, Title: title,
		Status: boardStatusActive, MyPermission: boardPermissionOwner,
		MemberCount: 1, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Store) boardPermission(ctx context.Context, boardID, userID string) (string, bool, error) {
	var permission string
	err := s.db.QueryRowContext(ctx, `
SELECT permission FROM server_board_members
WHERE board_id=?1 AND user_id_hash=?2`,
		boardID, userID).Scan(&permission)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return permission, true, nil
}

func scanBoard(row interface{ Scan(...any) error }, userID string) (Board, error) {
	var board Board
	var memberCount, recordCount int
	var myPermission sql.NullString
	err := row.Scan(&board.ID, &board.OwnerUserID, &board.AppID, &board.Title,
		&board.Status, &board.CreatedAt, &board.UpdatedAt,
		&memberCount, &recordCount, &myPermission)
	if err != nil {
		return Board{}, err
	}
	board.MemberCount = memberCount
	board.RecordCount = recordCount
	if userID != "" && myPermission.Valid {
		board.MyPermission = myPermission.String
	}
	return board, nil
}

const boardListColumns = `
b.id,b.owner_user_id_hash,b.app_id,b.title,b.status,b.created_at,b.updated_at,
(SELECT COUNT(*) FROM server_board_members m WHERE m.board_id=b.id),
(SELECT COUNT(*) FROM server_board_records r WHERE r.board_id=b.id AND r.deleted_at=0),
(SELECT m2.permission FROM server_board_members m2
 WHERE m2.board_id=b.id AND m2.user_id_hash=?1)`

func (s *Store) ListBoards(ctx context.Context, userID string) ([]Board, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT `+boardListColumns+`
FROM server_boards b
JOIN server_board_members m ON m.board_id=b.id AND m.user_id_hash=?1
WHERE b.status='active'
ORDER BY b.updated_at DESC,b.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Board{}
	for rows.Next() {
		board, err := scanBoard(rows, userID)
		if err != nil {
			return nil, err
		}
		items = append(items, board)
	}
	return items, rows.Err()
}

func (s *Store) BoardByID(ctx context.Context, boardID, userID string) (Board, bool, error) {
	var board Board
	err := s.db.QueryRowContext(ctx, `
SELECT `+boardListColumns+`
FROM server_boards b
WHERE b.id=?2`,
		userID, boardID).Scan(
		&board.ID, &board.OwnerUserID, &board.AppID, &board.Title,
		&board.Status, &board.CreatedAt, &board.UpdatedAt,
		&board.MemberCount, &board.RecordCount, new(sql.NullString))
	if errors.Is(err, sql.ErrNoRows) {
		return Board{}, false, nil
	}
	if err != nil {
		return Board{}, false, err
	}
	return board, true, nil
}

func (s *Store) PatchBoard(ctx context.Context, boardID string, req BoardPatchRequest) (Board, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Board{}, false, err
	}
	defer tx.Rollback()
	if req.Title != nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE server_boards SET title=?2,updated_at=?3 WHERE id=?1`,
			boardID, *req.Title, time.Now().UnixMilli()); err != nil {
			return Board{}, false, err
		}
	}
	if req.Status != nil {
		if _, err := tx.ExecContext(ctx,
			`UPDATE server_boards SET status=?2,updated_at=?3 WHERE id=?1`,
			boardID, *req.Status, time.Now().UnixMilli()); err != nil {
			return Board{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Board{}, false, err
	}
	return s.BoardByID(ctx, boardID, "")
}

func (s *Store) ListBoardMembers(ctx context.Context, boardID string) ([]BoardMember, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT m.user_id_hash,COALESCE(u.alias,''),m.permission,m.invited_by,m.created_at
FROM server_board_members m
LEFT JOIN server_users u ON u.user_id_hash=m.user_id_hash
WHERE m.board_id=?1
ORDER BY CASE m.permission WHEN 'owner' THEN 0 WHEN 'write' THEN 1 ELSE 2 END,
         COALESCE(u.alias,m.user_id_hash)`, boardID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BoardMember{}
	for rows.Next() {
		var item BoardMember
		if err := rows.Scan(&item.UserIDHash, &item.Alias, &item.Permission,
			&item.InvitedBy, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) boardMemberCount(ctx context.Context, tx *sql.Tx, boardID string) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM server_board_members WHERE board_id=?1`,
		boardID).Scan(&count)
	return count, err
}

func (s *Store) AddBoardMember(ctx context.Context, boardID, userID, permission, invitedBy string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	count, err := s.boardMemberCount(ctx, tx, boardID)
	if err != nil {
		return err
	}
	if count >= boardMaxMembers {
		return errBoardMemberLimit
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO server_board_members(board_id,user_id_hash,permission,invited_by,created_at)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(board_id,user_id_hash) DO NOTHING`,
		boardID, userID, permission, invitedBy, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		return errBoardMemberExists
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE server_boards SET updated_at=?2 WHERE id=?1`,
		boardID, time.Now().UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PatchBoardMember(ctx context.Context, boardID, userID, permission string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE server_board_members SET permission=?3
WHERE board_id=?1 AND user_id_hash=?2 AND permission!='owner'`,
		boardID, userID, permission)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errBoardNotFound
	}
	return nil
}

func (s *Store) RemoveBoardMember(ctx context.Context, boardID, userID string) error {
	result, err := s.db.ExecContext(ctx, `
DELETE FROM server_board_members
WHERE board_id=?1 AND user_id_hash=?2 AND permission!='owner'`,
		boardID, userID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errBoardNotFound
	}
	return nil
}

func (s *Store) UpsertBoardRecord(ctx context.Context, boardID, recordID, authorUserID string, payload []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM server_board_records WHERE board_id=?1 AND deleted_at=0`,
		boardID).Scan(&count); err != nil {
		return err
	}
	if count >= boardMaxRecords {
		return errBoardRecordLimit
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_board_records(board_id,record_id,author_user_id_hash,payload,updated_at,deleted_at)
VALUES(?1,?2,?3,?4,?5,0)
ON CONFLICT(board_id,record_id) DO UPDATE SET
	author_user_id_hash=excluded.author_user_id_hash,
	payload=excluded.payload,
	updated_at=excluded.updated_at,
	deleted_at=0`,
		boardID, recordID, authorUserID, string(payload), time.Now().UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE server_boards SET updated_at=?2 WHERE id=?1`,
		boardID, time.Now().UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteBoardRecord(ctx context.Context, boardID, recordID string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE server_board_records SET deleted_at=?3,updated_at=?3
WHERE board_id=?1 AND record_id=?2`,
		boardID, recordID, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errBoardNotFound
	}
	return nil
}

func (s *Store) ListBoardRecords(ctx context.Context, boardID string, since int64, limit int) ([]BoardRecord, bool, error) {
	if limit <= 0 || limit > boardMaxRecords {
		limit = boardMaxRecords
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT record_id,author_user_id_hash,payload,updated_at,deleted_at
FROM server_board_records
WHERE board_id=?1 AND updated_at>?2
ORDER BY updated_at,record_id
LIMIT ?3`, boardID, since, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := []BoardRecord{}
	for rows.Next() {
		var item BoardRecord
		var payload string
		if err := rows.Scan(&item.ID, &item.AuthorUserID, &payload,
			&item.UpdatedAt, &item.DeletedAt); err != nil {
			return nil, false, err
		}
		item.Payload = json.RawMessage(payload)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := false
	if len(items) > limit {
		items = items[:limit]
		truncated = true
	}
	return items, truncated, nil
}

var (
	errBoardNotFound       = errors.New("board not found")
	errBoardPermission     = errors.New("board permission denied")
	errBoardNotFriend      = errors.New("invite target must be an accepted friend")
	errBoardMemberExists   = errors.New("already a member")
	errBoardMemberLimit    = errors.New("member limit reached")
	errBoardRecordLimit    = errors.New("record limit reached")
	errBoardInvalidPayload = errors.New("payload must be a JSON object")
)

/* ------------------------------------------------------------------ */
/* handlers                                                            */
/* ------------------------------------------------------------------ */

func (s *Server) requireBoardPermission(w http.ResponseWriter, r *http.Request, permission string) (string, string, bool) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return "", "", false
	}
	boardID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/boards/"), "/")
	if slash := strings.Index(boardID, "/"); slash >= 0 {
		boardID = boardID[:slash]
	}
	if !validBoardID(boardID) {
		writeError(w, http.StatusBadRequest, "invalid board id")
		return "", "", false
	}
	mine, member, err := s.store.boardPermission(r.Context(), boardID, userID)
	if err != nil {
		slog.Error("board permission", "board", boardID, "error", err)
		writeError(w, http.StatusInternalServerError, "board failed")
		return "", "", false
	}
	if !member {
		writeError(w, http.StatusNotFound, errBoardNotFound.Error())
		return "", "", false
	}
	if permission == boardPermissionWrite && mine == boardPermissionRead {
		writeError(w, http.StatusForbidden, errBoardPermission.Error())
		return "", "", false
	}
	if permission == boardPermissionOwner && mine != boardPermissionOwner {
		writeError(w, http.StatusForbidden, errBoardPermission.Error())
		return "", "", false
	}
	return boardID, userID, true
}

func (s *Server) handleBoards(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleBoardCreate(w, r)
		return
	}
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	boards, err := s.store.ListBoards(r.Context(), userID)
	if err != nil {
		slog.Error("list boards", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "boards failed")
		return
	}
	writeJSON(w, http.StatusOK, BoardsResponse{Status: "ok", Boards: boards})
}

func (s *Server) handleBoardCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	var req BoardCreateRequest
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.AppID = strings.TrimSpace(req.AppID)
	if req.Title == "" || len(req.Title) > boardMaxTitle {
		writeError(w, http.StatusBadRequest, "title required (max 120 chars)")
		return
	}
	if req.AppID == "" {
		req.AppID = "krait"
	}
	boardID, err := randomBoardID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "board create failed")
		return
	}
	board, err := s.store.CreateBoard(r.Context(), boardID, userID, req.AppID, req.Title)
	if err != nil {
		slog.Error("create board", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "board create failed")
		return
	}
	writeJSON(w, http.StatusCreated, BoardDetailResponse{Status: "ok", Board: board,
		Members: []BoardMember{{
			UserIDHash: userID, Permission: boardPermissionOwner,
			InvitedBy: userID, CreatedAt: board.CreatedAt,
		}}})
}

func (s *Server) handleBoardRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/boards/"), "/")
	boardID, sub, _ := strings.Cut(rest, "/")
	if !validBoardID(boardID) {
		writeError(w, http.StatusBadRequest, "invalid board id")
		return
	}
	switch sub {
	case "":
		s.handleBoardDetail(w, r, boardID)
	case "members":
		s.handleBoardMembersRoute(w, r, boardID)
	case "records":
		s.handleBoardRecordsRoute(w, r, boardID)
	default:
		if strings.HasPrefix(sub, "records/") {
			s.handleBoardRecordRoute(w, r, boardID, strings.TrimPrefix(sub, "records/"))
			return
		}
		if strings.HasPrefix(sub, "members/") {
			s.handleBoardMemberRoute(w, r, boardID, strings.TrimPrefix(sub, "members/"))
			return
		}
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) handleBoardDetail(w http.ResponseWriter, r *http.Request, boardID string) {
	switch r.Method {
	case http.MethodGet:
		_, userID, ok := s.requireBoardPermission(w, r, boardPermissionRead)
		if !ok {
			return
		}
		board, found, err := s.store.BoardByID(r.Context(), boardID, userID)
		if err != nil || !found {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		members, err := s.store.ListBoardMembers(r.Context(), boardID)
		if err != nil {
			slog.Error("list board members", "board", boardID, "error", err)
			writeError(w, http.StatusInternalServerError, "board failed")
			return
		}
		board.MyPermission, _, _ = s.store.boardPermission(r.Context(), boardID, userID)
		writeJSON(w, http.StatusOK, BoardDetailResponse{Status: "ok", Board: board, Members: members})
	case http.MethodPatch:
		if _, _, ok := s.requireBoardPermission(w, r, boardPermissionWrite); !ok {
			return
		}
		var req BoardPatchRequest
		body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Title != nil {
			title := strings.TrimSpace(*req.Title)
			if title == "" || len(title) > boardMaxTitle {
				writeError(w, http.StatusBadRequest, "title required (max 120 chars)")
				return
			}
			req.Title = &title
		}
		board, found, err := s.store.PatchBoard(r.Context(), boardID, req)
		if err != nil || !found {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		writeJSON(w, http.StatusOK, BoardDetailResponse{Status: "ok", Board: board})
	case http.MethodDelete:
		if _, _, ok := s.requireBoardPermission(w, r, boardPermissionOwner); !ok {
			return
		}
		archived := boardStatusArchived
		if _, found, err := s.store.PatchBoard(r.Context(), boardID, BoardPatchRequest{Status: &archived}); err != nil || !found {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "archived"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleBoardMembersRoute(w http.ResponseWriter, r *http.Request, boardID string) {
	if r.Method == http.MethodPost {
		boardToken, userID, ok := s.requireBoardPermission(w, r, boardPermissionOwner)
		if !ok {
			return
		}
		s.handleBoardMemberInvite(w, r, boardToken, userID)
		return
	}
	if _, _, ok := s.requireBoardPermission(w, r, boardPermissionRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	members, err := s.store.ListBoardMembers(r.Context(), boardID)
	if err != nil {
		slog.Error("list board members", "board", boardID, "error", err)
		writeError(w, http.StatusInternalServerError, "board failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "members": members})
}

func (s *Server) handleBoardMemberInvite(w http.ResponseWriter, r *http.Request, boardID, userID string) {
	var req BoardMemberInviteRequest
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if !validBoardPermission(req.Permission) {
		writeError(w, http.StatusBadRequest, "permission must be read or write")
		return
	}
	target, found, err := s.store.ResolveAccountRef(r.Context(), req.Target)
	if err != nil || !found {
		writeError(w, http.StatusNotFound, "invite target not found")
		return
	}
	friends, err := s.store.AreFriends(r.Context(), userID, target)
	if err != nil {
		slog.Error("friend check", "board", boardID, "error", err)
		writeError(w, http.StatusInternalServerError, "invite failed")
		return
	}
	if !friends {
		writeError(w, http.StatusForbidden, errBoardNotFriend.Error())
		return
	}
	if err := s.store.AddBoardMember(r.Context(), boardID, target, req.Permission, userID); err != nil {
		if errors.Is(err, errBoardMemberExists) || errors.Is(err, errBoardMemberLimit) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("add board member", "board", boardID, "error", err)
		writeError(w, http.StatusInternalServerError, "invite failed")
		return
	}
	s.syncHub.publish(target, 0)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (s *Server) handleBoardMemberRoute(w http.ResponseWriter, r *http.Request, boardID, memberRef string) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	memberID := strings.ToLower(strings.TrimSpace(memberRef))
	if !validUserID(memberID) {
		writeError(w, http.StatusBadRequest, "invalid member id")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		if _, _, ok := s.requireBoardPermission(w, r, boardPermissionOwner); !ok {
			return
		}
		var req BoardMemberPatchRequest
		body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if !validBoardPermission(req.Permission) {
			writeError(w, http.StatusBadRequest, "permission must be read or write")
			return
		}
		if err := s.store.PatchBoardMember(r.Context(), boardID, memberID, req.Permission); err != nil {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if memberID == userID {
			// any member may leave
			if _, member, err := s.store.boardPermission(r.Context(), boardID, userID); err != nil || !member {
				writeError(w, http.StatusNotFound, errBoardNotFound.Error())
				return
			}
		} else if _, _, ok := s.requireBoardPermission(w, r, boardPermissionOwner); !ok {
			return
		}
		if err := s.store.RemoveBoardMember(r.Context(), boardID, memberID); err != nil {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleBoardRecordsRoute(w http.ResponseWriter, r *http.Request, boardID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, _, ok := s.requireBoardPermission(w, r, boardPermissionRead); !ok {
		return
	}
	since := int64(0)
	if raw := r.URL.Query().Get("since"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "invalid since")
			return
		}
		since = parsed
	}
	records, truncated, err := s.store.ListBoardRecords(r.Context(), boardID, since, 0)
	if err != nil {
		slog.Error("list board records", "board", boardID, "error", err)
		writeError(w, http.StatusInternalServerError, "records failed")
		return
	}
	response := BoardRecordsResponse{
		Status:     "ok",
		Records:    records,
		Since:      since,
		ServerTime: time.Now().UnixMilli(),
	}
	if truncated && len(records) > 0 {
		response.Truncated = true
		response.NextSince = records[len(records)-1].UpdatedAt
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleBoardRecordRoute(w http.ResponseWriter, r *http.Request, boardID, recordID string) {
	if !validBoardRecordID(recordID) {
		writeError(w, http.StatusBadRequest, "invalid record id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		_, userID, ok := s.requireBoardPermission(w, r, boardPermissionWrite)
		if !ok {
			return
		}
		var req BoardRecordPutRequest
		body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if len(req.Payload) == 0 || len(req.Payload) > boardMaxPayload ||
			string(req.Payload[0]) != "{" {
			writeError(w, http.StatusBadRequest, errBoardInvalidPayload.Error())
			return
		}
		if err := s.store.UpsertBoardRecord(r.Context(), boardID, recordID, userID, req.Payload); err != nil {
			if errors.Is(err, errBoardRecordLimit) {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			slog.Error("upsert board record", "board", boardID, "error", err)
			writeError(w, http.StatusInternalServerError, "record failed")
			return
		}
		s.notifyBoardMembers(r.Context(), boardID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if _, _, ok := s.requireBoardPermission(w, r, boardPermissionWrite); !ok {
			return
		}
		if err := s.store.DeleteBoardRecord(r.Context(), boardID, recordID); err != nil {
			writeError(w, http.StatusNotFound, errBoardNotFound.Error())
			return
		}
		s.notifyBoardMembers(r.Context(), boardID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) notifyBoardMembers(ctx context.Context, boardID string) {
	members, err := s.store.ListBoardMembers(ctx, boardID)
	if err != nil {
		return
	}
	for _, member := range members {
		s.syncHub.publish(member.UserIDHash, 0)
	}
}
