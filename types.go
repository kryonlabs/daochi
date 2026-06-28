package main

import "encoding/json"

type ChallengeResponse struct {
	UserIDHash string `json:"user_id_hash"`
	Nonce      string `json:"nonce"`
	ExpiresIn  int64  `json:"expires_in_seconds"`
}

type LoginRequest struct {
	UserIDHash string `json:"user_id_hash"`
	ClientID   string `json:"client_id"`
	PublicKey  string `json:"public_key,omitempty"`
}

type LoginResponse struct {
	Status       string `json:"status"`
	AuthToken    string `json:"auth_token"`
	ExpiresIn    int64  `json:"expires_in_seconds"`
	AccountAlias string `json:"account_alias,omitempty"`
}

type SyncRequest struct {
	ProtocolVersion     int             `json:"protocol_version,omitempty"`
	UserIDHash          string          `json:"user_id_hash"`
	ClientID            string          `json:"client_id"`
	ClientClock         int64           `json:"client_clock,omitempty"`
	PublicKey           string          `json:"public_key,omitempty"`
	SinceServerVersion  int64           `json:"since_server_version,omitempty"`
	ClientStateHash     string          `json:"client_state_hash,omitempty"`
	LastServerStateHash string          `json:"last_server_state_hash,omitempty"`
	FullSyncRequested   bool            `json:"full_sync_requested,omitempty"`
	Bootstrap           bool            `json:"bootstrap,omitempty"`
	Ops                 []SyncOp        `json:"ops,omitempty"`
	MeditationLogs      []MeditationLog `json:"meditation_logs,omitempty"`
	Habits              []Habit         `json:"habits,omitempty"`
	HabitDays           []HabitDay      `json:"habit_days,omitempty"`
	Sessions            []Session       `json:"sessions,omitempty"`
	SocialCache         []SocialCache   `json:"social_cache,omitempty"`
}

type SyncChanges struct {
	Habits         []Habit         `json:"habits"`
	HabitDays      []HabitDay      `json:"habit_days"`
	Sessions       []Session       `json:"sessions"`
	MeditationLogs []MeditationLog `json:"meditation_logs"`
	SocialCache    []SocialCache   `json:"social_cache"`
}

type SyncResponse struct {
	ProtocolVersion      int         `json:"protocol_version,omitempty"`
	Status               string      `json:"status"`
	Applied              SyncResult  `json:"applied"`
	AccountAlias         string      `json:"account_alias,omitempty"`
	ServerVersion        int64       `json:"server_version"`
	ServerClock          int64       `json:"server_clock,omitempty"`
	ServerStateHash      string      `json:"server_state_hash,omitempty"`
	BaseStateHash        string      `json:"base_state_hash,omitempty"`
	ChangesComplete      bool        `json:"changes_complete"`
	FullSnapshotRequired bool        `json:"full_snapshot_required"`
	AcceptedOps          []string    `json:"accepted_ops,omitempty"`
	Ops                  []SyncOp    `json:"ops,omitempty"`
	Changes              SyncChanges `json:"changes"`
}

type SyncOp struct {
	OpID       string          `json:"op_id"`
	ClientID   string          `json:"client_id"`
	Seq        int64           `json:"seq"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	LocalDate  int             `json:"local_date,omitempty"`
	OpType     string          `json:"op_type"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	CreatedAt  string          `json:"created_at,omitempty"`
}

type SocialCache struct {
	Kind      string          `json:"kind"`
	JSON      json.RawMessage `json:"json"`
	UpdatedAt string          `json:"updated_at"`
}

type DeleteRequest struct {
	UserIDHash string `json:"user_id_hash"`
}

type AliasRequest struct {
	UserIDHash string `json:"user_id_hash"`
	Alias      string `json:"alias"`
}

type AliasResponse struct {
	Status string `json:"status"`
	Alias  string `json:"alias"`
}

type FriendRequestCreateRequest struct {
	Target string `json:"target"`
}

type FriendRequestActionRequest struct {
	UserIDHash string `json:"user_id_hash,omitempty"`
}

type FriendRequestResponse struct {
	Status  string        `json:"status"`
	Request FriendRequest `json:"request"`
}

type FriendRequestsResponse struct {
	Incoming []FriendRequest `json:"incoming"`
	Outgoing []FriendRequest `json:"outgoing"`
}

type FriendsResponse struct {
	Friends []Friend `json:"friends"`
}

type ProfileStatsRequest struct {
	App     string          `json:"app"`
	Metrics []ProfileMetric `json:"metrics"`
}

type ProfileStatsResponse struct {
	Status  string `json:"status"`
	Applied int    `json:"applied"`
}

type FriendStatsResponse struct {
	Rows []FriendStatRow `json:"rows"`
}

type FriendRequest struct {
	ID              string `json:"id"`
	RequesterUserID string `json:"requester_user_id_hash"`
	RequesterAlias  string `json:"requester_alias,omitempty"`
	TargetUserID    string `json:"target_user_id_hash"`
	TargetAlias     string `json:"target_alias,omitempty"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type Friend struct {
	UserIDHash string `json:"user_id_hash"`
	Alias      string `json:"alias,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type ProfileMetric struct {
	Practice  string  `json:"practice"`
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Label     string  `json:"label,omitempty"`
	LocalDate int     `json:"local_date,omitempty"`
}

type FriendStatRow struct {
	UserIDHash string  `json:"user_id_hash"`
	Alias      string  `json:"alias,omitempty"`
	App        string  `json:"app"`
	Practice   string  `json:"practice"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Label      string  `json:"label,omitempty"`
	LocalDate  int     `json:"local_date,omitempty"`
	UpdatedAt  string  `json:"updated_at"`
}

type DeleteWithKeyRequest struct {
	UserIDHash  string `json:"user_id_hash"`
	ExportedKey string `json:"exported_key,omitempty"`
}

type MeditationLog struct {
	ID              string `json:"id"`
	SessionID       string `json:"session_id"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	Duration        int    `json:"duration,omitempty"`
	CompletedAt     string `json:"completed_at,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
}

type Habit struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ColorR         int    `json:"color_r"`
	ColorG         int    `json:"color_g"`
	ColorB         int    `json:"color_b"`
	SyncMode       int    `json:"sync_mode"`
	SyncActivity   int    `json:"sync_activity"`
	CounterEnabled int    `json:"counter_enabled"`
	SortOrder      int    `json:"sort_order"`
	DeletedAt      int64  `json:"deleted_at"`
	UpdatedAt      string `json:"updated_at"`
}

type HabitDay struct {
	HabitID   string `json:"habit_id"`
	LocalDate int    `json:"local_date"`
	Completed bool   `json:"completed"`
	Count     int    `json:"count"`
	UpdatedAt string `json:"updated_at"`
}

type Session struct {
	ID         string         `json:"id"`
	StartedAt  string         `json:"started_at"`
	LocalDate  int            `json:"local_date"`
	Topic      string         `json:"topic"`
	Activity   int            `json:"activity"`
	Source     string         `json:"source"`
	RoundsHash string         `json:"rounds_hash"`
	DeletedAt  int64          `json:"deleted_at"`
	UpdatedAt  string         `json:"updated_at"`
	Rounds     []SessionRound `json:"rounds,omitempty"`
}

type SessionRound struct {
	RoundIndex  int `json:"round_index"`
	Breaths     int `json:"breaths"`
	HoldSeconds int `json:"hold_seconds"`
}

type SyncResult struct {
	MeditationLogs int `json:"meditation_logs"`
	Habits         int `json:"habits"`
	HabitDays      int `json:"habit_days"`
	Sessions       int `json:"sessions"`
	SocialCache    int `json:"social_cache"`
}

type UkuProcess struct {
	ID              string        `json:"id"`
	OwnerUserIDHash string        `json:"owner_user_id_hash,omitempty"`
	Question        string        `json:"question"`
	Description     string        `json:"description,omitempty"`
	Visibility      string        `json:"visibility"`
	ProposalMinutes int           `json:"proposal_minutes"`
	VotingMinutes   int           `json:"voting_minutes"`
	NegativeWeight  int           `json:"negative_weight"`
	CreatedAt       string        `json:"created_at"`
	UpdatedAt       string        `json:"updated_at"`
	Proposals       []UkuProposal `json:"proposals,omitempty"`
	Votes           []UkuVote     `json:"votes,omitempty"`
}

type UkuProposal struct {
	ID               string `json:"id"`
	AuthorUserIDHash string `json:"author_user_id_hash,omitempty"`
	Title            string `json:"title"`
	Description      string `json:"description,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	DeletedAt        int64  `json:"deleted_at,omitempty"`
}

type UkuVote struct {
	VoterUserIDHash string         `json:"voter_user_id_hash,omitempty"`
	DisplayName     string         `json:"display_name,omitempty"`
	Scores          map[string]int `json:"scores"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

type UkuCreateProcessRequest struct {
	UserIDHash      string `json:"user_id_hash"`
	ID              string `json:"id,omitempty"`
	Question        string `json:"question"`
	Description     string `json:"description,omitempty"`
	Visibility      string `json:"visibility,omitempty"`
	ProposalMinutes int    `json:"proposal_minutes"`
	VotingMinutes   int    `json:"voting_minutes"`
	NegativeWeight  int    `json:"negative_weight"`
}

type UkuUpdateProcessRequest struct {
	UserIDHash  string `json:"user_id_hash"`
	Question    string `json:"question,omitempty"`
	Description string `json:"description,omitempty"`
	Visibility  string `json:"visibility,omitempty"`
}

type UkuProposalRequest struct {
	UserIDHash  string `json:"user_id_hash"`
	ID          string `json:"id,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

type UkuVoteRequest struct {
	UserIDHash  string         `json:"user_id_hash"`
	DisplayName string         `json:"display_name,omitempty"`
	Scores      map[string]int `json:"scores"`
}
