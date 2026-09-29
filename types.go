package main

import "encoding/json"

type AccountExportResponse struct {
	Status       string                      `json:"status"`
	UserIDHash   string                      `json:"user_id_hash"`
	AccountAlias string                      `json:"account_alias,omitempty"`
	ProfileIcon  int                         `json:"profile_icon,omitempty"`
	Tables       map[string][]map[string]any `json:"tables"`
}

type SyncRequest struct {
	ProtocolVersion     int               `json:"protocol_version,omitempty"`
	AppID               string            `json:"app_id,omitempty"`
	UserIDHash          string            `json:"user_id_hash"`
	ClientID            string            `json:"client_id"`
	ClientCapabilities  []string          `json:"client_capabilities,omitempty"`
	IncludeLegacyData   bool              `json:"include_legacy_data,omitempty"`
	ClientClock         int64             `json:"client_clock,omitempty"`
	PublicKey           string            `json:"public_key,omitempty"`
	SinceServerVersion  int64             `json:"since_server_version,omitempty"`
	ClientStateHash     string            `json:"client_state_hash,omitempty"`
	LastServerStateHash string            `json:"last_server_state_hash,omitempty"`
	FullSyncRequested   bool              `json:"full_sync_requested,omitempty"`
	Bootstrap           bool              `json:"bootstrap,omitempty"`
	Ops                 []SyncOp          `json:"ops,omitempty"`
	MeditationLogs      []MeditationLog   `json:"meditation_logs,omitempty"`
	Habits              []Habit           `json:"habits,omitempty"`
	HabitDays           []HabitDay        `json:"habit_days,omitempty"`
	Sessions            []Session         `json:"sessions,omitempty"`
	SocialCache         []SocialCache     `json:"social_cache,omitempty"`
	EncryptedRecords    []EncryptedRecord `json:"encrypted_records,omitempty"`
}

type SyncChanges struct {
	Habits           []Habit           `json:"habits"`
	HabitDays        []HabitDay        `json:"habit_days"`
	Sessions         []Session         `json:"sessions"`
	MeditationLogs   []MeditationLog   `json:"meditation_logs"`
	SocialCache      []SocialCache     `json:"social_cache"`
	EncryptedRecords []EncryptedRecord `json:"encrypted_records,omitempty"`
}

type SyncResponse struct {
	ProtocolVersion                   int                `json:"protocol_version,omitempty"`
	Status                            string             `json:"status"`
	ServerCapabilities                []string           `json:"server_capabilities,omitempty"`
	TransitionMode                    string             `json:"transition_mode,omitempty"`
	Applied                           SyncResult         `json:"applied"`
	AccountAlias                      string             `json:"account_alias,omitempty"`
	ProfileIcon                       int                `json:"profile_icon,omitempty"`
	ServerVersion                     int64              `json:"server_version"`
	ServerClock                       int64              `json:"server_clock,omitempty"`
	ServerStateHash                   string             `json:"server_state_hash,omitempty"`
	BaseStateHash                     string             `json:"base_state_hash,omitempty"`
	ChangesComplete                   bool               `json:"changes_complete"`
	FullSnapshotRequired              bool               `json:"full_snapshot_required"`
	AcceptedOps                       []string           `json:"accepted_ops,omitempty"`
	Ops                               []SyncOp           `json:"ops,omitempty"`
	Changes                           SyncChanges        `json:"changes"`
	Data                              *CleanData         `json:"data,omitempty"`
	Logs                              []SyncLog          `json:"logs,omitempty"`
	Deletes                           []SyncLog          `json:"deletes,omitempty"`
	EncryptedPayloads                 []EncryptedPayload `json:"encrypted_payloads,omitempty"`
	EncryptedPayloadsNextSinceVersion int64              `json:"encrypted_payloads_next_since_version,omitempty"`
	EncryptedPayloadsTruncated        bool               `json:"encrypted_payloads_truncated,omitempty"`
	UpgradeNotice                     string             `json:"upgrade_notice,omitempty"`
	MinSupportedProtocol              int                `json:"min_supported_protocol,omitempty"`
	// LatestProtocol echoes the negotiated protocol for shipped clients that
	// interpret a higher value as an application upgrade warning.
	LatestProtocol        int              `json:"latest_protocol,omitempty"`
	ServerLatestProtocol  int              `json:"server_latest_protocol,omitempty"`
	LegacyClients         []string         `json:"legacy_clients,omitempty"`
	LegacyWriteRequired   bool             `json:"legacy_write_required"`
	LegacyProjectionEpoch int64            `json:"legacy_projection_epoch,omitempty"`
	Diagnostics           *SyncDiagnostics `json:"diagnostics,omitempty"`
}

type CleanData struct {
	Habits           []Habit           `json:"habits"`
	HabitDays        []CleanHabitDay   `json:"habit_days"`
	Sessions         []Session         `json:"sessions"`
	MeditationLogs   []MeditationLog   `json:"meditation_logs"`
	Social           []SocialSnapshot  `json:"social,omitempty"`
	EncryptedRecords []EncryptedRecord `json:"encrypted_records,omitempty"`
	Friends          json.RawMessage   `json:"friends,omitempty"`
	FriendRequests   json.RawMessage   `json:"friend_requests,omitempty"`
}

type SyncLog struct {
	ServerVersion int64           `json:"server_version"`
	Kind          string          `json:"kind"`
	EntityType    string          `json:"entity_type"`
	EntityID      string          `json:"entity_id"`
	LocalDate     int             `json:"local_date,omitempty"`
	OpType        string          `json:"op_type,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	CreatedAt     string          `json:"created_at,omitempty"`
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

type SocialSnapshot struct {
	Kind      string          `json:"kind"`
	JSON      json.RawMessage `json:"json"`
	UpdatedAt string          `json:"updated_at"`
}

type SocialCache = SocialSnapshot

type EncryptedPayload struct {
	ID            int64           `json:"id"`
	ClientID      string          `json:"client_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     string          `json:"created_at,omitempty"`
	ServerVersion int64           `json:"server_version"`
}

type SyncDiagnosticReport struct {
	Status                   string             `json:"status"`
	UserIDHash               string             `json:"user_id_hash"`
	ServerVersion            int64              `json:"server_version"`
	StateHash                string             `json:"state_hash"`
	CompactedThroughVersion  int64              `json:"compacted_through_version"`
	TableCounts              map[string]int     `json:"table_counts"`
	EncryptedPayloadBytes    int64              `json:"encrypted_payload_bytes,omitempty"`
	LegacyClients            []string           `json:"legacy_clients,omitempty"`
	ActiveWebSocketSupported bool               `json:"active_websocket_supported"`
	RecentSyncAudit          []SyncAuditEntry   `json:"recent_sync_audit,omitempty"`
	RecentEncryptedPayloads  []EncryptedPayload `json:"recent_encrypted_payloads,omitempty"`
}
