package main

import "encoding/json"

const (
	ProfileIconNone    = 0
	ProfileIconBird    = 1
	ProfileIconBowl    = 2
	ProfileIconCactus  = 3
	ProfileIconHeart   = 4
	ProfileIconIncense = 5
	ProfileIconLotus   = 6
	ProfileIconTree1   = 7
	ProfileIconTree2   = 8
	ProfileIconTree3   = 9
	ProfileIconTree4   = 10
	ProfileIconTree5   = 11
)

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
	ServerTime   int64  `json:"server_time,omitempty"`
	AccountAlias string `json:"account_alias,omitempty"`
	ProfileIcon  int    `json:"profile_icon,omitempty"`
}

type NodePeer struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
}

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
	LatestProtocol                    int                `json:"latest_protocol,omitempty"`
	LegacyClients                     []string           `json:"legacy_clients,omitempty"`
	Diagnostics                       *SyncDiagnostics   `json:"diagnostics,omitempty"`
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

type CleanHabitDay struct {
	HabitID   string `json:"habit_id"`
	HabitName string `json:"habit_name,omitempty"`
	LocalDate int    `json:"local_date"`
	Completed bool   `json:"completed"`
	Count     int    `json:"count"`
	UpdatedAt string `json:"updated_at"`
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

type EncryptedRecord struct {
	Collection    string `json:"collection"`
	ID            string `json:"id"`
	KeyID         string `json:"key_id,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Ciphertext    string `json:"ciphertext,omitempty"`
	UpdatedAt     string `json:"updated_at"`
	DeletedAt     int64  `json:"deleted_at,omitempty"`
	ContentHash   string `json:"content_hash,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	ParentID      string `json:"parent_id,omitempty"`
}

type EncryptedPayload struct {
	ID            int64           `json:"id"`
	ClientID      string          `json:"client_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     string          `json:"created_at,omitempty"`
	ServerVersion int64           `json:"server_version"`
}

type SyncDiagnostics struct {
	SnapshotReason              string     `json:"snapshot_reason,omitempty"`
	RequestedSinceServerVersion int64      `json:"requested_since_server_version"`
	EffectiveSinceServerVersion int64      `json:"effective_since_server_version"`
	ClientClock                 int64      `json:"client_clock"`
	CompactedThroughVersion     int64      `json:"compacted_through_version,omitempty"`
	HasLocalChanges             bool       `json:"has_local_changes"`
	AcceptedOps                 int        `json:"accepted_ops"`
	RemoteOps                   int        `json:"remote_ops"`
	AppliedInput                SyncResult `json:"applied_input"`
	ReturnedChanges             SyncResult `json:"returned_changes"`
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

type SyncAuditEntry struct {
	ID                    int64      `json:"id,omitempty"`
	UserIDHash            string     `json:"user_id_hash,omitempty"`
	ClientID              string     `json:"client_id,omitempty"`
	AppID                 string     `json:"app_id,omitempty"`
	ProtocolVersion       int        `json:"protocol_version"`
	SinceServerVersion    int64      `json:"since_server_version"`
	ClientClock           int64      `json:"client_clock"`
	ServerVersion         int64      `json:"server_version"`
	Applied               SyncResult `json:"applied"`
	RemoteOps             int        `json:"remote_ops"`
	FullSnapshotRequired  bool       `json:"full_snapshot_required"`
	SnapshotReason        string     `json:"snapshot_reason,omitempty"`
	EncryptedPayload      bool       `json:"encrypted_payload"`
	EncryptedPayloadBytes int64      `json:"encrypted_payload_bytes,omitempty"`
	CreatedAt             string     `json:"created_at,omitempty"`
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

type ProfileIconRequest struct {
	UserIDHash  string `json:"user_id_hash"`
	ProfileIcon int    `json:"profile_icon"`
}

type ProfileIconResponse struct {
	Status      string `json:"status"`
	ProfileIcon int    `json:"profile_icon"`
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

type AppRegistration struct {
	AppID              string           `json:"app_id"`
	DisplayName        string           `json:"display_name"`
	Description        string           `json:"description,omitempty"`
	HomepageURL        string           `json:"homepage_url,omitempty"`
	SourceURL          string           `json:"source_url,omitempty"`
	PublicKey          string           `json:"public_key,omitempty"`
	Status             string           `json:"status"`
	AppSchemaVersion   int              `json:"app_schema_version,omitempty"`
	MinClientVersion   string           `json:"min_supported_client_version,omitempty"`
	CurrentVersion     string           `json:"current_client_version,omitempty"`
	CompatibilityUntil string           `json:"compatibility_until,omitempty"`
	CreatedAt          string           `json:"created_at,omitempty"`
	UpdatedAt          string           `json:"updated_at,omitempty"`
	ManifestVersion    int              `json:"manifest_version,omitempty"`
	ManifestHash       string           `json:"manifest_hash,omitempty"`
	ManifestSignature  string           `json:"manifest_signature,omitempty"`
	ApprovalSignature  string           `json:"approval_signature,omitempty"`
	ManifestExpiresAt  int64            `json:"manifest_expires_at,omitempty"`
	Collections        []AppCollection  `json:"collections,omitempty"`
	Capabilities       []string         `json:"capabilities,omitempty"`
	Features           []AppFeature     `json:"features,omitempty"`
	LegacyProtocols    []LegacyProtocol `json:"legacy_protocols,omitempty"`
	Keys               []AppKey         `json:"keys,omitempty"`
	TokenPolicies      []TokenPolicy    `json:"token_policies,omitempty"`
}

type AppCollection struct {
	AppID            string `json:"app_id,omitempty"`
	CollectionPrefix string `json:"collection_prefix"`
	Visibility       string `json:"visibility"`
	SchemaVersion    int    `json:"schema_version,omitempty"`
	Description      string `json:"description,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
}

type AppRegistryResponse struct {
	Apps []AppRegistration `json:"apps"`
}

type AppFeature struct {
	ID               string   `json:"id"`
	Collections      []string `json:"collections,omitempty"`
	RequiresSignedTx bool     `json:"requires_signed_tx,omitempty"`
	Description      string   `json:"description,omitempty"`
}

type LegacyProtocol struct {
	Name       string `json:"name"`
	Version    int    `json:"version,omitempty"`
	Status     string `json:"status"`
	ValidUntil string `json:"valid_until"`
}

type AppGrant struct {
	ID               string `json:"id"`
	UserIDHash       string `json:"user_id_hash,omitempty"`
	SourceAppID      string `json:"source_app_id"`
	TargetAppID      string `json:"target_app_id"`
	CollectionPrefix string `json:"collection_prefix"`
	Permission       string `json:"permission"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
	RevokedAt        string `json:"revoked_at,omitempty"`
}

type AppGrantRequest struct {
	SourceAppID      string `json:"source_app_id"`
	TargetAppID      string `json:"target_app_id"`
	CollectionPrefix string `json:"collection_prefix"`
	Permission       string `json:"permission,omitempty"`
}

type AppGrantsResponse struct {
	Grants []AppGrant `json:"grants"`
}

type AppRecordsResponse struct {
	Records []EncryptedRecord `json:"records"`
}

type TokenProduct struct {
	ProductID          string `json:"product_id"`
	TokenUnits         int64  `json:"token_units"`
	MoneroAtomicAmount int64  `json:"monero_atomic_amount,omitempty"`
}

type TokenAsset struct {
	IssuerID    string `json:"issuer_id"`
	AssetID     string `json:"asset_id"`
	DisplayName string `json:"display_name"`
	Decimals    int    `json:"decimals"`
	Status      string `json:"status"`
}

type TokenAssetsResponse struct {
	Assets []TokenAsset `json:"assets"`
}

type TokenProductsResponse struct {
	Products []TokenProduct `json:"products"`
}

type TokenIssuerResponse struct {
	IssuerID  string `json:"issuer_id"`
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
}

type TokenBalanceResponse struct {
	AccountID string `json:"account_id"`
	AssetID   string `json:"asset_id"`
	AppID     string `json:"app_id,omitempty"`
	Balance   int64  `json:"balance"`
}

type TokenLedgerResponse struct {
	Events []TokenReceipt `json:"events"`
}

type TokenReceipt struct {
	ReceiptID    string `json:"receipt_id"`
	IssuerID     string `json:"issuer_id"`
	AssetID      string `json:"asset_id"`
	AccountID    string `json:"account_id"`
	AppID        string `json:"app_id,omitempty"`
	EventType    string `json:"event_type"`
	AmountDelta  int64  `json:"amount_delta"`
	LedgerSeq    int64  `json:"ledger_seq"`
	PreviousHash string `json:"previous_hash"`
	EventHash    string `json:"event_hash"`
	CreatedAt    string `json:"created_at"`
	SourceType   string `json:"source_type"`
	SourceRef    string `json:"source_ref"`
	Signature    string `json:"signature"`
}

type TokenSpendRequest struct {
	AppID          string `json:"app_id"`
	AssetID        string `json:"asset_id"`
	Amount         int64  `json:"amount"`
	Action         string `json:"action"`
	IdempotencyKey string `json:"idempotency_key"`
	Metadata       string `json:"metadata,omitempty"`
}

type TokenSpendResponse struct {
	Status  string       `json:"status"`
	Balance int64        `json:"balance"`
	Receipt TokenReceipt `json:"receipt"`
}

type GooglePurchaseVerifyRequest struct {
	AppID         string `json:"app_id"`
	PackageName   string `json:"package_name"`
	ProductID     string `json:"product_id"`
	PurchaseToken string `json:"purchase_token"`
}

type TokenPurchaseResponse struct {
	Status  string       `json:"status"`
	Balance int64        `json:"balance"`
	Receipt TokenReceipt `json:"receipt"`
}

type MoneroInvoiceRequest struct {
	AppID     string `json:"app_id"`
	ProductID string `json:"product_id"`
}

type MoneroInvoiceResponse struct {
	ID           string        `json:"id"`
	AppID        string        `json:"app_id,omitempty"`
	Status       string        `json:"status"`
	ProductID    string        `json:"product_id"`
	AssetID      string        `json:"asset_id"`
	TokenUnits   int64         `json:"token_units"`
	AtomicAmount int64         `json:"atomic_amount"`
	Address      string        `json:"address"`
	AddressIndex int           `json:"address_index,omitempty"`
	PaymentID    string        `json:"payment_id,omitempty"`
	ExpiresAt    string        `json:"expires_at"`
	Receipt      *TokenReceipt `json:"receipt,omitempty"`
}

type TokenCheckpoint struct {
	LedgerSeq  int64  `json:"ledger_seq"`
	IssuerID   string `json:"issuer_id"`
	AssetID    string `json:"asset_id"`
	LedgerRoot string `json:"ledger_root"`
	Signature  string `json:"signature"`
	CreatedAt  string `json:"created_at"`
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
	UserIDHash  string `json:"user_id_hash"`
	Alias       string `json:"alias,omitempty"`
	ProfileIcon int    `json:"profile_icon,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type ProfileMetric struct {
	Practice  string  `json:"practice"`
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Label     string  `json:"label,omitempty"`
	LocalDate int     `json:"local_date,omitempty"`
}

type FriendStatRow struct {
	UserIDHash  string  `json:"user_id_hash"`
	Alias       string  `json:"alias,omitempty"`
	ProfileIcon int     `json:"profile_icon,omitempty"`
	App         string  `json:"app"`
	Practice    string  `json:"practice"`
	Metric      string  `json:"metric"`
	Value       float64 `json:"value"`
	Label       string  `json:"label,omitempty"`
	LocalDate   int     `json:"local_date,omitempty"`
	UpdatedAt   string  `json:"updated_at"`
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
	MoodBefore int            `json:"mood_before"`
	MoodAfter  int            `json:"mood_after"`
	Energy     int            `json:"energy"`
	Stress     int            `json:"stress"`
	Note       string         `json:"note"`
	Tags       string         `json:"tags"`
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
	MeditationLogs   int `json:"meditation_logs"`
	Habits           int `json:"habits"`
	HabitDays        int `json:"habit_days"`
	Sessions         int `json:"sessions"`
	SocialCache      int `json:"social_cache"`
	EncryptedRecords int `json:"encrypted_records,omitempty"`
}

type UkuProcess struct {
	ID              string        `json:"id"`
	OwnerUserIDHash string        `json:"owner_user_id_hash,omitempty"`
	Type            string        `json:"type"`
	Title           string        `json:"title"`
	Description     string        `json:"description,omitempty"`
	Visibility      string        `json:"visibility"`
	ProposalMinutes int           `json:"proposal_minutes"`
	VotingMinutes   int           `json:"voting_minutes"`
	NegativeWeight  int           `json:"negative_weight"`
	QuorumPercent   int           `json:"quorum_percent"`
	QuorumVotes     int           `json:"quorum_votes"`
	RequireReason   bool          `json:"require_vote_reason"`
	Outcome         string        `json:"outcome,omitempty"`
	ReviewAt        string        `json:"review_at,omitempty"`
	CreatedAt       string        `json:"created_at"`
	UpdatedAt       string        `json:"updated_at"`
	Options         []UkuOption   `json:"options,omitempty"`
	Proposals       []UkuProposal `json:"proposals,omitempty"`
	Votes           []UkuVote     `json:"votes,omitempty"`
	Audit           []UkuAudit    `json:"audit,omitempty"`
}

type UkuOption struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Position    int    `json:"position"`
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
	Reason          string         `json:"reason,omitempty"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

type UkuAudit struct {
	ID              int64           `json:"id"`
	ActorUserIDHash string          `json:"actor_user_id_hash,omitempty"`
	Action          string          `json:"action"`
	EntityType      string          `json:"entity_type"`
	EntityID        string          `json:"entity_id,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	CreatedAt       string          `json:"created_at"`
}

type UkuCreateProcessRequest struct {
	UserIDHash      string      `json:"user_id_hash"`
	ID              string      `json:"id,omitempty"`
	Type            string      `json:"type"`
	Title           string      `json:"title"`
	Description     string      `json:"description,omitempty"`
	Visibility      string      `json:"visibility,omitempty"`
	ProposalMinutes int         `json:"proposal_minutes"`
	VotingMinutes   int         `json:"voting_minutes"`
	NegativeWeight  int         `json:"negative_weight"`
	QuorumPercent   int         `json:"quorum_percent,omitempty"`
	QuorumVotes     int         `json:"quorum_votes,omitempty"`
	RequireReason   bool        `json:"require_vote_reason,omitempty"`
	Options         []UkuOption `json:"options,omitempty"`
}

type UkuUpdateProcessRequest struct {
	UserIDHash    string `json:"user_id_hash"`
	Title         string `json:"title,omitempty"`
	Description   string `json:"description,omitempty"`
	Visibility    string `json:"visibility,omitempty"`
	QuorumPercent *int   `json:"quorum_percent,omitempty"`
	QuorumVotes   *int   `json:"quorum_votes,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
	ReviewAt      string `json:"review_at,omitempty"`
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
	Reason      string         `json:"reason,omitempty"`
}
