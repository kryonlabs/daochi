package main

type AccountExportResponse struct {
	Status       string                      `json:"status"`
	UserIDHash   string                      `json:"user_id_hash"`
	AccountAlias string                      `json:"account_alias,omitempty"`
	ProfileIcon  int                         `json:"profile_icon,omitempty"`
	Tables       map[string][]map[string]any `json:"tables"`
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
