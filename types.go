package main

type ChallengeResponse struct {
	UserIDHash string `json:"user_id_hash"`
	Nonce      string `json:"nonce"`
	ExpiresIn  int64  `json:"expires_in_seconds"`
}

type SyncRequest struct {
	UserIDHash     string          `json:"user_id_hash"`
	PublicKey      string          `json:"public_key,omitempty"`
	MeditationLogs []MeditationLog `json:"meditation_logs,omitempty"`
	Preferences    []Preference    `json:"preferences,omitempty"`
	Habits         []Habit         `json:"habits,omitempty"`
	HabitDays      []HabitDay      `json:"habit_days,omitempty"`
	Sessions       []Session       `json:"sessions,omitempty"`
}

type DeleteRequest struct {
	UserIDHash string `json:"user_id_hash"`
}

type MeditationLog struct {
	ID              string `json:"id"`
	SessionID       string `json:"session_id"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	Duration        int    `json:"duration,omitempty"`
	CompletedAt     string `json:"completed_at,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
}

type Preference struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

type Habit struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ColorR       int    `json:"color_r"`
	ColorG       int    `json:"color_g"`
	ColorB       int    `json:"color_b"`
	SyncMode     int    `json:"sync_mode"`
	SyncActivity int    `json:"sync_activity"`
	SortOrder    int    `json:"sort_order"`
	DeletedAt    int64  `json:"deleted_at"`
	UpdatedAt    string `json:"updated_at"`
}

type HabitDay struct {
	HabitID   string `json:"habit_id"`
	LocalDate int    `json:"local_date"`
	Completed bool   `json:"completed"`
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
	Preferences    int `json:"preferences"`
	Habits         int `json:"habits"`
	HabitDays      int `json:"habit_days"`
	Sessions       int `json:"sessions"`
}
