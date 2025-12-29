package audit

import "time"

// Event is the raw event ingested by the assurance service.
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// Record is a tamper-evident log entry that wraps an Event.
type Record struct {
	Index     int64     `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Event     Event     `json:"event"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// RootRecord captures the Merkle root for a batch of event hashes.
type RootRecord struct {
	FromIndex int64     `json:"from_index"`
	ToIndex   int64     `json:"to_index"`
	RootHash  string    `json:"root_hash"`
	CreatedAt time.Time `json:"created_at"`
}

// VerifyReport summarizes chain verification.
type VerifyReport struct {
	OK           bool     `json:"ok"`
	Total        int64    `json:"total"`
	LastIndex    int64    `json:"last_index"`
	LastHash     string   `json:"last_hash"`
	RootsChecked int      `json:"roots_checked"`
	Errors       []string `json:"errors"`
}
