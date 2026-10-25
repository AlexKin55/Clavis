// Package cache is the agent's local SQLite persistence: once a reader
// key (AS) has been fetched from a Key Server and successfully used, it
// is stored locally so documents can be opened again while offline.
//
// The stored payload is wrapped under the agent's master key A, so the
// key material never sits in the database in plaintext.
package cache

import (
	"database/sql"
	"fmt"
	"time"

	// Register the pure-Go SQLite driver with database/sql.
	_ "modernc.org/sqlite"

	"github.com/clavis/clavis/internal/crypto"
)

const (
	// payload sizes: AS (32) + owner public signature key (32).
	payloadSize = 64
)

// Store is the SQLite-backed key cache.
type Store struct {
	db     *sql.DB
	master []byte // agent master key A (32 bytes)
}

// Open opens (and initializes) the SQLite database at path.
func Open(path string, master []byte) (*Store, error) {
	if len(master) != crypto.MasterKeySize {
		return nil, fmt.Errorf("cache: master key must be %d bytes", crypto.MasterKeySize)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("cache: open %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	// Avoid lock contention on the agent's single consumer.
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS reader_keys (
			owner_key_id TEXT PRIMARY KEY,
			blob         BLOB NOT NULL,
			created_at   INTEGER NOT NULL,
			hits         INTEGER NOT NULL DEFAULT 0
		)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cache: init schema: %w", err)
	}

	key := make([]byte, len(master))
	copy(key, master)
	return &Store{db: db, master: key}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Put stores (or refreshes) the reader key for the owner.
func (s *Store) Put(ownerKeyID [16]byte, readKey, pubSig []byte) error {
	if len(readKey) != crypto.MasterKeySize || len(pubSig) != 32 {
		return fmt.Errorf("cache: invalid payload sizes (%d, %d)", len(readKey), len(pubSig))
	}
	payload := make([]byte, 0, payloadSize)
	payload = append(payload, readKey...)
	payload = append(payload, pubSig...)

	blob, err := crypto.WrapKey(s.master, payload)
	if err != nil {
		return fmt.Errorf("cache: wrap reader key: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO reader_keys (owner_key_id, blob, created_at) VALUES (?, ?, ?)
		ON CONFLICT (owner_key_id) DO UPDATE SET blob = excluded.blob, hits = reader_keys.hits`,
		ownerHex(ownerKeyID), blob, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("cache: store reader key: %w", err)
	}
	return nil
}

// Get returns the cached reader key material for the owner.
func (s *Store) Get(ownerKeyID [16]byte) (readKey, pubSig []byte, ok bool) {
	var blob []byte
	err := s.db.QueryRow(`SELECT blob FROM reader_keys WHERE owner_key_id = ?`, ownerHex(ownerKeyID)).Scan(&blob)
	if err != nil {
		return nil, nil, false
	}
	_, _ = s.db.Exec(`UPDATE reader_keys SET hits = hits + 1 WHERE owner_key_id = ?`, ownerHex(ownerKeyID))

	payload, err := crypto.UnwrapKey(s.master, blob)
	if err != nil {
		return nil, nil, false
	}
	if len(payload) != payloadSize {
		return nil, nil, false
	}
	return payload[:32], payload[32:], true
}

// ownerHex is a compact hex (lowercase, no dashes) used as the DB key.
func ownerHex(owner [16]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(owner)*2)
	for i, v := range owner {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
