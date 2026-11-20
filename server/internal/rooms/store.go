// Package rooms is the relay mailbox of ROOMS.md section 3: rooms, devices,
// invites, roster records, epochs, ciphertext messages and blobs, kept in one
// SQLite database that only the relay reads.
package rooms

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS credentials (
	id             TEXT PRIMARY KEY,
	token          INTEGER NOT NULL,   -- 1 for an rt1 relay token
	exp            INTEGER NOT NULL,   -- the latest expiry seen for an rt1 holder
	max_rooms      INTEGER NOT NULL,
	stored_bytes   INTEGER NOT NULL,
	retention_days INTEGER NOT NULL,
	blob_bytes     INTEGER NOT NULL,
	gone_since     INTEGER             -- the key left the file or lost its room quota
);
CREATE TABLE IF NOT EXISTS rooms (
	id             TEXT PRIMARY KEY,
	credential     TEXT NOT NULL,
	created_at     INTEGER NOT NULL,
	set_up         INTEGER NOT NULL DEFAULT 0,
	max_bytes      INTEGER NOT NULL,
	retention_days INTEGER NOT NULL,
	blob_bytes     INTEGER NOT NULL,
	stored_bytes   INTEGER NOT NULL DEFAULT 0,
	next_seq       INTEGER NOT NULL DEFAULT 1,
	watermark      INTEGER NOT NULL DEFAULT 1,
	deleted_at     INTEGER
);
CREATE INDEX IF NOT EXISTS rooms_by_credential ON rooms(credential);
CREATE TABLE IF NOT EXISTS devices (
	id          TEXT PRIMARY KEY,
	room        TEXT NOT NULL,
	token       BLOB NOT NULL UNIQUE,  -- SHA-256 of the device token
	kind        TEXT NOT NULL,         -- device | custodian
	owner       INTEGER NOT NULL,
	sign_pub    TEXT NOT NULL,
	recv_pub    TEXT,
	revoked     INTEGER NOT NULL DEFAULT 0,
	acked       INTEGER NOT NULL DEFAULT 0,
	last_ack_at INTEGER,
	joined_at   INTEGER NOT NULL,
	push        TEXT
);
CREATE INDEX IF NOT EXISTS devices_by_room ON devices(room);
CREATE TABLE IF NOT EXISTS invites (
	id         TEXT PRIMARY KEY,
	room       TEXT NOT NULL,
	token      BLOB NOT NULL UNIQUE,   -- SHA-256 of the join token
	uses       INTEGER NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER NOT NULL,
	closed     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS invites_by_room ON invites(room);
CREATE TABLE IF NOT EXISTS roster (
	room   TEXT NOT NULL,
	n      INTEGER NOT NULL,
	entry  TEXT NOT NULL,
	sig    TEXT NOT NULL,
	prev   TEXT NOT NULL,
	signer TEXT NOT NULL,
	PRIMARY KEY (room, n)
);
CREATE TABLE IF NOT EXISTS epochs (
	room    TEXT NOT NULL,
	n       INTEGER NOT NULL,
	roster  INTEGER NOT NULL,          -- the n of the last roster record the creator verified, opaque here
	creator TEXT NOT NULL,
	wraps   TEXT NOT NULL,
	sig     TEXT NOT NULL,
	PRIMARY KEY (room, n)
);
CREATE TABLE IF NOT EXISTS messages (
	room   TEXT NOT NULL,
	seq    INTEGER NOT NULL,
	device TEXT NOT NULL,
	cid    TEXT NOT NULL,
	epoch  INTEGER NOT NULL,
	n      INTEGER NOT NULL,
	iv     TEXT NOT NULL,
	ct     TEXT NOT NULL,
	sig    TEXT NOT NULL,
	blob   TEXT,
	at     INTEGER NOT NULL,
	size   INTEGER NOT NULL,           -- decoded ct bytes, what the quota counts
	PRIMARY KEY (room, seq),
	UNIQUE (room, device, cid)
);
CREATE INDEX IF NOT EXISTS messages_by_blob ON messages(room, blob);
CREATE TABLE IF NOT EXISTS blobs (
	room  TEXT NOT NULL,
	id    TEXT NOT NULL,
	body  BLOB NOT NULL,
	size  INTEGER NOT NULL,
	at    INTEGER NOT NULL,
	named INTEGER NOT NULL DEFAULT 0,  -- a message has named it
	PRIMARY KEY (room, id)
);
`

// openDB opens or creates the database at path, readable by the relay's user
// only. One connection serialises every transaction, which is what makes a
// room's next sequence unique without retries.
func openDB(path string) (*sql.DB, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("rooms schema: %w", err)
	}
	return db, nil
}

// inTx runs fn in one transaction and commits it unless fn returns an error.
// An *apiError from fn still commits: some refusals (a credential that lost
// its room quota) record what they saw.
func inTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	ferr := fn(tx)
	var api *apiError
	if ferr != nil && !(errors.As(ferr, &api) && api.commit) {
		tx.Rollback()
		return ferr
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return ferr
}

// randomID draws n random bytes as base64url: 16 for ids, 32 for tokens.
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func digest(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Clock is the relay's notion of now for rooms.
type Clock func() time.Time
