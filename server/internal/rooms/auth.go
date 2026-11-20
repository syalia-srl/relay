package rooms

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/syalia-srl/relay/server/internal/relay"
)

// What a device route needs beyond a device token of the room.
const (
	owner       = 1 << iota // the device is an owner in the relay's view
	noCustodian             // the custodian holds no epoch key: 403
	write                   // refused with 423 while the room is read-only
)

type room struct {
	id            string
	credential    string
	createdAt     int64
	setUp         bool
	maxBytes      int64
	retentionDays int64
	blobBytes     int64
	storedBytes   int64
	nextSeq       int64
	watermark     int64
	deleted       bool
}

type device struct {
	id    string
	room  string
	kind  string
	owner bool
}

// call is a device route's request once its token, room and role passed.
type call struct {
	*request
	room   room
	device device
}

const roomColumns = `id, credential, created_at, set_up, max_bytes, retention_days, blob_bytes, stored_bytes, next_seq, watermark, deleted_at IS NOT NULL`

func scanRoom(row *sql.Row) (room, error) {
	var r room
	err := row.Scan(&r.id, &r.credential, &r.createdAt, &r.setUp, &r.maxBytes, &r.retentionDays,
		&r.blobBytes, &r.storedBytes, &r.nextSeq, &r.watermark, &r.deleted)
	return r, err
}

func loadRoom(tx *sql.Tx, id string) (room, error) {
	r, err := scanRoom(tx.QueryRow(`SELECT `+roomColumns+` FROM rooms WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, errNotFound
	}
	return r, err
}

// device wraps a device route: the token, the room (404, 410), the role, in
// ROOMS.md 3.3's order; the handler checks the body, then calls writable and
// the quota itself. Every answer once the token is accepted carries the
// room's watermark.
func (s *Service) device(need int, fn func(tx *sql.Tx, c *call) (reply, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := s.newRequest(w, r, r.Method != http.MethodGet)
		var out reply
		err := inTx(r.Context(), s.db, func(tx *sql.Tx) error {
			c, err := s.authDevice(tx, req, need)
			if err != nil {
				return err
			}
			out, err = fn(tx, c)
			return err
		})
		respond(w, out, err)
	}
}

func (s *Service) authDevice(tx *sql.Tx, req *request, need int) (*call, error) {
	token := bearer(req.r)
	if token == "" {
		return nil, errUnauthorized
	}
	var d device
	var revoked bool
	err := tx.QueryRow(`SELECT id, room, kind, owner, revoked FROM devices WHERE token = ?`, digest(token)).
		Scan(&d.id, &d.room, &d.kind, &d.owner, &revoked)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && revoked) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, err
	}
	rm, err := loadRoom(tx, req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if rm.id != d.room {
		return nil, errUnauthorized
	}
	if rm.deleted {
		return nil, errGone
	}
	req.headers.Set("Relay-Room-Watermark", strconv.FormatInt(rm.watermark, 10))
	if need&owner != 0 && !d.owner {
		return nil, errForbidden
	}
	if need&noCustodian != 0 && d.kind == "custodian" {
		return nil, errForbidden
	}
	return &call{request: req, room: rm, device: d}, nil
}

// credential is the relay's record of a credential that created rooms.
type credential struct {
	id        string
	token     bool
	exp       int64
	quota     relay.RoomQuota
	goneSince sql.NullInt64
}

func loadCredential(tx *sql.Tx, id string) (credential, error) {
	c := credential{id: id}
	err := tx.QueryRow(`SELECT token, exp, max_rooms, stored_bytes, retention_days, blob_bytes, gone_since
		FROM credentials WHERE id = ?`, id).
		Scan(&c.token, &c.exp, &c.quota.Max, &c.quota.StoredBytes, &c.quota.RetentionDays, &c.quota.BlobBytes, &c.goneSince)
	return c, err
}

// readOnlySince is when the credential went (ROOMS.md 3.6), 0 while its
// rooms are writable: its operator key left the file or it lost its room
// quota, or the latest relay token seen for its (iss, sub) expired.
func (c credential) readOnlySince(now int64) int64 {
	var since int64
	if c.goneSince.Valid {
		since = c.goneSince.Int64
	}
	if c.token && c.exp <= now && (since == 0 || c.exp < since) {
		since = c.exp
	}
	return since
}

// readOnlySince of a room, 0 while it is writable.
func readOnlySince(tx *sql.Tx, rm room, now int64) (int64, error) {
	c, err := loadCredential(tx, rm.credential)
	if err != nil {
		return 0, err
	}
	return c.readOnlySince(now), nil
}

// writable refuses a write to a read-only room with 423.
func writable(tx *sql.Tx, c *call) error {
	since, err := readOnlySince(tx, c.room, c.now)
	if err != nil {
		return err
	}
	if since != 0 {
		return errReadOnly
	}
	return nil
}

// presentCredential authenticates a credential route. Presenting a credential
// with a room quota records its quota and the latest expiry seen and ends its
// read-only state; one without a room quota is refused with 403 and, if it
// created rooms, makes them read-only from now.
func (s *Service) presentCredential(tx *sql.Tx, req *request) (relay.KeyInfo, error) {
	raw := bearer(req.r)
	if raw == "" {
		return relay.KeyInfo{}, errUnauthorized
	}
	info, ok := s.keys().Lookup(raw, s.now())
	if !ok {
		return info, errUnauthorized
	}
	if info.Rooms == nil {
		_, err := tx.Exec(`UPDATE credentials SET gone_since = ? WHERE id = ? AND gone_since IS NULL`, req.now, info.ID)
		if err != nil {
			return info, err
		}
		return info, &apiError{status: 403, code: "forbidden", commit: true}
	}
	q := info.Rooms
	_, err := tx.Exec(`INSERT INTO credentials (id, token, exp, max_rooms, stored_bytes, retention_days, blob_bytes, gone_since)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT (id) DO UPDATE SET exp = max(exp, excluded.exp), max_rooms = excluded.max_rooms,
			stored_bytes = excluded.stored_bytes, retention_days = excluded.retention_days,
			blob_bytes = excluded.blob_bytes, gone_since = NULL`,
		info.ID, info.Token, info.Exp, q.Max, q.StoredBytes, q.RetentionDays, q.BlobBytes)
	return info, err
}

// usedBytes is what a credential's rooms hold.
func usedBytes(tx *sql.Tx, credentialID string) (int64, error) {
	var n int64
	err := tx.QueryRow(`SELECT coalesce(sum(stored_bytes), 0) FROM rooms WHERE credential = ? AND deleted_at IS NULL`, credentialID).Scan(&n)
	return n, err
}

// reserve checks that n more bytes fit the room and its credential, and
// counts them against the room: 507 otherwise, storing nothing.
func reserve(tx *sql.Tx, rm room, n int64) error {
	if rm.storedBytes+n > rm.maxBytes {
		return errFull
	}
	c, err := loadCredential(tx, rm.credential)
	if err != nil {
		return err
	}
	used, err := usedBytes(tx, rm.credential)
	if err != nil {
		return err
	}
	if used+n > c.quota.StoredBytes {
		return errFull
	}
	_, err = tx.Exec(`UPDATE rooms SET stored_bytes = stored_bytes + ? WHERE id = ?`, n, rm.id)
	return err
}
