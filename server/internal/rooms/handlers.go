package rooms

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"unicode/utf8"
)

func nullable(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func limitsOf(rm room) map[string]int64 {
	return map[string]int64{"max_bytes": rm.maxBytes, "retention_days": rm.retentionDays, "blob_bytes": rm.blobBytes}
}

// queryInt reads an optional integer query parameter; a malformed or out of
// range one is 400.
func queryInt(r *http.Request, name string, fallback, min, max int64) (int64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min || n > max {
		return 0, errBadRequest
	}
	return n, nil
}

// --- credential routes ---

func (s *Service) createRoom(tx *sql.Tx, req *request) (reply, error) {
	info, err := s.presentCredential(tx, req)
	if err != nil {
		return reply{}, err
	}
	obj, err := req.object()
	if err != nil {
		return reply{}, err
	}
	ownerKeys, _ := obj["owner"].(map[string]any)
	custodianKeys, _ := obj["custodian"].(map[string]any)
	ownerSign, ok1 := jwk(ownerKeys["sign_pub"])
	ownerRecv, ok2 := jwk(ownerKeys["recv_pub"])
	custodianSign, ok3 := jwk(custodianKeys["sign_pub"])
	if !ok1 || !ok2 || !ok3 {
		return reply{}, errBadRequest
	}
	limits, err := info.Rooms.Limits(obj)
	if err != nil {
		return reply{}, errBadRequest
	}
	var count int64
	if err := tx.QueryRow(`SELECT count(*) FROM rooms WHERE credential = ? AND deleted_at IS NULL`, info.ID).Scan(&count); err != nil {
		return reply{}, err
	}
	if count >= info.Rooms.Max {
		return reply{}, errFull
	}

	roomID := randomID(16)
	ownerID, ownerToken := randomID(16), randomID(32)
	custodianID, custodianToken := randomID(16), randomID(32)
	if _, err := tx.Exec(`INSERT INTO rooms (id, credential, created_at, max_bytes, retention_days, blob_bytes)
		VALUES (?, ?, ?, ?, ?, ?)`, roomID, info.ID, req.now, limits.MaxBytes, limits.RetentionDays, limits.BlobBytes); err != nil {
		return reply{}, err
	}
	if _, err := tx.Exec(`INSERT INTO devices (id, room, token, kind, owner, sign_pub, recv_pub, joined_at)
		VALUES (?, ?, ?, 'device', 1, ?, ?, ?), (?, ?, ?, 'custodian', 1, ?, NULL, ?)`,
		ownerID, roomID, digest(ownerToken), ownerSign, ownerRecv, req.now,
		custodianID, roomID, digest(custodianToken), custodianSign, req.now); err != nil {
		return reply{}, err
	}
	log.Printf("room %s created", short(roomID))
	return reply{status: http.StatusCreated, body: map[string]any{
		"room": roomID, "device": ownerID, "token": ownerToken,
		"custodian": map[string]string{"device": custodianID, "token": custodianToken},
		"limits":    limits,
	}}, nil
}

func (s *Service) quota(tx *sql.Tx, req *request) (reply, error) {
	info, err := s.presentCredential(tx, req)
	if err != nil {
		return reply{}, err
	}
	var count int64
	if err := tx.QueryRow(`SELECT count(*) FROM rooms WHERE credential = ? AND deleted_at IS NULL`, info.ID).Scan(&count); err != nil {
		return reply{}, err
	}
	used, err := usedBytes(tx, info.ID)
	if err != nil {
		return reply{}, err
	}
	c, err := loadCredential(tx, info.ID)
	if err != nil {
		return reply{}, err
	}
	q := info.Rooms
	return reply{status: http.StatusOK, body: map[string]any{
		"rooms":           map[string]int64{"max": q.Max, "used": count},
		"stored_bytes":    map[string]int64{"max": q.StoredBytes, "used": used},
		"retention_days":  q.RetentionDays,
		"blob_bytes":      q.BlobBytes,
		"read_only_since": nullable(c.readOnlySince(req.now)),
	}}, nil
}

// --- invites and joining ---

func (s *Service) createInvite(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	uses, ok1 := intOf(obj, "uses", 1)
	expires, ok2 := intOf(obj, "expires_at", 0)
	if !ok1 || !ok2 || uses > maxInviteUses || expires <= c.now || expires > c.now+maxInviteDays*day {
		return reply{}, errBadRequest
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	id, token := randomID(16), randomID(32)
	if _, err := tx.Exec(`INSERT INTO invites (id, room, token, uses, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, c.room.id, digest(token), uses, expires); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusCreated, body: map[string]string{"invite": id, "token": token}}, nil
}

func (s *Service) closeInvite(tx *sql.Tx, c *call) (reply, error) {
	res, err := tx.Exec(`UPDATE invites SET closed = 1 WHERE id = ? AND room = ?`, c.r.PathValue("invite"), c.room.id)
	if err != nil {
		return reply{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return reply{}, errNotFound
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	return noContent(), nil
}

func (s *Service) join(tx *sql.Tx, req *request) (reply, error) {
	token := bearer(req.r)
	if token == "" {
		return reply{}, errUnauthorized
	}
	var invite, invRoom string
	var uses, used, expires int64
	var closed bool
	err := tx.QueryRow(`SELECT id, room, uses, used, expires_at, closed FROM invites WHERE token = ?`, digest(token)).
		Scan(&invite, &invRoom, &uses, &used, &expires, &closed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && closed) {
		return reply{}, errUnauthorized
	}
	if err != nil {
		return reply{}, err
	}
	rm, err := loadRoom(tx, req.r.PathValue("id"))
	if err != nil {
		return reply{}, err
	}
	if rm.id != invRoom {
		return reply{}, errUnauthorized
	}
	if rm.deleted {
		return reply{}, errGone
	}
	obj, err := req.object()
	if err != nil {
		return reply{}, err
	}
	sign, ok1 := jwk(obj["sign_pub"])
	recv, ok2 := jwk(obj["recv_pub"])
	if !ok1 || !ok2 {
		return reply{}, errBadRequest
	}
	if used >= uses || req.now >= expires {
		return reply{}, errConflict
	}
	since, err := readOnlySince(tx, rm, req.now)
	if err != nil {
		return reply{}, err
	}
	if since != 0 {
		return reply{}, errReadOnly
	}
	id, deviceToken := randomID(16), randomID(32)
	if _, err := tx.Exec(`UPDATE invites SET used = used + 1 WHERE id = ?`, invite); err != nil {
		return reply{}, err
	}
	if _, err := tx.Exec(`INSERT INTO devices (id, room, token, kind, owner, sign_pub, recv_pub, joined_at)
		VALUES (?, ?, ?, 'device', 0, ?, ?, ?)`, id, rm.id, digest(deviceToken), sign, recv, req.now); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusCreated, body: map[string]string{"device": id, "token": deviceToken}}, nil
}

// --- roster and epochs ---

func (s *Service) getRoster(tx *sql.Tx, c *call) (reply, error) {
	after, err := queryInt(c.r, "after", 0, 0, 1<<53-1)
	if err != nil {
		return reply{}, err
	}
	rows, err := tx.Query(`SELECT n, entry, sig, prev, signer FROM roster WHERE room = ? AND n > ? ORDER BY n`, c.room.id, after)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	entries := []map[string]any{}
	for rows.Next() {
		var n int64
		var entry, sig, prev, signer string
		if err := rows.Scan(&n, &entry, &sig, &prev, &signer); err != nil {
			return reply{}, err
		}
		entries = append(entries, map[string]any{
			"n": n, "entry": json.RawMessage(entry), "sig": sig, "prev": prev, "signer": signer,
		})
	}
	return reply{status: http.StatusOK, body: map[string]any{"entries": entries}}, rows.Err()
}

func (s *Service) postRoster(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	n, ok1 := intOf(obj, "n", 1)
	entry, ok2 := obj["entry"].(map[string]any)
	sig, ok3 := strOf(obj, "sig")
	prev, ok4 := strOf(obj, "prev")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return reply{}, errBadRequest
	}
	if len(c.body) > maxRecord {
		return reply{}, errTooLarge
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	var last int64
	if err := tx.QueryRow(`SELECT coalesce(max(n), 0) FROM roster WHERE room = ?`, c.room.id).Scan(&last); err != nil {
		return reply{}, err
	}
	if n != last+1 {
		return reply{}, errConflict
	}
	if _, err := tx.Exec(`INSERT INTO roster (room, n, entry, sig, prev, signer) VALUES (?, ?, ?, ?, ?, ?)`,
		c.room.id, n, raw(entry), sig, prev, c.device.id); err != nil {
		return reply{}, err
	}
	if n == 1 {
		if _, err := tx.Exec(`UPDATE rooms SET set_up = 1 WHERE id = ?`, c.room.id); err != nil {
			return reply{}, err
		}
	}
	return reply{status: http.StatusCreated, body: map[string]int64{"n": n}}, nil
}

func (s *Service) postEpoch(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	n, ok1 := intOf(obj, "n", 1)
	creator, ok2 := strOf(obj, "creator")
	wraps, ok3 := obj["wraps"].(map[string]any)
	sig, ok4 := strOf(obj, "sig")
	rosterN, ok5 := intOf(obj, "roster", 0) // stored and returned, never compared with the roster
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return reply{}, errBadRequest
	}
	if _, ok := b64(sig); !ok {
		return reply{}, errBadRequest
	}
	if creator != c.device.id {
		return reply{}, errForbidden
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	var last int64
	if err := tx.QueryRow(`SELECT coalesce(max(n), 0) FROM epochs WHERE room = ?`, c.room.id).Scan(&last); err != nil {
		return reply{}, err
	}
	if n != last+1 {
		return reply{}, errConflict
	}
	if _, err := tx.Exec(`INSERT INTO epochs (room, n, roster, creator, wraps, sig) VALUES (?, ?, ?, ?, ?, ?)`,
		c.room.id, n, rosterN, creator, raw(wraps), sig); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusCreated, body: map[string]int64{"n": n}}, nil
}

func (s *Service) getEpochs(tx *sql.Tx, c *call) (reply, error) {
	after, err := queryInt(c.r, "after", 0, 0, 1<<53-1)
	if err != nil {
		return reply{}, err
	}
	rows, err := tx.Query(`SELECT n, roster, creator, wraps, sig FROM epochs WHERE room = ? AND n > ? ORDER BY n`, c.room.id, after)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	epochs := []map[string]any{}
	for rows.Next() {
		var n, rosterN int64
		var creator, wraps, sig string
		if err := rows.Scan(&n, &rosterN, &creator, &wraps, &sig); err != nil {
			return reply{}, err
		}
		epochs = append(epochs, map[string]any{"n": n, "roster": rosterN, "creator": creator, "wraps": json.RawMessage(wraps), "sig": sig})
	}
	return reply{status: http.StatusOK, body: map[string]any{"epochs": epochs}}, rows.Err()
}

// --- the relay's view of membership ---

// otherOwners counts the owners left if target stopped being one.
func otherOwners(tx *sql.Tx, roomID, target string) (int64, error) {
	var n int64
	err := tx.QueryRow(`SELECT count(*) FROM devices WHERE room = ? AND owner = 1 AND revoked = 0 AND id != ?`, roomID, target).Scan(&n)
	return n, err
}

func (s *Service) setOwner(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	target, ok1 := strOf(obj, "device")
	makeOwner, ok2 := obj["owner"].(bool)
	if !ok1 || !ok2 {
		return reply{}, errBadRequest
	}
	var revoked bool
	err = tx.QueryRow(`SELECT revoked FROM devices WHERE id = ? AND room = ?`, target, c.room.id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && revoked) {
		return reply{}, errNotFound
	}
	if err != nil {
		return reply{}, err
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	if !makeOwner {
		left, err := otherOwners(tx, c.room.id, target)
		if err != nil {
			return reply{}, err
		}
		if left == 0 {
			return reply{}, errConflict
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET owner = ? WHERE id = ?`, makeOwner, target); err != nil {
		return reply{}, err
	}
	return noContent(), nil
}

func (s *Service) removeDevice(tx *sql.Tx, c *call) (reply, error) {
	target := c.r.PathValue("device")
	if target != c.device.id && !c.device.owner {
		return reply{}, errForbidden
	}
	var revoked, isOwner bool
	err := tx.QueryRow(`SELECT revoked, owner FROM devices WHERE id = ? AND room = ?`, target, c.room.id).Scan(&revoked, &isOwner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && revoked) {
		return reply{}, errNotFound
	}
	if err != nil {
		return reply{}, err
	}
	if isOwner {
		left, err := otherOwners(tx, c.room.id, target)
		if err != nil {
			return reply{}, err
		}
		if left == 0 {
			return reply{}, errConflict
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET revoked = 1, push = NULL WHERE id = ?`, target); err != nil {
		return reply{}, err
	}
	s.hub.dropDevice(c.room.id, target)
	return noContent(), nil
}

// --- messages ---

type message struct {
	Seq    int64  `json:"seq"`
	Device string `json:"device"`
	CID    string `json:"cid"`
	Epoch  int64  `json:"epoch"`
	N      int64  `json:"n"`
	IV     string `json:"iv"`
	CT     string `json:"ct"`
	Sig    string `json:"sig"`
	Blob   string `json:"blob,omitempty"`
	At     int64  `json:"at"`
}

func (s *Service) getMessages(tx *sql.Tx, c *call) (reply, error) {
	after, err := queryInt(c.r, "after", 0, 0, 1<<53-1)
	if err != nil {
		return reply{}, err
	}
	limit, err := queryInt(c.r, "limit", defaultPage, 1, maxPage)
	if err != nil {
		return reply{}, err
	}
	rows, err := tx.Query(`SELECT seq, device, cid, epoch, n, iv, ct, sig, coalesce(blob, ''), at
		FROM messages WHERE room = ? AND seq > ? ORDER BY seq LIMIT ?`, c.room.id, after, limit)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	messages := []message{}
	for rows.Next() {
		var m message
		if err := rows.Scan(&m.Seq, &m.Device, &m.CID, &m.Epoch, &m.N, &m.IV, &m.CT, &m.Sig, &m.Blob, &m.At); err != nil {
			return reply{}, err
		}
		messages = append(messages, m)
	}
	return reply{status: http.StatusOK, body: map[string]any{"messages": messages, "watermark": c.room.watermark}}, rows.Err()
}

func (s *Service) postMessage(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	cid, ok1 := strOf(obj, "cid")
	epoch, ok2 := intOf(obj, "epoch", 1)
	n, ok3 := intOf(obj, "n", 1)
	ivText, ok4 := strOf(obj, "iv")
	ctText, ok5 := strOf(obj, "ct")
	sigText, ok6 := strOf(obj, "sig")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !isID(cid, 16) {
		return reply{}, errBadRequest
	}
	iv, ok1 := b64(ivText)
	ct, ok2 := b64(ctText)
	sig, ok3 := b64(sigText)
	if !ok1 || !ok2 || !ok3 || len(iv) != 12 || len(sig) != 64 {
		return reply{}, errBadRequest
	}
	var blob any
	if v, named := obj["blob"]; named {
		id, ok := v.(string)
		if !ok || !isID(id, 16) {
			return reply{}, errBadRequest
		}
		blob = id
	}
	if len(ct) > maxCiphertext {
		return reply{}, errTooLarge
	}

	// A retry with the same cid stores nothing and gets the first sequence.
	var seq int64
	err = tx.QueryRow(`SELECT seq FROM messages WHERE room = ? AND device = ? AND cid = ?`, c.room.id, c.device.id, cid).Scan(&seq)
	if err == nil {
		return reply{status: http.StatusOK, body: map[string]int64{"seq": seq}}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return reply{}, err
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	if err := reserve(tx, c.room, int64(len(ct))); err != nil {
		return reply{}, err
	}
	seq = c.room.nextSeq
	if _, err := tx.Exec(`UPDATE rooms SET next_seq = next_seq + 1 WHERE id = ?`, c.room.id); err != nil {
		return reply{}, err
	}
	if _, err := tx.Exec(`INSERT INTO messages (room, seq, device, cid, epoch, n, iv, ct, sig, blob, at, size)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.room.id, seq, c.device.id, cid, epoch, n, ivText, ctText, sigText, blob, c.now, len(ct)); err != nil {
		return reply{}, err
	}
	if blob != nil {
		if _, err := tx.Exec(`UPDATE blobs SET named = 1 WHERE room = ? AND id = ?`, c.room.id, blob); err != nil {
			return reply{}, err
		}
	}
	// The socket hint goes out now; the fetch it prompts waits for this
	// transaction, since the database has one connection. Push sending is a
	// stub: no gateway is configured, so the relay sends nothing (ROOMS.md 3.7).
	s.hub.notify(c.room.id, seq)
	return reply{status: http.StatusCreated, body: map[string]int64{"seq": seq}}, nil
}

// --- blobs ---

// putBlob checks the token, room, role and id in one transaction, reads the
// body up to the room's blob size, and stores it in a second one.
func (s *Service) putBlob(w http.ResponseWriter, r *http.Request) {
	req := s.newRequest(w, r, false)
	blobID := r.PathValue("blob")
	var c *call
	err := inTx(r.Context(), s.db, func(tx *sql.Tx) error {
		var err error
		if c, err = s.authDevice(tx, req, noCustodian); err != nil {
			return err
		}
		if !isID(blobID, 16) {
			return errBadRequest
		}
		if r.ContentLength > c.room.blobBytes {
			return errTooLarge
		}
		return nil
	})
	if err != nil {
		respond(w, reply{}, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, c.room.blobBytes+1))
	if err != nil {
		respond(w, reply{}, errBadRequest)
		return
	}
	if int64(len(body)) > c.room.blobBytes {
		respond(w, reply{}, errTooLarge)
		return
	}
	err = inTx(r.Context(), s.db, func(tx *sql.Tx) error {
		rm, err := loadRoom(tx, c.room.id)
		if err != nil {
			return err
		}
		if rm.deleted {
			return errGone
		}
		c.room = rm
		if err := writable(tx, c); err != nil {
			return err
		}
		var taken int
		if err := tx.QueryRow(`SELECT count(*) FROM blobs WHERE room = ? AND id = ?`, rm.id, blobID).Scan(&taken); err != nil {
			return err
		}
		if taken > 0 {
			return errConflict
		}
		if err := reserve(tx, rm, int64(len(body))); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO blobs (room, id, body, size, at, named)
			VALUES (?, ?, ?, ?, ?, EXISTS (SELECT 1 FROM messages WHERE room = ? AND blob = ?))`,
			rm.id, blobID, body, len(body), req.now, rm.id, blobID)
		return err
	})
	respond(w, reply{status: http.StatusCreated}, err)
}

func (s *Service) getBlob(tx *sql.Tx, c *call) (reply, error) {
	var body []byte
	err := tx.QueryRow(`SELECT body FROM blobs WHERE room = ? AND id = ?`, c.room.id, c.r.PathValue("blob")).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return reply{}, errNotFound
	}
	if err != nil {
		return reply{}, err
	}
	if body == nil {
		body = []byte{}
	}
	return reply{status: http.StatusOK, raw: body}, nil
}

// --- acks, push, the room ---

func (s *Service) ack(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	seq, ok := intOf(obj, "seq", 0)
	if !ok {
		return reply{}, errBadRequest
	}
	// A device cannot hold what the room never assigned.
	seq = min(seq, c.room.nextSeq-1)
	if _, err := tx.Exec(`UPDATE devices SET acked = max(acked, ?), last_ack_at = ? WHERE id = ?`, seq, c.now, c.device.id); err != nil {
		return reply{}, err
	}
	return noContent(), nil
}

func (s *Service) setPush(tx *sql.Tx, c *call) (reply, error) {
	obj, err := c.object()
	if err != nil {
		return reply{}, err
	}
	v, present := obj["token"]
	if !present {
		return reply{}, errBadRequest
	}
	var token any
	if v != nil {
		text, ok := v.(string)
		if !ok || text == "" || utf8.RuneCountInString(text) > maxPushToken {
			return reply{}, errBadRequest
		}
		token = text
	}
	if err := writable(tx, c); err != nil {
		return reply{}, err
	}
	if _, err := tx.Exec(`UPDATE devices SET push = ? WHERE id = ?`, token, c.device.id); err != nil {
		return reply{}, err
	}
	return noContent(), nil
}

func (s *Service) getRoom(tx *sql.Tx, c *call) (reply, error) {
	rows, err := tx.Query(`SELECT id, kind, owner, last_ack_at FROM devices WHERE room = ? AND revoked = 0 ORDER BY rowid`, c.room.id)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	devices := []map[string]any{}
	for rows.Next() {
		var id, kind string
		var isOwner bool
		var lastAck sql.NullInt64
		if err := rows.Scan(&id, &kind, &isOwner, &lastAck); err != nil {
			return reply{}, err
		}
		role := "member"
		if isOwner {
			role = "owner"
		}
		var at any
		if lastAck.Valid {
			at = lastAck.Int64
		}
		devices = append(devices, map[string]any{"device": id, "kind": kind, "role": role, "last_ack_at": at})
	}
	if err := rows.Err(); err != nil {
		return reply{}, err
	}
	since, err := readOnlySince(tx, c.room, c.now)
	if err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusOK, body: map[string]any{
		"room": c.room.id, "devices": devices, "limits": limitsOf(c.room),
		"stored_bytes": c.room.storedBytes, "read_only_since": nullable(since),
	}}, nil
}

func (s *Service) deleteRoom(tx *sql.Tx, c *call) (reply, error) {
	if err := s.deleteRoomTx(tx, c.room.id, c.now); err != nil {
		return reply{}, err
	}
	return noContent(), nil
}

// deleteRoomTx deletes a room's content and leaves a tombstone, so the id and
// its device tokens answer 410 for 30 days. Its sockets stop watching it.
func (s *Service) deleteRoomTx(tx *sql.Tx, id string, now int64) error {
	for _, table := range []string{"messages", "blobs", "roster", "epochs", "invites"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE room = ?`, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET push = NULL WHERE room = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE rooms SET deleted_at = ?, stored_bytes = 0 WHERE id = ?`, now, id); err != nil {
		return err
	}
	s.hub.dropRoom(id)
	log.Printf("room %s deleted", short(id))
	return nil
}
