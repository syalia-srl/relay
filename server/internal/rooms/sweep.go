package rooms

import (
	"context"
	"database/sql"
	"log"
)

// Sweep applies ROOMS.md 3.6's rules of time: it deletes rooms never set up
// within an hour and rooms read-only for 30 days, marks operator keys that
// left the keys file, deletes acked and expired messages and blobs, and
// forgets tombstones after 30 days.
func (s *Service) Sweep() {
	s.sweep.Lock()
	defer s.sweep.Unlock()
	now := s.now().Unix()
	err := inTx(context.Background(), s.db, func(tx *sql.Tx) error {
		if err := s.purgeTombstones(tx, now); err != nil {
			return err
		}
		if err := s.deleteWhere(tx, now, `SELECT id FROM rooms WHERE deleted_at IS NULL AND set_up = 0 AND created_at <= ?`, now-setUpWithin); err != nil {
			return err
		}
		if err := s.checkOperatorKeys(tx, now); err != nil {
			return err
		}
		if err := s.deleteLongReadOnly(tx, now); err != nil {
			return err
		}
		return s.retain(tx, now)
	})
	if err != nil {
		log.Printf("rooms sweep: %v", err)
	}
}

func queryIDs(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Service) deleteWhere(tx *sql.Tx, now int64, query string, args ...any) error {
	ids, err := queryIDs(tx, query, args...)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.deleteRoomTx(tx, id, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) purgeTombstones(tx *sql.Tx, now int64) error {
	ids, err := queryIDs(tx, `SELECT id FROM rooms WHERE deleted_at <= ?`, now-tombstoneLife)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM devices WHERE room = ?`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM rooms WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// checkOperatorKeys marks an operator key gone from now when it left the keys
// file or lost its room quota, and otherwise follows its quota in the file.
// Only presenting the key again ends read-only.
func (s *Service) checkOperatorKeys(tx *sql.Tx, now int64) error {
	ids, err := queryIDs(tx, `SELECT id FROM credentials WHERE token = 0`)
	if err != nil {
		return err
	}
	keys := s.keys()
	for _, id := range ids {
		q, present := keys.OperatorRooms(id)
		if !present || q == nil {
			_, err = tx.Exec(`UPDATE credentials SET gone_since = ? WHERE id = ? AND gone_since IS NULL`, now, id)
		} else {
			_, err = tx.Exec(`UPDATE credentials SET max_rooms = ?, stored_bytes = ?, retention_days = ?, blob_bytes = ? WHERE id = ?`,
				q.Max, q.StoredBytes, q.RetentionDays, q.BlobBytes, id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) deleteLongReadOnly(tx *sql.Tx, now int64) error {
	ids, err := queryIDs(tx, `SELECT id FROM credentials`)
	if err != nil {
		return err
	}
	for _, id := range ids {
		c, err := loadCredential(tx, id)
		if err != nil {
			return err
		}
		if since := c.readOnlySince(now); since != 0 && since+readOnlyLife <= now {
			if err := s.deleteWhere(tx, now, `SELECT id FROM rooms WHERE credential = ? AND deleted_at IS NULL`, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// retain deletes, in each room, every message that each device of kind
// device that acked within 14 days has acked, and every message older than
// the room's retention. Both cut a prefix of sequences, so the watermark
// moves up past them. A device that never acked counts from when it joined.
func (s *Service) retain(tx *sql.Tx, now int64) error {
	rows, err := tx.Query(`SELECT id, next_seq, watermark, retention_days FROM rooms WHERE deleted_at IS NULL`)
	if err != nil {
		return err
	}
	type live struct {
		id                         string
		nextSeq, watermark, retain int64
	}
	var rooms []live
	for rows.Next() {
		var r live
		if err := rows.Scan(&r.id, &r.nextSeq, &r.watermark, &r.retain); err != nil {
			rows.Close()
			return err
		}
		rooms = append(rooms, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range rooms {
		last := r.nextSeq - 1
		expiredBefore := now - r.retain*day
		var ackMin, expiredSeq sql.NullInt64
		if err := tx.QueryRow(`SELECT min(acked) FROM devices WHERE room = ? AND kind = 'device' AND revoked = 0
			AND coalesce(last_ack_at, joined_at) > ?`, r.id, now-silentAfter).Scan(&ackMin); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT max(seq) FROM messages WHERE room = ? AND at <= ?`, r.id, expiredBefore).Scan(&expiredSeq); err != nil {
			return err
		}
		cut := last
		if ackMin.Valid && ackMin.Int64 < cut {
			cut = ackMin.Int64
		}
		if expiredSeq.Valid && expiredSeq.Int64 > cut {
			cut = expiredSeq.Int64
		}
		if watermark := cut + 1; watermark > r.watermark {
			var freed int64
			if err := tx.QueryRow(`SELECT coalesce(sum(size), 0) FROM messages WHERE room = ? AND seq < ?`, r.id, watermark).Scan(&freed); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM messages WHERE room = ? AND seq < ?`, r.id, watermark); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE rooms SET watermark = ?, stored_bytes = stored_bytes - ? WHERE id = ?`, watermark, freed, r.id); err != nil {
				return err
			}
		}
		// A blob goes with the last message that names it, at the room's
		// retention, or after a day when no message ever named it.
		const doomed = `room = ? AND (at <= ? OR (named = 0 AND at <= ?)
			OR (named = 1 AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.room = blobs.room AND m.blob = blobs.id)))`
		args := []any{r.id, expiredBefore, now - unnamedBlobLife}
		var freed int64
		if err := tx.QueryRow(`SELECT coalesce(sum(size), 0) FROM blobs WHERE `+doomed, args...).Scan(&freed); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM blobs WHERE `+doomed, args...); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE rooms SET stored_bytes = stored_bytes - ? WHERE id = ?`, freed, r.id); err != nil {
			return err
		}
	}
	return nil
}
