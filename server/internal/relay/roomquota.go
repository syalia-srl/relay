package relay

import (
	"encoding/json"
	"errors"
)

// RoomQuota is what a credential may hold in rooms (PROTOCOL.md 2.2,
// ROOMS.md 3.1). A credential without one creates no rooms.
type RoomQuota struct {
	Max           int64 `json:"max"`
	StoredBytes   int64 `json:"stored_bytes"`
	RetentionDays int64 `json:"retention_days"`
	BlobBytes     int64 `json:"blob_bytes"`
}

// RoomLimits are one room's own limits, fixed at creation.
type RoomLimits struct {
	MaxBytes      int64 `json:"max_bytes"`
	RetentionDays int64 `json:"retention_days"`
	BlobBytes     int64 `json:"blob_bytes"`
}

// Room defaults of ROOMS.md 3.1, before the credential bounds them.
const (
	defaultRoomMaxBytes      = 2_000_000_000
	defaultRoomRetentionDays = 30
)

// roomQuotaFrom reads the four limits under the given names. All four must be
// integers in range, with at least one room and one day; anything else means
// no room quota, never an invalid credential.
func roomQuotaFrom(obj map[string]any, max, stored, retention, blob string) *RoomQuota {
	var q RoomQuota
	var ok bool
	if q.Max, ok = intField(obj, max, 1, maxQuota); !ok {
		return nil
	}
	if q.StoredBytes, ok = intField(obj, stored, 0, maxQuota); !ok {
		return nil
	}
	if q.RetentionDays, ok = intField(obj, retention, 1, maxQuota); !ok {
		return nil
	}
	if q.BlobBytes, ok = intField(obj, blob, 0, maxQuota); !ok {
		return nil
	}
	return &q
}

// keyRoomQuota reads a keys.json entry's "rooms" object.
func keyRoomQuota(raw json.RawMessage) *RoomQuota {
	if len(raw) == 0 {
		return nil
	}
	value, err := decodeStrictJSON(raw)
	if err != nil {
		return nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return roomQuotaFrom(obj, "max", "stored_bytes", "retention_days", "blob_bytes")
}

var errBadLimits = errors.New("bad room limits")

// Limits clamps a create request's max_bytes and retention_days to the quota.
// A value that is named but is not an integer of at least 1 is refused.
func (q RoomQuota) Limits(req map[string]any) (RoomLimits, error) {
	l := RoomLimits{
		MaxBytes:      min(defaultRoomMaxBytes, q.StoredBytes),
		RetentionDays: min(defaultRoomRetentionDays, q.RetentionDays),
		BlobBytes:     q.BlobBytes,
	}
	if _, named := req["max_bytes"]; named {
		n, ok := intField(req, "max_bytes", 1, maxQuota)
		if !ok {
			return RoomLimits{}, errBadLimits
		}
		l.MaxBytes = min(n, q.StoredBytes)
	}
	if _, named := req["retention_days"]; named {
		n, ok := intField(req, "retention_days", 1, maxQuota)
		if !ok {
			return RoomLimits{}, errBadLimits
		}
		l.RetentionDays = min(n, q.RetentionDays)
	}
	return l, nil
}

// DecodeStrictJSON decodes one JSON value with numbers kept as json.Number and
// duplicate object keys refused (PROTOCOL.md section 1).
func DecodeStrictJSON(data []byte) (any, error) {
	return decodeStrictJSON(data)
}

// IntField reads an integer field under PROTOCOL.md section 1: a bare JSON
// integer between min and max, never a fraction, an exponent or a string.
func IntField(obj map[string]any, name string, min, max int64) (int64, bool) {
	return intField(obj, name, min, max)
}

// MaxInt is the largest integer PROTOCOL.md section 1 allows.
const MaxInt = maxQuota
