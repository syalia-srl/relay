package relay

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func digestOf(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// TestLoadsThePythonStateFile reads a file the old Python ChannelStore wrote,
// so phones paired on the public relay keep working after the switch.
func TestLoadsThePythonStateFile(t *testing.T) {
	store := NewStore("testdata/channels_v0.json")
	if store.Len() != 2 {
		t.Fatalf("loaded %d channels, want 2", store.Len())
	}
	ch, side, ok := store.ByToken(digestOf(strings.Repeat("11", 32)))
	if !ok || ch.ID != strings.Repeat("aa", 32) || side != sideA {
		t.Fatalf("mobile token did not resolve: %+v %d %v", ch, side, ok)
	}
	if !ch.MobileSeen || ch.CreatedAt != 1762000000.5 || ch.LastSeen != 1762100000.25 {
		t.Fatalf("row fields lost: %+v", ch)
	}
	_, side, ok = store.ByToken(digestOf(strings.Repeat("22", 32)))
	if !ok || side != sideB {
		t.Fatalf("bridge token did not resolve to the bridge slot: %d %v", side, ok)
	}
	unpaired, _, ok := store.ByToken(digestOf(strings.Repeat("33", 32)))
	if !ok || unpaired.MobileSeen {
		t.Fatalf("unpaired channel came back as seen: %+v", unpaired)
	}
}

func TestTheStoreFileHoldsNoTokenAndIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.json")
	store := NewStore(path)
	ch, mobile, bridge := store.Create(0, "", [3]int64{})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), mobile) || strings.Contains(string(raw), bridge) {
		t.Fatal("a plaintext token reached the store file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("store file mode %o, want 600", mode)
	}
	after := NewStore(path)
	if got, _, ok := after.ByToken(digestOf(bridge)); !ok || got.ID != ch.ID {
		t.Fatal("a restarted store did not find the channel")
	}
}

func TestV1ChannelsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.json")
	store := NewStore(path)
	ch, host, guest := store.Create(1, "sha256:abc", [3]int64{3, 4, 5})
	after := NewStore(path)
	got, side, ok := after.ByToken(digestOf(host))
	if !ok || got.ID != ch.ID || side != sideA {
		t.Fatal("the host token did not survive a restart")
	}
	if got.V != 1 || got.Key != "sha256:abc" || got.LimitChannels != 3 || got.LimitCreates != 4 || got.LimitBytes != 5 {
		t.Fatalf("v1 row lost its fields: %+v", got)
	}
	if _, _, ok := after.ByToken(digestOf(guest)); !ok {
		t.Fatal("the guest token did not survive a restart")
	}
}

func TestTokenShapes(t *testing.T) {
	store := NewStore("")
	v1, host, guest := store.Create(1, "", [3]int64{})
	if len(v1.ID) != 22 || len(host) != 43 || len(guest) != 43 {
		t.Fatalf("v1 id and tokens are %d/%d/%d characters", len(v1.ID), len(host), len(guest))
	}
	v0, mobile, bridge := store.Create(0, "", [3]int64{})
	if len(v0.ID) != 64 || len(mobile) != 64 || len(bridge) != 64 {
		t.Fatalf("v0 id and tokens are %d/%d/%d characters", len(v0.ID), len(mobile), len(bridge))
	}
	for _, s := range []string{v1.ID, host, guest} {
		if strings.ContainsAny(s, "=+/") {
			t.Fatalf("%q is not unpadded base64url", s)
		}
	}
}

func TestGCTakesOnlyUnclaimedAndAbandonedChannels(t *testing.T) {
	store := NewStore("")
	now := float64(time.Now().Unix())
	unclaimed, _, _ := store.Create(0, "", [3]int64{})
	fresh, _, _ := store.Create(1, "", [3]int64{})
	abandoned, _, _ := store.Create(0, "", [3]int64{})
	live, liveHost, _ := store.Create(1, "", [3]int64{})

	unclaimed.CreatedAt = now - GuestTTL - 1
	abandoned.MobileSeen = true
	abandoned.LastSeen = now - IdleTTL - 1
	live.GuestSeen = true
	live.CreatedAt = now - IdleTTL - 1
	live.LastSeen = now - IdleTTL - 1
	// A connected channel stays however old it is.
	live.conns[sideA] = &wsConn{}

	if gone := store.GC(now); gone != 2 {
		t.Fatalf("swept %d channels, want 2", gone)
	}
	if store.Get(unclaimed.ID) != nil || store.Get(abandoned.ID) != nil {
		t.Fatal("an old channel survived the sweep")
	}
	if store.Get(fresh.ID) == nil || store.Get(live.ID) == nil {
		t.Fatal("the sweep took a channel it should keep")
	}
	if _, _, ok := store.ByToken(digestOf(liveHost)); !ok {
		t.Fatal("the sweep left a token pointing nowhere")
	}
}

func TestUnwritableStoreKeepsChannelsInMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "channels.json")
	store := NewStore(path)
	ch, _, _ := store.Create(1, "", [3]int64{})
	if store.Get(ch.ID) == nil {
		t.Fatal("an unwritable store lost its channel")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the store wrote into a path it cannot use")
	}
}

func TestQuotasRefuseAndRecover(t *testing.T) {
	q := NewQuotas()
	now := int64(time.Now().Unix())
	if _, ok := q.Take("k", 2, now); !ok {
		t.Fatal("first creation refused")
	}
	if _, ok := q.Take("k", 2, now); !ok {
		t.Fatal("second creation refused")
	}
	retry, ok := q.Take("k", 2, now)
	if ok || retry != 60 {
		t.Fatalf("third creation: ok=%v retry=%d", ok, retry)
	}
	if _, ok := q.Take("k", 2, now+61); !ok {
		t.Fatal("the window did not free a slot")
	}
	if used := q.AddBytes("other", 10, now); used != 10 {
		t.Fatalf("byte count %d", used)
	}
	if used := q.Used("other", now+86400); used != 0 {
		t.Fatalf("yesterday's bytes survived midnight: %d", used)
	}
}

func TestLoadsAStateFileWithUnknownRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.json")
	body := `{"channels":[
		{"channel_id":"","hash_mobile":"","hash_bridge":""},
		{"channel_id":"c1","hash_mobile":"zz","hash_bridge":"","created_at":1,"last_seen":1},
		{"channel_id":"c2","hash_host":"` + strings.Repeat("ab", 32) + `","hash_guest":"","v":1,"created_at":1,"last_seen":1,"whatever":true}
	]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(path)
	if store.Len() != 2 {
		t.Fatalf("loaded %d channels, want the two rows with an id", store.Len())
	}
	if store.Get("") != nil {
		t.Fatal("a row without a channel id loaded")
	}
	if got := store.Get("c2"); got == nil || got.V != 1 {
		t.Fatal("the v1 row did not load")
	}
}

func TestSavedFileKeepsBothKindsOfRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.json")
	store := NewStore(path)
	v0, _, _ := store.Create(0, "", [3]int64{})
	v1, _, _ := store.Create(1, "sha256:def", [3]int64{})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Channels []map[string]any `json:"channels"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Channels) != 2 {
		t.Fatalf("%d rows on disk", len(file.Channels))
	}
	rows := map[string]map[string]any{}
	for _, row := range file.Channels {
		rows[row["channel_id"].(string)] = row
	}
	if _, ok := rows[v0.ID]["hash_mobile"]; !ok {
		t.Fatal("the v0 row lost its v0 field names")
	}
	if _, ok := rows[v0.ID]["v"]; ok {
		t.Fatal("the v0 row grew a version field")
	}
	row := rows[v1.ID]
	if row["v"] != float64(1) || row["key"] != "sha256:def" || row["hash_host"] == nil {
		t.Fatalf("the v1 row is missing its fields: %+v", row)
	}
}
