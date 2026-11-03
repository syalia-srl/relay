package relay

import (
	"encoding/json"
	"unicode/utf8"
)

type relayEntry struct {
	URL     string `json:"url"`
	Channel string `json:"channel"`
	Token   string `json:"token"`
}

func relayEntryFromJSON(value any) (relayEntry, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return relayEntry{}, false
	}
	urlText, ok := object["url"].(string)
	if !ok {
		return relayEntry{}, false
	}
	channel, ok := isB64URL(object["channel"], 22)
	if !ok {
		return relayEntry{}, false
	}
	token, ok := isB64URL(object["token"], 43)
	if !ok {
		return relayEntry{}, false
	}
	return relayEntry{URL: urlText, Channel: channel, Token: token}, true
}

// The side entitled to send each op; empty means either side.
var controlSenders = map[string]string{
	"relays":  "host",
	"close":   "guest",
	"closed":  "host",
	"revoked": "host",
	"ping":    "",
	"pong":    "",
}

type control struct {
	op     string
	relays []relayEntry
}

// parseControl applies, ignores (nil control) or aborts (an error) one control
// message.
func parseControl(text, receiver string) (*control, error) {
	if !utf8.ValidString(text) {
		return nil, violation("the control message is not UTF-8")
	}
	value, err := parseJSON(text)
	if err != nil {
		return nil, violation("the control message is not JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, violation("the control message is not an object")
	}
	op, ok := object["op"].(string)
	if !ok {
		return nil, violation("the control message has no op")
	}
	sender, known := controlSenders[op]
	if !known {
		return nil, nil
	}
	if sender != "" && sender == receiver {
		return nil, violation(op + " came from the wrong side")
	}
	if op != "relays" {
		return &control{op: op}, nil
	}
	raw, ok := object["relays"].([]any)
	if !ok || len(raw) < 1 || len(raw) > 16 {
		return nil, violation("invalid relay list")
	}
	entries := make([]relayEntry, 0, len(raw))
	for _, item := range raw {
		entry, ok := relayEntryFromJSON(item)
		if !ok {
			return nil, violation("invalid relay entry")
		}
		entries = append(entries, entry)
	}
	kept := make([]relayEntry, 0, len(entries))
	for _, entry := range entries {
		if urlAllowed(entry.URL) {
			kept = append(kept, entry)
		}
	}
	// PROTOCOL.md §8.3: filter the list as a whole and ignore it if nothing is left.
	if len(kept) == 0 {
		return nil, nil
	}
	return &control{op: op, relays: kept}, nil
}

type controlJSON struct {
	Op     string       `json:"op"`
	Relays []relayEntry `json:"relays,omitempty"`
}

func encodeControl(op string, relays []relayEntry) []byte {
	document := controlJSON{Op: op}
	if relays != nil {
		document.Relays = relays
	}
	// Every field is a string or a slice of strings, so this cannot fail.
	data, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return data
}
