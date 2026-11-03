package relay

import (
	"encoding/hex"
	"encoding/json"
	"time"
	"unicode/utf8"
)

const deviceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

type payload struct {
	dev        string
	hostPublic []byte
	psk        []byte
	expires    int64
	relays     []relayEntry
}

type payloadJSON struct {
	V      int          `json:"v"`
	HS     string       `json:"hs"`
	PSK    string       `json:"psk"`
	Dev    string       `json:"dev"`
	Exp    int64        `json:"exp"`
	Relays []relayEntry `json:"relays"`
}

func encodePayload(value payload) string {
	document := payloadJSON{
		V:      3,
		HS:     hex.EncodeToString(value.hostPublic),
		PSK:    hex.EncodeToString(value.psk),
		Dev:    value.dev,
		Exp:    value.expires,
		Relays: value.relays,
	}
	// Every field is a string, an integer or a slice of those, so this cannot fail.
	data, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// parsePayload checks a payload as a guest and keeps the relays that pass the
// URL policy of section 8.1.
func parsePayload(text string, now int64) (payload, error) {
	if !utf8.ValidString(text) {
		return payload{}, ErrPayloadInvalid
	}
	value, err := parseJSON(text)
	if err != nil {
		return payload{}, ErrPayloadInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return payload{}, ErrPayloadInvalid
	}
	version, ok := asInteger(object["v"])
	if !ok || version != 3 {
		return payload{}, ErrPayloadInvalid
	}
	hostHex, ok := isHex64(object["hs"])
	if !ok {
		return payload{}, ErrPayloadInvalid
	}
	pskHex, ok := isHex64(object["psk"])
	if !ok {
		return payload{}, ErrPayloadInvalid
	}
	dev, ok := object["dev"].(string)
	if !ok || !validDeviceID(dev) {
		return payload{}, ErrPayloadInvalid
	}
	expires, ok := asInteger(object["exp"])
	if !ok {
		return payload{}, ErrPayloadInvalid
	}
	// PROTOCOL.md §4: a guest SHOULD refuse a payload past exp by more than 60 s.
	if now > expires+60 {
		return payload{}, ErrPayloadInvalid
	}
	if name, present := object["name"]; present && name != nil {
		text, ok := name.(string)
		if !ok || utf8.RuneCountInString(text) > 100 {
			return payload{}, ErrPayloadInvalid
		}
	}
	if url, present := object["url"]; present && url != nil {
		text, ok := url.(string)
		if !ok || utf8.RuneCountInString(text) > 2048 {
			return payload{}, ErrPayloadInvalid
		}
	}
	rawRelays, ok := object["relays"].([]any)
	if !ok || len(rawRelays) < 1 || len(rawRelays) > 16 {
		return payload{}, ErrPayloadInvalid
	}
	entries := make([]relayEntry, 0, len(rawRelays))
	for _, raw := range rawRelays {
		entry, ok := relayEntryFromJSON(raw)
		if !ok {
			return payload{}, ErrPayloadInvalid
		}
		entries = append(entries, entry)
	}
	kept := make([]relayEntry, 0, len(entries))
	for _, entry := range entries {
		if urlAllowed(entry.URL) {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		return payload{}, ErrPayloadInvalid
	}
	hostPublic, _ := hex.DecodeString(hostHex)
	psk, _ := hex.DecodeString(pskHex)
	return payload{dev: dev, hostPublic: hostPublic, psk: psk, expires: expires, relays: kept}, nil
}

func validDeviceID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !containsByte(deviceChars, value[i]) {
			return false
		}
	}
	return true
}

func containsByte(text string, want byte) bool {
	for i := 0; i < len(text); i++ {
		if text[i] == want {
			return true
		}
	}
	return false
}

func unixNow() int64 {
	return time.Now().Unix()
}
