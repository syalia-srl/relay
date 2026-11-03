package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const vectorDirectory = "../vectors"

type expectedFrame struct {
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}

type transportVector struct {
	Sender    string          `json:"sender"`
	Plaintext json.RawMessage `json:"plaintext"`
	Frame     json.RawMessage `json:"frame"`
}

type handshakeVector struct {
	ProtocolName       string            `json:"protocol_name"`
	Dev                string            `json:"dev"`
	Channel            string            `json:"channel"`
	Prologue           string            `json:"prologue"`
	HostStaticPrivate  string            `json:"host_static_private"`
	HostStaticPublic   string            `json:"host_static_public"`
	GuestStaticPrivate string            `json:"guest_static_private"`
	GuestStaticPublic  string            `json:"guest_static_public"`
	GuestEphemeral     string            `json:"guest_ephemeral_private"`
	HostEphemeral      string            `json:"host_ephemeral_private"`
	PSK                string            `json:"psk"`
	Message1           string            `json:"message1"`
	Message2           string            `json:"message2"`
	Frame1             string            `json:"frame1"`
	Frame2             string            `json:"frame2"`
	HandshakeHash      string            `json:"handshake_hash"`
	PairingCode        string            `json:"pairing_code"`
	Transport          []transportVector `json:"transport"`
	FragmentedMessage  *fragmentedVector `json:"fragmented_message"`
}

type fragmentedVector struct {
	Length int   `json:"length"`
	Frames []int `json:"frames"`
}

type refusedPairing struct {
	Name     string `json:"name"`
	PSKUsed  string `json:"psk_used"`
	Channel  string `json:"channel"`
	Message1 string `json:"message1"`
}

type refusedConnect struct {
	Name               string `json:"name"`
	GuestStaticPrivate string `json:"guest_static_private"`
	Message1           string `json:"message1"`
}

func readVector(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func vectorKey(t *testing.T, private string) *memoryKey {
	t.Helper()
	key, err := memoryKeyFromPrivate(mustHex(t, private))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func vectorHandshake(t *testing.T, vector handshakeVector, role string, initiator bool, pattern string, psk []byte) *handshakeState {
	t.Helper()
	remoteHex := vector.HostStaticPublic
	ephemeral := vector.GuestEphemeral
	if role == "host" {
		remoteHex = vector.GuestStaticPublic
		ephemeral = vector.HostEphemeral
	}
	state, err := newHandshake(
		pattern,
		initiator,
		mustHex(t, vector.Prologue),
		vectorKey(t, map[string]string{"guest": vector.GuestStaticPrivate, "host": vector.HostStaticPrivate}[role]),
		mustHex(t, remoteHex),
		psk,
		mustHex(t, ephemeral),
	)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func checkFrame(t *testing.T, frameBytes []byte, raw json.RawMessage) {
	t.Helper()
	whole := append([]byte{0x01}, frameBytes...)
	if len(raw) > 0 && raw[0] == '"' {
		var expected string
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(whole); got != expected {
			t.Fatalf("frame is %s, want %s", got, expected)
		}
		return
	}
	var expected expectedFrame
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(whole)
	if got := hex.EncodeToString(digest[:]); got != expected.SHA256 {
		t.Fatalf("frame digest is %s, want %s", got, expected.SHA256)
	}
	if len(whole) != expected.Length {
		t.Fatalf("frame length is %d, want %d", len(whole), expected.Length)
	}
}

func checkHandshake(t *testing.T, vector handshakeVector, pattern string, first byte, psk []byte) {
	t.Helper()
	guest := vectorHandshake(t, vector, "guest", true, pattern, psk)
	host := vectorHandshake(t, vector, "host", false, pattern, psk)

	message1, err := guest.writeMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(message1); got != vector.Message1 {
		t.Fatalf("message1 is %s, want %s", got, vector.Message1)
	}
	if got := hex.EncodeToString(append([]byte{0x01}, frame(first, message1)...)); got != vector.Frame1 {
		t.Fatalf("frame1 is %s, want %s", got, vector.Frame1)
	}
	if _, err := host.readMessage(message1); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(host.remoteStatic); got != vector.GuestStaticPublic {
		t.Fatalf("remote static is %s, want %s", got, vector.GuestStaticPublic)
	}

	message2, err := host.writeMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(message2); got != vector.Message2 {
		t.Fatalf("message2 is %s, want %s", got, vector.Message2)
	}
	if got := hex.EncodeToString(append([]byte{0x01}, frame(frameAccept, message2)...)); got != vector.Frame2 {
		t.Fatalf("frame2 is %s, want %s", got, vector.Frame2)
	}
	if _, err := guest.readMessage(message2); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(guest.handshakeHash()); got != vector.HandshakeHash {
		t.Fatalf("guest handshake hash is %s, want %s", got, vector.HandshakeHash)
	}
	if got := hex.EncodeToString(host.handshakeHash()); got != vector.HandshakeHash {
		t.Fatalf("host handshake hash is %s, want %s", got, vector.HandshakeHash)
	}
	if pattern == "IKpsk1" && pairingCode(guest.handshakeHash()) != vector.PairingCode {
		t.Fatalf("pairing code is %s, want %s", pairingCode(guest.handshakeHash()), vector.PairingCode)
	}

	guestSession, err := newInitiatorSession(guest)
	if err != nil {
		t.Fatal(err)
	}
	hostSession, err := newResponderSession(host)
	if err != nil {
		t.Fatal(err)
	}
	var big []byte
	var fragmentPositions []int
	if vector.FragmentedMessage != nil {
		big = make([]byte, vector.FragmentedMessage.Length)
		for index := range big {
			big[index] = byte(index % 251)
		}
		fragmentPositions = vector.FragmentedMessage.Frames
	}
	var bigFrames [][]byte
	for index, item := range vector.Transport {
		sender, receiver := guestSession, hostSession
		if item.Sender == "host" {
			sender, receiver = hostSession, guestSession
		}
		var frameBytes []byte
		var expectedKind byte
		var expectedMessage []byte
		var expectedMore bool
		if positionOf(fragmentPositions, index) >= 0 {
			if bigFrames == nil {
				bigFrames, err = sender.frames(kindApplication, big)
				if err != nil {
					t.Fatal(err)
				}
			}
			frameBytes = bigFrames[positionOf(fragmentPositions, index)]
			checkFrame(t, frameBytes, item.Frame)
			expectedKind = kindApplication
			if index == fragmentPositions[len(fragmentPositions)-1] {
				expectedMessage = big
			} else {
				expectedMore = true
			}
		} else {
			var plaintextHex string
			if err := json.Unmarshal(item.Plaintext, &plaintextHex); err != nil {
				t.Fatal(err)
			}
			plaintext := mustHex(t, plaintextHex)
			var frames [][]byte
			frames, err = sender.frames(plaintext[0], plaintext[2:])
			if err != nil {
				t.Fatal(err)
			}
			if len(frames) != 1 {
				t.Fatalf("one plaintext made %d frames", len(frames))
			}
			frameBytes = frames[0]
			checkFrame(t, frameBytes, item.Frame)
			expectedKind, expectedMessage = plaintext[0], plaintext[2:]
		}
		kind, message, more, err := receiver.Decrypt(frameBytes[1:])
		if err != nil {
			t.Fatal(err)
		}
		if kind != expectedKind || more != expectedMore || !bytes.Equal(message, expectedMessage) {
			t.Fatalf("transport frame %d decrypted to (%d, %x, %t), want (%d, %x, %t)",
				index, kind, message, more, expectedKind, expectedMessage, expectedMore)
		}
	}
}

func positionOf(values []int, want int) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return -1
}

func TestPairingVector(t *testing.T) {
	var file struct {
		Cases []handshakeVector `json:"cases"`
	}
	readVector(t, "pairing.json", &file)
	checkHandshake(t, file.Cases[0], "IKpsk1", framePair, mustHex(t, file.Cases[0].PSK))
}

func TestPairingVectorRefused(t *testing.T) {
	var file struct {
		Cases   []handshakeVector `json:"cases"`
		Refused []refusedPairing  `json:"refused"`
	}
	readVector(t, "pairing.json", &file)
	vector := file.Cases[0]
	for _, refused := range file.Refused {
		t.Run(refused.Name, func(t *testing.T) {
			host, err := newHandshake(
				"IKpsk1",
				false,
				prologue("dev_01", refused.Channel),
				vectorKey(t, vector.HostStaticPrivate),
				nil,
				mustHex(t, vector.PSK),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := host.readMessage(mustHex(t, refused.Message1)); !isProtocolViolation(err) {
				t.Fatalf("read error is %v, want a protocol violation", err)
			}
		})
	}
}

func TestConnectVector(t *testing.T) {
	var file struct {
		Cases []handshakeVector `json:"cases"`
	}
	readVector(t, "connect.json", &file)
	checkHandshake(t, file.Cases[0], "KK", frameConnect, nil)
}

func TestConnectVectorRefused(t *testing.T) {
	var file struct {
		Cases   []handshakeVector `json:"cases"`
		Refused []refusedConnect  `json:"refused"`
	}
	readVector(t, "connect.json", &file)
	vector := file.Cases[0]
	for _, refused := range file.Refused {
		t.Run(refused.Name, func(t *testing.T) {
			host, err := newHandshake(
				"KK",
				false,
				prologue("dev_01", vector.Channel),
				vectorKey(t, vector.HostStaticPrivate),
				mustHex(t, vector.GuestStaticPublic),
				nil,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := host.readMessage(mustHex(t, refused.Message1)); !isProtocolViolation(err) {
				t.Fatalf("read error is %v, want a protocol violation", err)
			}
		})
	}
}

func TestRekeyVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Key              string `json:"key"`
			Rekeyed          string `json:"rekeyed"`
			NonceBefore      uint64 `json:"nonce_before"`
			PlaintextBefore  string `json:"plaintext_before"`
			CiphertextBefore string `json:"ciphertext_before"`
			NonceAfter       uint64 `json:"nonce_after"`
			PlaintextAfter   string `json:"plaintext_after"`
			CiphertextAfter  string `json:"ciphertext_after"`
		} `json:"cases"`
	}
	readVector(t, "rekey.json", &file)
	for _, vector := range file.Cases {
		cipher := newCipherState(mustHex(t, vector.Key), vector.NonceBefore)
		before, err := cipher.encrypt(nil, mustHex(t, vector.PlaintextBefore))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(before); got != vector.CiphertextBefore {
			t.Fatalf("ciphertext before is %s, want %s", got, vector.CiphertextBefore)
		}
		if got := hex.EncodeToString(cipher.key); got != vector.Rekeyed {
			t.Fatalf("rekeyed key is %s, want %s", got, vector.Rekeyed)
		}
		if got := hex.EncodeToString(rekey(mustHex(t, vector.Key))); got != vector.Rekeyed {
			t.Fatalf("rekey is %s, want %s", got, vector.Rekeyed)
		}
		if cipher.nonce != rekeyEvery {
			t.Fatalf("nonce is %d, want %d", cipher.nonce, rekeyEvery)
		}
		after, err := cipher.encrypt(nil, mustHex(t, vector.PlaintextAfter))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(after); got != vector.CiphertextAfter {
			t.Fatalf("ciphertext after is %s, want %s", got, vector.CiphertextAfter)
		}
		if cipher.nonce != rekeyEvery+1 {
			t.Fatalf("nonce is %d, want %d", cipher.nonce, rekeyEvery+1)
		}
	}
}

func TestPrologueVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Dev      string `json:"dev"`
			Channel  string `json:"channel"`
			Prologue string `json:"prologue"`
		} `json:"cases"`
	}
	readVector(t, "prologue.json", &file)
	for _, vector := range file.Cases {
		if got := hex.EncodeToString(prologue(vector.Dev, vector.Channel)); got != vector.Prologue {
			t.Fatalf("prologue is %s, want %s", got, vector.Prologue)
		}
	}
}

func TestPairingCodeVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			H    string `json:"h"`
			Code string `json:"code"`
		} `json:"cases"`
	}
	readVector(t, "pairing_code.json", &file)
	for _, vector := range file.Cases {
		if got := pairingCode(mustHex(t, vector.H)); got != vector.Code {
			t.Fatalf("code is %s, want %s", got, vector.Code)
		}
	}
}

func TestURLPolicyVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			URL     string `json:"url"`
			Allowed bool   `json:"allowed"`
		} `json:"cases"`
	}
	readVector(t, "url_policy.json", &file)
	for _, vector := range file.Cases {
		if got := urlAllowed(vector.URL); got != vector.Allowed {
			t.Fatalf("urlAllowed(%q) is %t, want %t", vector.URL, got, vector.Allowed)
		}
	}
}

func TestPairingPayloadVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name       string `json:"name"`
			Now        int64  `json:"now"`
			Text       string `json:"text"`
			Valid      bool   `json:"valid"`
			RelaysKept []int  `json:"relays_kept"`
		} `json:"cases"`
	}
	readVector(t, "pairing_payload.json", &file)
	for _, vector := range file.Cases {
		payload, err := parsePayload(vector.Text, vector.Now)
		if !vector.Valid {
			if !errors.Is(err, ErrPayloadInvalid) {
				t.Fatalf("%s: error is %v, want ErrPayloadInvalid", vector.Name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		var original struct {
			Relays []relayEntry `json:"relays"`
		}
		if err := json.Unmarshal([]byte(vector.Text), &original); err != nil {
			t.Fatal(err)
		}
		if len(payload.relays) != len(vector.RelaysKept) {
			t.Fatalf("%s: kept %d relays, want %d", vector.Name, len(payload.relays), len(vector.RelaysKept))
		}
		for index, kept := range vector.RelaysKept {
			if payload.relays[index] != original.Relays[kept] {
				t.Fatalf("%s: kept relay %d is %+v, want %+v", vector.Name, index, payload.relays[index], original.Relays[kept])
			}
		}
	}
}

func TestControlVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Text     string `json:"text"`
			Receiver string `json:"receiver"`
			Result   string `json:"result"`
		} `json:"cases"`
	}
	readVector(t, "control.json", &file)
	for _, vector := range file.Cases {
		control, err := parseControl(vector.Text, vector.Receiver)
		switch vector.Result {
		case "apply":
			if err != nil || control == nil {
				t.Fatalf("%q: control is %+v, error %v", vector.Text, control, err)
			}
		case "ignore":
			if err != nil || control != nil {
				t.Fatalf("%q: control is %+v, error %v", vector.Text, control, err)
			}
		default:
			if !isProtocolViolation(err) {
				t.Fatalf("%q: error is %v, want a protocol violation", vector.Text, err)
			}
		}
	}
}

type cacophonyMessage struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

type cacophonyVector struct {
	ProtocolName     string             `json:"protocol_name"`
	InitPrologue     string             `json:"init_prologue"`
	InitStatic       string             `json:"init_static"`
	InitRemoteStatic string             `json:"init_remote_static"`
	InitEphemeral    string             `json:"init_ephemeral"`
	InitPSKs         []string           `json:"init_psks"`
	RespPrologue     string             `json:"resp_prologue"`
	RespStatic       string             `json:"resp_static"`
	RespRemoteStatic string             `json:"resp_remote_static"`
	RespEphemeral    string             `json:"resp_ephemeral"`
	RespPSKs         []string           `json:"resp_psks"`
	HandshakeHash    string             `json:"handshake_hash"`
	Messages         []cacophonyMessage `json:"messages"`
}

func optionalHex(t *testing.T, text string) []byte {
	if text == "" {
		return nil
	}
	return mustHex(t, text)
}

func TestCacophonyVectors(t *testing.T) {
	var file struct {
		Vectors []cacophonyVector `json:"vectors"`
	}
	readVector(t, "tools/cacophony_subset.json", &file)
	patterns := map[string]string{
		"Noise_IKpsk1_25519_AESGCM_SHA256": "IKpsk1",
		"Noise_KK_25519_AESGCM_SHA256":     "KK",
	}
	seen := make(map[string]bool)
	for _, vector := range file.Vectors {
		pattern, wanted := patterns[vector.ProtocolName]
		if !wanted {
			continue
		}
		seen[vector.ProtocolName] = true
		var initiatorPSK, responderPSK []byte
		if len(vector.InitPSKs) > 0 {
			initiatorPSK = mustHex(t, vector.InitPSKs[0])
		}
		if len(vector.RespPSKs) > 0 {
			responderPSK = mustHex(t, vector.RespPSKs[0])
		}
		initiator, err := newHandshake(pattern, true, optionalHex(t, vector.InitPrologue),
			vectorKey(t, vector.InitStatic), optionalHex(t, vector.InitRemoteStatic), initiatorPSK,
			optionalHex(t, vector.InitEphemeral))
		if err != nil {
			t.Fatal(err)
		}
		responder, err := newHandshake(pattern, false, optionalHex(t, vector.RespPrologue),
			vectorKey(t, vector.RespStatic), optionalHex(t, vector.RespRemoteStatic), responderPSK,
			optionalHex(t, vector.RespEphemeral))
		if err != nil {
			t.Fatal(err)
		}
		var first, second, third, fourth *cipherState
		for index, message := range vector.Messages {
			payload := mustHex(t, message.Payload)
			expected := mustHex(t, message.Ciphertext)
			initiatorSends := index%2 == 0
			if first == nil {
				sender, receiver := initiator, responder
				if !initiatorSends {
					sender, receiver = responder, initiator
				}
				ciphertext, err := sender.writeMessage(payload)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ciphertext, expected) {
					t.Fatalf("%s message %d ciphertext differs", vector.ProtocolName, index)
				}
				got, err := receiver.readMessage(ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("%s message %d payload differs", vector.ProtocolName, index)
				}
				if initiator.finished() {
					if got := hex.EncodeToString(initiator.handshakeHash()); got != vector.HandshakeHash {
						t.Fatalf("initiator hash is %s, want %s", got, vector.HandshakeHash)
					}
					if got := hex.EncodeToString(responder.handshakeHash()); got != vector.HandshakeHash {
						t.Fatalf("responder hash is %s, want %s", got, vector.HandshakeHash)
					}
					first, second, err = initiator.split()
					if err != nil {
						t.Fatal(err)
					}
					third, fourth, err = responder.split()
					if err != nil {
						t.Fatal(err)
					}
				}
				continue
			}
			sender, receiver := first, third
			if !initiatorSends {
				sender, receiver = fourth, second
			}
			ciphertext, err := sender.encrypt(nil, payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ciphertext, expected) {
				t.Fatalf("%s transport message %d ciphertext differs", vector.ProtocolName, index)
			}
			got, err := receiver.decrypt(nil, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s transport message %d payload differs", vector.ProtocolName, index)
			}
		}
	}
	for name := range patterns {
		if !seen[name] {
			t.Fatalf("the cacophony subset has no %s vector", name)
		}
	}
}
