package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// L1 frame types (PROTOCOL.md section 3.2).
const (
	framePair      = 0x01
	frameConnect   = 0x02
	frameAccept    = 0x03
	frameTransport = 0x04
	frameAbort     = 0x05
)

// Transport message kinds and limits (PROTOCOL.md sections 7.1 and 7.2).
const (
	kindApplication = 0x00
	kindControl     = 0x01
	maxPayload      = 65_517
	maxMessage      = 16_777_216
	minTransport    = 18
	maxTransport    = 65_535
)

// prologue binds a handshake to one device and one channel (PROTOCOL.md §3.1).
func prologue(dev, channel string) []byte {
	device := []byte(dev)
	identifier := []byte(channel)
	out := make([]byte, 0, len("relay-channel/3")+4+len(device)+len(identifier))
	out = append(out, "relay-channel/3"...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(device)))
	out = append(out, device...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(identifier)))
	out = append(out, identifier...)
	return out
}

// pairingCode is the six digits the person types into the host (PROTOCOL.md §5.6).
func pairingCode(handshakeHash []byte) string {
	digest := sha256.Sum256(append([]byte("relay-channel/3 pairing code"), handshakeHash...))
	value := binary.BigEndian.Uint32(digest[:4])
	return fmt.Sprintf("%06d", value%1_000_000)
}

func frame(frameType byte, body []byte) []byte {
	out := make([]byte, 1+len(body))
	out[0] = frameType
	copy(out[1:], body)
	return out
}

// fragmentAssembler reassembles one direction's message and refuses a fragment
// that changes kind or grows the message past 16 MiB.
type fragmentAssembler struct {
	kind  int
	parts [][]byte
	size  int
}

func newFragmentAssembler() *fragmentAssembler {
	return &fragmentAssembler{kind: -1}
}

func (a *fragmentAssembler) push(kind byte, more bool, payload []byte) ([]byte, bool, error) {
	if a.kind == -1 {
		a.kind = int(kind)
	} else if int(kind) != a.kind {
		return nil, false, violation("a fragment changed kind")
	}
	a.size += len(payload)
	if a.size > maxMessage {
		return nil, false, violation("a message is larger than 16 MiB")
	}
	a.parts = append(a.parts, bytes.Clone(payload))
	if more {
		return nil, false, nil
	}
	message := bytes.Join(a.parts, nil)
	a.kind = -1
	a.parts = nil
	a.size = 0
	return message, true, nil
}
