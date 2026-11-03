package relay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	hashLen    = 32
	dhLen      = 32
	maxNonce   = ^uint64(0)
	rekeyEvery = uint64(1 << 20)
)

type noisePattern struct {
	preInitiator []string
	preResponder []string
	messages     [][]string
	psk          bool
}

var noisePatterns = map[string]noisePattern{
	"IKpsk1": {
		preResponder: []string{"s"},
		messages: [][]string{
			{"e", "es", "s", "ss", "psk"},
			{"e", "ee", "se"},
		},
		psk: true,
	},
	"KK": {
		preInitiator: []string{"s"},
		preResponder: []string{"s"},
		messages: [][]string{
			{"e", "es", "ss"},
			{"e", "ee", "se"},
		},
	},
}

// hkdf is Noise's HKDF: the chaining key is the salt and the result is split
// into the requested 32-byte outputs.
func hkdf(chainingKey, ikm []byte, outputs int) [][]byte {
	extract := hmac.New(sha256.New, chainingKey)
	extract.Write(ikm)
	temp := extract.Sum(nil)
	result := make([][]byte, 0, outputs)
	previous := []byte(nil)
	for index := 1; index <= outputs; index++ {
		expand := hmac.New(sha256.New, temp)
		expand.Write(previous)
		expand.Write([]byte{byte(index)})
		previous = expand.Sum(nil)
		result = append(result, previous)
	}
	return result
}

func nonceBytes(nonce uint64) [12]byte {
	var out [12]byte
	binary.BigEndian.PutUint64(out[4:], nonce)
	return out
}

func gcmFor(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("relay: an AES key is not 16, 24 or 32 bytes")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("relay: the GCM nonce size is invalid")
	}
	return aead
}

// rekey is Noise's Rekey() for AES-GCM.
func rekey(key []byte) []byte {
	aead := gcmFor(key)
	nonce := nonceBytes(maxNonce)
	return aead.Seal(nil, nonce[:], make([]byte, 32), nil)[:32]
}

// cipherState is a Noise cipher state: an optional key and a 64-bit counter.
type cipherState struct {
	key   []byte
	nonce uint64
}

func newCipherState(key []byte, nonce uint64) *cipherState {
	return &cipherState{key: key, nonce: nonce}
}

func (c *cipherState) encrypt(associatedData, plaintext []byte) ([]byte, error) {
	if c.key == nil {
		return plaintext, nil
	}
	if c.nonce == maxNonce {
		return nil, violation("the transport nonce is exhausted")
	}
	aead := gcmFor(c.key)
	nonce := nonceBytes(c.nonce)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, associatedData)
	c.advance()
	return ciphertext, nil
}

func (c *cipherState) decrypt(associatedData, ciphertext []byte) ([]byte, error) {
	if c.key == nil {
		return ciphertext, nil
	}
	if c.nonce == maxNonce {
		return nil, violation("the transport nonce is exhausted")
	}
	aead := gcmFor(c.key)
	nonce := nonceBytes(c.nonce)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, associatedData)
	if err != nil {
		// A failed tag leaves the counter alone, so a candidate and the current
		// session can each try the same frame (PROTOCOL.md §6.3).
		return nil, errTagFailure
	}
	c.advance()
	return plaintext, nil
}

func (c *cipherState) advance() {
	c.nonce++
	// PROTOCOL.md §7.3: both ends rekey after the frame whose nonce is 2^20 - 1.
	if c.nonce%rekeyEvery == 0 {
		c.key = rekey(c.key)
	}
}

// handshakeState is one side of an IKpsk1 or KK handshake.
type handshakeState struct {
	initiator       bool
	static          StaticKey
	remoteStatic    []byte
	psk             []byte
	fixedEphemeral  []byte
	ephemeral       *ecdh.PrivateKey
	remoteEphemeral []byte
	index           int
	h               []byte
	ck              []byte
	cipher          *cipherState
	pskMode         bool
	messages        [][]string
}

func newHandshake(pattern string, initiator bool, prologueBytes []byte, static StaticKey, remoteStatic, psk, ephemeral []byte) (*handshakeState, error) {
	definition, ok := noisePatterns[pattern]
	if !ok {
		return nil, errors.New("unsupported Noise pattern " + pattern)
	}
	if definition.psk && psk == nil {
		return nil, errors.New("IKpsk1 needs a psk")
	}
	state := &handshakeState{
		initiator:      initiator,
		static:         static,
		remoteStatic:   bytes.Clone(remoteStatic),
		psk:            psk,
		fixedEphemeral: bytes.Clone(ephemeral),
		cipher:         newCipherState(nil, 0),
		pskMode:        definition.psk,
		messages:       definition.messages,
	}
	name := []byte("Noise_" + pattern + "_25519_AESGCM_SHA256")
	if len(name) <= hashLen {
		state.h = make([]byte, hashLen)
		copy(state.h, name)
	} else {
		digest := sha256.Sum256(name)
		state.h = digest[:]
	}
	state.ck = bytes.Clone(state.h)
	if err := state.mixHash(prologueBytes); err != nil {
		return nil, err
	}
	for range definition.preInitiator {
		own := static.PublicKey()
		key := remoteStatic
		if initiator {
			key = own
		}
		if key == nil {
			return nil, errors.New("a pre-message static key is missing")
		}
		if err := state.mixHash(key); err != nil {
			return nil, err
		}
	}
	for range definition.preResponder {
		key := remoteStatic
		if !initiator {
			key = static.PublicKey()
		}
		if key == nil {
			return nil, errors.New("a pre-message static key is missing")
		}
		if err := state.mixHash(key); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (h *handshakeState) handshakeHash() []byte {
	return bytes.Clone(h.h)
}

func (h *handshakeState) finished() bool {
	return h.index == len(h.messages)
}

func (h *handshakeState) mixHash(data []byte) error {
	digest := sha256.Sum256(append(h.h, data...))
	h.h = digest[:]
	return nil
}

func (h *handshakeState) mixKey(ikm []byte) {
	output := hkdf(h.ck, ikm, 2)
	h.ck = output[0]
	h.cipher = newCipherState(output[1], 0)
}

func (h *handshakeState) mixKeyAndHash(ikm []byte) {
	output := hkdf(h.ck, ikm, 3)
	h.ck = output[0]
	_ = h.mixHash(output[1])
	h.cipher = newCipherState(output[2], 0)
}

func (h *handshakeState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := h.cipher.encrypt(h.h, plaintext)
	if err != nil {
		return nil, err
	}
	if err := h.mixHash(ciphertext); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (h *handshakeState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := h.cipher.decrypt(h.h, ciphertext)
	if err != nil {
		return nil, err
	}
	if err := h.mixHash(ciphertext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (h *handshakeState) dh(token string) ([]byte, error) {
	// "xy": x belongs to the initiator and y to the responder.
	mine, theirs := token[0], token[1]
	if !h.initiator {
		mine, theirs = theirs, mine
	}
	var remote []byte
	if theirs == 'e' {
		remote = h.remoteEphemeral
	} else {
		remote = h.remoteStatic
	}
	if remote == nil {
		return nil, violation(token + " has no remote key")
	}
	if mine == 'e' {
		if h.ephemeral == nil {
			return nil, violation(token + " has no local ephemeral key")
		}
		peer, err := ecdh.X25519().NewPublicKey(remote)
		if err != nil {
			return nil, violation("a remote X25519 key is invalid")
		}
		secret, err := h.ephemeral.ECDH(peer)
		if err != nil {
			return nil, violation("a remote X25519 key is invalid")
		}
		return secret, nil
	}
	secret, err := h.static.DH(remote)
	if err != nil {
		// A native key reports a bad remote key in its own way.
		return nil, violation("a remote X25519 key is invalid")
	}
	return secret, nil
}

func (h *handshakeState) writeMessage(payload []byte) ([]byte, error) {
	if h.finished() {
		return nil, violation("the handshake is already finished")
	}
	var out []byte
	for _, token := range h.messages[h.index] {
		switch token {
		case "e":
			if h.fixedEphemeral != nil {
				private, err := ecdh.X25519().NewPrivateKey(h.fixedEphemeral)
				if err != nil {
					return nil, violation("an X25519 ephemeral key is invalid")
				}
				h.ephemeral = private
			} else {
				private, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
				h.ephemeral = private
			}
			public := h.ephemeral.PublicKey().Bytes()
			out = append(out, public...)
			if err := h.mixHash(public); err != nil {
				return nil, err
			}
			if h.pskMode {
				h.mixKey(public)
			}
		case "s":
			ciphertext, err := h.encryptAndHash(h.static.PublicKey())
			if err != nil {
				return nil, err
			}
			out = append(out, ciphertext...)
		case "psk":
			h.mixKeyAndHash(h.psk)
		default:
			secret, err := h.dh(token)
			if err != nil {
				return nil, err
			}
			h.mixKey(secret)
		}
	}
	tag, err := h.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	out = append(out, tag...)
	h.index++
	return out, nil
}

func (h *handshakeState) readMessage(message []byte) ([]byte, error) {
	if h.finished() {
		return nil, violation("the handshake is already finished")
	}
	for _, token := range h.messages[h.index] {
		switch token {
		case "e":
			if len(message) < dhLen {
				return nil, violation("a handshake message is too short")
			}
			h.remoteEphemeral = bytes.Clone(message[:dhLen])
			message = message[dhLen:]
			if err := h.mixHash(h.remoteEphemeral); err != nil {
				return nil, err
			}
			if h.pskMode {
				h.mixKey(h.remoteEphemeral)
			}
		case "s":
			size := dhLen
			if h.cipher.key != nil {
				size += 16
			}
			if len(message) < size {
				return nil, violation("a handshake message is too short")
			}
			plaintext, err := h.decryptAndHash(message[:size])
			if err != nil {
				return nil, err
			}
			h.remoteStatic = plaintext
			message = message[size:]
		case "psk":
			h.mixKeyAndHash(h.psk)
		default:
			secret, err := h.dh(token)
			if err != nil {
				return nil, err
			}
			h.mixKey(secret)
		}
	}
	payload, err := h.decryptAndHash(message)
	if err != nil {
		return nil, err
	}
	h.index++
	return payload, nil
}

func (h *handshakeState) split() (c1, c2 *cipherState, err error) {
	if !h.finished() {
		return nil, nil, violation("the handshake is not finished")
	}
	output := hkdf(h.ck, nil, 2)
	return newCipherState(output[0], 0), newCipherState(output[1], 0), nil
}
