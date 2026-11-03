package relay

import (
	"context"
	"sync"
)

// session is the transport state of one side of one connection.
type session struct {
	send      *cipherState
	receive   *cipherState
	fragments *fragmentAssembler
	// A whole message's fragments must reach the socket together, and their
	// nonces in order, whichever goroutine sends them (PROTOCOL.md §7.2).
	sendMu sync.Mutex
}

func newInitiatorSession(handshake *handshakeState) (*session, error) {
	first, second, err := handshake.split()
	if err != nil {
		return nil, err
	}
	return &session{send: first, receive: second, fragments: newFragmentAssembler()}, nil
}

func newResponderSession(handshake *handshakeState) (*session, error) {
	first, second, err := handshake.split()
	if err != nil {
		return nil, err
	}
	// PROTOCOL.md §6.2: c1 carries guest-to-host frames and c2 host-to-guest.
	return &session{send: second, receive: first, fragments: newFragmentAssembler()}, nil
}

// frames is the L1 transport frames for one application or control message.
// The caller holds sendMu when the frames must stay together on the socket.
func (s *session) frames(kind byte, message []byte) ([][]byte, error) {
	if kind != kindApplication && kind != kindControl {
		return nil, violation("unknown message kind")
	}
	parts := len(message) / maxPayload
	if len(message)%maxPayload != 0 {
		parts++
	}
	if parts == 0 {
		parts = 1
	}
	frames := make([][]byte, 0, parts)
	for index := 0; index < parts; index++ {
		start := index * maxPayload
		end := min(start+maxPayload, len(message))
		flags := byte(0)
		if index < parts-1 {
			flags = 0x01
		}
		plaintext := make([]byte, 2+end-start)
		plaintext[0] = kind
		plaintext[1] = flags
		copy(plaintext[2:], message[start:end])
		ciphertext, err := s.send.encrypt(nil, plaintext)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame(frameTransport, ciphertext))
	}
	return frames, nil
}

// Send writes one message, holding the session lock across encryption and the
// socket write so fragments and nonces never interleave.
func (s *session) Send(ctx context.Context, socket *socket, kind byte, message []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	frames, err := s.frames(kind, message)
	if err != nil {
		return err
	}
	return socket.SendAll(ctx, frames)
}

// Decrypt returns one transport frame; more is true while fragments still
// follow.
func (s *session) Decrypt(body []byte) (kind byte, message []byte, more bool, err error) {
	if len(body) < minTransport || len(body) > maxTransport {
		return 0, nil, false, violation("a transport frame has the wrong length")
	}
	plaintext, err := s.receive.decrypt(nil, body)
	if err != nil {
		return 0, nil, false, err
	}
	kind = plaintext[0]
	flags := plaintext[1]
	if kind != kindApplication && kind != kindControl {
		return 0, nil, false, violation("unknown message kind")
	}
	if flags & ^byte(0x01) != 0 {
		return 0, nil, false, violation("unknown transport flags")
	}
	message, complete, err := s.fragments.push(kind, flags&0x01 != 0, plaintext[2:])
	if err != nil {
		return 0, nil, false, err
	}
	return kind, message, !complete, nil
}
