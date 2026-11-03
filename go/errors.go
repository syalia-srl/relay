package relay

import "errors"

// ErrPairingFailed is returned when a pairing ends without binding a key.
var ErrPairingFailed = errors.New("pairing failed")

// ErrRevoked is returned when the host revoked this guest, or forgot its channels.
var ErrRevoked = errors.New("the host revoked this guest")

// ErrPayloadInvalid is returned for a pairing payload that is malformed,
// expired or unacceptable (PROTOCOL.md section 4).
var ErrPayloadInvalid = errors.New("invalid pairing payload")

// ErrClosed is returned by a call on a host, guest or pairing that is closed.
var ErrClosed = errors.New("closed")

// WrongCodeError means the typed code matches no pending key. The pairing may
// continue, so it does not match ErrPairingFailed.
type WrongCodeError struct {
	// TriesLeft is how many typed codes the pairing still accepts.
	TriesLeft int
}

func (e *WrongCodeError) Error() string {
	return "wrong code, " + itoa(e.TriesLeft) + " tries left"
}

// protocolViolation is every protocol failure inside the library: a frame or
// message that breaks PROTOCOL.md. The socket loops catch this one type.
type protocolViolation struct {
	reason string
}

func (e *protocolViolation) Error() string {
	return e.reason
}

// errTagFailure is the one protocolViolation a caller tells apart: PROTOCOL.md
// section 6.3 tries a transport frame under the candidate before the current
// session, and only a failed tag leaves the second attempt possible.
var errTagFailure = &protocolViolation{reason: "the message does not authenticate"}

func violation(reason string) error {
	return &protocolViolation{reason: reason}
}

func isProtocolViolation(err error) bool {
	var target *protocolViolation
	return errors.As(err, &target)
}

func isTagFailure(err error) bool {
	return errors.Is(err, errTagFailure)
}

// socketClosedError is a WebSocket the relay closed, with the code it sent.
type socketClosedError struct {
	code int
}

func (e *socketClosedError) Error() string {
	return "the relay closed with " + itoa(e.code)
}

func closedStatus(err error) (int, bool) {
	var target *socketClosedError
	if errors.As(err, &target) {
		return target.code, true
	}
	return 0, false
}

// itoa avoids fmt in the error hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
