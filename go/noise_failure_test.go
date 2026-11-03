package relay

import (
	"errors"
	"strings"
	"testing"
)

func TestALowOrderEphemeralKeyIsAProtocolViolation(t *testing.T) {
	// A relay that sends an all-zero key must fail at the key itself, not at the
	// tag that follows from it, and only with the error the socket loops abort on.
	host, err := generateMemoryKey()
	if err != nil {
		t.Fatal(err)
	}
	guest, err := generateMemoryKey()
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := newHandshake("KK", true, nil, guest, host.PublicKey(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.writeMessage(nil); err != nil {
		t.Fatal(err)
	}
	_, err = initiator.readMessage(make([]byte, 48))
	if !isProtocolViolation(err) {
		t.Fatalf("read error is %v, want a protocol violation", err)
	}
	if !strings.Contains(err.Error(), "X25519") {
		t.Fatalf("error is %q, want it to name the invalid key", err)
	}
}

type failingStaticKey struct {
	public []byte
}

func (k *failingStaticKey) PublicKey() []byte { return k.public }

func (k *failingStaticKey) DH([]byte) ([]byte, error) {
	return nil, errors.New("the keystore refused")
}

func TestANativeKeyThatFailsItsDHIsAProtocolViolation(t *testing.T) {
	// A keystore reports a bad remote key in its own way; the socket loops only
	// abort on a protocol violation.
	host, err := generateMemoryKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := generateMemoryKey()
	if err != nil {
		t.Fatal(err)
	}
	native := &failingStaticKey{public: other.PublicKey()}
	initiator, err := newHandshake("KK", true, nil, native, host.PublicKey(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.writeMessage(nil); !isProtocolViolation(err) {
		t.Fatalf("write error is %v, want a protocol violation", err)
	}
}
