package relay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
)

// StaticKey is a static X25519 key pair that computes Diffie-Hellman without
// yielding its private half, so the key can live in an HSM or another process.
type StaticKey interface {
	// PublicKey is the 32-byte public key.
	PublicKey() []byte
	// DH is the 32-byte X25519 shared secret with peerPublic.
	DH(peerPublic []byte) ([]byte, error)
}

// memoryKey is a StaticKey whose private half lives in process memory.
type memoryKey struct {
	private *ecdh.PrivateKey
	public  []byte
}

func generateMemoryKey() (*memoryKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &memoryKey{private: private, public: private.PublicKey().Bytes()}, nil
}

func memoryKeyFromPrivate(private []byte) (*memoryKey, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return &memoryKey{private: key, public: key.PublicKey().Bytes()}, nil
}

func (k *memoryKey) PublicKey() []byte {
	return bytes.Clone(k.public)
}

func (k *memoryKey) DH(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != 32 {
		return nil, errors.New("an X25519 public key is 32 bytes")
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, err
	}
	return k.private.ECDH(peer)
}

func (k *memoryKey) privateBytes() []byte {
	return k.private.Bytes()
}
