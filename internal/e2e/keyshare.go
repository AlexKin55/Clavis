package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// ephKeySize is the X25519 public key size.
	ephKeySize = 32
	// sharedSecretInfo labels the session-key derivation.
	sharedSecretInfo = "clavis-e2e-shared-secret"
)

// OwnerShare sends the owner's reader key material (AS || owner pub) to
// the peer over the encrypted session channel. The document content never
// traverses the relay; only the wrapped reader material does, encrypted
// with the ECDH session key.
func OwnerShare(conn net.Conn, as, ownerPub []byte) error {
	// 1. Receive the peer's ephemeral public key.
	var peerPub [ephKeySize]byte
	if _, err := io.ReadFull(conn, peerPub[:]); err != nil {
		return fmt.Errorf("e2e: read peer public key: %w", err)
	}
	// 2. Generate ours and send it.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("e2e: generate key: %w", err)
	}
	if _, err := writeAll(conn, priv.PublicKey().Bytes()); err != nil {
		return fmt.Errorf("e2e: send public key: %w", err)
	}
	// 3. Derive the session key.
	shared, err := priv.ECDH(mustEcdhPub(peerPub[:]))
	if err != nil {
		return fmt.Errorf("e2e: derive shared secret: %w", err)
	}
	sessionKey := deriveSessionKey(shared)

	// 4. Send the reader material encrypted with AES-GCM.
	payload := make([]byte, 0, len(as)+len(ownerPub))
	payload = append(payload, as...)
	payload = append(payload, ownerPub...)
	return sendEncrypted(conn, sessionKey, payload)
}

// PeerReceive receives the owner's reader key material over the session
// channel. Returns (AS, ownerPub).
func PeerReceive(conn net.Conn) ([]byte, []byte, error) {
	// 1. Generate an ephemeral key and send its public part.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("e2e: generate key: %w", err)
	}
	if _, err := writeAll(conn, priv.PublicKey().Bytes()); err != nil {
		return nil, nil, fmt.Errorf("e2e: send public key: %w", err)
	}
	// 2. Receive the owner's public key.
	var ownerPub [ephKeySize]byte
	if _, err := io.ReadFull(conn, ownerPub[:]); err != nil {
		return nil, nil, fmt.Errorf("e2e: read owner public key: %w", err)
	}
	shared, err := priv.ECDH(mustEcdhPub(ownerPub[:]))
	if err != nil {
		return nil, nil, fmt.Errorf("e2e: derive shared secret: %w", err)
	}
	sessionKey := deriveSessionKey(shared)

	// 3. Receive and decrypt the reader material.
	payload, err := recvDecrypted(conn, sessionKey)
	if err != nil {
		return nil, nil, err
	}
	if len(payload) != 64 {
		return nil, nil, fmt.Errorf("e2e: unexpected reader material length %d", len(payload))
	}
	return payload[:32], payload[32:], nil
}

func deriveSessionKey(shared []byte) []byte {
	key, err := hkdf.Key(sha256.New, shared, nil, sharedSecretInfo, 32)
	if err != nil {
		panic(err) // unreachable: fixed output size
	}
	return key
}

func sendEncrypted(conn net.Conn, key, plain []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	if _, err := writeFrame(conn, sealed); err != nil {
		return err
	}
	return nil
}

func recvDecrypted(conn net.Conn, key []byte) ([]byte, error) {
	sealed, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("e2e: short sealed frame")
	}
	nonce, data := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("e2e: decrypt reader material: %w", err)
	}
	return plain, nil
}

// writeFrame sends a big-endian length-prefixed payload.
func writeFrame(conn net.Conn, payload []byte) (int, error) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writeAll(conn, header[:]); err != nil {
		return 0, err
	}
	return writeAll(conn, payload)
}

func readFrame(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("e2e: read frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > 1<<20 {
		return nil, fmt.Errorf("e2e: frame too large: %d", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("e2e: read frame payload: %w", err)
	}
	return buf, nil
}

func writeAll(conn net.Conn, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func mustEcdhPub(b []byte) *ecdh.PublicKey {
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		panic(err) // negotiated size, unreachable
	}
	return pub
}
