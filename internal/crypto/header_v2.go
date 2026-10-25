package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// Mode selects the per-file sharing mode (user choice per document).
type Mode byte

// Sharing modes.
const (
	// ModeProxy routes the reader key through the Key Server.
	ModeProxy Mode = 0x01
	// ModeE2E shares the reader key over a direct agent-to-agent channel.
	ModeE2E Mode = 0x02
)

// v2 header constants.
const (
	// HeaderV2Size is the fixed size of the version 2 header.
	HeaderV2Size = 88
	// WrappedKeySize is the AES-KeyWrap output for a 32-byte document key.
	WrappedKeySize = 40
)

// v2 header field offsets.
const (
	v2OffMagic     = 0
	v2OffVersion   = 4
	v2OffAlgorithm = 5
	v2OffMode      = 6
	v2OffOwner     = 8
	v2OffUUID      = 24
	v2OffNonce     = 40
	v2OffWrapped   = 48
)

// HeaderV2 is the version 2 protected-file header:
//
//	[magic 4][ver 1][algo 1][mode 1][res 1][owner_key_id 16]
//	[uuid 16][nonce 8][wrapped_dk 40]
//
// wrapped_dk = AES-KeyWrap(AS, DK), where AS is the agent's reader key
// registered on the server and DK is the per-document key. The signature
// over (header || SHA-256(ciphertext)) lives in the metadata block that
// follows the header (see metadata.go).
type HeaderV2 struct {
	Version    byte
	Algorithm  AlgorithmID
	Mode       Mode
	OwnerKeyID [16]byte
	UUID       [16]byte
	Nonce      [8]byte
	WrappedDK  [WrappedKeySize]byte
}

// NewHeaderV2 assembles a version 2 header.
func NewHeaderV2(ownerKeyID, uuid [16]byte, mode Mode, nonce [8]byte, wrappedDK [WrappedKeySize]byte) (*HeaderV2, error) {
	if mode != ModeProxy && mode != ModeE2E {
		return nil, fmt.Errorf("crypto: unknown document mode %d", mode)
	}
	return &HeaderV2{
		Version:    HeaderVersion + 1, // 0x02
		Algorithm:  AlgorithmAes256Ctr,
		Mode:       mode,
		OwnerKeyID: ownerKeyID,
		UUID:       uuid,
		Nonce:      nonce,
		WrappedDK:  wrappedDK,
	}, nil
}

// Encode serializes the header into HeaderV2Size bytes.
func (h *HeaderV2) Encode() []byte {
	buf := make([]byte, HeaderV2Size)
	copy(buf[v2OffMagic:v2OffVersion], MagicBytes)
	buf[v2OffVersion] = h.Version
	buf[v2OffAlgorithm] = byte(h.Algorithm)
	buf[v2OffMode] = byte(h.Mode)
	copy(buf[v2OffOwner:v2OffUUID], h.OwnerKeyID[:])
	copy(buf[v2OffUUID:v2OffNonce], h.UUID[:])
	copy(buf[v2OffNonce:v2OffWrapped], h.Nonce[:])
	copy(buf[v2OffWrapped:], h.WrappedDK[:])
	return buf
}

// ParseHeaderV2 decodes and validates a version 2 header.
func ParseHeaderV2(data []byte) (*HeaderV2, error) {
	if len(data) < HeaderV2Size {
		return nil, fmt.Errorf("crypto: v2 header too short: got %d, want %d", len(data), HeaderV2Size)
	}
	if string(data[v2OffMagic:v2OffVersion]) != MagicBytes {
		return nil, fmt.Errorf("crypto: invalid magic %q", data[v2OffMagic:v2OffVersion])
	}
	if data[v2OffVersion] != HeaderVersion+1 {
		return nil, fmt.Errorf("crypto: unsupported header version %d", data[v2OffVersion])
	}
	algo := AlgorithmID(data[v2OffAlgorithm])
	if !IsKnownAlgorithm(algo) {
		return nil, fmt.Errorf("crypto: unknown algorithm %d", algo)
	}
	mode := Mode(data[v2OffMode])
	if mode != ModeProxy && mode != ModeE2E {
		return nil, fmt.Errorf("crypto: unknown mode %d", mode)
	}

	h := &HeaderV2{
		Version:   data[v2OffVersion],
		Algorithm: algo,
		Mode:      mode,
	}
	copy(h.OwnerKeyID[:], data[v2OffOwner:v2OffUUID])
	copy(h.UUID[:], data[v2OffUUID:v2OffNonce])
	copy(h.Nonce[:], data[v2OffNonce:v2OffWrapped])
	copy(h.WrappedDK[:], data[v2OffWrapped:])
	return h, nil
}

// SignAndSerialize produces the header followed by the signature metadata
// block over (header, ciphertext). The signature is by the owner.
func SignAndSerialize(identity *AgentIdentity, h *HeaderV2, ciphertext []byte) []byte {
	out := h.Encode()
	out = append(out, SignatureBlock(h, identity, ciphertext)...)
	return out
}

// Verify checks the owner signature over (header, ciphertext).
func (h *HeaderV2) Verify(pub ed25519.PublicKey, ciphertext, sigBlock []byte) error {
	sig, err := ParseSignatureBlock(sigBlock)
	if err != nil {
		return err
	}
	payload := signaturePayload(h, ciphertext)
	if !VerifySignature(pub, payload, sig) {
		return fmt.Errorf("crypto: document signature verification failed")
	}
	return nil
}

// signaturePayload is header || SHA-256(ciphertext); signing a digest keeps
// signature verification cheap.
func signaturePayload(h *HeaderV2, ciphertext []byte) []byte {
	header := h.Encode()
	digest := sha256.Sum256(ciphertext)
	payload := make([]byte, 0, len(header)+sha256.Size)
	payload = append(payload, header...)
	payload = append(payload, digest[:]...)
	return payload
}
