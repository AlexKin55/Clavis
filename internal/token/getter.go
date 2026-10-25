package token

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/clavis/clavis/internal/crypto"
)

// blobSuffix is appended to the (canonical) document UUID for the
// token-wrapped key blob stored on disk.
const blobSuffix = ".wkey"

// Getter adapts an Unwrapper (hardware token) to crypto.KeyGetter.
//
// For a document without a blob yet, a fresh 32-byte key is generated and
// immediately wrapped by the token, so the raw key never exists on disk.
// The blob can only be unwrapped inside a logged-in token session; without
// the token the document is unreachable (the "token required" policy).
type Getter struct {
	unwrapper Unwrapper
	blobsDir  string
}

// NewGetter creates the token-backed key getter.
func NewGetter(unwrapper Unwrapper, blobsDir string) *Getter {
	return &Getter{unwrapper: unwrapper, blobsDir: blobsDir}
}

// LoadKey implements crypto.KeyGetter.
func (g *Getter) LoadKey(_ context.Context, docUUID [16]byte) ([]byte, error) {
	blobPath := filepath.Join(g.blobsDir, crypto.UUIDString(docUUID)+blobSuffix)

	blob, err := os.ReadFile(blobPath)
	if err == nil {
		key, err := g.unwrapper.Unwrap(blob)
		if err != nil {
			return nil, fmt.Errorf("token: unwrap key for %s: %w", crypto.UUIDString(docUUID), err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("token: unwrapped key length %d, want 32", len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("token: read blob %q: %w", blobPath, err)
	}

	// First use of this document: generate and wrap the key on the token.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("token: generate key: %w", err)
	}
	blob, err = g.unwrapper.Wrap(raw)
	if err != nil {
		return nil, fmt.Errorf("token: wrap key for %s: %w", crypto.UUIDString(docUUID), err)
	}
	dir := filepath.Dir(blobPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("token: create blobs dir: %w", err)
	}
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		return nil, fmt.Errorf("token: store blob %q: %w", blobPath, err)
	}
	return raw, nil
}

// BlobPath returns the expected blob path for the document (used by tests).
func BlobPath(blobsDir string, docUUID [16]byte) string {
	return filepath.Join(blobsDir, crypto.UUIDString(docUUID)+blobSuffix)
}
