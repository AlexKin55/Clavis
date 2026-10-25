package crypto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// maxKeyFileSize limits how much of the key file is read (hex or raw key).
const maxKeyFileSize = 4096

// KeyGetter provides the key material for a document identified by its UUID.
// Later phases will add HTTP (Key Server) and PKCS#11 backed implementations.
type KeyGetter interface {
	// LoadKey returns the key material for the document.
	LoadKey(ctx context.Context, docUUID [16]byte) ([]byte, error)
}

// FileKeyGetter reads the key from a local file.
//
// The file may contain either:
//   - 64 hex characters (32 bytes), or
//   - the raw key bytes (16, 24 or 32 bytes).
//
// The file is read once and cached; LoadKey returns a fresh copy of the key
// on every call.
type FileKeyGetter struct {
	path string

	// cached key material (loaded once).
	once sync.Once
	key  []byte
	err  error
}

// NewFileKeyGetter creates a key getter backed by the given file path.
// The file itself is not touched until the first LoadKey call.
func NewFileKeyGetter(path string) *FileKeyGetter {
	return &FileKeyGetter{path: path}
}

// LoadKey implements KeyGetter.
func (g *FileKeyGetter) LoadKey(_ context.Context, _ [16]byte) ([]byte, error) {
	g.once.Do(func() {
		g.key, g.err = loadKeyFromFile(g.path)
	})
	if g.err != nil {
		return nil, g.err
	}
	out := make([]byte, len(g.key))
	copy(out, g.key)
	return out, nil
}

func loadKeyFromFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: open key file %q: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	buf := make([]byte, maxKeyFileSize+1)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("crypto: read key file %q: %w", path, err)
	}
	if n > maxKeyFileSize {
		return nil, fmt.Errorf("crypto: key file %q is too large", path)
	}
	content := strings.TrimSpace(string(buf[:n]))
	if content == "" {
		return nil, fmt.Errorf("crypto: key file %q is empty", path)
	}

	// Try to parse the content as hex first.
	if decoded, err := hex.DecodeString(content); err == nil {
		if err := validateKeyLen(decoded); err != nil {
			return nil, fmt.Errorf("crypto: key file %q: %w", path, err)
		}
		return decoded, nil
	}

	// Otherwise treat the content as the raw key bytes.
	if err := validateKeyLen(buf[:n]); err != nil {
		return nil, fmt.Errorf("crypto: key file %q: %w", path, err)
	}
	return buf[:n], nil
}

func validateKeyLen(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("aes key must be 16, 24 or 32 bytes, got %d", len(key))
	}
}

// GenerateKeyFile writes a random 32-byte key to the given path in hex form
// (useful for tests and local setups).
func GenerateKeyFile(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("crypto: generate key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return fmt.Errorf("crypto: write key file %q: %w", path, err)
	}
	return nil
}
