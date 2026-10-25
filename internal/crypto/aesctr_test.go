package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestAesCtrRoundTrip encrypts and decrypts data of various lengths.
func TestAesCtrRoundTrip(t *testing.T) {
	key := testKey(t)
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatalf("NewAesCtr() error: %v", err)
	}

	lengths := []int{0, 1, 15, 16, 17, 100, 1000, 4096, 1024 * 1024}
	for _, n := range lengths {
		t.Run("len="+strconv.Itoa(n), func(t *testing.T) {
			plain := make([]byte, n)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}

			enc, err := c.Encrypt(plain, 0)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}
			if len(enc) != len(plain) {
				t.Errorf("Encrypt() length = %d, want %d", len(enc), len(plain))
			}

			dec, err := c.Decrypt(enc, 0)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}
			if !bytes.Equal(dec, plain) {
				t.Errorf("round trip mismatch for %d bytes", n)
			}

			// Encrypting ciphertext again must yield the original plaintext.
			twice, err := c.Encrypt(enc, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(twice, plain) {
				t.Errorf("double encryption mismatch for %d bytes", n)
			}
		})
	}
}

// TestAesCtrRandomAccess decrypts an arbitrary subrange of a file without
// touching the preceding bytes.
func TestAesCtrRandomAccess(t *testing.T) {
	key := testKey(t)
	nonce := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}

	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	const size = 1000
	plain := make([]byte, size)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	enc, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}

	start, end := 123, 456 // not block aligned
	sub, err := c.Decrypt(enc[start:end], int64(start))
	if err != nil {
		t.Fatalf("Decrypt(subrange) error: %v", err)
	}
	if !bytes.Equal(sub, plain[start:end]) {
		t.Error("random access subrange mismatch")
	}
}

// TestAesCtrChunkedEquivalence verifies that processing data in arbitrary
// chunks with matching offsets yields the same ciphertext as one pass.
func TestAesCtrChunkedEquivalence(t *testing.T) {
	key := testKey(t)
	nonce := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}

	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	const size = 1000
	plain := make([]byte, size)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	whole, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}

	chunks := []struct {
		start, end int
	}{{0, 200}, {200, 500}, {500, 500}, {500, 1000}}
	var combined []byte
	for _, ch := range chunks {
		part, err := c.Encrypt(plain[ch.start:ch.end], int64(ch.start))
		if err != nil {
			t.Fatal(err)
		}
		combined = append(combined, part...)
	}
	if !bytes.Equal(combined, whole) {
		t.Error("chunked processing mismatch vs single pass")
	}
}

// TestAesCtrMatchesStdlib cross-checks our keystream against
// cipher.NewCTR from the standard library for a zero offset.
func TestAesCtrMatchesStdlib(t *testing.T) {
	key := testKey(t)
	nonce := [8]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}

	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, 4096)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	got, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aesBlockSize)
	copy(iv[0:8], nonce[:])
	stream := cipher.NewCTR(block, iv)

	want := make([]byte, len(plain))
	stream.XORKeyStream(want, plain)

	if !bytes.Equal(got, want) {
		t.Error("keystream mismatch with cipher.NewCTR")
	}
}

// TestAesCtrKeyLengths verifies accepted and rejected key sizes.
func TestAesCtrKeyLengths(t *testing.T) {
	nonce := [8]byte{}
	for _, n := range []int{16, 24, 32} {
		if _, err := NewAesCtr(make([]byte, n), nonce); err != nil {
			t.Errorf("NewAesCtr(%d bytes) error: %v", n, err)
		}
	}
	for _, n := range []int{0, 1, 15, 33} {
		if _, err := NewAesCtr(make([]byte, n), nonce); err == nil {
			t.Errorf("NewAesCtr(%d bytes) error = nil, want an error", n)
		}
	}
}

// TestAesCtrNegativeOffset verifies rejection of a negative offset.
func TestAesCtrNegativeOffset(t *testing.T) {
	c, err := NewAesCtr(testKey(t), [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt([]byte("x"), -1); err == nil {
		t.Error("Encrypt(-1) error = nil, want an error")
	}
}

// TestCounterEncoding verifies the nonce || blockIndex counter layout.
func TestCounterEncoding(t *testing.T) {
	nonce := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ctr := counterFor(nonce, 3)

	if !bytes.Equal(ctr[0:8], nonce[:]) {
		t.Errorf("counter[0:8] = %x, want nonce %x", ctr[0:8], nonce)
	}
	if got := binary.BigEndian.Uint64(ctr[8:16]); got != 3 {
		t.Errorf("counter[8:16] = %d, want 3", got)
	}
	if len(ctr) != aesBlockSize {
		t.Errorf("counter length = %d, want %d", len(ctr), aesBlockSize)
	}
}

// TestAesCtrDeterministic verifies that the same key and nonce produce
// the same ciphertext.
func TestAesCtrDeterministic(t *testing.T) {
	key := testKey(t)
	nonce := [8]byte{4, 4, 4, 4, 4, 4, 4, 4}
	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("deterministic test payload")
	a, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encrypt(plain, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two encryptions differ for the same key/nonce")
	}
}
