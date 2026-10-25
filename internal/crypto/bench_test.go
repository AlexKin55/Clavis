package crypto

import (
	"crypto/rand"
	"sync"
	"testing"
)

const benchSize = 1 << 20 // 1 MiB

func benchCtr(t *testing.B, workers int) {
	t.Helper()
	key := make([]byte, 32)
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	c, err := NewAesCtr(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, benchSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		if workers <= 1 {
			if _, err := c.Encrypt(data, 0); err != nil {
				t.Fatal(err)
			}
			continue
		}
		// Parallel CTR: split the payload into block-aligned chunks.
		chunk := benchSize / workers
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			w := w
			go func() {
				defer wg.Done()
				off := w * chunk
				_, _ = c.Encrypt(data[off:off+chunk], int64(off))
			}()
		}
		wg.Wait()
	}
}

func BenchmarkAesCtrEncrypt1MB(t *testing.B)   { benchCtr(t, 1) }
func BenchmarkAesCtrEncrypt1MBx4(t *testing.B) { benchCtr(t, 4) }
func BenchmarkAesCtrEncrypt1MBx8(t *testing.B) { benchCtr(t, 8) }
