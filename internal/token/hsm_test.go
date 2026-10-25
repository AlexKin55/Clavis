package token

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// TestBackendSoftHSM exercises the real PKCS#11 path against an HSM
// (e.g. SoftHSM). It is skipped unless CLAVIS_HSM_MODULE points to a
// PKCS#11 module with an initialized token (pin 0000, label "Clavis"):
//
//	softhsm2-util --init-token --slot 0 --label Clavis --pin 0000 --so-pin 0000
//	CLAVIS_HSM_MODULE=/usr/lib64/softhsm/libsofthsm2.so go test ./internal/token/
func TestBackendSoftHSM(t *testing.T) {
	module := os.Getenv("CLAVIS_HSM_MODULE")
	if module == "" {
		t.Skip("CLAVIS_HSM_MODULE not set; skipping hardware token test")
	}

	backend, err := Open(Config{
		ModulePath:      module,
		TokenLabel:      "Clavis",
		PIN:             "0000",
		WrapKeyLabel:    "clavis-test-wrap",
		GenerateWrapKey: true,
	})
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer func() {
		_ = backend.Close()
	}()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}

	blob, err := backend.Wrap(raw)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if len(blob) == 0 || bytes.Equal(blob, raw) {
		t.Fatal("Wrap() returned an invalid blob")
	}

	got, err := backend.Unwrap(blob)
	if err != nil {
		t.Fatalf("Unwrap() error: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Error("unwrap mismatch")
	}
}
