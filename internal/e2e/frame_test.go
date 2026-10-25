package e2e

import (
	"net"
	"testing"
)

// TestFrameRoundTrip verifies the length-prefixed framing helpers (unit
// test, stays next to the implementation).
func TestFrameRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		_, _ = writeFrame(server, []byte("payload-123"))
		_ = server.Close()
	}()

	got, err := readFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload-123" {
		t.Errorf("frame payload = %q", got)
	}
}
