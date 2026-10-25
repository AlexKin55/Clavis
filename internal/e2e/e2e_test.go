package e2e

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// startRelay starts a RelayServer on a random port and serves it.
func startRelay(t *testing.T) *RelayServer {
	t.Helper()
	srv, err := NewRelayServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.Serve()
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// TestRelayPair verifies raw bytes flow between two relay peers in both
// directions.
func TestRelayPair(t *testing.T) {
	srv := startRelay(t)

	deadline := time.Now().Add(5 * time.Second)
	ownerConn, err := Dial(srv.Addr(), "sess-1", RoleOwner, "ag-owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })
	peerConn, err := Dial(srv.Addr(), "sess-1", RolePeer, "ag-peer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerConn.Close() })

	// Owner -> peer.
	toPeer := []byte("hello from owner")
	if _, err := ownerConn.Write(toPeer); err != nil {
		t.Fatal(err)
	}
	if err := peerConn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	gotPeer := make([]byte, len(toPeer))
	if _, err := io.ReadFull(peerConn, gotPeer); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(gotPeer, toPeer) {
		t.Errorf("peer payload mismatch: %q", gotPeer)
	}

	// Peer -> owner.
	toOwner := []byte("reply from peer")
	if _, err := peerConn.Write(toOwner); err != nil {
		t.Fatal(err)
	}
	if err := ownerConn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	gotOwner := make([]byte, len(toOwner))
	if _, err := io.ReadFull(ownerConn, gotOwner); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if !bytes.Equal(gotOwner, toOwner) {
		t.Errorf("owner payload mismatch: %q", gotOwner)
	}
}

// TestKeyShareOverRelay verifies the full e2e exchange: the owner sends
// AS and its public key directly to the peer through the relay; both end
// points derive the same session key and the relay never sees the plain.
func TestKeyShareOverRelay(t *testing.T) {
	srv := startRelay(t)

	as := bytes.Repeat([]byte{0xAB}, 32)
	ownerPub := bytes.Repeat([]byte{0xCD}, 32)

	errs := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		conn, err := Dial(srv.Addr(), "sess-ks", RoleOwner, "ag-owner")
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = conn.Close() }()
		errs <- OwnerShare(conn, as, ownerPub)
	}()

	go func() {
		defer wg.Done()
		conn, err := Dial(srv.Addr(), "sess-ks", RolePeer, "ag-peer")
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = conn.Close() }()
		gotAS, gotPub, err := PeerReceive(conn)
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(gotAS, as) {
			errs <- &testErr{"AS mismatch"}
			return
		}
		if !bytes.Equal(gotPub, ownerPub) {
			errs <- &testErr{"owner pub mismatch"}
			return
		}
		errs <- nil
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("key share failed: %v", err)
		}
	}
}

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }

// TestFrameRoundTrip verifies the length-prefixed framing helpers.
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

// TestRelayWaiterTimeout verifies the waiting slot auto-expires.
func TestRelayWaiterTimeout(t *testing.T) {
	srv := startRelay(t)
	conn, err := Dial(srv.Addr(), "sess-lone", RoleOwner, "ag-lone")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 1)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatal("expected timeout, got data")
	}
}
