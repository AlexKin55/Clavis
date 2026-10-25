// Package e2e_test contains black-box integration tests for the direct
// (end-to-end) key exchange over the relay.
package e2e_test

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/clavis/clavis/internal/e2e"
)

// startRelay starts a RelayServer on a random port and serves it.
func startRelay(t *testing.T) *e2e.RelayServer {
	t.Helper()
	srv, err := e2e.NewRelayServer("127.0.0.1:0")
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
	ownerConn, err := e2e.Dial(srv.Addr(), "sess-1", e2e.RoleOwner, "ag-owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })
	peerConn, err := e2e.Dial(srv.Addr(), "sess-1", e2e.RolePeer, "ag-peer")
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
// AS and its public key directly to the peer through the relay; the relay
// never sees the plain material.
func TestKeyShareOverRelay(t *testing.T) {
	srv := startRelay(t)

	as := bytes.Repeat([]byte{0xAB}, 32)
	ownerPub := bytes.Repeat([]byte{0xCD}, 32)

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := e2e.Dial(srv.Addr(), "sess-ks", e2e.RoleOwner, "ag-owner")
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = conn.Close() }()
		errs <- e2e.OwnerShare(conn, as, ownerPub)
	}()

	go func() {
		defer wg.Done()
		conn, err := e2e.Dial(srv.Addr(), "sess-ks", e2e.RolePeer, "ag-peer")
		if err != nil {
			errs <- err
			return
		}
		defer func() { _ = conn.Close() }()
		gotAS, gotPub, err := e2e.PeerReceive(conn)
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(gotAS, as) {
			errs <- &keyShareErr{"AS mismatch"}
			return
		}
		if !bytes.Equal(gotPub, ownerPub) {
			errs <- &keyShareErr{"owner pub mismatch"}
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

type keyShareErr struct{ msg string }

func (e *keyShareErr) Error() string { return e.msg }

// TestRelayWaiterTimeout verifies the waiting slot auto-expires.
func TestRelayWaiterTimeout(t *testing.T) {
	srv := startRelay(t)
	conn, err := e2e.Dial(srv.Addr(), "sess-lone", e2e.RoleOwner, "ag-lone")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatal("expected timeout, got data")
	}
}
