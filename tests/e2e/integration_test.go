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

// TestKeyShareOverRelay verifies the full e2e exchange (including the
// relay pairing): the owner sends
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
