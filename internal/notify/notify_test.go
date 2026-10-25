package notify

import "testing"

// TestPushRecent verifies basic push/recent semantics and id monotonicity.
func TestPushRecent(t *testing.T) {
	b := NewBus(10)
	if id := b.Push(KindInfo, "first"); id != 1 {
		t.Errorf("first Push id = %d, want 1", id)
	}
	if id := b.Push(KindOffline, "second"); id != 2 {
		t.Errorf("second Push id = %d, want 2", id)
	}

	recent := b.Recent()
	if len(recent) != 2 {
		t.Fatalf("Recent() len = %d, want 2", len(recent))
	}
	if recent[0].Text != "first" || recent[1].Text != "second" {
		t.Errorf("Recent() order = %+v, want chronological", recent)
	}
	if recent[1].Kind != KindOffline {
		t.Errorf("Recent()[1].Kind = %v, want KindOffline", recent[1].Kind)
	}
	if recent[1].ID != 2 {
		t.Errorf("Recent()[1].ID = %d, want 2", recent[1].ID)
	}
}

// TestBusRingOverflow verifies that the bus keeps only the most recent
// notices once the capacity is exhausted.
func TestBusRingOverflow(t *testing.T) {
	b := NewBus(3)
	for i := 0; i < 5; i++ {
		b.Push(KindInfo, "n")
	}
	recent := b.Recent()
	if len(recent) != 3 {
		t.Fatalf("Recent() len = %d, want 3 (ring capacity)", len(recent))
	}
	// IDs must be the three most recent ones, in order.
	if recent[0].ID != 3 || recent[1].ID != 4 || recent[2].ID != 5 {
		t.Errorf("Recent() IDs = [%d %d %d], want [3 4 5]", recent[0].ID, recent[1].ID, recent[2].ID)
	}
}

// TestKindString verifies the machine-readable kind names used by the GUI.
func TestKindString(t *testing.T) {
	cases := []struct {
		kind Kind
		want string
	}{
		{KindInfo, "info"},
		{KindKeyMissing, "key_missing"},
		{KindOffline, "offline"},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("Kind(%d).String() = %q, want %q", tc.kind, got, tc.want)
		}
	}
}
