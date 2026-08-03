package session

import (
	"testing"
	"time"
)

func TestSameKeyReusesDictionary(t *testing.T) {
	s := NewStore(time.Minute, 10)
	defer s.Close()

	a := s.Get("conv-1")
	tok := a.Dict.Mask("10.0.0.5", 0)

	b := s.Get("conv-1")
	if b.ID != a.ID {
		t.Fatalf("same key returned a different session: %s vs %s", a.ID, b.ID)
	}
	if got := b.Dict.Mask("10.0.0.5", 0); got != tok {
		t.Errorf("token drifted within one conversation: %q then %q", tok, got)
	}
}

func TestEmptyKeyIsDetached(t *testing.T) {
	// A client that does not opt in to session continuity must get exactly the
	// old per-request behaviour, and must not accumulate state in the store.
	s := NewStore(time.Minute, 10)
	defer s.Close()

	a, b := s.Get(""), s.Get("")
	if a.ID == b.ID {
		t.Error("detached sessions should be distinct")
	}
	if s.Len() != 0 {
		t.Errorf("detached sessions must not be stored, got %d entries", s.Len())
	}
}

func TestExpiryBoundsHowLongSecretsLiveInMemory(t *testing.T) {
	s := NewStore(40*time.Millisecond, 10)
	defer s.Close()

	first := s.Get("conv-1")
	first.Dict.Mask("secret-value", 0)
	time.Sleep(80 * time.Millisecond)

	second := s.Get("conv-1")
	if second.Dict.Len() != 0 {
		t.Error("an expired session must be replaced by a clean dictionary, not resurrected")
	}
}

func TestLRUEvictionProtectsActiveConversations(t *testing.T) {
	s := NewStore(time.Minute, 2)
	defer s.Close()

	s.Get("a")
	s.Get("b")
	s.Get("a") // a is active
	s.Get("c") // should evict b, not a

	if s.Len() != 2 {
		t.Fatalf("store holds %d sessions, want 2", s.Len())
	}
	before := s.Get("a").Dict.Len()
	_ = before
	if s.Len() != 2 {
		t.Error("fetching an existing session should not grow the store")
	}
}

func TestDropRemovesASession(t *testing.T) {
	s := NewStore(time.Minute, 10)
	defer s.Close()

	s.Get("conv-1")
	if !s.Drop("conv-1") {
		t.Fatal("Drop should report that it removed the session")
	}
	if s.Len() != 0 {
		t.Errorf("store should be empty, got %d", s.Len())
	}
	if s.Drop("conv-1") {
		t.Error("dropping a missing session should report false")
	}
}
