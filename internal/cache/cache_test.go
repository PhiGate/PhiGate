package cache

import (
	"testing"
	"time"
)

func TestKeyCollapsesIdenticalTemplates(t *testing.T) {
	// The whole cost argument rests on this: two alerts that compress to the
	// same template must produce the same key.
	a := Key("gpt-4o", []string{"disk full on <V1> at <V2>"}, nil, nil)
	b := Key("gpt-4o", []string{"disk full on <V1> at <V2>"}, nil, nil)
	if a != b {
		t.Fatal("identical templates produced different keys")
	}

	c := Key("gpt-4o", []string{"disk full on <V1> at <V3>"}, nil, nil)
	if a == c {
		t.Error("different templates must not share a key")
	}
	d := Key("phi4-mini", []string{"disk full on <V1> at <V2>"}, nil, nil)
	if a == d {
		t.Error("the model must be part of the key")
	}
}

func TestKeyIncludesSamplingParameters(t *testing.T) {
	temp := 0.9
	max := 100
	base := Key("gpt-4o", []string{"x"}, nil, nil)
	if Key("gpt-4o", []string{"x"}, &temp, nil) == base {
		t.Error("temperature must affect the key")
	}
	if Key("gpt-4o", []string{"x"}, nil, &max) == base {
		t.Error("max_tokens must affect the key")
	}
}

func TestGetPutAndExpiry(t *testing.T) {
	c := New(50*time.Millisecond, 10)
	c.Put("k", Entry{Content: "masked answer <V1>", PromptTokens: 100, CompletionTokens: 20})

	got, ok := c.Get("k")
	if !ok || got.Content != "masked answer <V1>" {
		t.Fatalf("expected a hit, got %+v ok=%v", got, ok)
	}
	if s := c.Stats(); s.Hits != 1 || s.TokensAvoided != 120 {
		t.Errorf("stats = %+v, want 1 hit and 120 tokens avoided", s)
	}

	time.Sleep(60 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("entry should have expired")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(time.Minute, 2)
	c.Put("a", Entry{Content: "a"})
	c.Put("b", Entry{Content: "b"})
	_, _ = c.Get("a") // a is now most-recently used
	c.Put("c", Entry{Content: "c"})

	if _, ok := c.Get("b"); ok {
		t.Error("b was least recently used and should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("a was recently used and should have survived")
	}
}

func TestDisabledCacheNeverStores(t *testing.T) {
	c := New(time.Minute, 0)
	c.Put("k", Entry{Content: "x"})
	if _, ok := c.Get("k"); ok {
		t.Error("a disabled cache must not serve entries")
	}
	if c.Stats().Enabled {
		t.Error("stats should report the cache as disabled")
	}
}
