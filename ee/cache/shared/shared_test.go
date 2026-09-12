// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/phigate/phigate/internal/cache"
)

// fakeBackend is a controllable shared medium.
type fakeBackend struct {
	mu      sync.Mutex
	data    map[string][]byte
	gets    int
	sets    int
	failGe  bool
	failSe  bool
	corrupt bool
}

func newFake() *fakeBackend { return &fakeBackend{data: map[string][]byte{}} }

func (f *fakeBackend) Get(_ context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.failGe {
		return nil, false, errors.New("backend down")
	}
	if f.corrupt {
		return []byte("{not json"), true, nil
	}
	v, ok := f.data[key]
	return v, ok, nil
}

func (f *fakeBackend) Set(_ context.Context, key string, val []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	if f.failSe {
		return errors.New("backend down")
	}
	f.data[key] = val
	return nil
}

func (f *fakeBackend) Close() error { return nil }

func localCache(t *testing.T) cache.Store {
	t.Helper()
	return cache.New(time.Minute, 100)
}

func entry() cache.Entry {
	return cache.Entry{
		Content: "restart the <V1> service", Model: "gpt-4o", Route: "cloud",
		PromptTokens: 120, CompletionTokens: 40,
	}
}

// TestASecondReplicaDoesNotPayForTheFirstsTemplate is the feature. Two stores
// stand in for two pods sharing one backend.
func TestASecondReplicaDoesNotPayForTheFirstsTemplate(t *testing.T) {
	be := newFake()
	podA := New(localCache(t), be, Options{})
	podB := New(localCache(t), be, Options{})

	podA.Put("k1", entry())

	got, ok := podB.Get("k1")
	if !ok {
		t.Fatal("the second replica missed a template the first had already paid for")
	}
	if got.Content != entry().Content {
		t.Errorf("content = %q, want %q", got.Content, entry().Content)
	}
	if podB.SharedStats().Hits != 1 {
		t.Errorf("shared hits = %d, want 1", podB.SharedStats().Hits)
	}
}

// TestASharedHitIsPromotedLocally. The second lookup on the same pod must not
// go back over the network.
func TestASharedHitIsPromotedLocally(t *testing.T) {
	be := newFake()
	podA := New(localCache(t), be, Options{})
	podB := New(localCache(t), be, Options{})
	podA.Put("k1", entry())

	if _, ok := podB.Get("k1"); !ok {
		t.Fatal("first lookup missed")
	}
	gets := be.gets
	if _, ok := podB.Get("k1"); !ok {
		t.Fatal("second lookup missed")
	}
	if be.gets != gets {
		t.Errorf("a promoted entry went back to the backend: %d extra get(s)", be.gets-gets)
	}
}

// TestALocalHitNeverTouchesTheBackend.
func TestALocalHitNeverTouchesTheBackend(t *testing.T) {
	be := newFake()
	s := New(localCache(t), be, Options{})
	s.Put("k1", entry())
	be.gets = 0

	if _, ok := s.Get("k1"); !ok {
		t.Fatal("local hit missed")
	}
	if be.gets != 0 {
		t.Errorf("a local hit made %d backend call(s)", be.gets)
	}
}

// TestAnOutageIsAMissNotAFailure. A shared cache that can fail a request is a
// new single point of failure bolted onto the request path. The worst outcome
// of treating an outage as a miss is the bill the community edition pays.
func TestAnOutageIsAMissNotAFailure(t *testing.T) {
	be := newFake()
	be.failGe, be.failSe = true, true
	s := New(localCache(t), be, Options{})

	s.Put("k1", entry()) // must not panic, must still populate locally
	if _, ok := s.Get("k1"); !ok {
		t.Error("a backend outage lost an entry the local tier was holding")
	}
	if _, ok := s.Get("absent"); ok {
		t.Error("a failing backend produced a hit")
	}
	if s.SharedStats().Errors == 0 {
		t.Error("backend errors were not counted; a tier doing nothing must be visible")
	}
}

// TestAnUnreadableValueIsTreatedAsAbsent covers version skew or a foreign
// writer in the same keyspace.
func TestAnUnreadableValueIsTreatedAsAbsent(t *testing.T) {
	be := newFake()
	be.corrupt = true
	s := New(localCache(t), be, Options{})

	if _, ok := s.Get("k1"); ok {
		t.Error("unparseable bytes were returned as a cache hit")
	}
	if s.SharedStats().Errors != 1 {
		t.Errorf("errors = %d, want 1", s.SharedStats().Errors)
	}
}

// TestPurgeLeavesTheSharedTierAlone. Purge reclaims local memory after a rule
// change; the shared entries are unreachable rather than wrong, because a new
// compression hashes to a new key, and flushing a store this process does not
// own would be the wrong trade.
func TestPurgeLeavesTheSharedTierAlone(t *testing.T) {
	be := newFake()
	podA := New(localCache(t), be, Options{})
	podB := New(localCache(t), be, Options{})
	podA.Put("k1", entry())

	podA.Purge()

	if _, ok := podB.Get("k1"); !ok {
		t.Error("one replica's purge emptied the shared tier for every other replica")
	}
}

// TestOnlyTheMaskedAnswerIsPublished. The tier must not widen what the cache
// holds: an entry is pre-hydration and its key is a digest, which is what makes
// sharing it a different question from sharing the session dictionary.
func TestOnlyTheMaskedAnswerIsPublished(t *testing.T) {
	be := newFake()
	s := New(localCache(t), be, Options{Prefix: "pg:"})
	s.Put("digest-key", entry())

	be.mu.Lock()
	defer be.mu.Unlock()
	for k, v := range be.data {
		if !strings.HasPrefix(k, "pg:") {
			t.Errorf("key %q ignored the configured prefix", k)
		}
		body := string(v)
		for _, forbidden := range []string{"10.24.8.19", "api.internal.corp", "password"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("an unmasked value reached the shared tier: %q in %s", forbidden, body)
			}
		}
		// Decode rather than match on the wire bytes: encoding/json escapes
		// "<" to \u003c, so a substring check for the placeholder fails on an
		// entry that carries it perfectly well.
		var stored cache.Entry
		if err := json.Unmarshal(v, &stored); err != nil {
			t.Fatalf("stored value does not decode: %v", err)
		}
		if !strings.Contains(stored.Content, "<V1>") {
			t.Errorf("the stored answer is not the pre-hydration one: %q", stored.Content)
		}
	}
}

// TestRedisBackendRoundTrips exercises the real client against an in-process
// server, so the Redis path is tested rather than merely written.
func TestRedisBackendRoundTrips(t *testing.T) {
	srv := miniredis.RunT(t)
	be, err := NewRedis(RedisOptions{Addr: srv.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	if err := be.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if _, ok, err := be.Get(ctx, "absent"); err != nil || ok {
		t.Errorf("absent key returned ok=%v err=%v, want false/nil", ok, err)
	}
	if err := be.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	val, ok, err := be.Get(ctx, "k")
	if err != nil || !ok || string(val) != "v" {
		t.Errorf("get = %q ok=%v err=%v", val, ok, err)
	}

	// TTL is honoured, so a stale template does not outlive its rules forever.
	srv.FastForward(2 * time.Minute)
	if _, ok, _ := be.Get(ctx, "k"); ok {
		t.Error("an entry outlived its TTL")
	}
}

// TestTwoStoresOverRealRedis is the end-to-end shape: two pods, one server.
func TestTwoStoresOverRealRedis(t *testing.T) {
	srv := miniredis.RunT(t)
	mk := func() *Store {
		be, err := NewRedis(RedisOptions{Addr: srv.Addr()})
		if err != nil {
			t.Fatal(err)
		}
		return New(localCache(t), be, Options{Prefix: "pg:", TTL: time.Minute})
	}
	podA, podB := mk(), mk()
	defer func() { _ = podA.Close(); _ = podB.Close() }()

	podA.Put("shape-digest", entry())
	got, ok := podB.Get("shape-digest")
	if !ok {
		t.Fatal("the second pod missed what the first published")
	}
	if got.PromptTokens != 120 || got.Route != "cloud" {
		t.Errorf("entry did not survive the round trip: %+v", got)
	}
}
