// Package session keeps compression sessions alive across the turns of a
// conversation.
//
// PhiGate originally created a fresh session per request. That made the same IP
// address <V1> in one turn and <V4> in the next, so a multi-turn conversation
// referred to the same host by different names and the model lost the thread.
// It also made caching impossible, because no two requests ever produced the
// same compressed text.
//
// Sessions live in memory only and expire: PhiGate's privacy guarantee rests on
// the fact that raw values are never persisted, so this store deliberately has
// no disk or Redis backend.
package session

import (
	"container/list"
	"sync"
	"time"

	"github.com/phigate/phigate/internal/compressor"
)

// Store is a bounded, TTL'd, in-memory map of conversation id -> Session.
// Eviction is LRU so a burst of one-shot requests cannot push out the sessions
// belonging to active conversations.
type Store struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	items map[string]*list.Element
	order *list.List // front = most recently used

	stop chan struct{}
	once sync.Once
}

type entry struct {
	key  string
	sess *compressor.Session
}

// NewStore returns a Store holding at most max sessions for at most ttl each.
// Zero or negative values fall back to defaults (30 minutes, 10k sessions).
func NewStore(ttl time.Duration, max int) *Store {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if max <= 0 {
		max = 10000
	}
	s := &Store{
		ttl:   ttl,
		max:   max,
		items: make(map[string]*list.Element),
		order: list.New(),
		stop:  make(chan struct{}),
	}
	go s.janitor()
	return s
}

// Get returns the session for key, creating it if absent. An empty key means
// "no conversation identity", so a detached single-use session is returned and
// nothing is stored — a client that does not opt in to session continuity gets
// exactly the old per-request behaviour.
func (s *Store) Get(key string) *compressor.Session {
	if key == "" {
		return compressor.NewSession()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[key]; ok {
		e := el.Value.(*entry)
		if time.Since(e.sess.LastUsed()) <= s.ttl {
			s.order.MoveToFront(el)
			e.sess.Touch()
			return e.sess
		}
		// Expired: drop it and fall through to create a fresh one, so a
		// resumed conversation gets a clean dictionary rather than stale
		// mappings whose values may no longer be accurate.
		s.removeElement(el)
	}

	sess := compressor.NewSessionWithID(key)
	el := s.order.PushFront(&entry{key: key, sess: sess})
	s.items[key] = el
	s.evictLocked()
	return sess
}

// Drop removes a session immediately. Exposed so an operator can purge a
// conversation's dictionary on request — the practical answer to "delete the
// data you hold about me".
func (s *Store) Drop(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.items[key]
	if !ok {
		return false
	}
	s.removeElement(el)
	return true
}

// Len reports the number of live sessions.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Close stops the background expiry goroutine.
func (s *Store) Close() {
	s.once.Do(func() { close(s.stop) })
}

func (s *Store) evictLocked() {
	for len(s.items) > s.max {
		if back := s.order.Back(); back != nil {
			s.removeElement(back)
			continue
		}
		return
	}
}

func (s *Store) removeElement(el *list.Element) {
	e := el.Value.(*entry)
	s.order.Remove(el)
	delete(s.items, e.key)
}

// janitor expires idle sessions. Expiry is what bounds how long a dictionary of
// real IPs and credentials sits in memory, so it runs even when the store is
// otherwise untouched.
func (s *Store) janitor() {
	interval := s.ttl / 4
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.expire()
		}
	}
}

func (s *Store) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*entry)
		if time.Since(e.sess.LastUsed()) > s.ttl {
			s.removeElement(el)
		}
		el = prev
	}
}
