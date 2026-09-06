// SPDX-License-Identifier: BUSL-1.1

package worm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phigate/phigate/internal/audit"
)

func newSink(t *testing.T, opts Options) (*Sink, string) {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = t.TempDir()
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, opts.Dir
}

func logN(t *testing.T, s *Sink, n int) {
	t.Helper()
	for i := range n {
		s.Log(audit.Event{
			RequestID: "req-" + string(rune('a'+i%26)),
			Tenant:    "team-sre",
			Route:     "local",
			Status:    200,
		})
	}
}

// lines returns every record file's lines, in chain order.
func lines(t *testing.T, dir string) (paths []string, all [][]string) {
	t.Helper()
	segs, err := segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range segs {
		b, err := os.ReadFile(seg)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, seg)
		all = append(all, strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	}
	return paths, all
}

func rewrite(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIntactChainVerifies(t *testing.T) {
	s, dir := newSink(t, Options{CheckpointEvery: 5})
	logN(t, s, 12)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("an untouched chain failed verification: %v", err)
	}
	if rep.Records < 12 {
		t.Errorf("verified %d records, want at least the 12 logged", rep.Records)
	}
	if rep.Checkpoints == 0 {
		t.Error("no checkpoint was written")
	}
	if rep.Dropped != 0 {
		t.Errorf("dropped = %d, want 0", rep.Dropped)
	}
	if rep.Head == "" {
		t.Error("report carries no chain head")
	}
}

// TestAlteringOneByteIsDetected is the claim the package exists for.
func TestAlteringOneByteIsDetected(t *testing.T) {
	s, dir := newSink(t, Options{CheckpointEvery: -1})
	logN(t, s, 6)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	paths, all := lines(t, dir)
	// Change the outcome of the third request — the edit someone would
	// actually make: turn a blocked request into an allowed one.
	var rec Record
	if err := json.Unmarshal([]byte(all[0][2]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Event.Status = 403
	edited, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	all[0][2] = string(edited)
	rewrite(t, paths[0], all[0])

	_, err = Verify(dir)
	var b *Break
	if !errors.As(err, &b) {
		t.Fatalf("an altered record was not detected: %v", err)
	}
	if b.Seq != 3 {
		t.Errorf("break reported at seq %d, want 3", b.Seq)
	}
	if !strings.Contains(b.Reason, "altered") {
		t.Errorf("reason does not say the record was altered: %q", b.Reason)
	}
}

// TestRemovingARecordIsDetected: deletion is the other half. A log you can
// quietly shorten is not an audit trail.
func TestRemovingARecordIsDetected(t *testing.T) {
	s, dir := newSink(t, Options{CheckpointEvery: -1})
	logN(t, s, 6)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	paths, all := lines(t, dir)
	all[0] = append(all[0][:2], all[0][3:]...) // drop the third record
	rewrite(t, paths[0], all[0])

	_, err := Verify(dir)
	var b *Break
	if !errors.As(err, &b) {
		t.Fatalf("a removed record was not detected: %v", err)
	}
	if !strings.Contains(b.Reason, "removed or inserted") {
		t.Errorf("reason does not describe a removal: %q", b.Reason)
	}
}

// TestReplacingTheTailIsDetected: rewriting the end of the log with internally
// consistent records still has to fail, or an attacker could truncate and
// continue. The chain's linkage is what catches it.
func TestReplacingTheTailIsDetected(t *testing.T) {
	s, dir := newSink(t, Options{CheckpointEvery: -1})
	logN(t, s, 6)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	paths, all := lines(t, dir)
	var rec Record
	if err := json.Unmarshal([]byte(all[0][4]), &rec); err != nil {
		t.Fatal(err)
	}
	// A forged record that hashes correctly *for itself* but claims a
	// predecessor it does not have.
	rec.Event.Status = 500
	rec.Prev = strings.Repeat("0", 64)
	rec.Hash = hashOf(rec)
	forged, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	all[0][4] = string(forged)
	rewrite(t, paths[0], all[0])

	_, err = Verify(dir)
	var b *Break
	if !errors.As(err, &b) {
		t.Fatalf("a re-hashed forgery was not detected: %v", err)
	}
	if !strings.Contains(b.Reason, "link") {
		t.Errorf("reason does not describe a broken link: %q", b.Reason)
	}
}

// TestChainSurvivesRestart: a restart must continue the chain. Starting a
// second one would look to a verifier exactly like the log being replaced.
func TestChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	first, _ := newSink(t, Options{Dir: dir, CheckpointEvery: -1})
	logN(t, first, 3)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, _ := newSink(t, Options{Dir: dir, CheckpointEvery: -1})
	logN(t, second, 3)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("chain broken across a restart: %v", err)
	}
	if rep.Records != 6 {
		t.Errorf("verified %d records across the restart, want 6", rep.Records)
	}
}

// TestChainSpansSegments: rotation must not break the linkage, or the chain
// would only ever be as long as one file.
func TestChainSpansSegments(t *testing.T) {
	s, dir := newSink(t, Options{SegmentMaxBytes: 400, CheckpointEvery: -1})
	logN(t, s, 20)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	segs, err := segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(segs))
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("chain broken across segments: %v", err)
	}
	if rep.Records != 20 || rep.Segments != len(segs) {
		t.Errorf("verified %d records over %d segments, want 20 over %d",
			rep.Records, rep.Segments, len(segs))
	}
}

// TestDroppedEventsBecomeAGapRecord: a full queue loses events, and the loss
// has to be inside the chain. A silent jump in sequence numbers is
// indistinguishable from a deletion, which would make the whole exercise
// pointless.
func TestDroppedEventsBecomeAGapRecord(t *testing.T) {
	s, dir := newSink(t, Options{QueueSize: 1, CheckpointEvery: -1})

	// Force drops by filling the queue faster than the writer drains it.
	for range 5000 {
		s.Log(audit.Event{RequestID: "req", Status: 200})
	}
	// One more after the flood, so the writer has a record to attach the gap
	// marker to.
	time.Sleep(50 * time.Millisecond)
	s.Log(audit.Event{RequestID: "last", Status: 200})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatalf("the chain broke while dropping records: %v", err)
	}
	if rep.Dropped == 0 {
		t.Skip("the writer kept up; nothing was dropped on this machine")
	}
	t.Logf("chain intact with %d recorded drops over %d records", rep.Dropped, rep.Records)
}

// TestLogDoesNotBlockWhenTheQueueIsFull: the seam's contract in one assertion.
// An audit destination that stalls must drop, never wait.
func TestLogDoesNotBlockWhenTheQueueIsFull(t *testing.T) {
	s, _ := newSink(t, Options{QueueSize: 1, CheckpointEvery: -1})

	done := make(chan struct{})
	go func() {
		for range 50000 {
			s.Log(audit.Event{RequestID: "req", Status: 200})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Log blocked the caller; the seam requires it to drop instead")
	}
}

// TestPruneRefusesToRemoveARetainedSegment is the half of a retention policy
// that makes it a control rather than a cleanup script.
func TestPruneRefusesToRemoveARetainedSegment(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	s, _ := newSink(t, Options{
		Dir:             dir,
		SegmentMaxBytes: 400,
		CheckpointEvery: -1,
		Retention:       24 * time.Hour,
		now:             func() time.Time { return now },
	})
	logN(t, s, 20)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(before))
	}

	removed, err := s.Prune()
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("Prune removed %v inside the retention period", removed)
	}
	for _, seg := range before {
		retained, err := s.Retained(seg)
		if err != nil {
			t.Fatal(err)
		}
		if !retained {
			t.Errorf("%s reported as not retained one minute after it was written", seg)
		}
	}
}

// TestPruneRemovesExpiredSegments: and the half that makes it a policy.
func TestPruneRemovesExpiredSegments(t *testing.T) {
	base := time.Now()
	clock := base
	dir := t.TempDir()
	s, _ := newSink(t, Options{
		Dir:             dir,
		SegmentMaxBytes: 400,
		CheckpointEvery: -1,
		Retention:       time.Hour,
		now:             func() time.Time { return clock },
	})
	logN(t, s, 20)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	before, _ := segments(dir)
	clock = base.Add(48 * time.Hour) // every segment is now expired

	removed, err := s.Prune()
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("Prune removed nothing well past the retention period")
	}
	// The segment the sink still holds open is never a candidate.
	after, _ := segments(dir)
	if len(after) != len(before)-len(removed) {
		t.Errorf("segments: %d before, %d removed, %d after", len(before), len(removed), len(after))
	}
}

// TestZeroRetentionDeletesNothing: a policy nobody configured must not be
// removing audit records.
func TestZeroRetentionDeletesNothing(t *testing.T) {
	s, dir := newSink(t, Options{SegmentMaxBytes: 400, CheckpointEvery: -1})
	logN(t, s, 20)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := segments(dir)

	removed, err := s.Prune()
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("Prune removed %v with no retention configured", removed)
	}
	after, _ := segments(dir)
	if len(after) != len(before) {
		t.Errorf("segment count changed from %d to %d", len(before), len(after))
	}
}

// TestRecordsCarryNoRawValues: the audit package's rule is that no field can
// hold a customer value, and wrapping its Event must not introduce one.
func TestRecordsCarryNoRawValues(t *testing.T) {
	s, dir := newSink(t, Options{CheckpointEvery: -1})
	s.Log(audit.Event{
		RequestID:  "req-1",
		PromptHash: audit.Hash("disk full on 10.0.0.5"),
		Tenant:     "team-sre",
		Status:     200,
	})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	segs, _ := segments(dir)
	b, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "10.0.0.5") {
		t.Fatalf("a raw value reached the audit chain: %s", b)
	}
}

// TestVerifyOnAnEmptyDirectory: an empty chain is intact, not broken. A fresh
// deployment must not report its audit log as tampered with.
func TestVerifyOnAnEmptyDirectory(t *testing.T) {
	rep, err := Verify(t.TempDir())
	if err != nil {
		t.Fatalf("an empty chain failed verification: %v", err)
	}
	if rep.Records != 0 || rep.Segments != 0 {
		t.Errorf("empty chain reported %d records over %d segments", rep.Records, rep.Segments)
	}
}

func TestHashCoversEveryField(t *testing.T) {
	base := Record{Seq: 1, TS: "2026-01-01T00:00:00Z", Kind: KindEvent, Prev: "abc",
		Event: &audit.Event{RequestID: "r", Status: 200}}
	original := hashOf(base)

	for name, mutate := range map[string]func(r *Record){
		"seq":     func(r *Record) { r.Seq = 2 },
		"ts":      func(r *Record) { r.TS = "2026-01-02T00:00:00Z" },
		"kind":    func(r *Record) { r.Kind = KindGap },
		"prev":    func(r *Record) { r.Prev = "def" },
		"dropped": func(r *Record) { r.Dropped = 7 },
		"event":   func(r *Record) { r.Event = &audit.Event{RequestID: "r", Status: 500} },
	} {
		mutated := base
		mutate(&mutated)
		if hashOf(mutated) == original {
			t.Errorf("changing %s did not change the hash; that field is unprotected", name)
		}
	}
}

// TestSegmentNamesSortChronologically underpins Verify, which walks segments in
// lexical order and would otherwise verify them out of order.
func TestSegmentNamesSortChronologically(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Sink{dir: dir, now: func() time.Time { return base }}
	first := s.newSegmentPath()
	s.now = func() time.Time { return base.Add(time.Second) }
	second := s.newSegmentPath()

	if filepath.Base(first) >= filepath.Base(second) {
		t.Errorf("segment names do not sort chronologically: %q then %q",
			filepath.Base(first), filepath.Base(second))
	}
}
