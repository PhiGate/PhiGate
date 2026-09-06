// SPDX-License-Identifier: BUSL-1.1

package worm

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Report is the outcome of verifying a chain.
type Report struct {
	// Records is how many were read before the chain was found intact or
	// broken, so a report on a broken chain still says how much of it stood.
	Records int
	// Segments is how many files the chain spans.
	Segments int
	// Checkpoints and Dropped summarise the chain's own markers. Dropped is
	// events the gateway lost to a full queue: the chain is intact and some
	// events are genuinely missing, which is a different finding from tampering
	// and has to read as one.
	Checkpoints int
	Dropped     uint64
	// Head is the chain's final hash.
	Head string
	// First and Last bound the chain in time.
	First, Last string
}

// Break describes where verification failed.
//
// It is a value rather than a bare error string because the first question
// after "the log was altered" is always "where", and an auditor needs the
// answer to bound the damage rather than discard the whole log.
type Break struct {
	Segment string
	Line    int
	Seq     uint64
	Reason  string
}

func (b *Break) Error() string {
	return fmt.Sprintf("audit chain broken at %s line %d (seq %d): %s",
		b.Segment, b.Line, b.Seq, b.Reason)
}

// Verify walks every segment in dir and recomputes the chain.
//
// It detects the three things that can be done to an append-only log: changing
// a record, removing one, and inserting one. All three break the linkage, and
// which one it was is visible in the reason.
func Verify(dir string) (Report, error) {
	segs, err := segments(dir)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Segments: len(segs)}

	var prev string
	var wantSeq uint64 = 1

	for _, seg := range segs {
		f, err := os.Open(seg)
		if err != nil {
			return rep, err
		}
		sc := newScanner(f)
		line := 0
		for sc.Scan() {
			line++
			if len(sc.Bytes()) == 0 {
				continue
			}
			var rec Record
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				_ = f.Close()
				return rep, &Break{seg, line, 0, "record is not valid JSON: " + err.Error()}
			}

			if rec.Seq != wantSeq {
				_ = f.Close()
				return rep, &Break{seg, line, rec.Seq, fmt.Sprintf(
					"sequence jumped: expected %d, found %d — %d record(s) removed or inserted",
					wantSeq, rec.Seq, diff(wantSeq, rec.Seq))}
			}
			if rec.Prev != prev {
				_ = f.Close()
				return rep, &Break{seg, line, rec.Seq,
					"does not link to the previous record; the record before it was altered or replaced"}
			}
			if got := hashOf(rec); got != rec.Hash {
				_ = f.Close()
				return rep, &Break{seg, line, rec.Seq,
					"content does not match its own hash; this record was altered"}
			}

			if rep.First == "" {
				rep.First = rec.TS
			}
			rep.Last = rec.TS
			rep.Records++
			switch rec.Kind {
			case KindCheckpoint:
				rep.Checkpoints++
			case KindGap:
				rep.Dropped += rec.Dropped
			}

			prev = rec.Hash
			wantSeq = rec.Seq + 1
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return rep, err
		}
		_ = f.Close()
	}
	rep.Head = prev
	return rep, nil
}

func diff(a, b uint64) uint64 {
	if b > a {
		return b - a
	}
	return a - b
}

// Prune removes segments whose newest record is older than the retention
// period, and refuses to touch anything younger.
//
// The refusal is the point. A retention policy that only deletes is a cleanup
// script; one that also declines to delete is a control, and "records are kept
// for N years and cannot be removed before then" is the sentence a retention
// requirement is actually written in. A zero retention deletes nothing at all,
// because a policy nobody configured should not be removing audit records.
func (s *Sink) Prune() (removed []string, err error) {
	if s.retention <= 0 {
		return nil, nil
	}
	segs, err := segments(s.dir)
	if err != nil {
		return nil, err
	}
	cutoff := s.now().Add(-s.retention)

	// The active segment is never a candidate, whatever its timestamps say.
	s.mu.Lock()
	active := ""
	if s.file != nil {
		active = s.file.Name()
	}
	s.mu.Unlock()

	for _, seg := range segs {
		if seg == active {
			continue
		}
		newest, err := newestRecordTime(seg)
		if err != nil {
			return removed, err
		}
		if newest.IsZero() || newest.After(cutoff) {
			continue // still within retention
		}
		if err := os.Remove(seg); err != nil {
			return removed, err
		}
		removed = append(removed, seg)
	}
	return removed, nil
}

// Retained reports whether a segment is still within the retention period, so
// an operator can be told why a removal was refused rather than only that it
// was.
func (s *Sink) Retained(segment string) (bool, error) {
	if s.retention <= 0 {
		return true, nil
	}
	newest, err := newestRecordTime(segment)
	if err != nil {
		return false, err
	}
	return newest.IsZero() || newest.After(s.now().Add(-s.retention)), nil
}

func newestRecordTime(path string) (time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = f.Close() }()

	var newest time.Time
	sc := newScanner(f)
	for sc.Scan() {
		var rec Record
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.TS); err == nil && ts.After(newest) {
			newest = ts
		}
	}
	return newest, sc.Err()
}
