// SPDX-License-Identifier: BUSL-1.1

// Package worm is an append-only, tamper-evident audit sink.
//
// # What it adds over writing JSON lines to a file
//
// The community edition's audit log answers "what happened". An ISMS, FISC or
// APPI audit asks a second question the first cannot: "how do you know this
// record was not edited afterwards?" A file anyone with write access can open
// in an editor has no answer, and "we ship it to a log pipeline" answers for
// the copy, not for the original.
//
// Every record here carries the hash of the record before it, so the log is a
// chain rather than a pile. Changing one byte of one record — or removing a
// record, or inserting one — breaks the linkage from that point on, and
// verification reports where. It does not prevent tampering; nothing running on
// the same machine as the file can. It makes tampering *evident*, which is what
// an auditor is actually asking for, and it is the property that survives being
// stated in a procurement questionnaire.
//
// # What it deliberately does not do
//
// It does not hold up the request path. audit.Sink's contract is that an
// implementation "must not block the request path; an audit destination that
// stalls must drop or buffer, never wait", so writes go through a bounded queue
// and a background writer. When the queue is full records are dropped — and the
// chain records that they were, see the gap marker below, because a silent gap
// is indistinguishable from a deletion and would make the whole exercise
// pointless.
package worm

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phigate/phigate/internal/audit"
)

// Kind distinguishes the three things a chain can contain.
type Kind string

const (
	// KindEvent is an ordinary gateway decision.
	KindEvent Kind = "event"
	// KindCheckpoint anchors the chain head periodically, so a verifier can
	// confirm a prefix without reading to the end and an operator has
	// something short to copy somewhere the gateway cannot reach.
	KindCheckpoint Kind = "checkpoint"
	// KindGap records that events were dropped because the queue was full.
	//
	// It exists so that loss is inside the chain rather than a hole in it. An
	// unexplained jump in sequence numbers is exactly what a deletion looks
	// like; a signed count of what was lost is not.
	KindGap Kind = "gap"
)

// Record is one line of the log.
//
// Field order is the hashed order, so it is also load-bearing: Hash covers
// every field above it. Nothing here can hold a raw value, because Event
// cannot — see the audit package's own doc.
type Record struct {
	Seq     uint64       `json:"seq"`
	TS      string       `json:"ts"`
	Kind    Kind         `json:"kind"`
	Prev    string       `json:"prev"`
	Event   *audit.Event `json:"event,omitempty"`
	Dropped uint64       `json:"dropped,omitempty"`
	Hash    string       `json:"hash"`
}

// Options configures a Sink.
type Options struct {
	// Dir is the directory the segments live in.
	Dir string
	// QueueSize bounds the records held between the request path and the
	// writer. Zero uses a default.
	QueueSize int
	// CheckpointEvery writes an anchor after this many records. Zero uses a
	// default; negative disables checkpoints.
	CheckpointEvery int
	// SegmentMaxBytes rotates to a new segment past this size. Zero uses a
	// default.
	SegmentMaxBytes int64
	// Retention is how long a segment must be kept. Prune refuses to remove
	// one younger than this. Zero means keep everything, which is the safe
	// default: a retention policy nobody set should not delete anything.
	Retention time.Duration

	// now is injectable for tests.
	now func() time.Time
}

// Sink implements audit.Sink.
type Sink struct {
	dir             string
	checkpointEvery int
	segmentMax      int64
	retention       time.Duration
	now             func() time.Time

	queue   chan Record
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Uint64

	// Written only by the writer goroutine.
	mu      sync.Mutex
	file    *os.File
	buf     *bufio.Writer
	written int64
	seq     uint64
	head    string
	sinceCP int
	// rotations disambiguates two segments created within the same timestamp.
	// The name carries the time so that lexical order is chronological order,
	// and a timestamp alone is not unique enough to rely on: two rotations
	// inside one clock tick produced the same name, so the second reopened the
	// first instead of starting a segment.
	rotations uint64
}

// Compile-time proof that the WORM sink satisfies the seam it substitutes.
var _ audit.Sink = (*Sink)(nil)

const (
	defaultQueueSize       = 4096
	defaultCheckpointEvery = 1000
	defaultSegmentMax      = 64 << 20
)

// New opens or resumes a chain in dir.
//
// Resuming matters: a restart must continue the existing chain rather than
// start a second one, or every restart would look to a verifier exactly like
// the log having been replaced.
func New(opts Options) (*Sink, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("worm: Dir is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("worm: create %s: %w", opts.Dir, err)
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.CheckpointEvery == 0 {
		opts.CheckpointEvery = defaultCheckpointEvery
	}
	if opts.SegmentMaxBytes <= 0 {
		opts.SegmentMaxBytes = defaultSegmentMax
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	s := &Sink{
		dir:             opts.Dir,
		checkpointEvery: opts.CheckpointEvery,
		segmentMax:      opts.SegmentMaxBytes,
		retention:       opts.Retention,
		now:             opts.now,
		queue:           make(chan Record, opts.QueueSize),
		done:            make(chan struct{}),
	}

	seq, head, err := resume(opts.Dir)
	if err != nil {
		return nil, err
	}
	s.seq, s.head = seq, head

	if err := s.openSegment(); err != nil {
		return nil, err
	}
	go s.run()
	return s, nil
}

// Enabled reports that events are being written.
func (s *Sink) Enabled() bool { return s != nil && !s.closed.Load() }

// Log queues one event. It never blocks and never returns an error, because the
// caller is a request handler that has nothing useful to do with either.
func (s *Sink) Log(e audit.Event) {
	if !s.Enabled() {
		return
	}
	select {
	case s.queue <- Record{Kind: KindEvent, Event: &e}:
	default:
		// The queue is full. Losing the record is bad; blocking the request
		// path is worse, and the seam says so. The loss is counted and the
		// next write records it in the chain.
		s.dropped.Add(1)
	}
}

// Dropped reports how many events were lost to a full queue. It is surfaced as
// a metric so a deployment cannot quietly stop auditing under load.
func (s *Sink) Dropped() uint64 { return s.dropped.Load() }

// Close drains the queue and closes the current segment.
func (s *Sink) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.queue)
	<-s.done

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf != nil {
		if err := s.buf.Flush(); err != nil {
			return err
		}
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// run is the single writer. Everything that mutates the chain happens here, so
// the chain has one order and it is the order records were accepted in.
func (s *Sink) run() {
	defer close(s.done)
	for rec := range s.queue {
		if n := s.dropped.Swap(0); n > 0 {
			_ = s.append(Record{Kind: KindGap, Dropped: n})
		}
		_ = s.append(rec)

		s.sinceCP++
		if s.checkpointEvery > 0 && s.sinceCP >= s.checkpointEvery {
			s.sinceCP = 0
			_ = s.append(Record{Kind: KindCheckpoint})
		}
	}
}

// append stamps, hashes, links and writes one record.
func (s *Sink) append(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	rec.Seq = s.seq
	rec.TS = s.now().UTC().Format(time.RFC3339Nano)
	rec.Prev = s.head
	rec.Hash = hashOf(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if s.written+int64(len(line)) > s.segmentMax {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := s.buf.Write(line)
	s.written += int64(n)
	if err != nil {
		return err
	}
	// Flushed per record rather than per batch. A buffered audit record lost to
	// a crash is a record of something that did happen, and the chain would
	// show the gap without being able to say what was in it.
	if err := s.buf.Flush(); err != nil {
		return err
	}
	s.head = rec.Hash
	return nil
}

// hashOf computes a record's hash over every field except the hash itself.
//
// The fields are joined with a separator that cannot occur in any of them, so
// no two different records can produce the same input — a length-extension of
// one field into the next is the classic way a naive concatenation is forged.
func hashOf(rec Record) string {
	h := sha256.New()
	writeField := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	writeField(fmt.Sprintf("%d", rec.Seq))
	writeField(rec.TS)
	writeField(string(rec.Kind))
	writeField(rec.Prev)
	writeField(fmt.Sprintf("%d", rec.Dropped))
	if rec.Event != nil {
		// json.Marshal on a struct emits fields in declaration order, so this
		// is deterministic for a given build. Maps inside Event are sorted by
		// encoding/json. Both properties are asserted by the round-trip test.
		b, _ := json.Marshal(rec.Event)
		writeField(string(b))
	} else {
		writeField("")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// openSegment opens the newest segment for appending, or starts a new one.
func (s *Sink) openSegment() error {
	segs, err := segments(s.dir)
	if err != nil {
		return err
	}
	var path string
	if len(segs) > 0 {
		path = segs[len(segs)-1]
	} else {
		path = s.newSegmentPath()
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("worm: open segment: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	s.file, s.buf, s.written = f, bufio.NewWriter(f), info.Size()
	return nil
}

func (s *Sink) rotateLocked() error {
	if err := s.buf.Flush(); err != nil {
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(s.newSegmentPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.file, s.buf, s.written = f, bufio.NewWriter(f), 0
	return nil
}

func (s *Sink) newSegmentPath() string {
	s.rotations++
	return filepath.Join(s.dir, fmt.Sprintf("audit-%s-%010d.jsonl",
		s.now().UTC().Format("20060102T150405.000000000"), s.rotations))
}

// segments lists the chain's files in order. The name carries the creation
// time, so lexical order is chronological order.
func segments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "audit-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

// resume reads the existing chain's head so a restart continues it.
func resume(dir string) (seq uint64, head string, err error) {
	segs, err := segments(dir)
	if err != nil {
		return 0, "", err
	}
	if len(segs) == 0 {
		return 0, "", nil
	}
	last := segs[len(segs)-1]
	f, err := os.Open(last)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()

	sc := newScanner(f)
	for sc.Scan() {
		var rec Record
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		seq, head = rec.Seq, rec.Hash
	}
	return seq, head, sc.Err()
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	return sc
}
