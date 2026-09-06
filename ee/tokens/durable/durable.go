// SPDX-License-Identifier: BUSL-1.1

// Package durable is a token ledger that survives a restart.
//
// # The gap it closes
//
// internal/tokens says of the community ledger that it is "honest for a PoC and
// wrong for a production quota: a rolling update or a crash resets every
// tenant's consumption to zero, so a monthly hard limit stops being a limit."
// That is the whole of this package's reason to exist. A monthly budget backed
// by memory is not a budget; it is a budget per deployment lifetime, and a
// customer deploying weekly has twelve times the allowance they were sold.
//
// # Why writes are batched
//
// bbolt fsyncs on commit. A transaction per request would put a disk flush in
// the request path of a gateway whose whole pitch is latency, so consumption is
// accumulated in memory and flushed on an interval and at close.
//
// The cost is bounded and stated rather than hidden: a crash loses at most one
// flush interval of accounting, so a tenant may come back with slightly less
// spend recorded than it made. Under-counting after a crash is the right
// direction to be wrong in — the alternative on offer is not "exact", it is
// "zero", which is what the community ledger does. It is also why the interval
// is short by default.
package durable

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/phigate/phigate/internal/tokens"
)

// bucketSpend holds one key per (tenant, period), so a period's consumption is
// a single read and periods expire by being written to no more.
var bucketSpend = []byte("spend")

// Period is one tenant's accounting for one budget period.
type Period struct {
	Tenant           string  `json:"tenant"`
	Start            string  `json:"start"` // RFC3339, the period's first instant
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	Requests         int64   `json:"requests"`
	BaselineTokens   int64   `json:"baseline_tokens"`
	CloudCost        float64 `json:"cloud_cost"`
	BaselineCost     float64 `json:"baseline_cost"`
}

// Options configures a Ledger.
type Options struct {
	// Path is the bbolt database file.
	Path string
	// Inner is the accounting the process-wide Totals come from. The community
	// ledger is the expected value: this package adds durability to the
	// per-tenant half and has no reason to reimplement the pricing arithmetic
	// that the FinOps figures are computed by.
	Inner tokens.LedgerStore
	// PeriodStart maps a time to the start of the budget period containing it.
	// The gateway's configuration owns the period and the timezone, so this
	// takes the function rather than reimplementing the calendar.
	PeriodStart func(time.Time) time.Time
	// FlushInterval bounds how much accounting a crash can lose. Zero uses a
	// default.
	FlushInterval time.Duration

	now func() time.Time
}

// Ledger is a durable, per-tenant TenantLedger.
type Ledger struct {
	db          *bolt.DB
	inner       tokens.LedgerStore
	periodStart func(time.Time) time.Time
	now         func() time.Time

	mu      sync.Mutex
	pending map[string]*Period // key -> accumulated, not yet flushed

	stop   chan struct{}
	closed sync.Once
	wg     sync.WaitGroup
}

var (
	_ tokens.LedgerStore  = (*Ledger)(nil)
	_ tokens.TenantLedger = (*Ledger)(nil)
)

const defaultFlushInterval = 2 * time.Second

// Open creates or reopens the ledger at opts.Path.
func Open(opts Options) (*Ledger, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("durable: Path is required")
	}
	if opts.Inner == nil {
		return nil, fmt.Errorf("durable: Inner is required")
	}
	if opts.PeriodStart == nil {
		return nil, fmt.Errorf("durable: PeriodStart is required")
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = defaultFlushInterval
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	db, err := bolt.Open(opts.Path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("durable: open %s: %w", opts.Path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketSpend)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	l := &Ledger{
		db:          db,
		inner:       opts.Inner,
		periodStart: opts.PeriodStart,
		now:         opts.now,
		pending:     map[string]*Period{},
		stop:        make(chan struct{}),
	}
	l.wg.Add(1)
	go l.flushLoop(opts.FlushInterval)
	return l, nil
}

// Record accounts one request.
//
// It never touches the disk: the request path is not where an fsync belongs.
func (l *Ledger) Record(r tokens.Record, baselineModel string) {
	l.inner.Record(r, baselineModel)
	if r.Tenant == "" {
		return
	}

	start := l.periodStart(l.now())
	k := key(r.Tenant, start)

	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.pending[k]
	if !ok {
		p = &Period{Tenant: r.Tenant, Start: start.Format(time.RFC3339)}
		l.pending[k] = p
	}
	p.Requests++
	p.PromptTokens += int64(r.PromptTokens)
	p.CompletionTokens += int64(r.CompletionTokens)
	p.BaselineTokens += int64(r.BaselineTokens)
}

// Totals returns the process-wide snapshot, which is the inner ledger's.
//
// It is deliberately not read from the database. Those figures answer "how much
// has this process saved", and a durable store would answer for every process
// that ever ran, which is a different question and not the one the dashboard
// is asking.
func (l *Ledger) Totals() tokens.Totals { return l.inner.Totals() }

// TenantTotals returns what a tenant has spent in the current period.
func (l *Ledger) TenantTotals(tenant string) tokens.Totals {
	start := l.periodStart(l.now())
	p := l.read(tenant, start)

	l.mu.Lock()
	if pending, ok := l.pending[key(tenant, start)]; ok {
		p.Requests += pending.Requests
		p.PromptTokens += pending.PromptTokens
		p.CompletionTokens += pending.CompletionTokens
		p.BaselineTokens += pending.BaselineTokens
	}
	l.mu.Unlock()

	return tokens.Totals{
		Requests:         p.Requests,
		PromptTokens:     p.PromptTokens,
		CompletionTokens: p.CompletionTokens,
		BaselineTokens:   p.BaselineTokens,
		Since:            p.Start,
	}
}

// Consumed reports what a tenant has spent at or after since.
//
// Unflushed consumption is included. Reading only what is on disk would let a
// tenant outrun its budget by exactly one flush interval, every interval, which
// for a fast client is most of its spend.
func (l *Ledger) Consumed(tenant string, since time.Time) (prompt, completion int64) {
	start := l.periodStart(since)
	p := l.read(tenant, start)
	prompt, completion = p.PromptTokens, p.CompletionTokens

	l.mu.Lock()
	if pending, ok := l.pending[key(tenant, start)]; ok {
		prompt += pending.PromptTokens
		completion += pending.CompletionTokens
	}
	l.mu.Unlock()
	return prompt, completion
}

// Flush writes accumulated consumption to disk.
func (l *Ledger) Flush() error {
	l.mu.Lock()
	if len(l.pending) == 0 {
		l.mu.Unlock()
		return nil
	}
	batch := l.pending
	l.pending = map[string]*Period{}
	l.mu.Unlock()

	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSpend)
		for k, add := range batch {
			var cur Period
			if raw := b.Get([]byte(k)); raw != nil {
				if err := json.Unmarshal(raw, &cur); err != nil {
					return err
				}
			} else {
				cur.Tenant, cur.Start = add.Tenant, add.Start
			}
			cur.Requests += add.Requests
			cur.PromptTokens += add.PromptTokens
			cur.CompletionTokens += add.CompletionTokens
			cur.BaselineTokens += add.BaselineTokens

			raw, err := json.Marshal(cur)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(k), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// Put the batch back rather than dropping it. A transient write
		// failure must not silently hand every tenant its allowance again.
		l.mu.Lock()
		for k, add := range batch {
			if p, ok := l.pending[k]; ok {
				p.Requests += add.Requests
				p.PromptTokens += add.PromptTokens
				p.CompletionTokens += add.CompletionTokens
				p.BaselineTokens += add.BaselineTokens
			} else {
				l.pending[k] = add
			}
		}
		l.mu.Unlock()
	}
	return err
}

// Close flushes and closes the database.
func (l *Ledger) Close() error {
	var err error
	l.closed.Do(func() {
		close(l.stop)
		l.wg.Wait()
		err = l.Flush()
		if cerr := l.db.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

// Periods returns every period on record, for a report or an invoice.
func (l *Ledger) Periods() ([]Period, error) {
	if err := l.Flush(); err != nil {
		return nil, err
	}
	var out []Period
	err := l.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSpend).ForEach(func(_, raw []byte) error {
			var p Period
			if err := json.Unmarshal(raw, &p); err != nil {
				return err
			}
			out = append(out, p)
			return nil
		})
	})
	return out, err
}

func (l *Ledger) flushLoop(every time.Duration) {
	defer l.wg.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			_ = l.Flush()
		}
	}
}

func (l *Ledger) read(tenant string, start time.Time) Period {
	var p Period
	_ = l.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketSpend).Get([]byte(key(tenant, start)))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &p)
	})
	if p.Start == "" {
		p.Tenant, p.Start = tenant, start.Format(time.RFC3339)
	}
	return p
}

// key is "<unix period start big-endian><tenant>".
//
// The timestamp leads so that bbolt's byte order groups a tenant's periods
// chronologically, and it is fixed-width big-endian so that order is numeric
// rather than lexical — "10" sorting before "9" would put a report's rows in
// the wrong sequence exactly once every ten periods.
func key(tenant string, start time.Time) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(start.Unix()))
	return string(b[:]) + tenant
}
