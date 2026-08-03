// Package metrics exposes PhiGate's counters in Prometheus text format.
//
// It is implemented against the exposition format directly rather than against
// the official client library. A security gateway that sits in the path of every
// LLM request should be auditable end to end, and the exposition format is a few
// dozen lines of text generation. PhiGate's only external dependency remains
// tree-sitter, which keeps the supply-chain surface a JP enterprise security
// review has to examine down to something one person can read in an afternoon.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds PhiGate's metrics.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*labelledCounter
	gauges   map[string]*gauge
	order    []string
}

type labelledCounter struct {
	help   string
	mu     sync.RWMutex
	values map[string]*atomic.Int64 // serialized labels -> value
	labels []string
}

type gauge struct {
	help string
	fn   func() float64
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{
		counters: make(map[string]*labelledCounter),
		gauges:   make(map[string]*gauge),
	}
}

// Counter registers a counter with the given label names and returns it.
// Re-registering the same name returns the existing counter.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.counters[name]
	if !ok {
		c = &labelledCounter{help: help, values: map[string]*atomic.Int64{}, labels: labels}
		r.counters[name] = c
		r.order = append(r.order, name)
	}
	return &Counter{name: name, c: c}
}

// Gauge registers a gauge sampled from fn at scrape time. Sampling on scrape
// keeps derived values (cache size, session count, cumulative savings) exact
// without a second bookkeeping path that could drift from the real one.
func (r *Registry) Gauge(name, help string, fn func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.gauges[name]; !ok {
		r.order = append(r.order, name)
	}
	r.gauges[name] = &gauge{help: help, fn: fn}
}

// Counter is a handle to a registered counter.
type Counter struct {
	name string
	c    *labelledCounter
}

// Inc adds one to the series identified by labelValues.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add adds n to the series identified by labelValues.
func (c *Counter) Add(n int64, labelValues ...string) {
	if c == nil {
		return
	}
	key := strings.Join(labelValues, "\x00")
	c.c.mu.RLock()
	v, ok := c.c.values[key]
	c.c.mu.RUnlock()
	if !ok {
		c.c.mu.Lock()
		if v, ok = c.c.values[key]; !ok {
			v = &atomic.Int64{}
			c.c.values[key] = v
		}
		c.c.mu.Unlock()
	}
	v.Add(n)
}

// Gather renders the registry in Prometheus text exposition format.
func (r *Registry) Gather() string {
	r.mu.RLock()
	names := make([]string, len(r.order))
	copy(names, r.order)
	counters := make(map[string]*labelledCounter, len(r.counters))
	for k, v := range r.counters {
		counters[k] = v
	}
	gauges := make(map[string]*gauge, len(r.gauges))
	for k, v := range r.gauges {
		gauges[k] = v
	}
	r.mu.RUnlock()

	var b strings.Builder
	for _, name := range names {
		if c, ok := counters[name]; ok {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, c.help, name)
			c.mu.RLock()
			keys := make([]string, 0, len(c.values))
			for k := range c.values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "%s%s %d\n", name, renderLabels(c.labels, k), c.values[k].Load())
			}
			c.mu.RUnlock()
			continue
		}
		if g, ok := gauges[name]; ok {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n",
				name, g.help, name, name, g.fn())
		}
	}
	return b.String()
}

// renderLabels turns the label names and a serialized value key into
// {name="value",…}. Values are escaped per the exposition format.
func renderLabels(names []string, key string) string {
	if len(names) == 0 || key == "" {
		return ""
	}
	vals := strings.Split(key, "\x00")
	parts := make([]string, 0, len(names))
	for i, n := range names {
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		parts = append(parts, fmt.Sprintf("%s=%q", n, escapeLabel(v)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
