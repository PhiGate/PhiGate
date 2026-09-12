package metrics

import (
	"strings"
	"testing"
)

// TestCumulativeTotalsArePublishedAsCounters.
//
// A cumulative figure published as a gauge cannot be summed over time: rate()
// and increase() are defined on counters, because only a counter carries the
// promise that a fall in value is a restart and not a real decrease. PhiGate's
// savings totals are per-process and reset with the pod, so as gauges they
// answered "what has this replica saved since it last started" — never "what
// did the deployment save last month", which is the only form a finance team
// asks in.
func TestCumulativeTotalsArePublishedAsCounters(t *testing.T) {
	r := New()
	r.CounterFunc("phigate_cost_saved_total", "Spend avoided.", func() float64 { return 12.5 })
	r.Gauge("phigate_sessions_active", "Live sessions.", func() float64 { return 3 })

	got := r.Gather()
	for _, want := range []string{
		"# TYPE phigate_cost_saved_total counter",
		"phigate_cost_saved_total 12.5",
		"# TYPE phigate_sessions_active gauge",
		"phigate_sessions_active 3",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from:\n%s", want, got)
		}
	}
	if strings.Contains(got, "# TYPE phigate_cost_saved_total gauge") {
		t.Error("a cumulative total is still typed as a gauge")
	}
}

// TestSampledValuesReadTheirSourceEachScrape. Sampling on scrape is what keeps
// these exact: a second bookkeeping path incremented on the request path would
// be free to drift from the ledger the dashboard and audit log report from.
func TestSampledValuesReadTheirSourceEachScrape(t *testing.T) {
	n := 0.0
	r := New()
	r.CounterFunc("x_total", "counts", func() float64 { n++; return n })

	if first, second := r.Gather(), r.Gather(); !strings.Contains(first, "x_total 1") ||
		!strings.Contains(second, "x_total 2") {
		t.Errorf("value was not re-read per scrape:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// TestRegisteringTwiceReplacesRatherThanDuplicates keeps a reload from
// publishing the same series twice.
func TestRegisteringTwiceReplacesRatherThanDuplicates(t *testing.T) {
	r := New()
	r.Gauge("g", "help", func() float64 { return 1 })
	r.CounterFunc("g", "help", func() float64 { return 2 })

	got := r.Gather()
	if strings.Count(got, "# TYPE g ") != 1 {
		t.Errorf("series declared more than once:\n%s", got)
	}
	if !strings.Contains(got, "# TYPE g counter") || !strings.Contains(got, "g 2") {
		t.Errorf("re-registration did not take effect:\n%s", got)
	}
}
