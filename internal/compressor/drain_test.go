package compressor

import (
	"strings"
	"testing"
)

func TestDrainClustersSimilarLines(t *testing.T) {
	d := NewDrain()
	s := NewSession()
	in := strings.Join([]string{
		"GET /api/users 200 in 12ms",
		"GET /api/users 200 in 47ms",
		"GET /api/users 200 in 8ms",
	}, "\n")

	out, err := d.Process(in, s)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(out, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 clustered template, got %d:\n%s", len(lines), out)
	}
	if !strings.Contains(out, "<*>") {
		t.Fatalf("varying position should become wildcard: %q", out)
	}
	if !strings.Contains(out, "(x3)") {
		t.Fatalf("cluster count annotation missing: %q", out)
	}
}

func TestDrainKeepsDistinctTemplates(t *testing.T) {
	d := NewDrain()
	s := NewSession()
	in := "GET /api/users 200 in 12ms\nPOST /api/login 401 in 3ms"
	out, err := d.Process(in, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(out, "\n")); got != 2 {
		t.Fatalf("expected 2 templates, got %d:\n%s", got, out)
	}
}

// TestDrainClustersMaskedLogLines is the regression test for the defect that
// made this stage a no-op on real input: the bucket key used the first token,
// which after masking is a unique <V*> per distinct timestamp. Since almost
// every log line starts with a timestamp, nothing ever clustered.
func TestDrainClustersMaskedLogLines(t *testing.T) {
	in := "2026-06-29T15:04:05Z ERROR conn refused to 10.0.0.5\n" +
		"2026-06-29T15:04:06Z ERROR conn refused to 10.0.0.5\n" +
		"2026-06-29T15:04:07Z ERROR conn refused to 10.0.0.5\n"

	s := NewSession()
	masked, err := NewMasker().Process(in, s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := NewDrain().Process(masked, s)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "(x3)") {
		t.Fatalf("three identical masked lines should collapse to one template with (x3), got:\n%s", out)
	}
	if n := strings.Count(out, "ERROR"); n != 1 {
		t.Errorf("expected 1 template line, found %d occurrences of ERROR:\n%s", n, out)
	}
}

// TestDrainKeepsDistinctTemplatesApart guards the opposite failure: clustering
// so aggressively that unrelated events merge into one meaningless line.
func TestDrainKeepsDistinctTemplatesApart(t *testing.T) {
	in := "<V1> ERROR disk full on <V2>\n<V3> INFO user login succeeded\n<V4> ERROR disk full on <V5>\n"
	out, err := NewDrain().Process(in, NewSession())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "(x2)") {
		t.Errorf("the two disk-full lines should cluster:\n%s", out)
	}
	if !strings.Contains(out, "login") {
		t.Errorf("the unrelated INFO line must survive as its own template:\n%s", out)
	}
}
