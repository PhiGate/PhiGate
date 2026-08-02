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
