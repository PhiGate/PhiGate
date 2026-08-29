package sandbox

import (
	"strings"
	"testing"
)

// collect wires a scanner to string sinks for assertions.
func collect(transform func(string) string) (*StreamScanner, *strings.Builder, *[]string) {
	var safe strings.Builder
	var blocks []string
	sc := NewStreamScanner(NewGuard(), transform,
		func(s string) error { safe.WriteString(s); return nil },
		func(v Verdict) error { blocks = append(blocks, v.Rule); return nil },
	)
	return sc, &safe, &blocks
}

func TestScannerBlocksAcrossChunks(t *testing.T) {
	sc, safe, blocks := collect(nil)
	// "rm -rf /" is split across three Write calls.
	for _, d := range []string{"first line\n", "rm -r", "f /\n", "echo after\n"} {
		if err := sc.Write(d); err != nil {
			t.Fatal(err)
		}
	}
	_ = sc.Close()

	if !strings.Contains(safe.String(), "first line") {
		t.Errorf("safe prefix lost: %q", safe.String())
	}
	if strings.Contains(safe.String(), "rm -rf") {
		t.Fatalf("destructive command emitted as safe: %q", safe.String())
	}
	if strings.Contains(safe.String(), "echo after") {
		t.Errorf("content after block should be sealed: %q", safe.String())
	}
	if len(*blocks) != 1 || (*blocks)[0] != "rm_recursive_force_root" {
		t.Fatalf("expected one rm_recursive_force block, got %v", *blocks)
	}
	if !sc.Blocked() {
		t.Error("scanner should report blocked")
	}
}

func TestScannerTransformsBeforeInspect(t *testing.T) {
	// The dangerous path only appears after hydration: <V1> -> "/".
	transform := func(s string) string { return strings.ReplaceAll(s, "<V1>", "/") }
	sc, safe, blocks := collect(transform)

	for _, d := range []string{"rm -rf <V", "1>\n"} {
		_ = sc.Write(d)
	}
	_ = sc.Close()

	if len(*blocks) != 1 {
		t.Fatalf("expected block after hydration, got %v (safe=%q)", *blocks, safe.String())
	}
}

// Prose is released as it arrives. Holding it to a newline is what made a
// single-paragraph answer arrive in one burst at the end of the stream.
func TestScannerReleasesProseBeforeNewline(t *testing.T) {
	sc, safe, _ := collect(nil)
	_ = sc.Write("the upstream timed out ")
	if safe.String() == "" {
		t.Fatal("prose should not wait for a newline")
	}
	_ = sc.Write("after three retries")
	_ = sc.Close()
	if got := safe.String(); got != "the upstream timed out after three retries" {
		t.Fatalf("prose altered in transit: %q", got)
	}
}

// A partial line that could still be read as a command is held, because the
// guard's verdict on it is not settled until the line ends.
func TestScannerHoldsPartialCommandUntilClose(t *testing.T) {
	sc, safe, _ := collect(nil)
	_ = sc.Write("systemctl status nginx")
	if safe.String() != "" {
		t.Fatalf("a partial command line should be held, got %q", safe.String())
	}
	_ = sc.Close()
	if safe.String() != "systemctl status nginx" {
		t.Fatalf("Close should flush the held line, got %q", safe.String())
	}
}

// The tail holdback covers a placeholder still in flight: releasing "<V" and
// then "1>" separately would hydrate neither.
func TestScannerHoldsPartialPlaceholder(t *testing.T) {
	transform := func(s string) string { return strings.ReplaceAll(s, "<V1>", "10.0.0.1") }
	sc, safe, _ := collect(transform)
	_ = sc.Write("the host is <V")
	if strings.Contains(safe.String(), "<V") {
		t.Fatalf("half a placeholder escaped: %q", safe.String())
	}
	_ = sc.Write("1> exactly")
	_ = sc.Close()
	if got := safe.String(); !strings.Contains(got, "10.0.0.1") {
		t.Fatalf("placeholder not hydrated across the split: %q", got)
	}
}
