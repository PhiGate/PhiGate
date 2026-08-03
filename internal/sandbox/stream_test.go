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

func TestScannerHoldsPartialLineUntilClose(t *testing.T) {
	sc, safe, _ := collect(nil)
	_ = sc.Write("partial without newline")
	if safe.String() != "" {
		t.Fatalf("partial line should be held, got %q", safe.String())
	}
	_ = sc.Close()
	if safe.String() != "partial without newline" {
		t.Fatalf("Close should flush partial, got %q", safe.String())
	}
}
