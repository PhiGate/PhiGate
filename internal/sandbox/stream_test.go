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

// countEmissions feeds text one byte at a time and reports how many separate
// releases the scanner made.
func countEmissions(t *testing.T, text string) int {
	t.Helper()
	n := 0
	sc := NewStreamScanner(NewGuard(), nil,
		func(string) error { n++; return nil },
		func(Verdict) error { return nil })
	for i := range len(text) {
		if err := sc.Write(text[i : i+1]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return n
}

// TestProseStreamsWordByWord is the regression test for an over-hold that the
// verdict-parity tests could not see.
//
// Those tests assert *what* the guard decides, so a scanner that reached the
// right verdict while holding the whole answer to the end passed all of them.
// It took running a real model to notice: a 605-character paragraph with no
// newline came back in four pieces rather than a hundred, because the first
// token of a held segment was "a" — a prefix of "alter" — and the SQL check
// matched prefixes. The commonest word in English silently reinstated the
// buffering this scanner exists to remove.
//
// So this asserts release *granularity*, which is the property an operator
// actually perceives as streaming.
func TestProseStreamsWordByWord(t *testing.T) {
	prose := "Nginx may return a 502 Bad Gateway error to <V1> if it is unable " +
		"to communicate with the upstream server, and a restart of the pool " +
		"is a reasonable first step to take here.\n"

	got := countEmissions(t, prose)
	if words := len(strings.Fields(prose)); got < words/2 {
		t.Errorf("prose released in %d pieces for %d words: the scanner is buffering, not streaming",
			got, words)
	}
}

// TestSingleLetterWordsDoNotHoldTheLine covers the whole class the "a" bug came
// from: a settled token that is a prefix of a SQL keyword or a binary name is
// not itself either of those, and must not hold its line.
func TestSingleLetterWordsDoNotHoldTheLine(t *testing.T) {
	for _, w := range []string{"a", "d", "u", "g", "r", "t", "al", "de", "up", "tr"} {
		text := "this is " + w + " word in an ordinary sentence that keeps going for a while\n"
		if got := countEmissions(t, text); got < 5 {
			t.Errorf("a line containing the word %q released in %d pieces: held as a possible statement", w, got)
		}
	}
}

// TestRealSQLStillHoldsItsLine is the other half: the fix must not have made
// the SQL check useless. A genuine bare statement is still held and blocked.
func TestRealSQLStillHoldsItsLine(t *testing.T) {
	var emitted strings.Builder
	sc := NewStreamScanner(NewGuard(), nil,
		func(s string) error { emitted.WriteString(s); return nil },
		func(Verdict) error { return nil })
	text := "DROP TABLE users;\n"
	for i := range len(text) {
		_ = sc.Write(text[i : i+1])
	}
	_ = sc.Close()

	if !sc.Blocked() {
		t.Errorf("a bare SQL statement was not blocked (emitted %q)", emitted.String())
	}
	if strings.Contains(emitted.String(), "DROP TABLE") {
		t.Errorf("released the statement before blocking: %q", emitted.String())
	}
}
