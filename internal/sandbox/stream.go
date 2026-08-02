package sandbox

import "strings"

// StreamScanner enforces the egress guardrail over a streaming response. Model
// output arrives as arbitrarily-split deltas; the scanner buffers them and only
// releases content one complete line at a time. Operating on whole lines means:
//
//   - a destructive command split across SSE chunks (e.g. "rm -r" + "f /") is
//     still inspected as a single unit, and
//   - hydration placeholders (<V1>) are never split mid-token, so transform()
//     can safely restore real values before inspection.
//
// Each complete line is transformed (hydrated), inspected, and then either
// emitted via onSafe or — if a rule fires — replaced by onBlock, after which the
// stream is sealed and all further output is discarded.
type StreamScanner struct {
	guard     Guard
	transform func(string) string // e.g. dictionary hydration
	onSafe    func(string) error  // emit transformed, vetted text
	onBlock   func(v Verdict) error

	buf     strings.Builder
	blocked bool
}

// NewStreamScanner wires a scanner to its guard and emit callbacks. transform
// may be nil (identity).
func NewStreamScanner(guard Guard, transform func(string) string, onSafe func(string) error, onBlock func(Verdict) error) *StreamScanner {
	if transform == nil {
		transform = func(s string) string { return s }
	}
	return &StreamScanner{guard: guard, transform: transform, onSafe: onSafe, onBlock: onBlock}
}

// Write feeds the next delta. Complete lines (terminated by '\n') are processed
// immediately; any trailing partial line is held until more data or Close.
func (s *StreamScanner) Write(delta string) error {
	if s.blocked {
		return nil // guardrail tripped: swallow the rest of the stream
	}
	s.buf.WriteString(delta)

	for {
		cur := s.buf.String()
		i := strings.IndexByte(cur, '\n')
		if i < 0 {
			break
		}
		line := cur[:i+1] // include newline
		s.buf.Reset()
		s.buf.WriteString(cur[i+1:])
		if err := s.process(line); err != nil || s.blocked {
			return err
		}
	}
	return nil
}

// Close flushes any held partial line. Call once the upstream stream ends.
func (s *StreamScanner) Close() error {
	if s.blocked {
		return nil
	}
	if rest := s.buf.String(); rest != "" {
		s.buf.Reset()
		return s.process(rest)
	}
	return nil
}

// Blocked reports whether the guardrail tripped during the stream.
func (s *StreamScanner) Blocked() bool { return s.blocked }

func (s *StreamScanner) process(line string) error {
	out := s.transform(line)
	if v := s.guard.Inspect(out); v.Blocked {
		s.blocked = true
		return s.onBlock(v)
	}
	return s.onSafe(out)
}
