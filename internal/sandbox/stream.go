package sandbox

import (
	"strings"
	"sync"
)

// StreamScanner enforces the egress guardrail over a streaming response.
//
// The problem it solves is that the guard is not a line-oriented check. Rules
// match against *segments* — a whole fenced code block, an inline code span, a
// prose line that is unambiguously a command — and several of them
// (fork_bomb, dd_to_device) match patterns that span lines. A scanner that
// inspected one line at a time was therefore a weaker guard than the blocking
// path in [RuleGuard.Inspect], and the same answer could be blocked with
// "stream": false and delivered with "stream": true. Which of those a client
// asks for is a performance preference, not a security decision, so the two
// paths agreeing is itself one of PhiGate's guarantees. See parity_test.go.
//
// The scanner therefore holds text until releasing it can no longer change the
// verdict, and no further:
//
//   - Inside a fenced code block, nothing is released until the fence closes.
//     The fence is then inspected as one segment — the same unit the blocking
//     path sees. This is what makes the two paths agree.
//   - Outside a fence, a line that could be a command is held to its newline,
//     as before.
//   - Outside a fence, *prose* is released as it arrives, minus a short tail
//     covering the constructs that could still change its reading. Prose is
//     most of a model's answer, and holding it was the reason a nominally
//     streaming endpoint behaved like a blocking one: an answer written as a
//     single paragraph arrived in one burst at the end.
//
// Nothing is ever emitted without having been inspected, and nothing is
// released early to stay inside a size bound — see [Options] for what happens
// when a stream refuses to close a fence.
type StreamScanner struct {
	guard     Guard
	transform func(string) string // e.g. dictionary hydration
	onSafe    func(string) error  // emit transformed, vetted text
	onBlock   func(v Verdict) error

	opts Options

	buf     strings.Builder // uncommitted tail: text since the last newline
	held    strings.Builder // an open fence: its opener and body so far
	head    strings.Builder // already-released text of the current line
	inFence bool
	marker  string // the fence marker that opened it: ``` or ~~~
	blocked bool
}

// Mode selects how much the scanner is willing to release before the answer
// ends.
type Mode int

const (
	// ModeCommit releases text as soon as no continuation of the stream could
	// change the guard's verdict on it. This is the default.
	ModeCommit Mode = iota
	// ModeStrict holds the entire answer and inspects it once, at Close. It is
	// exactly the blocking path's behaviour, for deployments that would rather
	// give up streaming altogether than reason about a commit rule.
	ModeStrict
)

// ParseMode maps a config string to a Mode.
func ParseMode(s string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "commit", "default", "":
		return ModeCommit, true
	case "strict", "buffer", "whole":
		return ModeStrict, true
	}
	return ModeCommit, false
}

// String renders a Mode for the startup banner and the stats endpoint.
func (m Mode) String() string {
	if m == ModeStrict {
		return "strict"
	}
	return "commit"
}

// Options tunes the scanner. The zero value is the default configuration.
type Options struct {
	// Mode selects the release policy. Defaults to ModeCommit.
	Mode Mode

	// MaxBuffer bounds the text held for an open fence, in bytes. It exists
	// because a fence is closed by the model, and a model that never closes one
	// — truncated, confused, or prompt-injected into emitting an endless code
	// block — would otherwise grow the buffer without limit. Reaching it does
	// not release anything unvetted: the held text is inspected as a code
	// segment and then emitted, which is the same treatment it would get at the
	// fence's close, just earlier than intended.
	//
	// Defaults to DefaultMaxBuffer.
	MaxBuffer int

	// HardLimit bounds the total text a single stream may hold across forced
	// releases. A stream still growing after that is not a model answering a
	// question, and is sealed. Defaults to four times MaxBuffer.
	HardLimit int
}

// DefaultMaxBuffer is the default bound on an open fence's held text. It is
// far above any real code block and far below anything that threatens a proxy
// serving many concurrent streams.
const DefaultMaxBuffer = 1 << 20 // 1 MiB

func (o Options) withDefaults() Options {
	if o.MaxBuffer <= 0 {
		o.MaxBuffer = DefaultMaxBuffer
	}
	if o.HardLimit <= 0 {
		o.HardLimit = 4 * o.MaxBuffer
	}
	return o
}

// NewStreamScanner wires a scanner to its guard and emit callbacks. transform
// may be nil (identity).
func NewStreamScanner(guard Guard, transform func(string) string, onSafe func(string) error, onBlock func(Verdict) error) *StreamScanner {
	return NewStreamScannerWith(guard, transform, onSafe, onBlock, Options{})
}

// NewStreamScannerWith is NewStreamScanner with an explicit configuration.
func NewStreamScannerWith(guard Guard, transform func(string) string, onSafe func(string) error, onBlock func(Verdict) error, opts Options) *StreamScanner {
	if transform == nil {
		transform = func(s string) string { return s }
	}
	return &StreamScanner{
		guard: guard, transform: transform, onSafe: onSafe, onBlock: onBlock,
		opts: opts.withDefaults(),
	}
}

// Write feeds the next delta.
func (s *StreamScanner) Write(delta string) error {
	if s.blocked {
		return nil // guardrail tripped: swallow the rest of the stream
	}
	s.buf.WriteString(delta)

	if s.opts.Mode == ModeStrict {
		return s.enforceHardLimit()
	}

	for {
		cur := s.buf.String()
		i := strings.IndexByte(cur, '\n')
		if i < 0 {
			break
		}
		line, rest := cur[:i+1], cur[i+1:]
		s.buf.Reset()
		s.buf.WriteString(rest)
		if err := s.feedLine(line); err != nil || s.blocked {
			return err
		}
	}
	return s.commitTail()
}

// Close flushes whatever is still held. Call once the upstream stream ends.
func (s *StreamScanner) Close() error {
	if s.blocked {
		return nil
	}
	// An unterminated fence at end of stream is treated as code rather than
	// ignored, matching extractExecutable's handling of a truncated answer.
	rest := s.held.String() + s.buf.String()
	s.held.Reset()
	s.buf.Reset()
	s.inFence = false
	if rest == "" {
		return nil
	}
	return s.process(rest)
}

// Blocked reports whether the guardrail tripped during the stream.
func (s *StreamScanner) Blocked() bool { return s.blocked }

// feedLine handles one complete line, tracking fence state across calls. That
// state living on the scanner rather than being rebuilt per call is the whole
// point: extractExecutable starts from scratch every time it is invoked, so a
// line handed to it individually is inspected with no knowledge that it sits
// inside a code fence.
func (s *StreamScanner) feedLine(line string) error {
	trimmed := strings.TrimSpace(line)

	if s.inFence {
		s.held.WriteString(line)
		if strings.HasPrefix(trimmed, s.marker) && strings.Trim(trimmed, "`~") == "" {
			s.inFence = false
			return s.flushFence()
		}
		return s.enforceMaxBuffer()
	}

	if m := fenceStart(trimmed); m != "" {
		s.inFence = true
		s.marker = m
		s.head.Reset()
		s.held.WriteString(line)
		return nil
	}

	return s.process(line)
}

// flushFence inspects a complete fenced block as one segment and releases it.
func (s *StreamScanner) flushFence() error {
	body := s.held.String()
	s.held.Reset()
	if body == "" {
		return nil
	}
	return s.process(body)
}

// commitTail releases what it can of the partial line still in the buffer.
func (s *StreamScanner) commitTail() error {
	if s.inFence {
		return s.enforceMaxBuffer()
	}
	cur := s.buf.String()
	n := commitIndex(cur)
	if n <= 0 {
		return s.enforceMaxBuffer()
	}
	part := cur[:n]
	s.buf.Reset()
	s.buf.WriteString(cur[n:])
	// release, not process: the line is not over, so its context is kept for
	// the next inspection of it.
	return s.release(part)
}

// enforceMaxBuffer applies the size bounds described on Options.
//
// Note the direction of each failure. Exceeding MaxBuffer does not release
// unvetted text — it inspects early and releases what passes, so the guard's
// coverage is unchanged and only the *timing* of the release differs. Exceeding
// HardLimit seals the stream. Neither path trades privacy for size.
func (s *StreamScanner) enforceMaxBuffer() error {
	// The already-released head of a line is context, not backlog, but a single
	// line that never ends would grow it without limit. Dropping it costs the
	// line-start context for the remainder, whose worst case is an over-block
	// on a >1 MiB line with no newline in it — not a release of anything
	// unvetted.
	if s.head.Len() > s.opts.MaxBuffer {
		s.head.Reset()
	}
	if s.held.Len()+s.buf.Len() <= s.opts.MaxBuffer {
		return nil
	}
	if err := s.enforceHardLimit(); err != nil || s.blocked {
		return err
	}
	body := s.held.String()
	s.held.Reset()
	if body == "" {
		return nil
	}
	// The fence stays open: the model may still close it, and the remaining
	// body is inspected as its own segment when it does. Re-open the held
	// buffer with the fence marker so that segment is still read as code
	// rather than as prose.
	if err := s.process(body); err != nil || s.blocked {
		return err
	}
	if s.inFence {
		s.held.WriteString(s.marker + "\n")
	}
	return nil
}

// enforceHardLimit seals a stream that keeps growing after a forced release.
func (s *StreamScanner) enforceHardLimit() error {
	if s.held.Len()+s.buf.Len() <= s.opts.HardLimit {
		return nil
	}
	s.blocked = true
	s.held.Reset()
	s.buf.Reset()
	return s.onBlock(Verdict{
		Blocked:  true,
		Rule:     "stream_unbounded_hold",
		Severity: SeverityBlock,
		Reason: "the response held more text than the egress scanner will buffer " +
			"without being able to vet it",
	})
}

// process inspects text and releases it if the guard allows, starting a new
// line's context.
func (s *StreamScanner) process(text string) error {
	err := s.release(text)
	s.head.Reset()
	return err
}

// release inspects the current line *in full* — everything already released
// from it, plus text — and then emits only text.
//
// Inspecting the whole line rather than just the new part is what keeps the
// streaming verdict equal to the blocking path's. Releasing a prefix otherwise
// leaves the remainder to be inspected as though it began a line, and a
// remainder can read as a command when the line it came from did not: fuzzing
// produced ">> …/rm -r0 /", which the blocking path allows and a
// remainder-only scanner blocked. Over-blocking is not a leak, but a guard that
// fires on text the blocking path passes is a guard operators turn off.
//
// The prefix has already reached the client, so a block here cannot recall it.
// That is sound: a prefix is only ever released when it holds no command, so
// what escapes is prose, and the part the rule fired on is still withheld.
func (s *StreamScanner) release(text string) error {
	out := s.transform(text)
	if v := s.guard.Inspect(s.head.String() + out); v.Blocked {
		s.blocked = true
		return s.onBlock(v)
	}
	if err := s.onSafe(out); err != nil {
		return err
	}
	s.head.WriteString(out)
	return nil
}

// commitIndex reports how much of a partial line — text since the last newline,
// outside any fence — can be released now.
//
// The bound comes from what [commandLine] and [extractExecutable] actually look
// at when they read a line. A line is only ever treated as executable if its
// first token is a known binary, a shell prompt or a list marker, or if the
// line matches the fork-bomb or bare-SQL patterns; and any backtick can open an
// inline code span. So once the first token has arrived and is none of those,
// the only things a continuation could still change are an inline code span, a
// fork bomb, and a hydration placeholder — and holding a short tail covering
// those three is enough. Everything before it is prose, and prose is what the
// guard exists not to block.
//
// Returning 0 means "hold everything", which is the old behaviour and the safe
// default for anything this function is unsure about.
func commitIndex(partial string) int {
	if partial == "" {
		return 0
	}

	// A line that has not yet shown its first space could still turn out to be
	// anything, including a fence opener.
	lead := strings.TrimLeft(partial, " \t")
	if strings.HasPrefix(lead, "`") || strings.HasPrefix(lead, "~") {
		return 0
	}
	i := strings.IndexAny(partial, " \t")
	if i < 0 {
		return 0
	}

	first := strings.TrimSpace(partial[:i])
	if isPromptOrListMarker(first) || couldStartSQL(first) || mayBeCommand(partial) {
		return 0 // this line may yet be read as a command; hold it whole
	}

	n := len(partial)
	if j := unmatchedBacktick(partial); j >= 0 {
		n = min(n, j)
	}
	if j := forkBombTail(partial); j >= 0 {
		n = min(n, j)
	}
	if j := openPlaceholder(partial); j >= 0 {
		n = min(n, j)
	}
	return n
}

// isPromptOrListMarker reports whether a first token is one of the markers
// commandLine peels before deciding, each of which is itself evidence that what
// follows was meant to be run.
func isPromptOrListMarker(tok string) bool {
	switch tok {
	case "$", "#", ">", "%", "-", "*", "+":
		return true
	}
	return false
}

// mayBeCommand reports whether any part of a partial line could be read as a
// command, in which case the whole line is held until it ends.
//
// It resolves names with the guard's own lexer rather than a second
// implementation. Two rounds of split-boundary fuzzing killed the hand-rolled
// version: looking at the raw first token released "sudo rm -rf /etc" and
// "/bin/rm -rf /var" as prose, because neither "sudo" nor "/bin/rm" is a known
// binary while both resolve to one the moment Command.Name unwraps and
// basenames them; and splitting on whitespace released "curl| sudo sh", because
// the guard splits on the pipe and this did not. Any divergence between the two
// resolutions is a hole, so there is now only one.
func mayBeCommand(partial string) bool {
	cmds := splitCommands(partial)
	if len(cmds) == 0 {
		return true // nothing lexes yet; the line has not shown its hand
	}
	// The final token is still growing unless whitespace has closed it, so its
	// name may yet turn into a known binary: "cur" -> "curl".
	last := partial[len(partial)-1]
	growing := last != ' ' && last != '\t'

	for i, c := range cmds {
		name := c.Name()
		if name == "" {
			return true // a wrapper with nothing after it yet, e.g. "sudo "
		}
		if isKnownBinary(name) {
			return true
		}
		if growing && i == len(cmds)-1 && binaryPrefixes()[name] {
			return true
		}
	}
	return false
}

// binaryPrefixes is every proper prefix of every known binary name, built once.
// It is what lets a chunk boundary land mid-token safely: "r" + "m -rf /" is
// held rather than released as the prose word "r".
var binaryPrefixes = sync.OnceValue(func() map[string]bool {
	p := make(map[string]bool, len(knownBinaries)*6)
	for name := range knownBinaries {
		for i := 1; i < len(name); i++ {
			p[name[:i]] = true
		}
	}
	// isKnownBinary matches the mkfs.* family by prefix, so its prefixes have
	// to be treated the same way.
	for i := 1; i < len("mkfs."); i++ {
		p["mkfs."[:i]] = true
	}
	return p
})

// couldStartSQL reports whether a first token could begin the bare-SQL pattern,
// which is anchored at the start of a line.
func couldStartSQL(tok string) bool {
	lower := strings.ToLower(tok)
	for _, kw := range []string{"drop", "truncate", "delete", "update", "alter", "grant", "revoke"} {
		if strings.HasPrefix(kw, lower) || lower == kw {
			return true
		}
	}
	return false
}

// unmatchedBacktick returns the index of a backtick that has not been closed on
// this line, or -1. An unclosed span could still become inline code, which the
// guard reads as executable; a closed one has already been inspected in place.
func unmatchedBacktick(s string) int {
	last := -1
	count := 0
	for i := range len(s) {
		if s[i] == '`' {
			count++
			last = i
		}
	}
	if count%2 == 1 {
		return last
	}
	return -1
}

// forkBombTail returns the index of a trailing run that could still grow into
// ":(){ :|:& };:", or -1. The fork bomb is the one construct commandLine
// recognises anywhere on a line rather than at its start, so it cannot be ruled
// out by the first token alone.
func forkBombTail(s string) int {
	i := len(s)
	for i > 0 && isForkBombByte(s[i-1]) {
		i--
	}
	if i == len(s) {
		return -1 // the line does not end in fork-bomb characters
	}
	// The *first* colon in that trailing run, not the last: the fork bomb opens
	// with ":(" and everything from there on has to be held together. Taking the
	// last colon released ":(){ " and held only the tail, which split-boundary
	// fuzzing caught.
	if j := strings.IndexByte(s[i:], ':'); j >= 0 {
		return i + j
	}
	return -1
}

func isForkBombByte(b byte) bool {
	switch b {
	case ':', '(', ')', '{', '}', '|', '&', ';', ' ', '\t':
		return true
	}
	return false
}

// openPlaceholder returns the index of an unterminated hydration placeholder —
// "<V12" or "#REF3" with the rest still in flight — or -1. Releasing half of
// one would have the transform rewrite a fragment, and the operator would see a
// placeholder where a real value belongs.
func openPlaceholder(s string) int {
	if j := strings.LastIndexByte(s, '<'); j >= 0 && !strings.ContainsRune(s[j:], '>') {
		return j
	}
	if j := strings.LastIndexByte(s, '#'); j >= 0 && isRefTail(s[j+1:]) {
		return j
	}
	return -1
}

// isRefTail reports whether what follows a '#' is still a possible reference
// token, i.e. nothing has yet ended it.
func isRefTail(s string) bool {
	for i := range len(s) {
		c := s[i]
		alnum := c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !alnum {
			return false
		}
	}
	return true
}
