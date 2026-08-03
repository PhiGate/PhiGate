package sandbox

import "strings"

// Command is one simple command extracted from model output: an argv, plus the
// original text it came from for audit records.
type Command struct {
	// Argv is the tokenized command, quotes removed.
	Argv []string
	// Raw is the source text of this command.
	Raw string
	// Piped is true when this command's output feeds another via '|'.
	Piped bool
	// PipedFrom holds the argv of the command feeding this one, if any. It is
	// what lets a rule recognise "curl … | sh" as a unit.
	PipedFrom []string
}

// Name returns the base name of the executable, with any path and any
// leading environment assignments stripped. "sudo" and friends are unwrapped so
// "sudo /bin/rm -rf /" is recognised as an "rm".
func (c Command) Name() string {
	for i, tok := range c.Argv {
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") && i == 0 {
			continue // leading VAR=value assignment
		}
		base := tok
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		switch base {
		case "sudo", "doas", "env", "nohup", "time", "exec", "command", "busybox":
			continue // wrapper: the real command is the next token
		}
		return base
	}
	return ""
}

// Args returns the arguments following the resolved command name.
func (c Command) Args() []string {
	name := c.Name()
	for i, tok := range c.Argv {
		base := tok
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		if base == name {
			return c.Argv[i+1:]
		}
	}
	return nil
}

// HasFlag reports whether any of the given short flags is present, accounting
// for bundling. HasFlag("r", "R") matches "-r", "-R", "-rf", "-fR" and
// "--recursive" when longs are supplied too.
//
// This is why the guard tokenizes instead of pattern-matching: the old regex
// deny list caught "rm -rf" but let "rm -f -r" and "rm --force --recursive"
// straight through.
func (c Command) HasFlag(shorts string, longs ...string) bool {
	for _, a := range c.Args() {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--") {
			name := strings.TrimPrefix(a, "--")
			if i := strings.IndexByte(name, '='); i >= 0 {
				name = name[:i]
			}
			for _, l := range longs {
				if name == l {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				if strings.ContainsRune(shorts, ch) {
					return true
				}
			}
		}
	}
	return false
}

// Operands returns the non-flag arguments — the things a command acts upon.
func (c Command) Operands() []string {
	var out []string
	endOfFlags := false
	for _, a := range c.Args() {
		if a == "--" {
			endOfFlags = true
			continue
		}
		if !endOfFlags && strings.HasPrefix(a, "-") && len(a) > 1 {
			continue
		}
		out = append(out, a)
	}
	return out
}

// HasArg reports whether any argument equals s.
func (c Command) HasArg(s string) bool {
	for _, a := range c.Argv {
		if a == s {
			return true
		}
	}
	return false
}

// splitCommands lexes a shell fragment into simple commands, honouring quoting
// and splitting on the operators that separate commands: ; & && || | and
// newlines. It is intentionally a lexer and not a parser — the guard needs to
// know "which programs are invoked with which arguments", not to build an AST.
func splitCommands(src string) []Command {
	var (
		out     []Command
		argv    []string
		cur     strings.Builder
		rawFrom int
		i       int
		quote   byte
		pipedIn []string
		piped   bool
	)

	flushTok := func() {
		if cur.Len() > 0 {
			argv = append(argv, cur.String())
			cur.Reset()
		}
	}
	flushCmd := func(end int, nextPiped bool) {
		flushTok()
		if len(argv) > 0 {
			c := Command{Argv: argv, Raw: strings.TrimSpace(src[rawFrom:end]), Piped: nextPiped}
			if piped {
				c.PipedFrom = pipedIn
			}
			out = append(out, c)
			if nextPiped {
				pipedIn = argv
				piped = true
			} else {
				pipedIn, piped = nil, false
			}
		}
		argv = nil
		rawFrom = end
	}

	for i = 0; i < len(src); i++ {
		ch := src[i]

		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			if quote == '"' && ch == '\\' && i+1 < len(src) {
				i++
				cur.WriteByte(src[i])
				continue
			}
			cur.WriteByte(ch)
			continue
		}

		switch ch {
		case '\'', '"':
			quote = ch
		case '\\':
			if i+1 < len(src) {
				i++
				if src[i] != '\n' {
					cur.WriteByte(src[i])
				}
			}
		case ' ', '\t':
			flushTok()
		case '\n', ';':
			flushCmd(i, false)
			rawFrom = i + 1
		case '|':
			if i+1 < len(src) && src[i+1] == '|' {
				flushCmd(i, false)
				i++
			} else {
				flushCmd(i, true)
			}
			rawFrom = i + 1
		case '&':
			if i+1 < len(src) && src[i+1] == '&' {
				i++
			}
			flushCmd(i, false)
			rawFrom = i + 1
		default:
			cur.WriteByte(ch)
		}
	}
	flushCmd(len(src), false)
	return out
}
