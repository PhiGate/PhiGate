package sandbox

import (
	"regexp"
	"strings"
)

var (
	// forkBombPattern is checked during extraction as well as during rule
	// evaluation: ":(){ :|:& };:" does not lex to a recognisable argv, so it
	// would otherwise never reach a rule.
	forkBombPattern = regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&\s*\}\s*;\s*:`)
	// sqlStatementPattern recognises a bare SQL statement in prose. Assistants
	// routinely answer with SQL and no code fence.
	sqlStatementPattern = regexp.MustCompile(`(?i)^\s*(?:drop|truncate|delete\s+from|update|alter|grant|revoke)\s+\S`)
)

// isKnownBinary reports whether name is a program the guard will treat as a
// command in prose. Families with a suffix — mkfs.ext4, mkfs.xfs — are matched
// by prefix so a filesystem-specific variant is not silently ignored.
func isKnownBinary(name string) bool {
	if knownBinaries[name] {
		return true
	}
	return strings.HasPrefix(name, "mkfs.")
}

// Scope is where in the model's answer a span of text came from.
type Scope int

const (
	// ScopeProse is ordinary explanation. Nothing here is executed, so the
	// guard must not block on it.
	ScopeProse Scope = iota
	// ScopeCode is inside a fenced or inline code block.
	ScopeCode
	// ScopeCommandLine is a prose line that is unambiguously a command.
	ScopeCommandLine
)

// Segment is a span of model output with its scope and detected language.
type Segment struct {
	Text  string
	Scope Scope
	Lang  string
}

// extractExecutable returns the parts of text that could plausibly be run.
//
// This is the single most important correction to the original guard. That
// version matched regexes against the *entire* answer, so an SRE assistant
// writing "if that fails, reboot the node" or "graceful shutdown is configured
// via SIGTERM" had its answer blocked as a destructive command. A guard that
// fires on English prose gets switched off within a day, and a guard that is
// switched off protects nothing.
//
// Scoping to code blocks and unambiguous command lines keeps the guard on the
// text an operator might actually paste into a terminal.
func extractExecutable(text string) []Segment {
	var segs []Segment

	lines := strings.Split(text, "\n")
	inFence := false
	fenceMarker := ""
	fenceLang := ""
	var fenceBody []string

	flushFence := func() {
		if len(fenceBody) > 0 {
			segs = append(segs, Segment{
				Text:  strings.Join(fenceBody, "\n"),
				Scope: ScopeCode,
				Lang:  fenceLang,
			})
		}
		fenceBody = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if marker := fenceStart(trimmed); marker != "" && !inFence {
			inFence = true
			fenceMarker = marker
			fenceLang = strings.ToLower(strings.TrimSpace(strings.TrimLeft(trimmed, "`~")))
			continue
		}
		if inFence {
			if strings.HasPrefix(trimmed, fenceMarker) && strings.Trim(trimmed, "`~") == "" {
				inFence = false
				flushFence()
				fenceLang = ""
				continue
			}
			fenceBody = append(fenceBody, line)
			continue
		}

		// Outside a fence: inline code spans and unambiguous command lines.
		for _, span := range inlineCode(line) {
			segs = append(segs, Segment{Text: span, Scope: ScopeCode})
		}
		if cmd := commandLine(line); cmd != "" {
			segs = append(segs, Segment{Text: cmd, Scope: ScopeCommandLine})
		}
	}
	if inFence {
		// Unterminated fence — a truncated or still-streaming answer. Treat
		// what we have as code rather than ignoring it.
		flushFence()
	}
	return segs
}

// fenceStart returns the fence marker if trimmed opens a code fence.
func fenceStart(trimmed string) string {
	switch {
	case strings.HasPrefix(trimmed, "```"):
		return "```"
	case strings.HasPrefix(trimmed, "~~~"):
		return "~~~"
	}
	return ""
}

// inlineCode returns the contents of `backtick` spans on a line.
func inlineCode(line string) []string {
	var out []string
	for {
		i := strings.IndexByte(line, '`')
		if i < 0 {
			return out
		}
		rest := line[i+1:]
		j := strings.IndexByte(rest, '`')
		if j < 0 {
			return out
		}
		if span := strings.TrimSpace(rest[:j]); span != "" {
			out = append(out, span)
		}
		line = rest[j+1:]
	}
}

// commandLine reports the command on a prose line, or "" if the line is prose.
//
// Requiring positive evidence — a flag, a path, a redirect, or a bare
// single-token invocation — is what separates "run rm -rf /var/cache" from
// "then reboot the node once the rollout finishes".
func commandLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" {
		return ""
	}
	// Strip a shell prompt if present. A leading prompt is itself strong
	// evidence the author meant this to be executed.
	prompted := false
	for _, p := range []string{"$ ", "# ", "> ", "% "} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimSpace(s[len(p):])
			prompted = true
			break
		}
	}
	if s == "" {
		return ""
	}

	// Markdown list markers precede commands often enough to be worth peeling.
	for _, p := range []string{"- ", "* ", "+ "} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimSpace(s[len(p):])
			break
		}
	}

	// Constructs that are unambiguously executable regardless of how they are
	// tokenized: a fork bomb is not valid English, and a bare SQL statement in
	// an ops answer is meant to be run.
	if forkBombPattern.MatchString(s) || sqlStatementPattern.MatchString(s) {
		return s
	}

	cmds := splitCommands(s)
	if len(cmds) == 0 {
		return ""
	}
	name := cmds[0].Name()
	if name == "" || !isKnownBinary(name) {
		return ""
	}
	if prompted {
		return s
	}

	// A line that reads as a sentence is an explanation, even if it opens with
	// a word that happens to also be a program name. This single test does the
	// work: requiring a flag or a path as positive evidence sounded safer but
	// silently ignored subcommand-style invocations like "systemctl stop nginx"
	// and "kubectl delete pods --all"'s shorter cousins.
	if looksLikeSentence(s) {
		return ""
	}
	return s
}

// sentenceWords are function words that essentially never appear as bare shell
// arguments but appear constantly in operator prose.
var sentenceWords = map[string]bool{
	"the": true, "then": true, "this": true, "that": true, "your": true,
	"you": true, "should": true, "will": true, "would": true, "can": true,
	"could": true, "and": true, "but": true, "with": true, "from": true,
	"into": true, "after": true, "before": true, "once": true, "when": true,
	"if": true, "because": true, "which": true, "there": true, "these": true,
	"those": true, "please": true, "make": true, "sure": true, "node": true,
	"pod": true, "server": true, "service": true, "cluster": true,
	"instance": true, "machine": true, "host": true, "container": true,
}

func looksLikeSentence(s string) bool {
	fields := strings.Fields(strings.ToLower(s))
	hits := 0
	for _, f := range fields {
		if sentenceWords[strings.Trim(f, ".,;:!?()\"'")] {
			hits++
		}
	}
	if hits >= 2 {
		return true
	}
	// Trailing sentence punctuation with any function word at all.
	last := s[len(s)-1]
	return hits >= 1 && (last == '.' || last == '?' || last == '!' || last == 0x82)
}

// knownBinaries is the set of program names the guard is willing to treat as a
// command when it appears in prose. Restricting to a known set keeps ordinary
// English from being lexed as shell.
var knownBinaries = map[string]bool{
	"rm": true, "rmdir": true, "dd": true, "mkfs": true, "shred": true,
	"chmod": true, "chown": true, "chgrp": true, "truncate": true,
	"shutdown": true, "reboot": true, "poweroff": true, "halt": true,
	"init": true, "systemctl": true, "service": true, "killall": true,
	"pkill": true, "kill": true, "find": true, "xargs": true,
	"curl": true, "wget": true, "sh": true, "bash": true, "zsh": true,
	"kubectl": true, "helm": true, "docker": true, "podman": true,
	"iptables": true, "nft": true, "ufw": true, "firewall-cmd": true,
	"mysql": true, "psql": true, "mongo": true, "redis-cli": true,
	"terraform": true, "aws": true, "gcloud": true, "az": true,
	"git": true, "npm": true, "pip": true, "apt": true, "yum": true, "dnf": true,
	"mv": true, "cp": true, "ln": true, "tar": true, "unzip": true,
	"echo": true, "cat": true, "printf": true, "tee": true, "history": true,
	"journalctl": true, "nc": true, "ncat": true, "sfdisk": true, "deluser": true,
	"parted": true, "fdisk": true, "mkswap": true, "wipefs": true,
	"crontab": true, "at": true, "userdel": true, "groupdel": true,
}
