package redact

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed packs/*.json
var builtinPacks embed.FS

var (
	errDuplicateRule    = errors.New("duplicate rule name")
	errUnknownValidator = errors.New("unknown validator")
)

// RuleError identifies which rule failed to load, so a typo in a customer's
// custom pack names the offending rule instead of failing anonymously.
type RuleError struct {
	Rule string
	Err  error
}

func (e *RuleError) Error() string { return fmt.Sprintf("rule %q: %v", e.Rule, e.Err) }
func (e *RuleError) Unwrap() error { return e.Err }

// BuiltinPackNames lists the rule packs compiled into the binary.
func BuiltinPackNames() []string {
	entries, err := fs.ReadDir(builtinPacks, "packs")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}

// LoadBuiltinPacks returns the named built-in packs, or all of them when no
// names are given. Loading a pack that does not exist is an error rather than a
// silent no-op: a typo in PHIGATE_REDACT_PACKS must not quietly disable
// credential detection.
func LoadBuiltinPacks(names ...string) ([]Pack, error) {
	if len(names) == 0 {
		names = BuiltinPackNames()
	}
	packs := make([]Pack, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		b, err := builtinPacks.ReadFile("packs/" + n + ".json")
		if err != nil {
			return nil, fmt.Errorf("unknown built-in rule pack %q (have %v)", n, BuiltinPackNames())
		}
		var p Pack
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("parse built-in pack %q: %w", n, err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// LoadPackDir reads every *.json rule pack in dir. This is how an enterprise
// ships its own detection rules — internal employee-ID formats, project
// codenames, customer identifiers — without forking the binary.
func LoadPackDir(dir string) ([]Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rule pack dir: %w", err)
	}
	var packs []Pack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var p Pack
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if p.Name == "" {
			p.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	return packs, nil
}

// RulesFromDir flattens every rule in every pack under dir.
func RulesFromDir(dir string) ([]Rule, error) {
	packs, err := LoadPackDir(dir)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, p := range packs {
		rules = append(rules, p.Rules...)
	}
	return rules, nil
}
