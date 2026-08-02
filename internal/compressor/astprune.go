package compressor

import (
	"regexp"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// ASTPruner performs structural pruning of code/config snippets using
// tree-sitter. It parses a snippet into its syntax tree, then re-emits a
// compact skeleton that keeps the logical structure (keywords, operators,
// punctuation) and ERROR/MISSING nodes while replacing business values
// (identifiers, string/number literals) and comments with type placeholders.
//
// Pruning is intentionally LOSSY: the original source is NOT byte-for-byte
// reconstructable from the skeleton. This is acceptable because a cloud LLM
// only needs the logical structure to reason about a defect, and stripping the
// values is precisely what keeps business data inside the gateway. Masker /
// RefDict tokens remain fully hydratable; pruned code is summarised, not
// rebuilt. Stripped leaf values are still recorded in the dictionary on a
// best-effort basis.
type ASTPruner struct {
	langs map[string]*tree_sitter.Language
}

// NewASTPruner returns a pruner with the Go and Python grammars loaded.
func NewASTPruner() *ASTPruner {
	return &ASTPruner{
		langs: map[string]*tree_sitter.Language{
			"go":     tree_sitter.NewLanguage(tree_sitter_go.Language()),
			"python": tree_sitter.NewLanguage(tree_sitter_python.Language()),
		},
	}
}

// Name implements Stage.
func (a *ASTPruner) Name() string { return "astprune" }

// Process detects whether the input is a supported code snippet; if so it
// returns the pruned skeleton, otherwise it returns the input unchanged so that
// plain logs flow through untouched.
func (a *ASTPruner) Process(input string, s *Session) (string, error) {
	lang := detectLang(input)
	if lang == "" {
		return input, nil
	}
	grammar, ok := a.langs[lang]
	if !ok {
		return input, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(grammar); err != nil {
		return input, nil // fail open: never block traffic on a parser hiccup
	}

	src := []byte(input)
	tree := parser.Parse(src, nil)
	if tree == nil {
		return input, nil
	}
	defer tree.Close()

	var tokens []string
	collectLeaves(tree.RootNode(), src, false, s, &tokens)
	if len(tokens) == 0 {
		return input, nil
	}
	return joinTokens(tokens), nil
}

// collectLeaves walks the tree depth-first, appending one token per leaf node.
// inError propagates the fact that an ancestor is an ERROR node so malformed
// regions are preserved verbatim (they are the most diagnostically useful part
// of a broken snippet).
func collectLeaves(n *tree_sitter.Node, src []byte, inError bool, s *Session, out *[]string) {
	if n == nil {
		return
	}
	malformed := inError || n.IsError() || n.IsMissing()

	// Replace a whole value node (string/number literal, identifier, …) with a
	// single placeholder and do not descend into it. Doing this at node level —
	// not leaf level — collapses composite literals such as Go's
	// interpreted_string_literal ("\"" + content + "\"") into one <str> token.
	// Skipped inside malformed regions, which we keep verbatim.
	if !malformed {
		if ph, isValue := valuePlaceholder(n.Kind()); isValue {
			if v := strings.TrimSpace(n.Utf8Text(src)); v != "" {
				s.Dict.Mask(v, ClassVar) // best-effort record
			}
			*out = append(*out, ph)
			return
		}
	}

	if n.ChildCount() == 0 {
		text := strings.TrimSpace(n.Utf8Text(src))
		// Preserve malformed tokens so the model sees the actual defect.
		if malformed {
			if text != "" {
				*out = append(*out, text)
			}
			return
		}
		// Drop comments entirely — pure business/PII risk, no structural value.
		if n.Kind() == "comment" {
			return
		}
		// Keyword / operator / punctuation: keep verbatim as structure.
		if text != "" {
			*out = append(*out, text)
		}
		return
	}

	childErr := inError || n.IsError()
	for i := uint(0); i < n.ChildCount(); i++ {
		collectLeaves(n.Child(i), src, childErr, s, out)
	}
}

// valuePlaceholder maps a leaf node kind to its anonymised placeholder. The
// boolean reports whether the kind is a value that should be replaced.
func valuePlaceholder(kind string) (string, bool) {
	switch kind {
	case "identifier", "field_identifier", "package_identifier",
		"dotted_name", "label_name", "property_identifier":
		return "<id>", true
	case "type_identifier", "primitive_type":
		return "<type>", true
	case "interpreted_string_literal", "raw_string_literal",
		"string", "string_literal", "string_content":
		return "<str>", true
	case "int_literal", "integer":
		return "<int>", true
	case "float_literal", "float":
		return "<float>", true
	case "rune_literal", "character":
		return "<rune>", true
	case "imaginary_literal":
		return "<num>", true
	default:
		return "", false
	}
}

var (
	goMarkers = regexp.MustCompile(`(?m)^\s*package\s+\w+|func\s|:=`)
	pyMarkers = regexp.MustCompile(`(?m)^\s*(def|class|import|from)\s|print\(|elif\b`)
)

// detectLang returns "go", "python", or "" using conservative source markers,
// so that ordinary log lines are never misclassified as code.
func detectLang(s string) string {
	switch {
	case goMarkers.MatchString(s):
		return "go"
	case pyMarkers.MatchString(s):
		return "python"
	default:
		return ""
	}
}

// noSpaceBefore/noSpaceAfter control pretty joining of the token stream so the
// skeleton reads naturally instead of "func <id> ( ) {".
var (
	noSpaceBefore = map[string]bool{")": true, "]": true, "}": true, ",": true, ":": true, ";": true, ".": true}
	noSpaceAfter  = map[string]bool{"(": true, "[": true, ".": true, "@": true}
)

func joinTokens(tokens []string) string {
	var b strings.Builder
	for i, t := range tokens {
		if i > 0 {
			prev := tokens[i-1]
			if !noSpaceBefore[t] && !noSpaceAfter[prev] {
				b.WriteByte(' ')
			}
		}
		b.WriteString(t)
	}
	return b.String()
}
