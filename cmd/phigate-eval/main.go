// Command phigate-eval measures what PhiGate actually does to a payload.
//
// It exists because the two claims PhiGate is sold on are empirical, and until
// now nobody could check either of them:
//
//   - **Compression.** How many tokens does the pipeline actually remove, on
//     realistic AIOps input rather than on a hand-picked example? `bench` answers
//     that, per stage, so a reviewer can see which stage earns its cost.
//   - **Quality.** Does compressing and anonymising make the answers worse? This
//     is the first question every enterprise buyer asks and the hardest to
//     answer honestly. `eval` answers it by sending each case twice — once raw
//     to the cloud model, once through PhiGate — and scoring both answers with a
//     judge model against a rubric.
//
// The output is deliberately reproducible and boring: a table anyone can rerun.
// A published quality-versus-savings curve is worth more to a conservative buyer
// than any claim in a README.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/tokens"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bench":
		err = runBench(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	case "leak":
		err = runLeak(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "phigate-eval:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `phigate-eval — measure PhiGate's compression, safety and answer quality

  bench  -dir <path>            token reduction per pipeline stage over a corpus
  eval   -cases <file.json>     answer quality: raw cloud vs through PhiGate, judged
  leak   -dir <path>            assert no secret in a corpus survives redaction

Corpora: point -dir at a directory of .log/.txt files. Public AIOps datasets
(LogHub: HDFS, BGL, Spark, Thunderbird) work directly and make the numbers
independently reproducible.
`)
}

// ---------------------------------------------------------------- bench

// stageResult is one row of the bench table. The json tags matter: -json exists
// to be piped into other tools, and emitting Go's exported field names would
// make the schema an accident of the struct definition.
type stageResult struct {
	Stage string `json:"stage"`
	// Tokens remaining after this stage and everything before it.
	Tokens int `json:"tokens"`
	// Reduction is this stage's own contribution, as a percentage of what
	// reached it.
	Reduction float64 `json:"marginal_percent"`
	// Cumulative is the total reduction against the raw input.
	Cumulative float64 `json:"cumulative_percent"`
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	dir := fs.String("dir", "", "directory of log/code files to benchmark")
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	_ = fs.Parse(args)

	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}
	files, err := corpusFiles(*dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no .log/.txt/.json files found under %s", *dir)
	}

	counter := tokens.NewHeuristic()
	engine, err := redact.NewEngine(redact.Options{
		InternalDomains: []string{"internal", "corp", "local", "lan"},
	})
	if err != nil {
		return err
	}

	// Each cumulative pipeline prefix, so every stage's marginal contribution
	// is visible rather than only the total.
	stages := []struct {
		name  string
		build func() *compressor.Pipeline
	}{
		{"raw", nil},
		{"+masker", func() *compressor.Pipeline {
			return compressor.NewPipelineWith(compressor.NewMaskerWith(engine))
		}},
		{"+drain", func() *compressor.Pipeline {
			return compressor.NewPipelineWith(compressor.NewMaskerWith(engine), compressor.NewDrain())
		}},
		{"+refdict", func() *compressor.Pipeline {
			return compressor.NewPipelineWith(compressor.NewMaskerWith(engine),
				compressor.NewDrain(), compressor.NewRefDict())
		}},
		{"+astprune", func() *compressor.Pipeline {
			return compressor.NewPipelineWith(compressor.NewMaskerWith(engine),
				compressor.NewDrain(), compressor.NewRefDict(), compressor.NewASTPruner())
		}},
	}

	results := make([]stageResult, 0, len(stages))
	var rawTotal int
	prev := 0

	for _, st := range stages {
		total := 0
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			text := string(b)
			if st.build != nil {
				out, err := st.build().Compress(text, compressor.NewSession())
				if err != nil {
					return fmt.Errorf("%s: %w", f, err)
				}
				text = out
			}
			total += counter.Estimate(text)
		}
		if st.name == "raw" {
			rawTotal = total
		}
		r := stageResult{Stage: st.name, Tokens: total}
		if rawTotal > 0 {
			r.Cumulative = 100 * float64(rawTotal-total) / float64(rawTotal)
		}
		if prev > 0 {
			r.Reduction = 100 * float64(prev-total) / float64(prev)
		}
		prev = total
		results = append(results, r)
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"files": len(files), "stages": results,
		})
	}

	fmt.Printf("\nPhiGate compression benchmark — %d files under %s\n\n", len(files), *dir)
	fmt.Printf("  %-12s %12s %14s %14s\n", "STAGE", "TOKENS", "MARGINAL", "CUMULATIVE")
	fmt.Printf("  %-12s %12s %14s %14s\n", "-----", "------", "--------", "----------")
	for _, r := range results {
		marginal := "—"
		if r.Reduction != 0 {
			marginal = fmt.Sprintf("%.1f%%", r.Reduction)
		}
		fmt.Printf("  %-12s %12d %14s %13.1f%%\n", r.Stage, r.Tokens, marginal, r.Cumulative)
	}
	final := results[len(results)-1]
	fmt.Printf("\n  Prompt tokens reduced by %.1f%% before routing.\n", final.Cumulative)
	fmt.Printf("  Note: requests the router keeps local, and template-cache hits, avoid\n")
	fmt.Printf("  100%% of cloud prompt cost. This figure measures compression alone.\n\n")
	return nil
}

// ---------------------------------------------------------------- leak

func runLeak(args []string) error {
	fs := flag.NewFlagSet("leak", flag.ExitOnError)
	dir := fs.String("dir", "", "directory of files to scan")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}

	engine, err := redact.NewEngine(redact.Options{
		InternalDomains: []string{"internal", "corp", "local", "lan"},
	})
	if err != nil {
		return err
	}
	files, err := corpusFiles(*dir)
	if err != nil {
		return err
	}

	byCategory := map[redact.Category]int{}
	byRule := map[string]int{}
	total := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for _, fd := range engine.Detect(string(b)) {
			byCategory[fd.Category]++
			byRule[fd.Rule]++
			total++
		}
	}

	fmt.Printf("\nRedaction sweep — %d files, %d sensitive spans detected\n\n", len(files), total)
	fmt.Println("  BY CLASSIFICATION")
	for _, c := range []redact.Category{
		redact.CategorySecret, redact.CategoryPII, redact.CategoryNetwork,
		redact.CategoryPath, redact.CategoryIdentifier, redact.CategoryTemporal,
	} {
		if n := byCategory[c]; n > 0 {
			fmt.Printf("    %-12s %-14s %6d\n", c, "("+c.Sensitivity().String()+")", n)
		}
	}
	fmt.Println("\n  BY RULE")
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return byRule[rules[i]] > byRule[rules[j]] })
	for _, r := range rules {
		fmt.Printf("    %-28s %6d\n", r, byRule[r])
	}
	fmt.Println()
	return nil
}

// ---------------------------------------------------------------- eval

// evalCase is one quality test: a question, and what a good answer contains.
type evalCase struct {
	Name     string `json:"name"`
	Prompt   String `json:"prompt"`
	Rubric   string `json:"rubric"`
	Category string `json:"category,omitempty"`
}

// String is a plain string alias kept for JSON clarity in the case file.
type String = string

type evalResult struct {
	Name         string  `json:"name"`
	RawScore     float64 `json:"raw_score"`
	GatedScore   float64 `json:"phigate_score"`
	Delta        float64 `json:"delta"`
	RawTokens    int     `json:"raw_prompt_tokens"`
	GatedTokens  int     `json:"phigate_prompt_tokens"`
	TokenSaving  float64 `json:"token_saving_percent"`
	GatedRoute   string  `json:"phigate_route"`
	JudgeComment string  `json:"judge_comment,omitempty"`
}

func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	cases := fs.String("cases", "", "JSON file of evaluation cases")
	gateway := fs.String("gateway", "http://localhost:8080/v1", "PhiGate base URL")
	gatewayKey := fs.String("gateway-key", os.Getenv("PHIGATE_CLIENT_KEY"), "PhiGate API key")
	baseline := fs.String("baseline", "https://api.openai.com/v1", "baseline (uncompressed) base URL")
	baselineKey := fs.String("baseline-key", os.Getenv("OPENAI_API_KEY"), "baseline API key")
	model := fs.String("model", "gpt-4o", "model to answer with")
	judgeModel := fs.String("judge", "gpt-4o", "model to score answers")
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	_ = fs.Parse(args)

	if *cases == "" {
		return fmt.Errorf("-cases is required")
	}
	raw, err := os.ReadFile(*cases)
	if err != nil {
		return err
	}
	var doc struct {
		Cases []evalCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if len(doc.Cases) == 0 {
		return fmt.Errorf("no cases in %s", *cases)
	}

	counter := tokens.NewHeuristic()
	ctx := context.Background()
	results := make([]evalResult, 0, len(doc.Cases))

	for _, c := range doc.Cases {
		// Baseline: the raw prompt straight to the cloud model — what the
		// enterprise does today, without PhiGate.
		rawAnswer, _, err := ask(ctx, *baseline, *baselineKey, *model, c.Prompt)
		if err != nil {
			return fmt.Errorf("baseline %s: %w", c.Name, err)
		}
		// Through PhiGate: compressed, anonymised, routed.
		gatedAnswer, hdr, err := ask(ctx, *gateway, *gatewayKey, *model, c.Prompt)
		if err != nil {
			return fmt.Errorf("phigate %s: %w", c.Name, err)
		}

		rawScore, comment, err := judge(ctx, *baseline, *baselineKey, *judgeModel, c, rawAnswer)
		if err != nil {
			return fmt.Errorf("judge baseline %s: %w", c.Name, err)
		}
		gatedScore, _, err := judge(ctx, *baseline, *baselineKey, *judgeModel, c, gatedAnswer)
		if err != nil {
			return fmt.Errorf("judge phigate %s: %w", c.Name, err)
		}

		rawTok := counter.Estimate(c.Prompt)
		gatedTok := atoiHeader(hdr.Get("X-PhiGate-Tokens-Saved"))
		saving := 0.0
		if rawTok > 0 {
			saving = 100 * float64(gatedTok) / float64(rawTok)
		}

		results = append(results, evalResult{
			Name: c.Name, RawScore: rawScore, GatedScore: gatedScore,
			Delta: gatedScore - rawScore, RawTokens: rawTok,
			GatedTokens: rawTok - gatedTok, TokenSaving: saving,
			GatedRoute: hdr.Get("X-PhiGate-Route"), JudgeComment: comment,
		})
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results})
	}

	fmt.Printf("\nPhiGate quality evaluation — %d cases, judge=%s\n\n", len(results), *judgeModel)
	fmt.Printf("  %-24s %8s %8s %8s %10s %8s\n", "CASE", "RAW", "PHIGATE", "DELTA", "SAVED", "ROUTE")
	fmt.Printf("  %-24s %8s %8s %8s %10s %8s\n", "----", "---", "-------", "-----", "-----", "-----")
	var sumRaw, sumGated, sumSaving float64
	for _, r := range results {
		fmt.Printf("  %-24s %8.2f %8.2f %+8.2f %9.1f%% %8s\n",
			truncate(r.Name, 24), r.RawScore, r.GatedScore, r.Delta, r.TokenSaving, r.GatedRoute)
		sumRaw += r.RawScore
		sumGated += r.GatedScore
		sumSaving += r.TokenSaving
	}
	n := float64(len(results))
	fmt.Printf("\n  mean quality: raw %.2f → PhiGate %.2f (%+.2f)\n", sumRaw/n, sumGated/n, (sumGated-sumRaw)/n)
	fmt.Printf("  mean prompt-token saving: %.1f%%\n", sumSaving/n)
	fmt.Printf("\n  Report both numbers together. A saving figure without the quality\n")
	fmt.Printf("  figure beside it is the number every buyer already distrusts.\n\n")
	return nil
}

// ask sends one prompt and returns the answer plus the response headers, so the
// caller can read PhiGate's routing and savings metadata.
func ask(ctx context.Context, baseURL, key, model, prompt string) (string, http.Header, error) {
	body, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	cl := &http.Client{Timeout: 3 * time.Minute}
	resp, err := cl.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", nil, err
	}
	if len(out.Choices) == 0 {
		return "", resp.Header, fmt.Errorf("no choices returned")
	}
	return out.Choices[0].Message.Content, resp.Header, nil
}

// judge scores an answer against the case rubric on a 0-10 scale.
//
// The judge always runs against the *baseline* endpoint, never through PhiGate.
// Scoring the gateway with the gateway in the loop would let compression
// artefacts influence the score that is supposed to measure them.
func judge(ctx context.Context, baseURL, key, model string, c evalCase, answer string) (float64, string, error) {
	prompt := fmt.Sprintf(`You are grading an IT operations assistant's answer.

QUESTION:
%s

RUBRIC — a good answer should:
%s

ANSWER TO GRADE:
%s

Respond with only JSON: {"score": <0-10 number>, "comment": "<one sentence>"}.
Grade on technical correctness and actionability. Do not reward verbosity.`,
		c.Prompt, c.Rubric, answer)

	out, _, err := ask(ctx, baseURL, key, model, prompt)
	if err != nil {
		return 0, "", err
	}
	var verdict struct {
		Score   float64 `json:"score"`
		Comment string  `json:"comment"`
	}
	clean := strings.TrimSpace(out)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	if err := json.Unmarshal([]byte(strings.TrimSpace(clean)), &verdict); err != nil {
		return 0, "", fmt.Errorf("judge returned unparseable output %q: %w", truncate(out, 120), err)
	}
	return verdict.Score, verdict.Comment, nil
}

// ---------------------------------------------------------------- helpers

func corpusFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".log", ".txt", ".json", ".go", ".py", ".yaml", ".yml", ".sql":
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func atoiHeader(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
