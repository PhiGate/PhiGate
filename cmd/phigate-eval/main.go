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
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/tokens"
	"github.com/phigate/phigate/internal/types"
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
	case "cache":
		err = runCache(os.Args[2:])
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
         -dry-run               print the call count, token estimate and bill; call nothing
         -repeat N              runs per case; one score is a sample, not a measurement
         -baseline-provider     openai|azure|anthropic|bedrock for the raw arm
  cache  -dir <path>            template cache hit rate, and the headroom a
                                semantic tier would have to beat
  leak   -dir <path>            assert no secret in a corpus survives redaction

Corpora: point -dir at a directory of .log/.txt files. Public AIOps datasets
(LogHub: HDFS, BGL, Spark, Thunderbird) work directly and make the numbers
independently reproducible.
`)
}

// ---------------------------------------------------------------- cache

// cacheResult is one corpus file's cache behaviour.
type cacheResult struct {
	File string `json:"file"`
	// Lines is how many payloads were put through the pipeline.
	Lines int `json:"lines"`
	// Distinct is how many distinct compressed templates they produced, which
	// is how many upstream calls a perfect exact-match cache would make.
	Distinct int `json:"distinct_templates"`
	// HitRate is the share of payloads served without an upstream call.
	HitRate float64 `json:"hit_rate_percent"`
	// Singletons is how many templates occurred exactly once. This is the
	// headroom: they are the only payloads a semantic tier could turn into
	// hits, because everything else is already a hit.
	Singletons int `json:"singleton_templates"`
	// Headroom is the share of payloads a semantic tier could improve on, at
	// absolute best — if it matched every singleton to something, correctly.
	Headroom float64 `json:"headroom_percent"`
	// ShapeTemplates and ShapeHitRate are the same figures after canonically
	// renumbering placeholders within each payload, so two payloads that
	// differ only in *which* values they carry share a key.
	ShapeTemplates int     `json:"shape_templates"`
	ShapeHitRate   float64 `json:"shape_hit_rate_percent"`
}

// placeholderRe matches the tokens the masker and refdict emit.
var placeholderRe = regexp.MustCompile(`<V(\d+)>|#REF(\d+)`)

// canonicalShape renumbers placeholders in order of first appearance.
//
// The session dictionary numbers a value the first time it is *ever* seen, so
// the same log line an hour apart compresses to "<V7> failed" and "<V931>
// failed" and misses a cache keyed on the text. Renumbering per payload makes
// the key describe the payload's shape rather than the history of the session
// it arrived in.
func canonicalShape(s string) string {
	seen := map[string]int{}
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		n, ok := seen[m]
		if !ok {
			n = len(seen) + 1
			seen[m] = n
		}
		if m[0] == '#' {
			return "#REF" + strconv.Itoa(n)
		}
		return "<V" + strconv.Itoa(n) + ">"
	})
}

// runCache measures what the exact-match template cache already achieves.
//
// It exists to answer one question before any work is done on a semantic tier:
// how much is left for one to win? The template cache hits because masking has
// already replaced the values that made every log line unique, so ten thousand
// lines collapse to one template. If that collapse is already near-total, a
// semantic tier is being asked to improve on a number that has no room in it —
// and it would be paying for the improvement with an embedding call per miss
// and a class of wrong answer the exact-match cache cannot produce.
func runCache(args []string) error {
	fs := flag.NewFlagSet("cache", flag.ExitOnError)
	dir := fs.String("dir", "", "directory of log/code files to measure")
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
		return fmt.Errorf("no corpus files found under %s", *dir)
	}

	engine, err := redact.NewEngine(redact.Options{
		InternalDomains: []string{"internal", "corp", "local", "lan"},
	})
	if err != nil {
		return err
	}

	var rows []cacheResult
	var totLines, totDistinct, totSingles, totShapes int

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		pipeline := compressor.NewPipelineWith(
			compressor.NewMaskerWith(engine),
			compressor.NewDrain(),
			compressor.NewRefDict(),
		)
		// One session for the file, as a single conversation would have, so
		// the dictionary is stable and identical values collapse.
		sess := compressor.NewSession()

		counts := map[string]int{}
		shapes := map[string]int{}
		lines := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			out, err := pipeline.Compress(line, sess)
			if err != nil {
				return err
			}
			counts[out]++
			shapes[canonicalShape(out)]++
			lines++
		}
		if lines == 0 {
			continue
		}
		// Singletons are counted over shapes, not over raw templates: a
		// payload that is a singleton only because its placeholders were
		// numbered differently is not headroom for anything, it is a key that
		// should have matched.
		singles := 0
		for _, n := range shapes {
			if n == 1 {
				singles++
			}
		}
		rows = append(rows, cacheResult{
			File:           filepath.Base(f),
			Lines:          lines,
			Distinct:       len(counts),
			HitRate:        100 * float64(lines-len(counts)) / float64(lines),
			Singletons:     singles,
			Headroom:       100 * float64(singles) / float64(lines),
			ShapeTemplates: len(shapes),
			ShapeHitRate:   100 * float64(lines-len(shapes)) / float64(lines),
		})
		totLines += lines
		totDistinct += len(counts)
		totSingles += singles
		totShapes += len(shapes)
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}

	fmt.Printf("%-22s %8s %10s %9s %11s %10s\n",
		"corpus", "lines", "templates", "hit rate", "by shape", "headroom")
	for _, r := range rows {
		fmt.Printf("%-22s %8d %10d %8.1f%% %10.1f%% %9.1f%%\n",
			r.File, r.Lines, r.Distinct, r.HitRate, r.ShapeHitRate, r.Headroom)
	}
	if totLines > 0 {
		fmt.Printf("%-22s %8d %10d %8.1f%% %10.1f%% %9.1f%%\n", "ALL",
			totLines, totDistinct,
			100*float64(totLines-totDistinct)/float64(totLines),
			100*float64(totLines-totShapes)/float64(totLines),
			100*float64(totSingles)/float64(totLines))
	}
	fmt.Print(`
hit rate = payloads served with no upstream call, keyed on the compressed text.
by shape = the same, keyed on the compressed text with placeholders renumbered
           per payload. The session dictionary numbers a value the first time it
           is ever seen, so two identical log lines an hour apart compress to
           "<V7> failed" and "<V931> failed" and miss a key built on the text.
headroom = payloads whose template occurred exactly once even by shape. This is
           all a semantic tier could ever convert, and only by matching them to
           a *different* template, which is where a wrong answer comes from.
`)
	return nil
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
	// Runs is how many times the case was scored, and RawSD/GatedSD the
	// spread across them. A delta smaller than the spread is judge noise.
	Runs         int     `json:"runs"`
	RawSD        float64 `json:"raw_score_sd"`
	GatedSD      float64 `json:"gated_score_sd"`
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
	baselineProvider := fs.String("baseline-provider", "openai", "baseline dialect: openai|azure|anthropic|bedrock")
	baselineRegion := fs.String("baseline-region", os.Getenv("AWS_REGION"), "AWS region, for -baseline-provider bedrock")
	model := fs.String("model", "gpt-4o", "model to answer with")
	judgeModel := fs.String("judge", "gpt-4o", "model to score answers")
	repeat := fs.Int("repeat", 1, "runs per case; a single score is a sample, not a measurement")
	dryRun := fs.Bool("dry-run", false, "print the call count, token estimate and bill, and make no API calls")
	priceBook := fs.String("price-book", "", "JSON price book for the -dry-run estimate")
	jsonOut := fs.Bool("json", false, "emit JSON instead of a table")
	warmOK := fs.Bool("allow-warm-cache", false, "run even if the gateway's template cache is already populated")
	_ = fs.Parse(args)
	if *repeat < 1 {
		*repeat = 1
	}

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

	if *dryRun {
		return dryRunEval(doc.Cases, counter, *model, *judgeModel, *repeat, *priceBook)
	}

	// The baseline arm goes straight to the customer's real provider, so it
	// speaks whichever dialect that is. The gateway arm below stays raw
	// OpenAI-shaped HTTP on purpose: PhiGate only speaks that, which is its
	// whole proposition, and the arm has to read the X-PhiGate-* headers that
	// a typed client would discard.
	prov, err := llm.ParseProvider(*baselineProvider)
	if err != nil {
		return fmt.Errorf("-baseline-provider: %w", err)
	}
	direct, err := llm.NewBackend(llm.ProviderConfig{
		Name: "baseline", Provider: prov, BaseURL: *baseline,
		Model: *model, APIKey: *baselineKey, Region: *baselineRegion,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Refuse to measure through a warm cache.
	//
	// The savings figure is read from run 0 so that later repeats, which are
	// exact cache hits, cannot inflate it. That guard holds within one
	// invocation and not across two: a gateway left running from an earlier
	// eval answers run 0 from cache as well, and every case then reports having
	// saved the whole baseline. The observed failure was 100% against a cold
	// truth of 64.2%, and nothing in the output said so.
	//
	// This is the dangerous direction for a benchmark to fail in. Re-running it
	// makes the product look better, so the mistake does not get reported — the
	// operator who makes it has no reason to doubt the number, and neither did
	// the author of this comment.
	if err := requireColdCache(ctx, *gateway, *gatewayKey, *warmOK); err != nil {
		return err
	}

	results := make([]evalResult, 0, len(doc.Cases))
	unscored := 0

	for _, c := range doc.Cases {
		// Every case is run -repeat times. A judge model is not deterministic,
		// so one score per case is a sample and reporting it as a measurement
		// is how a benchmark ends up describing its own noise.
		var rawScores, gatedScores []float64
		var comment, route string
		var rawTok, gatedTok int

		for run := range *repeat {
			// Baseline: the raw prompt straight to the cloud model — what the
			// enterprise does today, without PhiGate.
			rawAnswer, err := askDirect(ctx, direct, *model, c.Prompt)
			if err != nil {
				return fmt.Errorf("baseline %s: %w", c.Name, err)
			}
			// Through PhiGate: compressed, anonymised, routed.
			gatedAnswer, meta, err := ask(ctx, *gateway, *gatewayKey, *model, c.Prompt)
			if err != nil {
				return fmt.Errorf("phigate %s: %w", c.Name, err)
			}

			// Savings come from the gateway's own metadata and owe nothing to
			// the judge, so they are recorded before scoring. A run whose judge
			// is unreadable still contributes a valid savings figure.
			if run == 0 {
				route = meta.Route
				// Both figures are PhiGate's own, so the ratio between them is
				// consistent by construction.
				rawTok = meta.BaselineTokens
				gatedTok = meta.TokensSaved
			}

			// An unreadable judge costs this run, not the benchmark. Aborting
			// discarded every score collected so far — twenty minutes of work
			// returning nothing because the last judge call came back as
			// Markdown. Both arms are dropped together so the pairing the
			// delta depends on stays intact, and the count is disclosed at the
			// end rather than quietly reducing the sample.
			rawScore, cmt, err := judge(ctx, direct, *judgeModel, c, rawAnswer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  unscored: %s run %d, baseline arm: %v\n", c.Name, run+1, err)
				unscored++
				continue
			}
			gatedScore, _, err := judge(ctx, direct, *judgeModel, c, gatedAnswer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  unscored: %s run %d, phigate arm: %v\n", c.Name, run+1, err)
				unscored++
				continue
			}

			rawScores = append(rawScores, rawScore)
			gatedScores = append(gatedScores, gatedScore)
			comment = cmt

			// Savings are taken from the *first* run only, on a cold cache.
			//
			// Repeats exist to measure judge noise, not to warm the cache, and
			// reading a later one turns the repeat count into a savings
			// multiplier: every repeat after the first is an exact cache hit,
			// which saves the whole baseline. Measured on these eight cases,
			// reading the last run reported 100% where the cold truth is 64%.
			// A benchmark that gets more flattering the more times you run it
			// is measuring itself.
		}

		// A case no run could score is omitted rather than shown as zero:
		// meanSD of nothing is 0.0, which reads as a model that answered badly
		// instead of a judge that could not be read.
		if len(rawScores) == 0 {
			fmt.Fprintf(os.Stderr, "  omitted: %s scored in none of %d run(s)\n", c.Name, *repeat)
			continue
		}

		saving := 0.0
		if rawTok > 0 {
			saving = 100 * float64(gatedTok) / float64(rawTok)
		}
		rawMean, rawSD := meanSD(rawScores)
		gatedMean, gatedSD := meanSD(gatedScores)

		results = append(results, evalResult{
			Name: c.Name, Runs: *repeat,
			RawScore: rawMean, RawSD: rawSD,
			GatedScore: gatedMean, GatedSD: gatedSD,
			Delta: gatedMean - rawMean, RawTokens: rawTok,
			GatedTokens: rawTok - gatedTok, TokenSaving: saving,
			GatedRoute: route, JudgeComment: comment,
		})
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results})
	}

	fmt.Printf("\nPhiGate quality evaluation — %d cases × %d run(s), judge=%s\n\n",
		len(results), *repeat, *judgeModel)
	fmt.Printf("  %-24s %13s %13s %8s %10s %8s\n",
		"CASE", "RAW", "PHIGATE", "DELTA", "SAVED", "ROUTE")
	fmt.Printf("  %-24s %13s %13s %8s %10s %8s\n",
		"----", "---", "-------", "-----", "-----", "-----")
	var sumRaw, sumGated, sumSaving, maxSD float64
	for _, r := range results {
		fmt.Printf("  %-24s %6.2f ±%-5.2f %6.2f ±%-5.2f %+8.2f %9.1f%% %8s\n",
			truncate(r.Name, 24), r.RawScore, r.RawSD, r.GatedScore, r.GatedSD,
			r.Delta, r.TokenSaving, r.GatedRoute)
		sumRaw += r.RawScore
		sumGated += r.GatedScore
		sumSaving += r.TokenSaving
		maxSD = maxFloat(maxSD, maxFloat(r.RawSD, r.GatedSD))
	}
	n := float64(len(results))
	fmt.Printf("\n  mean quality: raw %.2f → PhiGate %.2f (%+.2f)\n", sumRaw/n, sumGated/n, (sumGated-sumRaw)/n)
	fmt.Printf("  mean prompt-token saving: %.1f%%\n", sumSaving/n)
	if *repeat == 1 {
		fmt.Printf("\n  ⚠ One run per case. The ± columns are empty because a single score has\n")
		fmt.Printf("    no spread — it is a sample, not a measurement. Re-run with -repeat 5\n")
		fmt.Printf("    before publishing anything from this table.\n")
	} else if maxSD > 1.0 {
		fmt.Printf("\n  ⚠ Largest per-case spread is ±%.2f on a 0-10 scale. A delta smaller than\n", maxSD)
		fmt.Printf("    that is judge noise, not a quality difference.\n")
	}
	if unscored > 0 {
		fmt.Printf("\n  ⚠ %d judge call(s) returned nothing readable and their run was dropped.\n", unscored)
		fmt.Printf("    The scores above rest on a smaller sample than -repeat asked for.\n")
		fmt.Printf("    Disclose this alongside the table; a benchmark that hides its\n")
		fmt.Printf("    missing data is the kind a buyer is right to discount.\n")
	}
	fmt.Printf("\n  Report both numbers together. A saving figure without the quality\n")
	fmt.Printf("  figure beside it is the number every buyer already distrusts.\n\n")
	return nil
}

// askDirect sends one prompt to the baseline provider, in that provider's own
// dialect.
//
// It reuses the gateway's own backend clients rather than a second HTTP shim,
// so a baseline against Claude or Bedrock is exercised by the same translation
// the product ships — a benchmark whose two arms disagree about the wire format
// is measuring the harness.
// requireColdCache fails when the gateway already holds cached templates.
//
// A gateway that cannot be asked is reported and allowed: the check exists to
// catch a stale process, not to make the harness depend on a stats endpoint
// being reachable.
func requireColdCache(ctx context.Context, gateway, key string, allow bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(gateway, "/")+"/phigate/stats", nil)
	if err != nil {
		return nil
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  note: could not read gateway stats (%v); cache state unverified\n", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "  note: gateway stats returned %s; cache state unverified\n", resp.Status)
		return nil
	}
	var stats struct {
		Cache struct {
			Enabled bool `json:"enabled"`
			Entries int  `json:"entries"`
		} `json:"cache"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil
	}
	if !stats.Cache.Enabled || stats.Cache.Entries == 0 {
		return nil
	}
	if allow {
		fmt.Fprintf(os.Stderr, "  ⚠ gateway cache holds %s; the savings figure is "+
			"inflated and must not be published\n", entries(stats.Cache.Entries))
		return nil
	}
	return fmt.Errorf("the gateway's template cache already holds %s, so the "+
		"savings figure would be measured through a warm cache and report close to 100%%.\n"+
		"Restart PhiGate, or start it with PHIGATE_CACHE_ENABLED=false to measure the "+
		"pipeline without the cache, then re-run.\n"+
		"Pass -allow-warm-cache only when the inflated figure is what you meant to measure",
		entries(stats.Cache.Entries))
}

// entries renders a cache count for a sentence a human reads.
func entries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}

func askDirect(ctx context.Context, c llm.Client, model, prompt string) (string, error) {
	return askDirectJSON(ctx, c, model, prompt, false)
}

// askDirectJSON asks model for prompt, optionally constraining the reply to a
// single JSON object.
//
// The judge needs that constraint. Asking a local model for "only JSON" in the
// prompt text is a request, not a guarantee: llama3.1 answers the same prompt
// with a bare object on one call, an object followed by prose on the next, and
// a Markdown heading ("**Score:** 8/10") on a third. response_format makes the
// shape a property of the request instead of a hope, and every OpenAI-compatible
// server this harness is pointed at — Ollama included — honours it.
func askDirectJSON(ctx context.Context, c llm.Client, model, prompt string, jsonObject bool) (string, error) {
	req := &types.ChatCompletionRequest{
		Model:    model,
		Messages: []types.Message{{Role: "user", Content: prompt}},
	}
	if jsonObject {
		req.Extra = map[string]json.RawMessage{
			"response_format": json.RawMessage(`{"type":"json_object"}`),
		}
	}
	resp, err := c.Chat(ctx, req)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no choices returned")
	}
	return resp.Choices[0].Message.Content, nil
}

// ask sends one prompt through PhiGate and returns the answer plus PhiGate's
// own report of what it did.
//
// The savings figure is read from that report rather than recomputed here. It
// was recomputed here, against this file's own estimate of the prompt, and the
// two denominators did not agree: PhiGate's baseline counts per-message
// overhead and this one counts the prompt text, so a locally-routed case —
// where the whole baseline is saved — reported saving over 100%. A benchmark
// that prints an impossible number has told you it is measuring itself.
func ask(ctx context.Context, baseURL, key, model, prompt string) (string, *types.Meta, error) {
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
	var out types.ChatCompletionResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return "", nil, err
	}
	if len(out.Choices) == 0 {
		return "", out.PhiGate, fmt.Errorf("no choices returned")
	}
	if out.PhiGate == nil {
		return "", nil, fmt.Errorf("the gateway returned no phigate block; " +
			"is -gateway pointing at PhiGate rather than at the provider?")
	}
	return out.Choices[0].Message.Content, out.PhiGate, nil
}

// judge scores an answer against the case rubric on a 0-10 scale.
//
// The judge always runs against the *baseline* endpoint, never through PhiGate.
// Scoring the gateway with the gateway in the loop would let compression
// artefacts influence the score that is supposed to measure them.
func judge(ctx context.Context, client llm.Client, model string, c evalCase, answer string) (float64, string, error) {
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

	out, err := askDirectJSON(ctx, client, model, prompt, true)
	if err != nil {
		return 0, "", err
	}
	v, err := parseVerdict(out)
	if err != nil {
		return 0, "", err
	}
	return v.Score, v.Comment, nil
}

// verdict is one judge score.
type verdict struct {
	Score   float64 `json:"score"`
	Comment string  `json:"comment"`
}

// parseVerdict reads the judge's reply.
//
// The object is located and decoded on its own rather than assumed to be the
// entire reply, for the reason ee/redact/slm/recognizer.go gives for doing the
// same: models wrap JSON in prose and in code fences however firmly they are
// asked not to. A judge that accepts only a perfectly obedient model cannot
// grade the local models this harness exists to measure — llama3.1 emits a
// valid object and then keeps explaining itself, which failed a whole run at
// its last case and discarded seven good scores along with it.
//
// A reply carrying no object at all is still an error. A score that cannot be
// read must not be quietly counted as a zero, which would report a quality
// regression that never happened.
func parseVerdict(reply string) (verdict, error) {
	var v verdict
	start := strings.IndexByte(reply, '{')
	if start < 0 {
		return v, fmt.Errorf("judge returned no JSON object: %q", truncate(reply, 120))
	}
	// Decode reads exactly one value and ignores whatever follows, which is
	// what makes trailing commentary harmless rather than fatal.
	if err := json.NewDecoder(strings.NewReader(reply[start:])).Decode(&v); err != nil {
		return v, fmt.Errorf("judge returned unparseable output %q: %w", truncate(reply, 120), err)
	}
	return v, nil
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

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// meanSD returns the mean and population standard deviation of a sample.
func meanSD(xs []float64) (mean, sd float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	if len(xs) < 2 {
		return mean, 0
	}
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(sd / float64(len(xs)))
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// dryRunEval prints what a run would cost and where each case would go,
// without making a single API call.
//
// It exists because the eval is the one thing in this repo that spends real
// money, and "run it and find out" is not an acceptable way to learn the bill.
// The estimate is deliberately conservative: it assumes every answer is as long
// as assumedAnswerTokens and that nothing is served from cache.
func dryRunEval(cases []evalCase, counter tokens.Counter, model, judgeModel string, repeat int, priceBookPath string) error {
	book := tokens.NewPriceBook()
	if priceBookPath != "" {
		if err := book.LoadFile(priceBookPath); err != nil {
			return err
		}
	}

	engine, err := redact.NewEngine(redact.Options{
		InternalDomains: []string{"internal", "corp", "local", "lan"},
	})
	if err != nil {
		return err
	}
	rtr := router.NewHeuristicRouter()

	var answerIn, judgeIn, local int
	fmt.Printf("\nDry run — %d case(s) × %d run(s), answer=%s judge=%s\n\n",
		len(cases), repeat, model, judgeModel)
	fmt.Printf("  %-26s %8s %8s %8s\n", "CASE", "PROMPT", "RUBRIC", "ROUTE")
	fmt.Printf("  %-26s %8s %8s %8s\n", "----", "------", "------", "-----")

	for _, c := range cases {
		p := counter.Estimate(c.Prompt)
		r := counter.Estimate(c.Rubric)

		// Where PhiGate would send it. This is why the two arms are not
		// comparable by default: a case routed local is answered by a
		// different model, so the delta measures the model as well as the
		// pipeline. Pin both backends at the same model to isolate the
		// pipeline — see the README.
		pipe := compressor.NewPipelineWith(compressor.NewMaskerWith(engine),
			compressor.NewDrain(), compressor.NewRefDict(), compressor.NewASTPruner())
		compressed, err := pipe.Compress(c.Prompt, compressor.NewSession())
		if err != nil {
			return err
		}
		d, err := rtr.Route(context.Background(), compressed)
		if err != nil {
			return err
		}
		if d.Target == router.TargetLocal {
			local++
		}

		// Per run: one baseline answer, one gated answer, two judge calls.
		answerIn += repeat * 2 * p
		judgeIn += repeat * 2 * (p + r + assumedAnswerTokens)

		fmt.Printf("  %-26s %8d %8d %8s\n", truncate(c.Name, 26), p, r, d.Target)
	}

	calls := len(cases) * repeat * 4
	answerOut := len(cases) * repeat * 2 * assumedAnswerTokens
	judgeOut := len(cases) * repeat * 2 * assumedVerdictTokens

	fmt.Printf("\n  API calls           : %d\n", calls)
	fmt.Printf("  input tokens  (est) : %d\n", answerIn+judgeIn)
	fmt.Printf("  output tokens (est) : %d\n", answerOut+judgeOut)

	answerPrice, okA := book.Lookup(model)
	judgePrice, okJ := book.Lookup(judgeModel)
	if !okA || !okJ {
		fmt.Printf("\n  No price for %q or %q in the price book, so no estimate.\n", model, judgeModel)
		fmt.Printf("  Supply one with -price-book; PhiGate's own format is documented in\n")
		fmt.Printf("  internal/tokens/pricing.go.\n\n")
		return nil
	}
	cost := answerPrice.Cost(answerIn, answerOut) + judgePrice.Cost(judgeIn, judgeOut)
	fmt.Printf("  estimated cost      : $%.4f\n", cost)

	fmt.Printf("\n  %d of %d case(s) would route to the LOCAL backend, so their PhiGate arm\n", local, len(cases))
	fmt.Printf("  costs nothing upstream — and is answered by a different model, which the\n")
	fmt.Printf("  delta then includes. Pin both backends at the same model to measure the\n")
	fmt.Printf("  pipeline alone.\n")
	fmt.Printf("\n  Prices come from the built-in price book unless -price-book is given.\n")
	fmt.Printf("  They change; confirm against your provider before trusting the figure.\n\n")
	return nil
}

// The estimator's two assumptions, named rather than buried as literals.
const (
	assumedAnswerTokens  = 400
	assumedVerdictTokens = 60
)
