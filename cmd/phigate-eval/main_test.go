package main

import "testing"

// TestParseVerdictAcceptsWhatModelsActuallyReturn.
//
// The harness exists to measure local models, so its judge parser has to
// tolerate what a local model actually emits rather than what the prompt asked
// for. Every case below except the last was observed or is one step from it;
// the trailing-prose case is verbatim the shape that failed a full eval run at
// its final case and discarded the seven scores before it.
func TestParseVerdictAcceptsWhatModelsActuallyReturn(t *testing.T) {
	for name, tc := range map[string]struct {
		reply string
		score float64
	}{
		"bare":            {`{"score": 8, "comment": "good"}`, 8},
		"fenced":          {"```json\n{\"score\": 7, \"comment\": \"ok\"}\n```", 7},
		"trailing prose":  {`{"score": 8, "comment": "correct"} Rationale: the answer names the right check.`, 8},
		"leading prose":   {"Here is my grade:\n{\"score\": 6, \"comment\": \"thin\"}", 6},
		"trailing object": {`{"score": 9, "comment": "x"} {"score": 1}`, 9},
		"integer score":   {`{"score": 10, "comment": "complete"}`, 10},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := parseVerdict(tc.reply)
			if err != nil {
				t.Fatalf("parseVerdict(%q) errored: %v", tc.reply, err)
			}
			if v.Score != tc.score {
				t.Errorf("score = %v, want %v", v.Score, tc.score)
			}
		})
	}
}

// TestParseVerdictRefusesWhatItCannotRead. An unreadable score must not become
// a zero: that reports a quality regression the model never produced.
func TestParseVerdictRefusesWhatItCannotRead(t *testing.T) {
	for name, reply := range map[string]string{
		"no object": "I cannot grade this answer.",
		"empty":     "",
		"truncated": `{"score": 8, "comment": "cut off mid`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseVerdict(reply); err == nil {
				t.Errorf("parseVerdict(%q) returned no error; an unreadable score must not count as zero", reply)
			}
		})
	}
}
