// SPDX-License-Identifier: BUSL-1.1

package slm

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// gazetteer finds where a surname occurs in text.
//
// It is a filter, not a detector. Its job is to keep the model from being asked
// about text that cannot contain a name, and it is tuned for recall: every
// occurrence of a listed surname is a candidate, including the many that are
// place names, compounds, or parts of longer words. Masking on this alone would
// be precisely the over-masking jp.json declined to ship when it disabled
// jp_name_kanji by default.
type gazetteer struct {
	// byFirstRune indexes surnames by their first rune, so scanning is one
	// map lookup per character rather than a pass over the whole list.
	byFirstRune map[rune][]string
	maxLen      int
}

func newGazetteer(words []string) *gazetteer {
	g := &gazetteer{byFirstRune: map[rune][]string{}}
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		r, _ := utf8.DecodeRuneInString(w)
		g.byFirstRune[r] = append(g.byFirstRune[r], w)
		if len(w) > g.maxLen {
			g.maxLen = len(w)
		}
	}
	// Longest first, so 佐々木 is preferred over 佐々 at the same position.
	for r := range g.byFirstRune {
		sort.Slice(g.byFirstRune[r], func(i, j int) bool {
			return len(g.byFirstRune[r][i]) > len(g.byFirstRune[r][j])
		})
	}
	return g
}

// candidates returns each surname occurrence, extended over the characters that
// follow it.
//
// The extension matters: a name is a surname *plus a given name*, and masking
// only the surname would leave half the value in the text. Japanese personal
// names run to about four characters after the surname, and the recognizer is
// what decides where this one actually ends — the span offered here is the
// widest plausible one, and an implementation may return a shorter span inside
// it.
func (g *gazetteer) candidates(text string) []Span {
	var out []Span
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size <= 1 {
			i++
			continue
		}
		matched := 0
		for _, w := range g.byFirstRune[r] {
			if strings.HasPrefix(text[i:], w) {
				matched = len(w)
				break
			}
		}
		if matched == 0 {
			i += size
			continue
		}
		out = append(out, Span{Start: i, End: i + matched + trailingNameBytes(text[i+matched:])})
		i += matched
	}
	return out
}

// maxGivenNameRunes bounds how far past a surname a candidate reaches. Japanese
// given names are one to three characters in the overwhelming majority; four is
// the generous end and keeps a runaway span from swallowing a sentence.
const maxGivenNameRunes = 4

// particleStarts are the hiragana that, immediately after a name, are far more
// often grammar than part of it.
//
// The extension below has to cross hiragana, because a good many given names
// are written in it. It also has to stop, or "田中太郎です" becomes a candidate
// including the copula and the model is asked whether a name-plus-です is a
// name. These are the characters that end the run: the case particles, the
// topic and object markers, and the openings of the polite copula.
var particleStarts = map[rune]bool{
	'は': true, 'が': true, 'を': true, 'に': true, 'へ': true, 'と': true,
	'で': true, 'も': true, 'の': true, 'や': true, 'か': true, 'ね': true,
	'よ': true, 'ま': true, 'だ': true, 'な': true,
}

// trailingNameBytes measures the run of characters after a surname that could
// belong to the same name.
//
// One space is allowed first, because "田中 太郎" is an ordinary way to write a
// full name and stopping at the space would offer the model a surname with the
// given name left in the clear beside it. Punctuation, digits and Latin letters
// end the run, which keeps a candidate from running into the rest of the
// sentence and presenting the model with a span it can only answer wrongly.
func trailingNameBytes(rest string) int {
	n := 0
	if r, size := utf8.DecodeRuneInString(rest); r == ' ' || r == '\u3000' {
		// Only useful if a name actually follows; a trailing space is not part
		// of a name.
		next, _ := utf8.DecodeRuneInString(rest[size:])
		if isNameRune(next) && !particleStarts[next] {
			n = size
		}
	}
	afterSpace := n

	runes := 0
	for n < len(rest) && runes < maxGivenNameRunes {
		r, size := utf8.DecodeRuneInString(rest[n:])
		if !isNameRune(r) || (isHiragana(r) && particleStarts[r]) {
			break
		}
		n += size
		runes++
	}
	if n == afterSpace {
		return 0 // nothing followed but the space
	}
	return n
}

func isHiragana(r rune) bool { return r >= 0x3040 && r <= 0x309F }

func isNameRune(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF: // CJK unified ideographs
		return true
	case isHiragana(r):
		return true
	case r >= 0x30A0 && r <= 0x30FF: // katakana
		return true
	case r == 'ヶ' || r == '々':
		return true
	}
	return false
}

// DefaultSurnames is the built-in gazetteer: the most common Japanese family
// names, which cover a large share of the population by design.
//
// It is a starting point rather than a census. A deployment whose records skew
// regionally should supply its own list through Options.Gazetteer — the layer's
// recall is bounded by this, and a name whose surname is not here is never
// offered to the model at all.
func DefaultSurnames() []string {
	return []string{
		"佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "渡邊", "山本", "中村", "小林",
		"加藤", "吉田", "山田", "佐々木", "山口", "松本", "井上", "木村", "林", "斎藤",
		"斉藤", "齋藤", "清水", "山崎", "阿部", "森", "池田", "橋本", "石川", "山下",
		"小川", "石井", "長谷川", "後藤", "岡田", "近藤", "前田", "藤田", "遠藤", "青木",
		"坂本", "村上", "太田", "金子", "藤井", "福田", "西村", "三浦", "竹内", "中島",
		"岡本", "松田", "原田", "中野", "小野", "田村", "藤原", "中川", "和田", "中山",
		"石田", "上田", "森田", "原", "内田", "柴田", "酒井", "宮崎", "横山", "高木",
		"安藤", "宮本", "大野", "小島", "谷口", "工藤", "今井", "高田", "増田", "丸山",
		"杉山", "村田", "大塚", "新井", "小山", "平野", "菅原", "武田", "上野", "杉本",
		"島田", "菊地", "菊池", "野口", "松井", "渡部", "野村", "松尾", "市川", "水野",
	}
}
