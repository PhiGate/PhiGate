package redact

import "strings"

// validators are checksum functions applied to a candidate match. They exist so
// broad, cheap patterns can be used safely: "twelve consecutive digits" would be
// unusably noisy as a My Number rule, but "twelve digits whose check digit is
// valid" has a false-positive rate near 1-in-11.
//
// A validator returns true when the match should be kept.
var validators = map[string]func(string) bool{
	"luhn":             validLuhn,
	"jp_mynumber":      validMyNumber,
	"jp_corporate_no":  validCorporateNumber,
	"not_all_same":     notAllSameDigit,
	"plausible_secret": plausibleSecret,
}

// digitsOf strips separators commonly used inside formatted numbers.
func digitsOf(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validLuhn implements the Luhn checksum used by payment cards, plus an issuer
// prefix check.
//
// Luhn alone is not enough, and benchmarking against public log corpora proved
// it: roughly one in ten random digit runs satisfies Luhn, so on 16,000 lines of
// LogHub system logs the rule fired 674 times — every one a Hadoop block id or a
// process id, not a card. That is not merely dictionary noise. A card is
// classified as PII, PII is "confidential", and confidential payloads are
// confined to the local model — so a false positive silently stops ordinary
// infrastructure logs from ever reaching the cloud backend, degrading both
// answer quality and the routing economics the product is sold on.
//
// Requiring a real Issuer Identification Number alongside Luhn removes
// essentially all of them, because an ID that passes Luhn still has to begin
// with a digit sequence some card network actually issues.
func validLuhn(s string) bool {
	d := digitsOf(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	if !notAllSameDigit(d) {
		return false
	}
	// A bare 19-digit run is far more often an identifier than a card. Real
	// 19-digit cards exist but are nearly always written in groups when a
	// human pastes one into a ticket, and the grouped form still matches.
	if len(d) == 19 && len(strings.TrimSpace(s)) == 19 {
		return false
	}
	if !plausibleCardIIN(d) {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// plausibleCardIIN reports whether d begins with an Issuer Identification
// Number that a card network actually assigns, and has a length that issuer
// uses. JCB is included deliberately: it is the dominant domestic card brand in
// Japan, and a JP-focused product that missed it would fail on exactly the
// records it most needs to protect.
func plausibleCardIIN(d string) bool {
	n := len(d)
	pfx := func(i, j int) int {
		if j > n {
			return -1
		}
		v := 0
		for _, c := range d[i:j] {
			v = v*10 + int(c-'0')
		}
		return v
	}
	p1, p2, p3, p4 := pfx(0, 1), pfx(0, 2), pfx(0, 3), pfx(0, 4)

	switch {
	case p1 == 4: // Visa
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55: // Mastercard
		return n == 16
	case p4 >= 2221 && p4 <= 2720: // Mastercard 2-series
		return n == 16
	case p2 == 34 || p2 == 37: // American Express
		return n == 15
	case p4 == 6011 || p2 == 65: // Discover
		return n >= 16 && n <= 19
	case p3 >= 644 && p3 <= 649: // Discover
		return n >= 16 && n <= 19
	case p4 >= 3528 && p4 <= 3589: // JCB — the major Japanese issuer
		return n >= 16 && n <= 19
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38, p2 == 39: // Diners Club
		return n >= 14 && n <= 19
	case p2 == 62: // UnionPay
		return n >= 16 && n <= 19
	}
	return false
}

// validMyNumber implements the check digit of the Japanese Individual Number
// (個人番号 / マイナンバー), defined by 総務省令 as:
//
//	check = 11 - ( Σ(n=1..11) P(n)·Q(n) ) mod 11
//	P(n)  = the (n+1)-th digit counting from the lowest order
//	Q(n)  = n+1 when n+1 ≤ 6, otherwise n-5
//	check = 0 when the result is 10 or 11
//
// Detecting My Number correctly is the single most important JP-specific
// requirement: it is 特定個人情報 under the My Number Act and must never reach a
// cloud LLM.
func validMyNumber(s string) bool {
	d := digitsOf(s)
	if len(d) != 12 || !notAllSameDigit(d) {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(d[11-n] - '0')
		q := n + 1
		if n > 6 {
			q = n - 5
		}
		sum += p * q
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return check == int(d[11]-'0')
}

// validCorporateNumber implements the check digit of the Japanese Corporate
// Number (法人番号): a 13-digit value whose leading digit is the check digit over
// the trailing 12.
//
//	check = 9 - ( ( Σ odd-position digits ·1 + Σ even-position digits ·2 ) mod 9 )
//
// counting positions from the lowest order of the 12-digit body.
func validCorporateNumber(s string) bool {
	d := digitsOf(s)
	if len(d) != 13 || !notAllSameDigit(d) {
		return false
	}
	body := d[1:] // 12-digit body
	sum := 0
	for n := 1; n <= 12; n++ {
		p := int(body[12-n] - '0')
		if n%2 == 1 {
			sum += p
		} else {
			sum += 2 * p
		}
	}
	return 9-(sum%9) == int(d[0]-'0')
}

// notAllSameDigit rejects placeholder runs like 000000000000 or 111111111111,
// which appear constantly in test fixtures and redacted sample logs.
func notAllSameDigit(s string) bool {
	d := digitsOf(s)
	if d == "" {
		return false
	}
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return true
		}
	}
	return false
}

// plausibleSecret filters key-like matches that are obviously placeholders.
// Masking "password=<redacted>" or "token=YOUR_TOKEN_HERE" adds dictionary noise
// and makes the compression ratio look better than it is.
func plausibleSecret(s string) bool {
	t := strings.Trim(strings.TrimSpace(s), `"'`)
	if len(t) < 4 {
		return false
	}
	switch strings.ToLower(t) {
	case "none", "null", "nil", "true", "false", "empty", "unset", "redacted",
		"<redacted>", "changeme", "xxxx", "****", "...", "***":
		return false
	}
	if strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">") {
		return false // template placeholder, e.g. <your-token>
	}
	if strings.HasPrefix(t, "${") || strings.HasPrefix(t, "$(") {
		return false // shell/CI variable reference, not a literal
	}
	allStars := true
	for _, r := range t {
		if r != '*' && r != 'x' && r != 'X' && r != '.' {
			allStars = false
			break
		}
	}
	return !allStars
}
