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

// validLuhn implements the Luhn checksum used by payment cards. Without it, a
// credit-card pattern fires on any 13-19 digit run — order numbers, trace IDs,
// and log sequence numbers included.
func validLuhn(s string) bool {
	d := digitsOf(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	if !notAllSameDigit(d) {
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
