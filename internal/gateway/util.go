package gateway

import (
	"io"
	"net/http"
	"strconv"
)

// io_ReadAllLimited reads a bounded request body.
func io_ReadAllLimited(r *http.Request, max int64) ([]byte, error) {
	if max <= 0 {
		max = 4 << 20
	}
	return io.ReadAll(io.LimitReader(r.Body, max))
}

// trimFloat renders a float with at most one decimal place and no trailing zero.
func trimFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	if len(s) > 2 && s[len(s)-2:] == ".0" {
		return s[:len(s)-2]
	}
	return s
}
