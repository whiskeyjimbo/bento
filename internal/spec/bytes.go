package spec

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseBytes accepts "128M", "1G", "65536", "4K" etc. and returns
// the byte count. Suffixes are powers-of-1024 (K=1024, M=1024², G=1024³).
// Bare numbers are treated as bytes. Returns 0 + error for invalid
// input. Case-insensitive ("1g" == "1G").
func ParseBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSpace(strings.ToUpper(s))
	var multiplier int64 = 1
	switch s[len(s)-1] {
	case 'K':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'M':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'G':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("byte size cannot be negative: %d", n)
	}
	return n * multiplier, nil
}
