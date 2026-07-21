package main

import (
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// theme renders the interactive UI with ANSI color, but only when the output is a
// real terminal. It is deliberately self-contained - it imports nothing from the
// store or policy - so the whole file can lift into tack unchanged.
//
// Color is disabled when NO_COLOR is set or the output is not a TTY. That second
// rule is also what keeps test output clean: tests write to an in-memory buffer, not
// a terminal, so every assertion sees plain text with no escape codes to match around.
type theme struct{ on bool }

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
)

// newTheme enables color only for a terminal writer with NO_COLOR unset. A non-file
// writer (an in-memory test buffer) or a redirected file yields a no-color theme.
func newTheme(w io.Writer) theme {
	if os.Getenv("NO_COLOR") != "" {
		return theme{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return theme{}
	}
	fi, err := f.Stat()
	if err != nil {
		return theme{}
	}
	return theme{on: fi.Mode()&os.ModeCharDevice != 0}
}

// paint wraps s in an ANSI code and a reset, or returns it unchanged when color is
// off or the string is empty (so an empty field never emits a dangling escape).
func (t theme) paint(code, s string) string {
	if !t.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (t theme) bold(s string) string  { return t.paint(ansiBold, s) }
func (t theme) dim(s string) string   { return t.paint(ansiDim, s) }
func (t theme) allow(s string) string { return t.paint(ansiGreen, s) }
func (t theme) deny(s string) string  { return t.paint(ansiRed, s) }
func (t theme) warn(s string) string  { return t.paint(ansiYellow, s) }

// kindLabel colors an access-kind word by kind, so read/write/exec/reach are
// distinguishable at a glance.
// kindLabel colors an access-kind label. Callers pad before coloring (so the plain
// runes are measured for alignment), so the switch is on the trimmed kind while the
// paint keeps the padding - otherwise the four-letter kinds ("read", "exec") arrive
// padded to five columns and never match.
func (t theme) kindLabel(kind string) string {
	switch strings.TrimSpace(kind) {
	case "read":
		return t.paint(ansiBlue, kind)
	case "write":
		return t.paint(ansiYellow, kind)
	case "exec":
		return t.paint(ansiMagenta, kind)
	case "reach":
		return t.paint(ansiCyan, kind)
	}
	return kind
}

// The status glyphs and prompt caret. Text-presentation symbols, not emoji, so
// terminal width stays predictable.
func (t theme) markAllow() string { return t.allow("✓") } // ✓
func (t theme) markDeny() string  { return t.deny("✗") }  // ✗
func (t theme) caret() string     { return t.bold("›") }  // ›

// pad right-pads s to w display columns, measured on the plain runes so an already
// colored string is not mis-measured by its escape codes (callers pad before color).
func pad(s string, w int) string {
	if n := w - utf8.RuneCountInString(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}
