package main

import (
	"regexp"
	"strings"
	"testing"
)

// ansiRE matches an ANSI SGR sequence, so a test can strip color and check the
// payload underneath survived intact.
var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// The color path is never exercised by the other tests (they write to a buffer, so
// color is off). This forces it on and checks every wrapper is well-formed: the
// plain payload survives, the string is reset-terminated, and there is exactly one
// balanced reset (no dangling escape that would bleed color into later output).
func TestThemeWrappingIsWellFormed(t *testing.T) {
	th := theme{on: true}
	cases := []struct{ name, got, plain string }{
		{"allow", th.allow("ok"), "ok"},
		{"deny", th.deny("no"), "no"},
		{"warn", th.warn("net"), "net"},
		{"bold", th.bold("x"), "x"},
		{"dim", th.dim("hint"), "hint"},
		{"kind read", th.kindLabel("read"), "read"},
		{"kind write", th.kindLabel("write"), "write"},
		{"mark allow", th.markAllow(), "✓"},
		{"mark deny", th.markDeny(), "✗"},
		{"caret", th.caret(), "›"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if stripped := ansiRE.ReplaceAllString(tc.got, ""); stripped != tc.plain {
				t.Errorf("payload after stripping color = %q, want %q (raw %q)", stripped, tc.plain, tc.got)
			}
			if tc.got == tc.plain {
				t.Errorf("color was not applied to %q", tc.plain)
			}
			if !strings.HasSuffix(tc.got, ansiReset) {
				t.Errorf("%q is not reset-terminated - it would bleed color forward", tc.got)
			}
			if n := strings.Count(tc.got, ansiReset); n != 1 {
				t.Errorf("expected exactly one reset, got %d in %q", n, tc.got)
			}
		})
	}

	// An unknown kind is returned verbatim (no color), and an off theme and an empty
	// payload never emit an escape - so a blank field cannot leave a dangling code.
	if th.kindLabel("mystery") != "mystery" {
		t.Error("an unknown kind must not be colored")
	}
	if (theme{}).allow("ok") != "ok" {
		t.Error("an off theme must pass text through unchanged")
	}
	if th.allow("") != "" {
		t.Error("an empty payload must not emit an escape sequence")
	}
}
