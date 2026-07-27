package policy

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// valid is the minimal well-formed policy; tests mutate a copy to isolate one
// invariant at a time.
func valid() Policy {
	return Policy{Entrypoint: "./fetch.py", Interpreter: "python3"}
}

func TestValidateAcceptsWellFormedPolicy(t *testing.T) {
	p := valid()
	p.Env = []string{"LANG", "AWS_DEFAULT_REGION", "_UNDERSCORE1"}
	p.Read = []string{"."}
	p.Write = []string{"/tmp/out"}
	p.Network = []NetworkRule{
		{Host: "api.github.com", Port: "443"},
		{Host: ".example.com", Port: "8000-9000"},
		{Host: "*", Port: "*"},
		{Host: "10.0.0.1", Port: "5432"},
	}
	p.Exec = ExecNoneStrict
	p.Limits = Limits{Memory: "128M", CPU: "100%", PIDs: 32}

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// Only a LEADING tilde names a home directory. A file genuinely named with one is an
// ordinary path, and "./~backup" is the documented way to grant it - a contains-rule
// would refuse both spellings and leave such a file ungrantable. Args are never
// expanded, so a tilde there is just an argument.
func TestValidateAcceptsNonLeadingTildes(t *testing.T) {
	p := valid()
	p.Entrypoint = "./~backup"
	p.Read = []string{"./~odd", "data/~x", "/home/u/~"}
	p.Write = []string{"~/out", "~"}
	p.Args = []string{"~operator/keys"}

	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A genuine right-to-left path carries directional letters (Arabic, Hebrew), which
// have inherent direction and are not the explicit bidi format controls the
// Trojan-Source class rejects, plus other non-ASCII (accents, CJK, emoji). None of
// these must be refused - the control/bidi gate targets format characters only.
func TestValidateAcceptsNonASCIIAndRTLPaths(t *testing.T) {
	p := valid()
	p.Entrypoint = "/home/u/مشروع/run.py" // "project" in Arabic letters
	// Two runes sit deliberately outside the screen: the variation selector, which rides
	// along on real emoji filenames and hides nothing on its own, and a genuine U+FFFD,
	// which is three decodable bytes and a visible glyph rather than the undecodable
	// byte the screen refuses.
	p.Read = []string{"/data/café", "/データ/入力", "/emoji/📁", "/emoji/⚠️.txt", "/data/we�ird"}
	p.Args = []string{"--name=مرحبا", "--dir=Ελληνικά"}
	if err := p.Validate(); err != nil {
		t.Errorf("a policy with legitimate non-ASCII/RTL paths must validate: %v", err)
	}
}

// The screen tells an undecodable byte from a genuine U+FFFD by the decoded size, which
// is only sound if Go's decoder reports size 1 for every malformed sequence - not just
// the lone bad byte. Overlongs, surrogate halves, and out-of-range 4-byte forms are the
// ones that would slip through as clean if it ever reported more, so the property is
// pinned against utf8.ValidString rather than against a list of cases.
func TestFirstUnsafeRuneAgreesWithUTF8Validity(t *testing.T) {
	for _, s := range []string{
		"/data/x\xc0\xafy",         // overlong '/'
		"/data/x\xed\xa0\x80y",     // surrogate half
		"/data/x\xf4\x90\x80\x80y", // above U+10FFFF
		"/data/x\xf0\x82\x82\xacy", // overlong U+20AC
		"/data/x\xc3",              // truncated at end of string
		"/data/x\xe2\x80",          // truncated three-byte form
		"/data/x\x9by",             // the raw 8-bit CSI
		"/data/x�y",                // a genuine replacement character, which is fine
		"/data/plain",
	} {
		_, bad := FirstUnsafeRune(s)
		if want := !utf8.ValidString(s); bad != want {
			t.Errorf("FirstUnsafeRune(%q) reported %v, but utf8.ValidString says the string is valid=%v", s, bad, !want)
		}
	}
}

func TestValidateEmptyExecModeDefaultsValid(t *testing.T) {
	p := valid()
	if err := p.Validate(); err != nil {
		t.Fatalf("empty exec mode should be valid (means none): %v", err)
	}
}

// Validate is the gate for Go embedders, who construct a Policy directly rather
// than parsing a manifest. Each case is a malformed policy that must never reach
// a backend.
func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Policy)
		want string
	}{
		{"no entrypoint", func(p *Policy) { p.Entrypoint = "" }, "entrypoint is required"},
		{"env with space", func(p *Policy) { p.Env = []string{"OUT = required"} }, "invalid env name"},
		{"env with arrow glyph", func(p *Policy) { p.Env = []string{"OUT ← note"} }, "invalid env name"},
		{"env starting with digit", func(p *Policy) { p.Env = []string{"1PATH"} }, "invalid env name"},
		{"bad exec mode", func(p *Policy) { p.Exec = ExecMode("yes") }, "invalid exec mode"},
		{"empty host", func(p *Policy) { p.Network = []NetworkRule{{Host: "", Port: "80"}} }, "empty host"},
		{"non-canonical ip", func(p *Policy) { p.Network = []NetworkRule{{Host: "127.1", Port: "80"}} }, "canonical IP"},
		{"integer ip", func(p *Policy) { p.Network = []NetworkRule{{Host: "2852039166", Port: "80"}} }, "canonical IP"},
		{"bad hostname", func(p *Policy) { p.Network = []NetworkRule{{Host: "a_b.com", Port: "80"}} }, "not a valid hostname"},
		// An address has no subdomains, so matchHost would apply this as a string suffix:
		// it can only ever match a hostname ending in those characters, never the address
		// the author meant to allow.
		{"suffix wildcard over an ipv4 literal", func(p *Policy) { p.Network = []NetworkRule{{Host: ".10.0.0.1", Port: "80"}} }, "cannot be written over an IP address"},
		{"suffix wildcard over an ipv6 literal", func(p *Policy) { p.Network = []NetworkRule{{Host: ".::1", Port: "80"}} }, "cannot be written over an IP address"},
		{"host with newline", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com\nb", Port: "80"}} }, "control or reserved"},
		{"empty port", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: ""}} }, "empty port"},
		{"port out of range", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "70000"}} }, "out of range"},
		{"inverted range", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "900-100"}} }, "inverted"},
		// The proxy refuses a CONNECT target spelled this way, so such a rule would
		// validate and then match nothing - a silently dead allowlist entry.
		{"leading-zero port", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "08080"}} }, "plain decimal"},
		{"leading-zero range end", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "8000-09000"}} }, "plain decimal"},
		{"signed port", func(p *Policy) { p.Network = []NetworkRule{{Host: "a.com", Port: "+443"}} }, "plain decimal"},
		{"negative pids", func(p *Policy) { p.Limits = Limits{PIDs: -1} }, "pids must not be negative"},
		{"cpu without percent", func(p *Policy) { p.Limits = Limits{CPU: "100"} }, "must be a percentage"},
		{"cpu non-numeric", func(p *Policy) { p.Limits = Limits{CPU: "abc%"} }, "plain decimal percentage"},
		{"cpu control char", func(p *Policy) { p.Limits = Limits{CPU: "50\n%"} }, "plain decimal percentage"},
		{"cpu NaN", func(p *Policy) { p.Limits = Limits{CPU: "NaN%"} }, "plain decimal percentage"},
		{"cpu Inf", func(p *Policy) { p.Limits = Limits{CPU: "Inf%"} }, "plain decimal percentage"},
		{"cpu negative", func(p *Policy) { p.Limits = Limits{CPU: "-50%"} }, "plain decimal percentage"},
		// Spellings Go's ParseFloat takes and systemd's CPUQuota does not: they used to
		// validate and then fail at scope creation, after the operator was told the policy
		// was well-formed.
		{"cpu hex float", func(p *Policy) { p.Limits = Limits{CPU: "0x1p4%"} }, "plain decimal percentage"},
		{"cpu exponent", func(p *Policy) { p.Limits = Limits{CPU: "1e3%"} }, "plain decimal percentage"},
		{"cpu signed", func(p *Policy) { p.Limits = Limits{CPU: "+50%"} }, "plain decimal percentage"},
		{"cpu bare dot", func(p *Policy) { p.Limits = Limits{CPU: ".5%"} }, "plain decimal percentage"},
		// A digit string long enough to overflow float64 is decimal but not a real bound.
		{"cpu overflowing", func(p *Policy) { p.Limits = Limits{CPU: strings.Repeat("9", 400) + "%"} }, "too large"},
		// systemd parses a quota into permyriad, so a third fractional digit is invalid to
		// it and a zero quota is "too small". Both were verified against systemd directly;
		// accepting them here is the late-failure contract this validation exists to remove.
		{"cpu three fractional digits", func(p *Policy) { p.Limits = Limits{CPU: "12.345%"} }, "plain decimal percentage"},
		{"cpu zero", func(p *Policy) { p.Limits = Limits{CPU: "0%"} }, "is zero"},
		{"cpu zero with fraction", func(p *Policy) { p.Limits = Limits{CPU: "0.00%"} }, "is zero"},
		{"cpu leading zero", func(p *Policy) { p.Limits = Limits{CPU: "07%"} }, "plain decimal percentage"},
		// parseBytes used to trim, so this validated and then failed in systemd.
		{"memory with surrounding space", func(p *Policy) { p.Limits = Limits{Memory: " 128M "} }, "limits.memory"},
		{"memory with inner space", func(p *Policy) { p.Limits = Limits{Memory: "128 M"} }, "limits.memory"},
		{"unparseable memory", func(p *Policy) { p.Limits = Limits{Memory: "lots"} }, "limits.memory"},
		// An empty grant renders as "read: []" in the validate summary but resolves to
		// the working directory in the enforcer, so it reads as no grant and is not one.
		{"empty read grant", func(p *Policy) { p.Read = []string{""} }, "read[0] is empty"},
		{"empty write grant", func(p *Policy) { p.Write = []string{"/out", ""} }, "write[1] is empty"},
		// Host-independent, so it belongs at this gate rather than beside the expansion:
		// `bento validate` runs Validate but does not resolve paths, and refusing later
		// let validate print ok and approve stamp a manifest that could never run.
		{"other user's home in read", func(p *Policy) { p.Read = []string{"~operator/keys"} }, "read[0] \"~operator/keys\" names another user's home"},
		{"other user's home in write", func(p *Policy) { p.Write = []string{"/out", "~backup"} }, "write[1]"},
		{"other user's home in entrypoint", func(p *Policy) { p.Entrypoint = "~operator/run.sh" }, "entrypoint"},
		{"other user's home in interpreter", func(p *Policy) { p.Interpreter = "~operator/py" }, "interpreter"},
		{"escape in entrypoint", func(p *Policy) { p.Entrypoint = "/bin/true\x1b]0;PWNED\x07" }, "control character"},
		{"escape in interpreter", func(p *Policy) { p.Interpreter = "python3\x1b[31m" }, "control character"},
		{"escape in arg", func(p *Policy) { p.Args = []string{"--flag\x07"} }, "control character"},
		{"escape in read path", func(p *Policy) { p.Read = []string{"/data\nfoo"} }, "control character"},
		{"escape in write path", func(p *Policy) { p.Write = []string{"/out\x1b"} }, "control character"},
		{"c1 control in path", func(p *Policy) { p.Read = []string{"/data\u009b31m"} }, "control character"},
		{"bidi override in read path", func(p *Policy) { p.Read = []string{"/data/\u202egpj.exe"} }, "bidirectional formatting character"},
		{"bidi isolate in entrypoint", func(p *Policy) { p.Entrypoint = "/bin/\u2066run\u2069" }, "bidirectional formatting character"},
		{"bidi override in arg", func(p *Policy) { p.Args = []string{"--out=\u202dsafe"} }, "bidirectional formatting character"},
		{"zero-width space hides a segment", func(p *Policy) { p.Read = []string{"/data/\u200bsecret"} }, "zero-width or invisible"},
		{"zero-width joiner in path", func(p *Policy) { p.Write = []string{"/out/a\u200db"} }, "zero-width or invisible"},
		{"bom in entrypoint", func(p *Policy) { p.Entrypoint = "\ufeff/bin/run" }, "zero-width or invisible"},
		{"word joiner in arg", func(p *Policy) { p.Args = []string{"--x\u2060y"} }, "zero-width or invisible"},
		{"emoji ZWJ sequence rejected (deliberate tradeoff)", func(p *Policy) { p.Read = []string{"/data/\U0001F468\u200D\U0001F469.png"} }, "zero-width or invisible"},
		{"soft hyphen in path", func(p *Policy) { p.Read = []string{"/data/se\u00adcret"} }, "zero-width or invisible"},
		{"invisible math operator in arg", func(p *Policy) { p.Args = []string{"--x\u2061y"} }, "zero-width or invisible"},
		// A tag character carries no glyph at all, so the host below renders to an
		// operator as plain "example.com" while granting something else.
		{"tag character in arg", func(p *Policy) { p.Args = []string{"--host=ex\U000E0041ample.com"} }, "zero-width or invisible"},
		{"tag block terminator in path", func(p *Policy) { p.Read = []string{"/data/x\U000E007F"} }, "zero-width or invisible"},
		{"language tag in path", func(p *Policy) { p.Read = []string{"/data/\U000E0001x"} }, "zero-width or invisible"},
		{"mongolian vowel separator in path", func(p *Policy) { p.Read = []string{"/data/se\u180ecret"} }, "zero-width or invisible"},
		// The Hangul fillers are not format characters but render as blank, which is the
		// same spoof by a different table.
		{"hangul choseong filler in path", func(p *Policy) { p.Read = []string{"/data/se\u115fcret"} }, "zero-width or invisible"},
		{"hangul jungseong filler in path", func(p *Policy) { p.Read = []string{"/data/se\u1160cret"} }, "zero-width or invisible"},
		{"hangul filler in entrypoint", func(p *Policy) { p.Entrypoint = "/bin/ru\u3164n" }, "zero-width or invisible"},
		{"halfwidth hangul filler in arg", func(p *Policy) { p.Args = []string{"--x\uffa0y"} }, "zero-width or invisible"},
		{"combining grapheme joiner in path", func(p *Policy) { p.Read = []string{"/data/se\u034fcret"} }, "zero-width or invisible"},
		// A raw 0x9b decodes as RuneError rather than as U+009B, so no rune predicate
		// ever sees the 8-bit CSI a terminal would act on. The screen has to decode to
		// judge, which makes an undecodable byte its blind spot unless it says so.
		{"raw 8-bit CSI in path", func(p *Policy) { p.Read = []string{"/data/x\x9by"} }, "invalid UTF-8"},
		{"truncated multibyte in arg", func(p *Policy) { p.Args = []string{"--x=\xc3"} }, "invalid UTF-8"},
		// The renderer breaks the line here, so the grant reads as "/data/public" and
		// the segment that widens it sits on a line the operator never connects to it.
		{"line separator in read path", func(p *Policy) { p.Read = []string{"/data/public /../secrets"} }, "a line separator"},
		{"paragraph separator in arg", func(p *Policy) { p.Args = []string{"--out=safe /etc"} }, "a line separator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.mut(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateNilPolicy(t *testing.T) {
	var p *Policy
	if err := p.Validate(); err == nil {
		t.Error("nil policy should not validate")
	}
}

func TestLimitsIsZero(t *testing.T) {
	if !(Limits{}).IsZero() {
		t.Error("empty Limits should be zero")
	}
	if (Limits{PIDs: 1}).IsZero() {
		t.Error("Limits with PIDs set should not be zero")
	}
}

func TestParseBytes(t *testing.T) {
	cases := map[string]int64{"1024": 1024, "1K": 1 << 10, "128M": 128 << 20, "2G": 2 << 30}
	for in, want := range cases {
		got, err := parseBytes(in)
		if err != nil {
			t.Errorf("parseBytes(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseBytes(%q) = %d, want %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "lots", "-1", "12X3"} {
		if _, err := parseBytes(bad); err == nil {
			t.Errorf("parseBytes(%q) should fail", bad)
		}
	}
}
