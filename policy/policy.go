// Package policy defines the validated permission model at the core of Bento.
//
// A Policy is the permission declaration a script runs under. It is pure domain
// data and behavior: no I/O, no serialization format, no platform knowledge, and
// no dependency on any enforcement backend. Backends (Linux, macOS) and
// frontends (CLI, JSON, library) all depend on this package; it depends on
// nothing of theirs. Empty/nil fields mean "deny".
//
// Validate is the single gate on a well-formed Policy. Every construction path
// must pass through it - the YAML loader and Go library embedders alike - so an
// invalid Policy can never reach a backend.
package policy

import (
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Policy is the permission declaration for a single script or binary.
type Policy struct {
	// Entrypoint is the script or compiled binary to run.
	Entrypoint string
	// Interpreter runs the entrypoint (e.g. "python3"). Empty means the
	// entrypoint is its own interpreter: a compiled ELF/Mach-O binary.
	Interpreter string
	// Args are fixed arguments passed to the entrypoint.
	Args []string
	// Env is an allowlist of host environment-variable NAMES passed through to
	// the sandbox when set. Values are never declared here.
	Env []string
	// Read and Write are host paths granted read-only and read-write access.
	Read  []string
	Write []string
	// Network is the outbound egress allowlist. Nil or empty denies all egress.
	Network []NetworkRule
	// Exec is the subprocess-spawning policy. The zero value is ExecNone.
	Exec ExecMode
	// Limits are resource ceilings; the zero value imposes none.
	Limits Limits
}

// ExecMode is the subprocess-spawning policy.
type ExecMode string

const (
	// ExecNone (default) soft-blocks execve: it stops the exec paths glibc/musl
	// use (subprocess/fork+exec/os.system) but a raw execveat can still spawn.
	ExecNone ExecMode = "none"
	// ExecNoneStrict additionally blocks fork/vfork and process-creating clone
	// while permitting thread-creating clone. Not a total no-child guarantee:
	// execveat and io_uring remain reachable.
	ExecNoneStrict ExecMode = "none-strict"
	// ExecAll permits arbitrary subprocesses. It never relaxes filesystem or
	// network confinement.
	ExecAll ExecMode = "all"
)

// NetworkRule is one outbound allowance. There is exactly one rule form: a host
// and a port, both strings. Port is a string so a single port and a range never
// differ in type.
type NetworkRule struct {
	// Host is a literal hostname, a ".suffix" wildcard (matches subdomains, not
	// the bare domain), a canonical IP literal, or "*" (any host).
	Host string
	// Port is a literal port ("443"), an inclusive range ("8000-9000"), or "*".
	Port string
}

// Limits are per-run resource ceilings. Empty string / zero means unset.
type Limits struct {
	// Memory is a byte quantity (e.g. "128M", "1G").
	Memory string
	// CPU is a percentage quota (e.g. "100%", "50%").
	CPU string
	// PIDs caps the number of tasks (processes + threads).
	PIDs int
}

// IsZero reports whether no limit is set.
func (l Limits) IsZero() bool { return l == Limits{} }

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// cpuPercentRe is the percentage spelling accepted for Limits.CPU, matched against the
// value with its "%" removed. Validate forwards the string to systemd verbatim, so a
// spelling Go's ParseFloat takes and systemd's CPUQuota does not - "0x1p4%", "1e3%",
// "+50%" - passed validation and then failed at scope creation, long after the operator
// was told the policy was well-formed.
//
// The two-digit fraction is not cosmetic: systemd parses a quota into permyriad
// (hundredths of a percent), so it rejects "12.345%" outright. Matching that bound here
// is what makes the difference between an early refusal and a late one.
//
// This is deliberately NARROWER than systemd rather than identical to it. systemd takes
// "07%"; bento refuses the leading zero, as it does for a port, so one quota has one
// spelling - two policies that mean the same thing but differ textually would otherwise
// carry different fingerprints and need separate approvals. ".5%" and "50.%" are refused
// on the same principle. The direction is what matters: narrower means a policy that
// validates will run, wider means the false contract this exists to remove.
var cpuPercentRe = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$`)

// Validate reports whether the policy is well-formed. It is the one gate every
// construction path passes through, so a Go embedder building a Policy directly
// gets the same guarantees as a manifest parsed from YAML.
//
// It reports the first problem only. A frontend rendering the whole list to someone
// editing the policy - which is what a manifest is - calls Problems instead.
func (p *Policy) Validate() error {
	if probs := p.Problems(); len(probs) > 0 {
		return probs[0]
	}
	return nil
}

// Problems returns every malformed field, in the order the checks below run, so a
// manifest with several mistakes can be fixed in one pass rather than one run per
// mistake. Empty means the policy is well-formed.
//
// Two screens still answer on their own, where a list would be worse than a terse
// answer: a nil policy has no fields to examine, and a value carrying a deceiving
// character is echoed back in its own refusal - listing it beside unrelated problems
// buries the one line the reader has to look at closely, which is why that screen runs
// before anything is collected. Exec and Limits report their own first problem each,
// which is where the list stops being exhaustive.
func (p *Policy) Problems() []error {
	if p == nil {
		return []error{fmt.Errorf("policy: nil policy")}
	}
	// The path and argument fields are echoed verbatim by the frontends - the
	// validate summary, error messages naming a bad path - so a deceiving character in
	// one lets an untrusted manifest mislead the operator reading it: a control
	// character reprograms the terminal (ESC/OSC window spoofing, hidden text), a bidi
	// override reorders the display, a zero-width character hides a segment, a line
	// separator pushes the rest off the display, and a byte that does not decode at all
	// carries an 8-bit control past every rune predicate - each so a value reads as
	// something other than what it grants. No legitimate path or
	// argument carries any of them. Rejecting here, at the
	// single gate every construction path passes through, closes it for the CLI and Go
	// embedders alike; the host field is already guarded separately.
	fields := append([]string{p.Entrypoint, p.Interpreter}, p.Args...)
	fields = append(append(fields, p.Read...), p.Write...)
	for _, f := range fields {
		if r, ok := FirstUnsafeRune(f); ok {
			return []error{fmt.Errorf("policy: value %q contains %s, which is not allowed in a path or argument", f, DescribeUnsafeRune(r))}
		}
	}
	var probs []error
	if p.Entrypoint == "" {
		probs = append(probs, fmt.Errorf("policy: entrypoint is required"))
	}
	// An empty path grant is not a grant of nothing. It survives the manifest-dir
	// anchoring untouched, renders as "read: []" in the validate summary - so an operator
	// reviewing the run sees no grant at all - and then the enforcer joins it onto the
	// working directory, handing the target everything under it. A manifest carrying
	// write: [""] and run from $HOME grants the whole home directory under a value that
	// reads as absent. Read and Write are the only fields where empty means that: an
	// absent Interpreter and an empty argv element (sh -c '') are both legitimate, which
	// is why this cannot fold into the character screen above.
	for _, l := range []struct {
		name  string
		paths []string
	}{{"read", p.Read}, {"write", p.Write}} {
		for i, path := range l.paths {
			if path == "" {
				// The YAML hint earns its place: an unquoted `- ~` is the null tag, so the
				// manifest most likely to land here reads as a home grant and decodes to nothing.
				probs = append(probs, fmt.Errorf("policy: %s[%d] is empty; a grant must name a path (an empty value reads as no grant but resolves to the working directory; in YAML, quote a bare tilde as \"~\" - unquoted it is null)", l.name, i))
			}
		}
	}
	// A leading "~" means the invoking user's home, and nothing else: "~operator/keys"
	// would need a passwd lookup, and both fallbacks - treating it as relative, or as
	// the invoker's own home - grant something other than what the manifest names. The
	// rule holds regardless of the host it is checked on, which is why it belongs here
	// rather than beside the expansion: validate runs this gate but does not resolve
	// paths, so refusing later would let validate print ok and approve stamp a manifest
	// that can never run. Only a leading tilde is special - "./~backup" and "data/~x"
	// name ordinary files and pass, and Args are never expanded at all.
	for _, f := range []struct {
		name string
		path string
	}{{"entrypoint", p.Entrypoint}, {"interpreter", p.Interpreter}} {
		if err := screenTilde(f.name, f.path); err != nil {
			probs = append(probs, err)
		}
	}
	for _, l := range []struct {
		name  string
		paths []string
	}{{"read", p.Read}, {"write", p.Write}} {
		for i, path := range l.paths {
			if err := screenTilde(fmt.Sprintf("%s[%d]", l.name, i), path); err != nil {
				probs = append(probs, err)
			}
		}
	}
	// A write grant of home itself is refused wherever it is checked, because the
	// credential stores it would make writable sit at fixed names inside home: whatever
	// $HOME turns out to be, `~/.ssh` is under it. That is what lets the refusal live
	// here, at a gate that never looks at the host, rather than only in the enforcer -
	// `bento validate` runs this and would otherwise print ok for a manifest that can
	// never run. The enforcer still refuses the same grant spelled absolutely
	// (write: /home/u), which needs $HOME to recognize.
	//
	// Read is deliberately exempt: `read: "~"` is the documented broad grant, and the
	// shields stay engaged inside it. Only write would put the shields' parent in reach.
	for i, w := range p.Write {
		if rest, ok := strings.CutPrefix(w, "~"); ok && filepath.Clean("/"+rest) == "/" {
			probs = append(probs, fmt.Errorf("policy: write[%d] %q grants your home directory or a parent of it, which would make the credential stores bento shields inside it (~/.ssh, ~/.aws, ...) writable through their parent; grant the specific directory the program writes to", i, w))
		}
	}
	for _, name := range p.Env {
		if !envNameRe.MatchString(name) {
			probs = append(probs, fmt.Errorf("policy: invalid env name %q: must match [A-Za-z_][A-Za-z0-9_]* (env is an allowlist of variable names, not values)", name))
		}
	}
	if err := p.Exec.validate(); err != nil {
		probs = append(probs, err)
	}
	for i, r := range p.Network {
		if err := r.Validate(); err != nil {
			probs = append(probs, fmt.Errorf("policy: network rule %d: %w", i, err))
		}
	}
	if err := p.Limits.validate(); err != nil {
		probs = append(probs, err)
	}
	return probs
}

// NamesOtherUserHome reports whether path uses the "~operator/keys" spelling. Only a
// leading tilde is special: "./~backup" and "data/~x" name ordinary files.
//
// Exported because the refusal has to hold at two places that cannot share a call
// stack - Validate, the gate every construction path passes through and the only one
// `bento validate` runs, and the tilde expansion in package manifest, which a Go
// embedder can reach with a policy it built itself.
func NamesOtherUserHome(path string) bool {
	rest, ok := strings.CutPrefix(path, "~")
	return ok && rest != "" && !strings.HasPrefix(rest, "/")
}

// RequireExpanded refuses a policy whose paths still carry a leading "~", which means
// manifest.Resolve has not run on it. It is the enforcement boundary's precondition,
// not a well-formedness check, which is why it is separate from Validate: on the CLI
// path Validate runs at the parse gate, before the fingerprint check and therefore
// before resolution, where "~/.config" is exactly what the manifest is supposed to say.
//
// Past that boundary a tilde is no longer a home reference - enforce takes it as a
// relative path, so `read: ["~/.config"]` mounts a directory of that literal name,
// which does not exist. The run then succeeds, attests every layer, and grants
// nothing: the same silent no-grant expandHome exists to prevent, reached by a Go
// embedder who built the policy by hand and never called Resolve.
func (p *Policy) RequireExpanded() error {
	// Answered here rather than left to the callers' Validate, which refuses nil first
	// on every path bento itself takes: this is exported for the same embedders, who can
	// reach it on its own.
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	for _, f := range []struct {
		name string
		path string
	}{{"entrypoint", p.Entrypoint}, {"interpreter", p.Interpreter}} {
		if err := screenExpanded(f.name, f.path); err != nil {
			return err
		}
	}
	for _, l := range []struct {
		name  string
		paths []string
	}{{"read", p.Read}, {"write", p.Write}} {
		for i, path := range l.paths {
			if err := screenExpanded(fmt.Sprintf("%s[%d]", l.name, i), path); err != nil {
				return err
			}
		}
	}
	return nil
}

func screenExpanded(field, path string) error {
	if strings.HasPrefix(path, "~") {
		return fmt.Errorf("policy: %s %q still names home with a tilde; the enforcer does not expand it and would take it as a relative path, granting nothing. Resolve the policy first (manifest.Resolve) or write the path out in full", field, path)
	}
	return nil
}

func screenTilde(field, path string) error {
	if NamesOtherUserHome(path) {
		return fmt.Errorf("policy: %s %q names another user's home directory, which bento does not expand; write the path out in full (a file of that name beside the manifest is \"./%s\")", field, path, path)
	}
	return nil
}

// FirstUnsafeRune returns the first character in s that must not appear in a value
// a frontend echoes to the operator - a control character, a bidi override, a
// zero-width/invisible one, or a line separator - and true, or (0, false) when s is
// clean. It backs both
// the path/argument screen here and the manifest provenance screen, so every field
// an untrusted manifest can populate is held to the same rule.
//
// A byte that is not valid UTF-8 is reported as utf8.RuneError, which DescribeUnsafeRune
// names as invalid UTF-8. The screen has to decode to judge, so an undecodable byte
// would otherwise pass as clean while still reaching the terminal: 0x9B alone is the
// 8-bit CSI some terminals act on, and no rune predicate ever sees it. A genuine
// U+FFFD decodes to three bytes and is left alone.
func FirstUnsafeRune(s string) (rune, bool) {
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				return utf8.RuneError, true
			}
		}
		if unsafeInField(r) {
			return r, true
		}
	}
	return 0, false
}

// DescribeUnsafeRune names what FirstUnsafeRune reported, for an error message: the
// class of the offending rune and its code point, or just "invalid UTF-8" for an
// undecodable byte, which has no code point to name.
func DescribeUnsafeRune(r rune) string {
	if r == utf8.RuneError {
		return unsafeKind(r)
	}
	return fmt.Sprintf("%s (U+%04X)", unsafeKind(r), r)
}

// unsafeInField reports whether r must not appear in a path or argument field: a
// control character, a bidirectional formatting character, a zero-width/invisible one,
// or a line separator. Each is a way an untrusted manifest deceives an operator reading
// the value - a control character reprograms the terminal, a bidi override reorders the
// display, an invisible character hides a segment or makes two different paths render
// identically, a line separator pushes the rest of the value off the displayed line -
// so a path shows as something other than what it grants.
func unsafeInField(r rune) bool {
	return isControl(r) || isBidiOverride(r) || isInvisible(r) || isLineSeparator(r)
}

// unsafeKind names the class of an unsafeInField rune for the error message. The bidi
// overrides are also format characters, so they are tested first to keep the specific
// name for the class an operator most needs to recognize.
func unsafeKind(r rune) string {
	switch {
	case r == utf8.RuneError:
		return "invalid UTF-8"
	case isBidiOverride(r):
		return "a bidirectional formatting character"
	case isLineSeparator(r):
		return "a line separator"
	case isInvisible(r):
		return "a zero-width or invisible character"
	default:
		return "a control character"
	}
}

// isControl reports whether r is a C0 control, DEL, or a C1 control. These never
// appear in a legitimate path or argument, and each is a way for untrusted manifest
// content to reprogram the terminal it is later printed to (ESC begins every 7-bit
// ANSI/OSC sequence; U+009B and U+009D are the 8-bit CSI and OSC that some terminals
// honor directly).
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// isLineSeparator reports whether r is the Unicode line or paragraph separator
// (U+2028, U+2029). Neither is a C0/C1 control, a format character, or default-ignorable,
// so the other three screens all miss them, yet many renderers break the line on one -
// which pushes the rest of a path off the display, so what the operator reads is a
// prefix of what is granted. Like the bidi controls this is a closed set of two, so it
// is spelled out rather than deferred to the Zl/Zp tables.
func isLineSeparator(r rune) bool {
	return r == 0x2028 || r == 0x2029
}

// isBidiOverride reports whether r is a Unicode bidirectional embedding, override,
// or isolate control (U+202A-U+202E, U+2066-U+2069) - the "Trojan Source" class.
// These reorder how the surrounding text is displayed without changing its bytes, so
// a value renders as something other than what it grants (a path that reads as
// "/safe" but resolves to "/evil"). Legitimate right-to-left paths carry directional
// letters, which have inherent direction and are not these explicit format controls,
// so rejecting these does not reject real RTL filenames.
func isBidiOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// isInvisible reports whether r renders as nothing: the format characters (Cf - the
// soft hyphen, the zero-width space and joiners, the word joiner, the byte-order mark,
// the Mongolian vowel separator, the tag block) and the other default-ignorable code
// points (the Hangul fillers, the combining grapheme joiner, the rest of the tag
// block). In a path any of them is a spoof - hiding a segment, or making two distinct
// grants render identically. Unlike isControl and isBidiOverride, which screen closed
// sets, this one is open-ended and grows with Unicode, so it defers to the property
// tables rather than an enumeration that goes stale.
//
// The union is deliberately wide. It sweeps in runes with legitimate text-shaping uses
// - the joiners U+200C/U+200D for Persian/Indic and emoji ZWJ sequences, the Arabic
// prepended-concatenation marks - but a manifest is a reviewed security boundary where
// an invisible character is a red flag worth refusing loudly: a file whose name truly
// needs one can be granted through its parent directory. Variation selectors are left
// out, being neither Cf nor default-ignorable: U+FE0F rides along on real emoji
// filenames and does not hide anything on its own.
func isInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || unicode.Is(defaultIgnorable, r)
}

// defaultIgnorable is resolved once: unicode.Is panics on a nil table, so a bad key
// would surface at validation time rather than at build.
var defaultIgnorable = unicode.Properties["Other_Default_Ignorable_Code_Point"]

// canonical resolves the zero value to the default it stands for, so a policy that
// omits the mode and one that spells it out are one mode, not two.
func (m ExecMode) canonical() ExecMode {
	if m == "" {
		return ExecNone
	}
	return m
}

func (m ExecMode) validate() error {
	switch m {
	case "", ExecNone, ExecNoneStrict, ExecAll:
		return nil
	default:
		return fmt.Errorf("policy: invalid exec mode %q: want one of none, none-strict, all", string(m))
	}
}

// Validate reports whether the rule can appear in a policy: its host must be a
// hostname, a ".suffix" wildcard, a canonical IP literal, or "*", and its port a
// literal, a range, or "*". Exported so a producer of rules - the profiler, turning an
// observed CONNECT into a proposal - can screen one before it builds a policy, instead
// of discovering it at the final marshal with the whole run's work already done.
func (r NetworkRule) Validate() error {
	if err := validateHostPattern(r.Host); err != nil {
		return err
	}
	return validatePort(r.Port)
}

// validateHostPattern accepts a network-rule host: a literal hostname, a
// ".suffix" wildcard, a canonical IP literal, or "*". It rejects control
// characters, IPv6 zone ids, overlong names, and non-canonical IP shorthand
// (e.g. "127.1", "2852039166") that string-mismatches a rule but still resolves
// to a real address.
func validateHostPattern(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if strings.ContainsAny(host, "\x00\r\n\t %") {
		return fmt.Errorf("host %q contains control or reserved characters", host)
	}
	if host == "*" {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host %q too long", host)
	}
	match := host
	wildcard := strings.HasPrefix(host, ".")
	if wildcard {
		match = host[1:]
		if match == "" {
			return fmt.Errorf("host %q: suffix wildcard needs a domain after the dot", host)
		}
	}
	if ip := net.ParseIP(match); ip != nil {
		// A suffix wildcard is a subdomain match, and an address has no subdomains. The
		// rule is not merely redundant: matchHost would apply it as a string suffix, so
		// it can only ever match a hostname that happens to end in those characters -
		// never the address the author meant to allow. Refuse it rather than let a rule
		// that reads like "the 10.0.0.1 network" authorize nothing it names.
		if wildcard {
			return fmt.Errorf("host %q: a suffix wildcard cannot be written over an IP address (an address has no subdomains; write %s to allow it)", host, match)
		}
		if ip.String() != match {
			return fmt.Errorf("host %q is not canonical (write it as %s)", match, ip.String())
		}
		return nil
	}
	if isIPShorthand(match) {
		return fmt.Errorf("host %q is not a canonical IP address (write a full dotted-quad or a hostname)", match)
	}
	if !isHostname(match) {
		return fmt.Errorf("host %q is not a valid hostname", host)
	}
	return nil
}

// isIPShorthand reports whether s is digits-and-dots only. Such a string that
// net.ParseIP already rejected is malformed IP shorthand (e.g. "127.1",
// "2852039166"), not a hostname.
func isIPShorthand(s string) bool {
	return strings.IndexFunc(s, func(c rune) bool {
		return (c < '0' || c > '9') && c != '.'
	}) < 0
}

func isHostname(h string) bool {
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' && i > 0 && i < len(label)-1:
			default:
				return false
			}
		}
	}
	// The rightmost label must contain a non-digit. An all-numeric final label
	// means the string is IP shorthand the libc resolver treats as an address,
	// not a name - rejecting it stops a rule that string-mismatches an allowlist
	// entry but still resolves to a real host.
	last := labels[len(labels)-1]
	return strings.IndexFunc(last, func(c rune) bool { return c < '0' || c > '9' }) >= 0
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("empty port (use a number, a lo-hi range, or \"*\")")
	}
	if port == "*" {
		return nil
	}
	if lo, hi, ok := strings.Cut(port, "-"); ok {
		l, err := parsePortNum(lo)
		if err != nil {
			return err
		}
		h, err := parsePortNum(hi)
		if err != nil {
			return err
		}
		if l > h {
			return fmt.Errorf("port range %q is inverted", port)
		}
		return nil
	}
	_, err := parsePortNum(port)
	return err
}

func parsePortNum(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q out of range 1-65535", s)
	}
	// strconv.Atoi also accepts "08080" and "+443", spellings the proxy refuses in
	// a CONNECT target. A rule written that way would validate and then match
	// nothing, which is a silently dead allowlist entry rather than a loud error.
	if s != strconv.Itoa(n) {
		return 0, fmt.Errorf("port %q must be plain decimal (%d)", s, n)
	}
	return n, nil
}

func (l Limits) validate() error {
	if l.PIDs < 0 {
		return fmt.Errorf("policy: limits.pids must not be negative")
	}
	if l.CPU != "" {
		num, ok := strings.CutSuffix(l.CPU, "%")
		if !ok {
			return fmt.Errorf("policy: limits.cpu %q must be a percentage (e.g. \"100%%\")", l.CPU)
		}
		if !cpuPercentRe.MatchString(num) {
			return fmt.Errorf("policy: limits.cpu %q must be a plain decimal percentage (e.g. \"100%%\" or \"12.5%%\"); %q is not one", l.CPU, num)
		}
		// The spelling is decimal by here, but an arbitrarily long digit string still
		// overflows to +Inf, and a quota systemd cannot read may be ignored outright -
		// running the target with no cpu cap at all, which is the failure a limit exists
		// to prevent. NaN and a negative are unreachable past the pattern.
		pct, err := strconv.ParseFloat(num, 64)
		if err != nil || math.IsInf(pct, 0) {
			return fmt.Errorf("policy: limits.cpu %q is too large to be a real bound", l.CPU)
		}
		// systemd's floor is one permyriad, so it refuses "0%" and "0.00%" as too small.
		// The fraction is at most two digits by here, which makes this comparison exact.
		if pct == 0 {
			return fmt.Errorf("policy: limits.cpu %q is zero; the smallest quota is \"0.01%%\" (omit limits.cpu for no cap)", l.CPU)
		}
	}
	if l.Memory != "" {
		if _, err := parseBytes(l.Memory); err != nil {
			return fmt.Errorf("policy: limits.memory: %w", err)
		}
	}
	return nil
}

// parseBytes parses a byte quantity with a K/M/G suffix (powers of 1024), or a
// bare byte count. Validate uses it to reject an unparseable Limits.Memory; the
// backend passes the original string to systemd, which parses it again.
func parseBytes(s string) (int64, error) {
	// No whitespace trimming, here or around the number: the backend hands the ORIGINAL
	// string to systemd, so a value this accepts and systemd rejects (" 128M ") is a
	// policy that validates and then fails at scope creation.
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M', 'm':
		mult = 1 << 20
	case 'G', 'g':
		mult = 1 << 30
	}
	num := s
	if mult != 1 {
		num = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(num, 10, 64)
	// A number too big for int64 is spelled correctly and merely out of range, so it gets
	// the range answer rather than advice about a format it already followed.
	if errors.Is(err, strconv.ErrRange) || (err == nil && n > math.MaxInt64/mult) {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	if err == nil && n < 0 {
		return 0, fmt.Errorf("size %q cannot be negative", s)
	}
	if err != nil {
		// "128MB" and "1.5G" are the natural spellings and both land here, so the
		// message has to say what to write instead - the accepted form is nowhere in
		// the value the reader typed.
		return 0, fmt.Errorf("invalid size %q, want a plain byte count or a K/M/G suffix (e.g. \"128M\")", s)
	}
	return n * mult, nil
}
