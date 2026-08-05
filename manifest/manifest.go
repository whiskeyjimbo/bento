// Package manifest parses Bento's YAML manifest into a validated policy.Policy.
//
// It is the serialization adapter: the domain knows nothing about YAML, and the
// wire format and its parsing concerns live only here. Unknown fields are a hard
// error at every level of the document - the manifest is machine-owned, so a
// shape mistake is caught at the boundary rather than silently carried inward.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/token"

	"github.com/whiskeyjimbo/bento/policy"
)

// maxManifestBytes caps how much of the input Parse reads. A manifest is a small
// YAML file; the cap keeps a mistyped `bento run ./some-huge-binary` from streaming
// megabytes through the decoder (and, before the UTF-8 check below existed, onto the
// terminal). Generous by three orders of magnitude over any real manifest.
const maxManifestBytes = 1 << 20

// manifest is the on-disk YAML shape, kept separate from policy.Policy so the
// domain carries no serialization concerns.
type manifest struct {
	Entrypoint  string `yaml:"entrypoint,omitempty"`
	Interpreter string `yaml:"interpreter,omitempty"`
	// InterpreterArgs are the interpreter's own options; Args are the script's.
	InterpreterArgs []string      `yaml:"interpreter_args,omitempty"`
	Args            []string      `yaml:"args,omitempty"`
	Env             []string      `yaml:"env,omitempty"`
	Read            []string      `yaml:"read,omitempty"`
	Write           []string      `yaml:"write,omitempty"`
	Network         []networkRule `yaml:"network,omitempty"`
	Exec            string        `yaml:"exec,omitempty"`
	ExecAllow       []string      `yaml:"exec_allow,omitempty"`
	Limits          *limits       `yaml:"limits,omitempty"`
	Provenance      *Provenance   `yaml:"provenance,omitempty"`
}

// Provenance is the tool-written block that records how a manifest was produced
// and stamps the policy it was approved for. It is a real field, not a comment,
// because re-marshalling drops comments - and this block must survive the tool
// rewriting the file.
type Provenance struct {
	// GeneratedBy names the tool/version that produced the manifest.
	GeneratedBy string `yaml:"generated-by,omitempty"`
	// GeneratedAt is when it was produced or last approved.
	GeneratedAt string `yaml:"generated-at,omitempty"`
	// Approves is the policy fingerprint this manifest was approved for. If it no
	// longer matches the policy, the permissions changed without re-approval.
	Approves string `yaml:"approves,omitempty"`
	// BlockedHosts are the "host:port" destinations the profiling run reached for and
	// its egress guard refused, because the name resolved into space the sandbox must
	// not reach. approve names any network rule that reaches one (by policy.Allows, so a
	// wildcard rule covering the destination is called out too), and a reader is not asked
	// to approve egress the tool itself refused.
	//
	// It describes how the manifest was drafted rather than what it grants, so it stays
	// out of the approval fingerprint (which covers the policy only) - otherwise a
	// re-profile that resolved a name differently would report an approved manifest as
	// stale over a permission that never changed. The cost of staying out is that the
	// record is advisory and unauthenticated: a manifest arriving from elsewhere can carry
	// a refusal that never happened, or have had one stripped, without the stamp noticing.
	// It is a prompt to look, never a permission and never a claim of safety.
	BlockedHosts []string `yaml:"blocked-hosts,omitempty"`
}

// isZero reports whether a provenance block carries nothing, so Marshal leaves the key
// out entirely. It is written out rather than compared against the zero value because
// Provenance holds a slice and is no longer comparable.
func (p Provenance) isZero() bool {
	return p.GeneratedBy == "" && p.GeneratedAt == "" && p.Approves == "" && len(p.BlockedHosts) == 0
}

// Document is a parsed manifest: its validated policy and its provenance.
type Document struct {
	Policy     *policy.Policy
	Provenance Provenance
}

type networkRule struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type limits struct {
	Memory string `yaml:"memory"`
	CPU    string `yaml:"cpu"`
	PIDs   int    `yaml:"pids"`
}

// UnmarshalYAML rejects the bare "host:port" scalar form with an actionable
// message rather than a decoder type error.
//
// It must take the func(any) error form: that callback re-enters the *same*
// decoder, so DisallowUnknownField still applies to the keys inside a rule. The
// ast.Node and []byte unmarshaler forms build a fresh decoder and silently drop
// strictness, which would let a typo'd key inside a network rule pass unnoticed.
func (r *networkRule) UnmarshalYAML(unmarshal func(any) error) error {
	var scalar string
	if err := unmarshal(&scalar); err == nil {
		return fmt.Errorf("network rule must be a mapping with `host:` and `port:` keys, not the bare string %q (write it as `- {host: api.example.com, port: \"443\"}`)", scalar)
	}
	type plain networkRule
	var p plain
	if err := unmarshal(&p); err != nil {
		return err
	}
	*r = networkRule(p)
	return nil
}

// Parse parses a YAML manifest into a validated policy and its provenance.
//
// The manifest is untrusted input - the whole point of bento is running scripts
// under manifests it did not write - so the input is guarded before it reaches the
// decoder, and the decoder's error is sanitized before it is returned. goccy/go-yaml
// annotates a parse error by echoing the offending source line; that line is
// attacker-controlled, so passing it through verbatim would let a hostile manifest
// (or a binary mistaken for one) write raw escape sequences to the operator's
// terminal. See sanitizeControl.
func Parse(r io.Reader) (*Document, error) {
	if r == nil {
		return nil, fmt.Errorf("manifest: nil reader")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("manifest: reading input: %w", err)
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("manifest: input is larger than %d bytes, which is not a manifest", maxManifestBytes)
	}
	// A manifest is text. Rejecting non-UTF-8 up front turns `bento run ./a-binary`
	// into a clear error instead of feeding raw bytes to the YAML decoder (whose error
	// would then echo those bytes back). This does not catch a text manifest that
	// embeds escape sequences - that is what sanitizing the decoder error covers.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("manifest: input is not valid UTF-8 text, so it is not a manifest")
	}
	if err := screenSource(string(data)); err != nil {
		return nil, err
	}
	var m manifest
	dec := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField())
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("manifest: %s", sanitizeControl(err.Error()))
	}
	// A manifest is a single policy document. A YAML stream with a second document
	// (after a "---") would otherwise be parsed with only the first governing and the
	// rest silently dropped - reject it so a second, ignored policy cannot hide.
	var extra manifest
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("manifest: %s", sanitizeControl(err.Error()))
		}
		return nil, fmt.Errorf("manifest: contains more than one YAML document; a manifest must be a single policy")
	}
	p := m.toPolicy()
	if err := joinProblems(p.Problems()); err != nil {
		return nil, err
	}
	var prov Provenance
	if m.Provenance != nil {
		prov = *m.Provenance
	}
	if err := screenProvenance(prov); err != nil {
		return nil, err
	}
	return &Document{Policy: p, Provenance: prov}, nil
}

// joinProblems renders everything wrong with a parsed policy as one error, so an author
// fixing a manifest sees the whole list instead of one field per run. A single problem
// is returned untouched: the header would be noise around the one line that matters.
func joinProblems(probs []error) error {
	switch len(probs) {
	case 0:
		return nil
	case 1:
		return probs[0]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "the manifest has %d problems:", len(probs))
	for _, p := range probs {
		fmt.Fprintf(&b, "\n  %s", p)
	}
	return errors.New(b.String())
}

// screenSource rejects the YAML constructs that let a manifest's decoded meaning differ
// from the text a reviewer read, or let a small input expand without bound. It runs on the
// source because both failures happen inside the decoder, so nothing downstream of the
// decode can see them.
//
// It lexes with the decoder's own lexer rather than searching for the indicator bytes.
// '&', '*' and '!' are ordinary characters inside a quoted scalar, a comment, or a path -
// "read: [/data/*]" is a manifest someone writes on purpose - so a byte scan would refuse
// legitimate input. Lexing is linear in the source and expands nothing: the alias bomb
// that exhausts memory in Decode tokenizes in well under a millisecond, which is what
// makes it safe to run this on the untrusted input it exists to screen.
//
// Only the line number is reported, never the offending token. The source is
// attacker-controlled - the reason sanitizeControl exists below - so echoing an anchor
// name or tag string into an error the operator's terminal renders would reopen at a new
// site exactly what this file is careful about everywhere else.
func screenSource(data string) error {
	for _, tok := range lexer.Tokenize(data) {
		switch tok.Type {
		case token.TagType:
			// A tag makes the decoded value differ from the bytes on the line: read:
			// [!!binary "L2V0Yy9zaGFkb3c="] decodes to /etc/shadow. approve fingerprints
			// the DECODED policy, so the approval would be genuine for a grant no reviewer
			// could see. Every tag is refused, not just !!binary - a custom !foo tag is the
			// same divergence between what was read and what runs.
			return fmt.Errorf("manifest: line %d uses an explicit YAML tag; a tag decodes to a value the line does not show, so an approval would attest a grant no reviewer saw", lineOf(tok))
		case token.AnchorType, token.AliasType, token.MergeKeyType:
			// Nested aliases expand geometrically at decode time, and maxManifestBytes
			// caps the SOURCE, not the expansion - a few hundred bytes exhausts memory.
			// Refusing the construct outright also keeps a manifest readable as written:
			// a merge key means the grants in force are not the grants on the page.
			return fmt.Errorf("manifest: line %d uses a YAML anchor, alias, or merge key; these expand without bound at decode time and hide what a manifest grants, so a manifest must spell its values out", lineOf(tok))
		}
	}
	return nil
}

// lineOf reports a token's 1-based source line, or 0 when the lexer left no position.
func lineOf(tok *token.Token) int {
	if tok.Position == nil {
		return 0
	}
	return tok.Position.Line
}

// sanitizeControl drops the control characters an untrusted manifest could smuggle
// into a decoder error that is printed to a terminal: ESC (the lead byte of every
// 7-bit ANSI/OSC sequence), BEL, carriage return, the other C0 controls and DEL,
// and the C1 range U+0080-U+009F. The C1 codes matter because the input is UTF-8
// text, so a manifest can carry U+009B (CSI) or U+009D (OSC) directly - a terminal
// honoring 8-bit controls acts on those with no ESC at all, which a C0-only filter
// would let straight through (verified: goccy echoes a literal U+009B in its
// annotation). Tab and newline are kept - the decoder lays out its line/caret
// annotation with them, and neither reprograms a terminal.
func sanitizeControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// Load parses a YAML manifest and returns just its validated policy.
func Load(r io.Reader) (*policy.Policy, error) {
	d, err := Parse(r)
	if err != nil {
		return nil, err
	}
	return d.Policy, nil
}

// Resolve rewrites a policy's relative paths against the manifest's own directory,
// so a manifest means the same thing regardless of where it is read from. It is
// deliberately NOT part of Load: the approval fingerprint attests the manifest as
// written, so resolving first would change it. Call it after that check, and before
// anything that touches the named files.
//
// The anchor is absolutized, so a relative manifest path ("./m.yaml", anchor ".")
// still yields absolute grants. Anything that persists or crosses a process - a
// written manifest, a landlock rule, a bind mount, a store key - would otherwise
// carry a path that means whatever the resolving process's cwd meant.
func Resolve(p *policy.Policy, manifestPath string) error {
	// Refused rather than skipped: a caller who lost their policy would get a silent
	// success and go on to enforce paths that were never anchored.
	if p == nil {
		return fmt.Errorf("manifest: nil Policy; path resolution has nothing to anchor")
	}
	base, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return fmt.Errorf("manifest: cannot anchor %s to an absolute directory: %w", manifestPath, err)
	}
	if p.Entrypoint, err = resolveAgainst(base, p.Entrypoint); err != nil {
		return err
	}
	if p.Interpreter, err = resolveInterpreter(base, p.Interpreter); err != nil {
		return err
	}
	for i, r := range p.Read {
		if p.Read[i], err = resolveAgainst(base, r); err != nil {
			return err
		}
	}
	for i, w := range p.Write {
		if p.Write[i], err = resolveAgainst(base, w); err != nil {
			return err
		}
	}
	// Anchored like the grants rather than treated as a command name: an allowlist entry
	// names one file, and resolveInterpreter's PATH-search branch would turn a bare name
	// into whatever that name resolves to on the host at run time - which is the opposite
	// of what an allowlist is for.
	for i, e := range p.ExecAllow {
		if p.ExecAllow[i], err = resolveAgainst(base, e); err != nil {
			return err
		}
	}
	return nil
}

// resolveInterpreter anchors a path-shaped interpreter to the manifest's directory,
// following exec.LookPath's own rule: a name carrying a separator is a path, and a
// bare name is a PATH search. Without this, `interpreter: venv/bin/python` resolves
// against whatever directory the caller was invoked from - a different interpreter
// per caller, fingerprinting identically. A bare `python3` is left alone: it means
// "the host's python3" and joining it to the manifest directory would name a file
// that almost never exists.
func resolveInterpreter(base, interp string) (string, error) {
	// The tilde check comes first: a bare "~" carries no separator, so the PATH-search
	// branch below would otherwise hand it to exec.LookPath as a command name.
	if !strings.HasPrefix(interp, "~") && !strings.ContainsRune(interp, filepath.Separator) {
		return interp, nil
	}
	return resolveAgainst(base, interp)
}

// NonAnchoring reports whether a manifest path means something other than "relative
// to the manifest's own directory". Those are the paths that pin a manifest to one
// location: the approval stamp attests the manifest as written, so a manifest whose
// grants are all relative keeps a single approval across every checkout it is copied
// into, and one absolute or ~ path silently ends that.
//
// It is the inverse of the branch resolveAgainst takes to join a path to the base, and
// sits beside it so the two cannot drift - a path form added there and not here would
// stop being reported without anything failing. A ~ path counts: it anchors to whoever
// runs it rather than to the manifest, which pins harder than an absolute path does.
func NonAnchoring(path string) bool {
	return strings.HasPrefix(path, "~") || filepath.IsAbs(path)
}

func resolveAgainst(base, path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		return expandHome(path)
	}
	if path == "" || filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Join(base, path), nil
}

// expandHome rewrites a leading "~" to the invoking user's home directory. Without
// it a grant of "~/.ssh/id_rsa" is just a relative path: it anchors to the manifest
// directory, names a file that does not exist, mounts nothing, and reports nothing -
// a manifest that reads as granting home while granting nothing, and a shield test
// that passes because there was no grant to shield against.
//
// Only the current user's home is expandable. policy.Validate refuses the
// "~operator/keys" spelling at the parse gate, so `bento validate` reports it rather
// than leaving it for a run; the same rule is re-checked here because a Go embedder
// can hand Resolve a policy it built without going through Validate, and joining
// "operator/keys" onto the invoker's own home would grant a path nobody named.
func expandHome(path string) (string, error) {
	rest, ok := strings.CutPrefix(path, "~")
	if !ok {
		return "", fmt.Errorf("manifest: %q is not a tilde path", path)
	}
	if policy.NamesOtherUserHome(path) {
		return "", fmt.Errorf("manifest: %q names another user's home directory, which bento does not expand; write the path out in full", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("manifest: cannot expand %q: resolving home directory: %w", path, err)
	}
	// os.UserHomeDir returns $HOME verbatim, so a relative or empty value would produce
	// a grant that lands wherever the enforcing process's cwd points - the same silent
	// misplacement the expansion exists to fix. internal/linux refuses it for the same
	// reason; this layer cannot import that one.
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("manifest: cannot expand %q: home directory %q is not absolute", path, home)
	}
	// Policy's character screen runs at Parse, over the manifest as written. Expansion
	// happens after, so $HOME is the one thing that reaches a policy path without
	// passing it - and the resolved path is what the warnings and --json envelopes echo.
	if r, ok := policy.FirstUnsafeRune(home); ok {
		return "", fmt.Errorf("manifest: cannot expand %q: home directory %q contains %s, which is not allowed in a path", path, home, policy.DescribeUnsafeRune(r))
	}
	// Cleaned because the shield and grant comparisons downstream are exact string
	// equality against filepath.Clean(home): a trailing slash in $HOME would make
	// "~" resolve to a path that matches home everywhere except where it counts.
	return filepath.Clean(filepath.Join(home, rest)), nil
}

// Marshal serializes a policy and its provenance to canonical manifest YAML. The
// manifest is machine-owned, so this is how the tool writes it after profiling
// or approval, rather than editing the file in place.
func Marshal(p *policy.Policy, prov Provenance) ([]byte, error) {
	// The same gate Parse applies on the way in, so a manifest bento writes is one bento
	// can read back - Marshal used to write files Parse would then refuse, and an empty
	// policy marshalled to "{}" with no error at all. It runs BEFORE fromPolicy, which
	// dereferences p. The first problem is enough here, where Parse lists them all: a
	// manifest bento writes is one it built or already parsed, so a problem in it is a
	// bug in bento rather than a field an author is about to fix.
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := screenProvenance(prov); err != nil {
		return nil, err
	}
	m := fromPolicy(p)
	if !prov.isZero() {
		m.Provenance = &prov
	}
	return yaml.Marshal(&m)
}

// screenProvenance rejects a provenance field carrying a character that would deceive the
// operator it is echoed to ("generated by X at Y"). Both directions need it and for the
// same reason: on the way in a hostile manifest carries hostile provenance, and on the way
// out bento profile derives the file it writes from a target's own behavior, so an
// attacker-influenced value would be written to disk and then rendered by the footer that
// tells the operator to read it.
func screenProvenance(prov Provenance) error {
	fields := []string{prov.GeneratedBy, prov.GeneratedAt, prov.Approves}
	// The blocked hosts are CONNECT targets the profiled code chose, so they are the
	// most attacker-influenced values the block can carry - and approve echoes them.
	fields = append(fields, prov.BlockedHosts...)
	for _, f := range fields {
		if r, ok := policy.FirstUnsafeRune(f); ok {
			return fmt.Errorf("manifest: provenance value %q contains %s", f, policy.DescribeUnsafeRune(r))
		}
	}
	return nil
}

func fromPolicy(p *policy.Policy) manifest {
	m := manifest{
		Entrypoint:      p.Entrypoint,
		Interpreter:     p.Interpreter,
		InterpreterArgs: p.InterpreterArgs,
		Args:            p.Args,
		Env:             p.Env,
		Read:            p.Read,
		Write:           p.Write,
		Exec:            string(p.Exec),
		ExecAllow:       p.ExecAllow,
	}
	for _, r := range p.Network {
		m.Network = append(m.Network, networkRule{Host: r.Host, Port: r.Port})
	}
	if !p.Limits.IsZero() {
		m.Limits = &limits{Memory: p.Limits.Memory, CPU: p.Limits.CPU, PIDs: p.Limits.PIDs}
	}
	return m
}

func (m *manifest) toPolicy() *policy.Policy {
	p := &policy.Policy{
		Entrypoint:      m.Entrypoint,
		Interpreter:     m.Interpreter,
		InterpreterArgs: m.InterpreterArgs,
		Args:            m.Args,
		Env:             m.Env,
		Read:            m.Read,
		Write:           m.Write,
		Exec:            policy.ExecMode(m.Exec),
		ExecAllow:       m.ExecAllow,
	}
	// An absent exec: means the default, deny-subprocesses posture. Resolving it
	// here keeps every consumer from having to treat "" as a special case.
	if m.Exec == "" {
		p.Exec = policy.ExecNone
	}
	for _, r := range m.Network {
		p.Network = append(p.Network, policy.NetworkRule{Host: r.Host, Port: r.Port})
	}
	if m.Limits != nil {
		p.Limits = policy.Limits{Memory: m.Limits.Memory, CPU: m.Limits.CPU, PIDs: m.Limits.PIDs}
	}
	return p
}
