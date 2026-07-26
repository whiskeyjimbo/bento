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
	Entrypoint  string        `yaml:"entrypoint,omitempty"`
	Interpreter string        `yaml:"interpreter,omitempty"`
	Args        []string      `yaml:"args,omitempty"`
	Env         []string      `yaml:"env,omitempty"`
	Read        []string      `yaml:"read,omitempty"`
	Write       []string      `yaml:"write,omitempty"`
	Network     []networkRule `yaml:"network,omitempty"`
	Exec        string        `yaml:"exec,omitempty"`
	Limits      *limits       `yaml:"limits,omitempty"`
	Provenance  *Provenance   `yaml:"provenance,omitempty"`
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
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var prov Provenance
	if m.Provenance != nil {
		prov = *m.Provenance
	}
	// Provenance is returned to the caller and echoed by a frontend ("generated by X
	// at Y"), so it must be held to the same screen as the policy's path fields: a
	// hostile manifest carries hostile provenance, and Parse's whole contract is
	// untrusted input. Without this a control/bidi/zero-width character in these
	// strings would reach the terminal unfiltered.
	for _, f := range []string{prov.GeneratedBy, prov.GeneratedAt, prov.Approves} {
		if r, ok := policy.FirstUnsafeRune(f); ok {
			return nil, fmt.Errorf("manifest: provenance value %q contains %s (U+%04X)", f, policy.UnsafeRuneKind(r), r)
		}
	}
	return &Document{Policy: p, Provenance: prov}, nil
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

// Marshal serializes a policy and its provenance to canonical manifest YAML. The
// manifest is machine-owned, so this is how the tool writes it after profiling
// or approval, rather than editing the file in place.
func Marshal(p *policy.Policy, prov Provenance) ([]byte, error) {
	m := fromPolicy(p)
	if prov != (Provenance{}) {
		m.Provenance = &prov
	}
	return yaml.Marshal(&m)
}

func fromPolicy(p *policy.Policy) manifest {
	m := manifest{
		Entrypoint:  p.Entrypoint,
		Interpreter: p.Interpreter,
		Args:        p.Args,
		Env:         p.Env,
		Read:        p.Read,
		Write:       p.Write,
		Exec:        string(p.Exec),
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
		Entrypoint:  m.Entrypoint,
		Interpreter: m.Interpreter,
		Args:        m.Args,
		Env:         m.Env,
		Read:        m.Read,
		Write:       m.Write,
		Exec:        policy.ExecMode(m.Exec),
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
