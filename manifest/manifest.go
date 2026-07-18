// Package manifest parses Bento's YAML manifest into a validated policy.Policy.
//
// It is the serialization adapter: the domain knows nothing about YAML, and the
// wire format and its parsing concerns live only here. Unknown fields are a hard
// error at every level of the document - the manifest is machine-owned, so a
// shape mistake is caught at the boundary rather than silently carried inward.
package manifest

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml"

	"github.com/whiskeyjimbo/bento-v2/policy"
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
	var m manifest
	if err := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField()).Decode(&m); err != nil && err != io.EOF {
		return nil, fmt.Errorf("manifest: %s", sanitizeControl(err.Error()))
	}
	p := m.toPolicy()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var prov Provenance
	if m.Provenance != nil {
		prov = *m.Provenance
	}
	return &Document{Policy: p, Provenance: prov}, nil
}

// sanitizeControl drops the control characters an untrusted manifest could smuggle
// into a decoder error that is printed to a terminal: ESC (the lead byte of every
// ANSI/OSC sequence), BEL, carriage return, and the other C0 controls and DEL. Tab
// and newline are kept - the decoder's line/caret annotation is laid out with them,
// and neither reprograms a terminal. The input is already known to be valid UTF-8,
// so the multi-byte C1 range cannot appear as raw control bytes.
func sanitizeControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
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
