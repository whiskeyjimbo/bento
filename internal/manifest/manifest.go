// Package manifest parses Bento's YAML manifest into a validated policy.Policy.
//
// It is the serialization adapter: the domain knows nothing about YAML, and the
// wire format and its parsing concerns live only here. Unknown fields are a hard
// error at every level of the document - the manifest is machine-owned, so a
// shape mistake is caught at the boundary rather than silently carried inward.
package manifest

import (
	"fmt"
	"io"

	"github.com/goccy/go-yaml"

	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

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
func Parse(r io.Reader) (*Document, error) {
	if r == nil {
		return nil, fmt.Errorf("manifest: nil reader")
	}
	var m manifest
	if err := yaml.NewDecoder(r, yaml.DisallowUnknownField()).Decode(&m); err != nil && err != io.EOF {
		return nil, fmt.Errorf("manifest: %w", err)
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
