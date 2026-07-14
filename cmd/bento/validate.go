package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/internal/manifest"
	"github.com/whiskeyjimbo/bento-v2/internal/policy"
)

func newValidateCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "validate <manifest>",
		Short: "Check a manifest and show the permissions it grants",
		Long: "validate parses the manifest, rejects any malformed field, and prints the\n" +
			"permissions it would grant — so the boundary can be reviewed before running\n" +
			"anything inside it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadManifest(args[0])
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(os.Stdout, toPolicyJSON(p))
			}
			writePolicySummary(os.Stdout, args[0], p)
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the parsed policy as JSON")
	return cmd
}

// loadManifest reads and validates a manifest. Relative paths inside it are
// resolved against the manifest's own directory, so a manifest means the same
// thing regardless of where bento is invoked from.
func loadManifest(path string) (*policy.Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p, err := manifest.Load(f)
	if err != nil {
		return nil, err
	}

	base := filepath.Dir(path)
	p.Entrypoint = resolveAgainst(base, p.Entrypoint)
	for i, r := range p.Read {
		p.Read[i] = resolveAgainst(base, r)
	}
	for i, w := range p.Write {
		p.Write[i] = resolveAgainst(base, w)
	}
	return p, nil
}

func resolveAgainst(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

type policyJSON struct {
	Entrypoint  string   `json:"entrypoint"`
	Interpreter string   `json:"interpreter,omitempty"`
	Args        []string `json:"args,omitempty"`
	Env         []string `json:"env,omitempty"`
	Read        []string `json:"read,omitempty"`
	Write       []string `json:"write,omitempty"`
	Network     []string `json:"network"`
	Exec        string   `json:"exec"`
}

func toPolicyJSON(p *policy.Policy) policyJSON {
	out := policyJSON{
		Entrypoint:  p.Entrypoint,
		Interpreter: p.Interpreter,
		Args:        p.Args,
		Env:         p.Env,
		Read:        p.Read,
		Write:       p.Write,
		Exec:        string(p.Exec),
		Network:     []string{},
	}
	for _, r := range p.Network {
		out.Network = append(out.Network, r.Host+":"+r.Port)
	}
	return out
}

func writePolicySummary(w io.Writer, path string, p *policy.Policy) {
	fmt.Fprintf(w, "manifest:     %s — ok\n", path)
	fmt.Fprintf(w, "entrypoint:   %s\n", p.Entrypoint)
	if p.Interpreter != "" {
		fmt.Fprintf(w, "interpreter:  %s\n", p.Interpreter)
	} else {
		fmt.Fprintf(w, "interpreter:  (none — the entrypoint is a compiled binary)\n")
	}
	fmt.Fprintf(w, "read:         %s\n", orNone(p.Read))
	fmt.Fprintf(w, "write:        %s\n", orNone(p.Write))
	fmt.Fprintf(w, "env:          %s\n", orNone(p.Env))

	if len(p.Network) == 0 {
		fmt.Fprintf(w, "network:      denied (no egress)\n")
	} else {
		rules := make([]string, 0, len(p.Network))
		for _, r := range p.Network {
			rules = append(rules, r.Host+":"+r.Port)
		}
		fmt.Fprintf(w, "network:      %v\n", rules)
		for _, r := range p.Network {
			if isLoopbackHost(r.Host) {
				fmt.Fprintf(w, "  note: %q is a loopback address. The sandbox exempts loopback from the egress\n", r.Host)
				fmt.Fprintf(w, "        proxy so a script can reach its own in-sandbox services, which means this\n")
				fmt.Fprintf(w, "        rule will NOT reach a service on the host's loopback. Use a routable\n")
				fmt.Fprintf(w, "        address if you meant the host.\n")
			}
		}
	}

	switch p.Exec {
	case policy.ExecAll:
		fmt.Fprintf(w, "exec:         allowed (the script may spawn subprocesses)\n")
	case policy.ExecNoneStrict:
		fmt.Fprintf(w, "exec:         blocked, strictly (no subprocesses, no fork)\n")
	default:
		fmt.Fprintf(w, "exec:         blocked (no subprocesses)\n")
	}

	fmt.Fprintf(w, "\nEverything not listed above is denied. Credentials, SSH keys, and shell\n")
	fmt.Fprintf(w, "profiles are shielded even if a path above would otherwise expose them.\n")
}

// isLoopbackHost reports whether a network-rule host is one the sandbox's
// NO_PROXY exempts, so a rule for it would not reach the host's loopback.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return fmt.Sprint(v)
}
