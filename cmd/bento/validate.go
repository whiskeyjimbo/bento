package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/manifest"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

func newValidateCmd() *cobra.Command {
	var (
		asJSON bool
		strict bool
	)

	cmd := &cobra.Command{
		Use:   "validate <manifest>",
		Short: "Check a manifest and show the permissions it grants",
		Long: "validate parses the manifest, rejects any malformed field, and prints the\n" +
			"permissions it would grant - so the boundary can be reviewed before running\n" +
			"anything inside it.\n\n" +
			"It also checks the approval: a manifest whose permissions changed since it was\n" +
			"approved is reported. --strict makes a stale or missing approval a failure (exit\n" +
			"non-zero), for use as a CI gate; without it, a stale approval is only a warning.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := loadDocument(args[0])
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(os.Stdout, toPolicyJSON(doc.Policy))
			}
			writePolicySummary(os.Stdout, args[0], doc.Policy)
			return reportApproval(os.Stdout, doc, strict)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the parsed policy as JSON")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail if the manifest's approval is stale or missing")
	return cmd
}

// resolveManifestPaths rewrites a policy's relative paths against the manifest's
// own directory, so a manifest means the same thing regardless of where bento is
// invoked from. It must run AFTER the approval fingerprint is checked: the
// fingerprint attests the manifest as written, so resolving first would change it.
func resolveManifestPaths(p *policy.Policy, manifestPath string) {
	base := filepath.Dir(manifestPath)
	p.Entrypoint = resolveAgainst(base, p.Entrypoint)
	for i, r := range p.Read {
		p.Read[i] = resolveAgainst(base, r)
	}
	for i, w := range p.Write {
		p.Write[i] = resolveAgainst(base, w)
	}
}

func resolveAgainst(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// loadDocument parses a manifest into its policy and provenance without resolving
// paths, so approval and the fingerprint check see the manifest exactly as
// written. (run resolves paths for execution; the fingerprint attests the
// manifest, so it must not depend on where bento was invoked.)
func loadDocument(path string) (*manifest.Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return manifest.Parse(f)
}

// approvalState describes how a manifest's stored approval relates to its current
// policy.
type approvalState int

const (
	approvalUnstamped approvalState = iota // no provenance approval recorded
	approvalCurrent                        // stored fingerprint matches the policy
	approvalStale                          // policy changed since it was approved
)

func checkApproval(doc *manifest.Document) approvalState {
	switch doc.Provenance.Approves {
	case "":
		return approvalUnstamped
	case doc.Policy.Fingerprint():
		return approvalCurrent
	default:
		return approvalStale
	}
}

// reportApproval prints the approval status and, under strict, fails when it is
// not current - the CI signal that a manifest's permissions changed without
// re-approval.
func reportApproval(w io.Writer, doc *manifest.Document, strict bool) error {
	switch checkApproval(doc) {
	case approvalCurrent:
		fmt.Fprintf(w, "\napproval:     current (approved for these permissions)\n")
		return nil
	case approvalUnstamped:
		fmt.Fprintf(w, "\napproval:     not approved - run `bento approve` after reviewing the permissions above\n")
		if strict {
			return fmt.Errorf("manifest is not approved")
		}
	case approvalStale:
		fmt.Fprintf(w, "\napproval:     STALE - the permissions changed since this manifest was approved\n")
		fmt.Fprintf(w, "              re-review and run `bento approve` to re-stamp it\n")
		if strict {
			return fmt.Errorf("manifest approval is stale: permissions changed since it was approved")
		}
	}
	return nil
}

type policyJSON struct {
	Entrypoint  string      `json:"entrypoint"`
	Interpreter string      `json:"interpreter,omitempty"`
	Args        []string    `json:"args,omitempty"`
	Env         []string    `json:"env,omitempty"`
	Read        []string    `json:"read,omitempty"`
	Write       []string    `json:"write,omitempty"`
	Network     []string    `json:"network"`
	Exec        string      `json:"exec"`
	Limits      *limitsJSON `json:"limits,omitempty"`
}

type limitsJSON struct {
	Memory string `json:"memory,omitempty"`
	CPU    string `json:"cpu,omitempty"`
	PIDs   int    `json:"pids,omitempty"`
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
	if !p.Limits.IsZero() {
		out.Limits = &limitsJSON{Memory: p.Limits.Memory, CPU: p.Limits.CPU, PIDs: p.Limits.PIDs}
	}
	return out
}

func writePolicySummary(w io.Writer, path string, p *policy.Policy) {
	fmt.Fprintf(w, "manifest:     %s - ok\n", path)
	fmt.Fprintf(w, "entrypoint:   %s\n", p.Entrypoint)
	if p.Interpreter != "" {
		fmt.Fprintf(w, "interpreter:  %s\n", p.Interpreter)
	} else {
		fmt.Fprintf(w, "interpreter:  (none - the entrypoint is a compiled binary)\n")
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
		fmt.Fprintf(w, "exec:         blocked, strictly (no subprocesses; fork/vfork/clone blocked, threads allowed)\n")
		fmt.Fprintf(w, "  note: fork/clone blocking needs an architecture-specific seccomp filter\n")
		fmt.Fprintf(w, "        (amd64). Where it is unavailable, run and doctor report the exec-strict\n")
		fmt.Fprintf(w, "        layer degraded and --strict refuses it.\n")
	default:
		fmt.Fprintf(w, "exec:         blocked on the standard exec path (execve)\n")
		fmt.Fprintf(w, "  note: execve covers effectively every real subprocess (fork+exec, os/exec,\n")
		fmt.Fprintf(w, "        system). execveat stays open by construction - the launcher needs it -\n")
		fmt.Fprintf(w, "        so a program written to spawn through execveat is not stopped.\n")
	}

	if !p.Limits.IsZero() {
		var parts []string
		if p.Limits.Memory != "" {
			parts = append(parts, "memory "+p.Limits.Memory)
		}
		if p.Limits.CPU != "" {
			parts = append(parts, "cpu "+p.Limits.CPU)
		}
		if p.Limits.PIDs > 0 {
			parts = append(parts, fmt.Sprintf("pids %d", p.Limits.PIDs))
		}
		fmt.Fprintf(w, "limits:       %s\n", strings.Join(parts, ", "))
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
