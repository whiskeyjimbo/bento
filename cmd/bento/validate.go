package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
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
			"non-zero), for use as a CI gate; without it, a stale approval is only a warning.\n" +
			"--json carries the same verdict as an `approval` field and honors --strict too.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, _, err := loadDocument(args[0], cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if asJSON {
				out := toPolicyJSON(doc.Policy)
				out.Approval = approvalName(checkApproval(doc))
				if err := writeJSON(os.Stdout, out); err != nil {
					return err
				}
				// The envelope is written first so a strict failure still leaves the
				// machine consumer a parseable answer on stdout; the error goes to
				// stderr and the non-zero exit, exactly as the human mode's does.
				return strictApprovalError(doc, strict)
			}
			writePolicySummary(os.Stdout, args[0], doc.Policy, resolvedGrants(doc.Policy, args[0]))
			return reportApproval(os.Stdout, doc, strict)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the parsed policy as JSON")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail if the manifest's approval is stale or missing")
	return cmd
}

// loadDocument parses a manifest into its policy and provenance without resolving
// paths, so approval and the fingerprint check see the manifest exactly as
// written. (run resolves paths for execution; the fingerprint attests the
// manifest, so it must not depend on where bento was invoked.)
//
// Anyone else who can write the manifest or a directory leading to it is reported to
// warn, since the approval it carries is only worth what its location is; callers that
// report the same thing themselves pass io.Discard. The trust is returned alongside so
// approve can refuse on it without a second open - the facts must describe the same
// inode these bytes came from.
func loadDocument(path string, warn io.Writer) (*manifest.Document, manifestTrust, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, manifestTrust{}, err
	}
	defer f.Close()
	trust, err := inspectManifest(f, path)
	if err != nil {
		return nil, manifestTrust{}, err
	}
	warnUntrusted(warn, trust.flaws(uint32(os.Geteuid())))
	doc, err := manifest.Parse(f)
	return doc, trust, err
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
	case approvalUnstamped:
		fmt.Fprintf(w, "\napproval:     not approved - run `bento approve` after reviewing the permissions above\n")
	case approvalStale:
		fmt.Fprintf(w, "\napproval:     STALE - the permissions changed since this manifest was approved\n")
		fmt.Fprintf(w, "              re-review and run `bento approve` to re-stamp it\n")
	}
	return strictApprovalError(doc, strict)
}

// strictApprovalError is the strict verdict on its own, shared by the human and
// --json paths so the gate cannot hold in one output mode and lapse in the other.
func strictApprovalError(doc *manifest.Document, strict bool) error {
	if !strict {
		return nil
	}
	switch checkApproval(doc) {
	case approvalUnstamped:
		return fmt.Errorf("manifest is not approved")
	case approvalStale:
		return fmt.Errorf("manifest approval is stale: permissions changed since it was approved")
	default:
		return nil
	}
}

// approvalName is the machine-readable spelling of an approval state, so --json
// can express the same verdict the human summary prints.
func approvalName(s approvalState) string {
	switch s {
	case approvalCurrent:
		return "current"
	case approvalStale:
		return "stale"
	default:
		return "unapproved"
	}
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
	// Approval is "current", "stale", or "unapproved" - the same verdict the human
	// summary prints, so a machine gate can read the outcome as a field rather than
	// inferring it from the exit code.
	Approval string `json:"approval,omitempty"`
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

// resolvedGrants reports what this host would make of the policy's grants, for display
// beside the manifest's own spelling. A reviewer approving `read: ["~"]` or `read: [./data]`
// otherwise has to work out which directory that lands on, and `~` in particular depends
// on an environment the fingerprint does not attest.
//
// It resolves a deep copy: Resolve rewrites the slices in place, and a struct copy shares
// their backing arrays, so resolving through one would leave the caller's policy holding
// absolute paths - and validate fingerprints that policy afterwards, which would report
// every approved manifest as stale.
//
// A host that cannot resolve them (an unusable $HOME) yields nil rather than an error:
// the approval verdict validate exists to give is a property of the manifest, and must
// not start depending on where it is checked.
func resolvedGrants(p *policy.Policy, manifestPath string) *policy.Policy {
	cp := *p
	cp.Read = slices.Clone(p.Read)
	cp.Write = slices.Clone(p.Write)
	if err := manifest.Resolve(&cp, manifestPath); err != nil {
		return nil
	}
	return &cp
}

func writePolicySummary(w io.Writer, path string, p, resolved *policy.Policy) {
	var resolvedRead, resolvedWrite []string
	if resolved != nil {
		resolvedRead, resolvedWrite = resolved.Read, resolved.Write
	}
	fmt.Fprintf(w, "manifest:     %s - ok\n", path)
	fmt.Fprintf(w, "entrypoint:   %s\n", p.Entrypoint)
	if p.Interpreter != "" {
		fmt.Fprintf(w, "interpreter:  %s\n", p.Interpreter)
	} else {
		fmt.Fprintf(w, "interpreter:  (none - the entrypoint is a compiled binary)\n")
	}
	fmt.Fprintf(w, "read:         %s\n", orNone(p.Read))
	writeResolvedGrants(w, p.Read, resolvedRead)
	fmt.Fprintf(w, "write:        %s\n", orNone(p.Write))
	writeResolvedGrants(w, p.Write, resolvedWrite)
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

// writeResolvedGrants prints the resolved spelling of a grant list under the literal
// one, and only where the two differ - an absolute grant already says where it lands,
// and repeating it would bury the lines that carry new information.
func writeResolvedGrants(w io.Writer, literal, resolved []string) {
	if len(resolved) != len(literal) || slices.Equal(literal, resolved) {
		return
	}
	for i, lit := range literal {
		if lit != resolved[i] {
			fmt.Fprintf(w, "  on this host: %s\n", resolved[i])
		}
	}
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
