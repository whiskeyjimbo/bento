package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/enforce"
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
			doc, trust, err := loadDocument(args[0])
			if err != nil {
				return err
			}
			warnStampAtRisk(cmd.ErrOrStderr(), doc, trust)
			if asJSON {
				out := toPolicyJSON(doc.Policy, resolvedGrants(doc.Policy, args[0]))
				out.Approval = approvalName(checkApproval(doc))
				if err := writeJSON(os.Stdout, out); err != nil {
					return err
				}
				// The envelope is written first so a strict failure still leaves the
				// machine consumer a parseable answer on stdout; the error goes to
				// stderr and the non-zero exit, exactly as the human mode's does.
				return strictApprovalError(doc, strict)
			}
			writePolicySummary(os.Stdout, args[0], doc.Policy, resolvedGrants(doc.Policy, args[0]), doc.Provenance.BlockedHosts)
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
// The trust facts are returned alongside so a caller can report or refuse on them
// without a second open - they must describe the same inode these bytes came from. It
// does not report them itself: whether anyone else can change the manifest only costs
// something once there is a stamp to devalue, which is not knowable until it is parsed.
// See warnStampAtRisk.
func loadDocument(path string) (*manifest.Document, manifestTrust, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, manifestTrust{}, err
	}
	defer f.Close()
	trust, err := inspectManifest(f, path)
	if err != nil {
		return nil, manifestTrust{}, err
	}
	doc, err := manifest.Parse(f)
	if err != nil {
		return doc, trust, notAManifest(f, path, err)
	}
	return doc, trust, nil
}

// notAManifest replaces a parse error with the mistake it usually is: the script was
// named where its manifest belongs. The parser's own complaint quotes the script's first
// lines, which reads as a problem with the file's contents rather than with which file
// was named, and nothing in it points at the manifest. Every command that takes one
// loads through here, so run, validate and approve all get the same answer.
//
// It replaces the error only where the file plainly is a program, so a genuinely
// malformed manifest still gets the parser's diagnosis, and never adds to it - a second
// line beside a diagnosis this specific is one more thing to skim past.
func notAManifest(f *os.File, path string, parseErr error) error {
	if !looksLikeScript(f, path) {
		return parseErr
	}
	// The suggestion is stat-ed before it is offered: profile writes the manifest beside
	// the script under this name, so it is usually there, and naming one that is not would
	// send the reader to a file they would have to draft anyway.
	if suggestion := path + ".manifest.yaml"; fileExists(suggestion) {
		return fmt.Errorf("%s looks like a script, not a manifest. Did you mean %s?", path, suggestion)
	}
	return fmt.Errorf("%s looks like a script, not a manifest. Run `bento profile %s` to draft one, then pass that", path, path)
}

// looksLikeScript reports whether a file bento failed to parse is a program rather than a
// mangled manifest. A shebang is the cheap signal; the extensions bento already maps to an
// interpreter are the other, since a manifest never carries one.
func looksLikeScript(f *os.File, path string) bool {
	if guessInterpreter(path) != "" {
		return true
	}
	// Parse consumed the file, so the shebang is behind the offset. A seek that fails
	// leaves the parser's error in place, which is the right answer when nothing here
	// could be read.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	var head [2]byte
	n, _ := io.ReadFull(f, head[:])
	return n == 2 && string(head[:]) == "#!"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
	Entrypoint  string   `json:"entrypoint"`
	Interpreter string   `json:"interpreter,omitempty"`
	Args        []string `json:"args,omitempty"`
	Env         []string `json:"env,omitempty"`
	Read        []string `json:"read,omitempty"`
	Write       []string `json:"write,omitempty"`
	// ResolvedRead/ResolvedWrite name what each grant reaches on this host, for the
	// entries where that differs from the spelling - a ~ or relative prefix, or a
	// symlink. read/write stay literal because that is what the fingerprint attests and
	// what a consumer diffing across runs must be able to compare; these say what
	// approving it would hand over. Absent when every grant names its own target.
	ResolvedRead  []grantTargetJSON `json:"resolved_read,omitempty"`
	ResolvedWrite []grantTargetJSON `json:"resolved_write,omitempty"`
	Network       []string          `json:"network"`
	Exec          string            `json:"exec"`
	Limits        *limitsJSON       `json:"limits,omitempty"`
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

func toPolicyJSON(p, resolved *policy.Policy) policyJSON {
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
	// A host that could not resolve the grants (an unusable $HOME) yields nil here, the
	// same degradation the human summary makes: the approval verdict this command exists
	// to give is a property of the manifest and must not start depending on the host.
	if resolved != nil {
		out.ResolvedRead = toGrantTargetsJSON(p.Read, resolved.Read)
		out.ResolvedWrite = toGrantTargetsJSON(p.Write, resolved.Write)
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

// blockedHosts is the manifest's record of the destinations the profiling run's egress
// guard refused (provenance, not permission), used to mark the network rules that cover
// one. approve passes nil: writeApprovalCallouts raises the same rules where the reader
// is deciding, and printing it twice on one screen teaches them to skim the block.
func writePolicySummary(w io.Writer, path string, p, resolved *policy.Policy, blockedHosts []string) {
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
	writeSandboxHome(w, p)

	if len(p.Network) == 0 {
		fmt.Fprintf(w, "network:      denied (no egress)\n")
	} else {
		rules := make([]string, 0, len(p.Network))
		for _, r := range p.Network {
			rules = append(rules, r.Host+":"+r.Port)
		}
		fmt.Fprintf(w, "network:      %v\n", rules)
		covering, unreadable := rulesCoveringBlockedHost(p, blockedHosts)
		for _, r := range covering {
			fmt.Fprintf(w, "  note: the profiling run reached a destination %q port %q covers and bento's\n", r.Host, r.Port)
			fmt.Fprintf(w, "        egress guard refused it - the name resolved to an address a sandbox must\n")
			fmt.Fprintf(w, "        not reach (loopback, private space, or cloud metadata). An enforced run\n")
			fmt.Fprintf(w, "        refuses it the same way; this rule does not widen it.\n")
		}
		for _, key := range unreadable {
			fmt.Fprintf(w, "  note: the manifest records %q as a destination profiling was refused, but that\n", key)
			fmt.Fprintf(w, "        is not a host:port anything can match against the rules above - it was\n")
			fmt.Fprintf(w, "        hand-edited.\n")
		}
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
		fmt.Fprintf(w, "limits:       %s\n", describeLimits(p.Limits))
	}

	fmt.Fprintf(w, "\nEverything not listed above is denied. Credentials, SSH keys, and shell\n")
	fmt.Fprintf(w, "profiles are shielded even if a path above would otherwise expose them.\n")
}

// writeSandboxHome states what HOME will be inside the box when the manifest does not
// pass the caller's through. The remap is deliberate - a sandbox inheriting the real HOME
// would put every credential store one expanduser away - but nothing says it happened, so
// a script using the ordinary `~/.config/...` idiom fails on a path its author never
// wrote and reads as a bug in their own code. validate is where the reader is already
// reviewing permissions, which is before the first confusing traceback rather than after.
func writeSandboxHome(w io.Writer, p *policy.Policy) {
	if slices.Contains(p.Env, "HOME") {
		return
	}
	fmt.Fprintf(w, "  note: HOME is not passed through, so inside the sandbox it is %s and `~`\n", enforce.SandboxHome)
	fmt.Fprintf(w, "        expands there, not to your home directory. Grants above are matched\n")
	fmt.Fprintf(w, "        against host paths, so a script resolving ~ itself will miss them -\n")
	fmt.Fprintf(w, "        write the paths it opens absolute, or allowlist HOME here.\n")
}

// writeResolvedGrants prints the resolved spelling of a grant list under the literal
// one, and only where the two differ - an absolute grant that names its own target
// already says where it lands, and repeating it would bury the lines that carry new
// information.
//
// Symlinks are followed as well as ~ and relative prefixes, because the reviewer's
// question is what the grant reaches, and a link answers it differently from the name.
// A ~ grant under a $HOME whose .ssh is a symlink elsewhere reads as a scratch path here
// and binds that link's target at run time; the run warning names it, but by then the
// manifest is approved. The stamp attests the manifest text, so this line is what the
// approval is worth - a link that moves afterward changes what the same approved
// manifest reaches, and only the run-time output will say so.
//
// The target is enumerated from the host, so it is quoted: a directory whose name holds a
// newline would otherwise print as a second line and forge a summary line of its own.
func writeResolvedGrants(w io.Writer, literal, resolved []string) {
	for _, t := range toGrantTargetsJSON(literal, resolved) {
		fmt.Fprintf(w, "  on this host: %q\n", t.OnHost)
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
