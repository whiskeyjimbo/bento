package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
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
			"approved is reported. And it checks that the manifest can actually run here -\n" +
			"that the entrypoint exists and the interpreter is on PATH - so the gate does not\n" +
			"pass a manifest `run` refuses at its first step. --strict makes a stale or missing\n" +
			"approval, or a manifest this host cannot start, a failure (exit non-zero), for use\n" +
			"as a CI gate; without it they are only warnings. --json carries the same verdicts\n" +
			"as `approval` and `runnable` fields and honors --strict too.\n\n" +
			"validate builds no sandbox, so it runs on a host bento cannot run a manifest on.\n" +
			"Off Linux it cannot check who else can write an approved manifest, and says so\n" +
			"rather than passing over the question - a warning, as every trust finding is.",
		Args: exactArgs(1, "a manifest path"),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, trust, err := loadDocument(args[0])
			if err != nil {
				return err
			}
			warnStampAtRisk(cmd.ErrOrStderr(), doc, trust)
			resolved := resolvedGrants(doc.Policy, args[0])
			run := checkRunnable(resolved)
			if asJSON {
				out := toPolicyJSON(doc.Policy, resolved, doc.Provenance.BlockedHosts)
				out.Approval = approvalName(checkApproval(doc))
				out.setRunnable(run)
				if err := writeJSON(os.Stdout, out); err != nil {
					return err
				}
				// The envelope is written first so a strict failure still leaves the
				// machine consumer a parseable answer on stdout; the error goes to
				// stderr and the non-zero exit, exactly as the human mode's does.
				if err := strictApprovalError(doc, strict); err != nil {
					return err
				}
				return strictRunnableError(run, strict)
			}
			writePolicySummary(os.Stdout, args[0], doc.Policy, resolved, doc.Provenance.BlockedHosts)
			writeRunnability(os.Stdout, run)
			if err := reportApproval(os.Stdout, doc, strict); err != nil {
				return err
			}
			return strictRunnableError(run, strict)
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
		fmt.Fprintf(w, "              %s, so bento cannot\n", noStampDiff)
		fmt.Fprintf(w, "              show which field changed - re-review the whole manifest above and\n")
		fmt.Fprintf(w, "              run `bento approve` to re-stamp it\n")
	}
	return strictApprovalError(doc, strict)
}

// noStampDiff is why a stale approval cannot be shown as a diff. Every refusal that sends
// a reader back to re-review says it - run's, validate's report, validate --strict - and
// it is one string for the reason the grant refusals are: a reader who meets the answer in
// CI and again at the terminal must not have to work out whether they are the same claim.
// Without it the reasonable reading is that bento knows the delta and is withholding it.
const noStampDiff = "the stamp is a hash of the permissions, not a copy of them, so there is no diff to show"

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
		return fmt.Errorf("manifest approval is stale: permissions changed since it was approved (%s)", noStampDiff)
	default:
		return nil
	}
}

// runnability is what this host makes of the program a manifest names. validate used to
// answer only "does this parse, and is it approved", so a moved entrypoint or a typo'd
// interpreter passed the gate and failed at run's first step - the CI case, where the
// manifest is checked on one machine and the failure lands on another.
//
// It is a property of the host, not of the manifest, so it is reported beside the
// approval rather than folded into it: an unrunnable manifest here may be exactly right
// where it is meant to run.
type runnability struct {
	// problems are the reasons run would refuse before the script started. Worded as run
	// words them, since that is the message the reader will meet if they ignore this one.
	problems []string
	// fileishWrites are write grants that name nothing on this host and are spelled like
	// a file. Not a problem, because nothing here can know: run creates the directory and
	// the script may well have meant one. Silence is still wrong - write grants name
	// directories, so a grant meant as a file leaves a host directory called
	// `output.json` and the file the script wanted never appears.
	fileishWrites []string
	// missingReads are read grants naming nothing on this host. Not a problem: a grant
	// may name a path the script creates, or one that exists only on the target machine.
	// Silence is still wrong - the grant matches nothing, the sandbox denies quietly, and
	// that is the failure run's own epilogue warns is hard to diagnose.
	missingReads []string
	// unresolved marks a host that could not answer at all, which resolvedGrants reports
	// as a nil policy. Reported as unknown rather than as a pass: the summary's footer
	// already says a run here is refused for the same reason.
	unresolved bool
}

// checkRunnable asks the resolved policy - the one naming host paths - what run would
// find. Passing the manifest's own spelling would stat a relative entrypoint against
// whatever directory validate was invoked from, and resolving the manifest's policy in
// place would make every approved manifest read as stale (see resolvedGrants).
func checkRunnable(resolved *policy.Policy) runnability {
	if resolved == nil {
		return runnability{unresolved: true}
	}
	var r runnability
	if _, err := os.Stat(resolved.Entrypoint); err != nil {
		r.problems = append(r.problems, fmt.Sprintf("entrypoint %q: %v", resolved.Entrypoint, err))
	}
	// An empty interpreter means the entrypoint runs itself: a compiled binary. LookPath
	// covers both spellings the backend accepts - a bare name searched on PATH, and a
	// path checked where it points.
	if resolved.Interpreter != "" {
		if _, err := exec.LookPath(resolved.Interpreter); err != nil {
			r.problems = append(r.problems, fmt.Sprintf("interpreter %q not found: %v", resolved.Interpreter, err))
		}
	}
	// A host that cannot work out where the shields anchor yields no problems rather than
	// an error: the summary's footer already reports that gap in words, and a run there is
	// refused for the same reason, so failing --strict on it would only rename it.
	shieldedReads, _ := shieldedReadProblems(resolved.Read)
	shieldedWrites, _ := shieldedWriteProblems(resolved.Write)
	r.problems = append(r.problems, append(shieldedReads, shieldedWrites...)...)
	r.problems = append(r.problems, loopedGrantProblems(resolved.Read, resolved.Write)...)
	r.problems = append(r.problems, fileWriteGrantProblems(resolved.Write)...)
	r.fileishWrites = fileishWriteGrants(resolved.Write)
	r.missingReads = missingReadGrants(resolved.Read)
	return r
}

// loopedGrantProblems reports the grants whose symlinks loop, read and write alike, since
// the backend refuses either kind on the same fact and in the same sentence.
//
// ELOOP is the one stat error that decides anything here. It is the answer the backend
// itself acts on (internal/linux checkGrantNotLooped matches ELOOP and nothing else), so
// parity holds on every other error too: a grant bento cannot stat because a directory
// above it is unreadable says nothing about what run will find, since the sandbox sees
// that tree as a different user.
func loopedGrantProblems(read, write []string) []string {
	var problems []string
	seen := map[string]bool{}
	// One host fact, said once: the same path may be granted for reading and for writing,
	// and the backend refuses on the first of them it reaches.
	for _, g := range slices.Concat(read, write) {
		if seen[g] {
			continue
		}
		seen[g] = true
		if _, err := os.Stat(filepath.Clean(g)); errors.Is(err, syscall.ELOOP) {
			problems = append(problems, grantrefusal.Looped(g).Error())
		}
	}
	return problems
}

// fileWriteGrantProblems reports the write grants that already exist as something other
// than a directory, in the words the backend refuses them with - the case validate exists
// to catch before run's first step.
//
// Cleaned before it is statted, because `dir/file.txt/` stats as ENOTDIR and would
// otherwise be neither a problem nor a note - while run resolves the trailing slash away
// and refuses it as the file it is.
func fileWriteGrantProblems(write []string) []string {
	var problems []string
	for _, g := range write {
		if fi, err := os.Stat(filepath.Clean(g)); err == nil && !fi.IsDir() {
			problems = append(problems, grantrefusal.WriteIsFile(g).Error())
		}
	}
	return problems
}

// writeRunnability prints the host's verdict in the same shape as the approval line
// below it, and lists the notes that are not a verdict at all.
func writeRunnability(w io.Writer, r runnability) {
	switch {
	case r.unresolved:
		fmt.Fprintf(w, "\nrunnable:     unknown - this host could not resolve the manifest's paths\n")
	case len(r.problems) > 0:
		fmt.Fprintf(w, "\nrunnable:     NO - this host cannot start what the manifest names\n")
		for _, p := range r.problems {
			fmt.Fprintf(w, "              %s\n", p)
		}
	default:
		fmt.Fprintf(w, "\nrunnable:     yes (the entrypoint and interpreter resolve on this host)\n")
	}
	for _, g := range r.fileishWrites {
		fmt.Fprintf(w, "  note: this write grant is spelled like a file, but write grants name\n")
		fmt.Fprintf(w, "        directories: %q.\n", g)
		fmt.Fprintf(w, "        run creates a directory under that name, so the script's own write to\n")
		fmt.Fprintf(w, "        that path fails with \"is a directory\". Grant the parent directory\n")
		fmt.Fprintf(w, "        instead, unless a directory is what was meant.\n")
	}
	for _, g := range r.missingReads {
		fmt.Fprintf(w, "  note: this read grant names nothing on this host, so it grants nothing and\n")
		fmt.Fprintf(w, "        the sandbox denies that path without saying why: %q.\n", g)
		fmt.Fprintf(w, "        Fine if the script creates it, or if the manifest is meant for another\n")
		fmt.Fprintf(w, "        machine; otherwise it is a typo that will read as a permission bug.\n")
	}
}

// strictRunnableError is the strict verdict on runnability, shared by the human and
// --json paths for the same reason strictApprovalError is. A host that could not resolve
// the paths does not fail: the manifest was not shown to be wrong, and validate's other
// answers already degrade rather than refuse there.
func strictRunnableError(r runnability, strict bool) error {
	if !strict || len(r.problems) == 0 {
		return nil
	}
	return fmt.Errorf("manifest cannot run on this host: %s", strings.Join(r.problems, "; "))
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
	// NetworkBlocked lists the network rules that cover a destination the profiling
	// run's egress guard refused, and NetworkBlockedUnreadable the recorded keys that
	// are not a host:port anything can match against a rule (a hand-edited provenance
	// block). Both are notes rather than gates - an enforced run refuses the
	// destination the same way whatever is approved - but --json --strict is the CI
	// shape, and a rule naming a destination bento will not reach is least likely to be
	// caught by hand there.
	NetworkBlocked           []string `json:"network_blocked,omitempty"`
	NetworkBlockedUnreadable []string `json:"network_blocked_unreadable,omitempty"`
	// ShieldedGrants are the read grants that name a mandatory credential shield
	// exactly, which lifts it for the run. The same exposure the human summary and
	// approve's callouts raise; a CI gate reads it here. Absent, like ResolvedRead,
	// on a host that could not answer - see toPolicyJSON.
	ShieldedGrants []string    `json:"shielded_grants,omitempty"`
	Exec           string      `json:"exec"`
	Limits         *limitsJSON `json:"limits,omitempty"`
	// Approval is "current", "stale", or "unapproved" - the same verdict the human
	// summary prints, so a machine gate can read the outcome as a field rather than
	// inferring it from the exit code.
	Approval string `json:"approval,omitempty"`
	// Runnable says whether this host can start what the manifest names, with
	// RunnableProblems carrying run's own wording for why not. A pointer because absent
	// is a third answer - the host could not resolve the paths at all - and the same pair
	// resolved_read makes: see toPolicyJSON.
	Runnable         *bool    `json:"runnable,omitempty"`
	RunnableProblems []string `json:"runnable_problems,omitempty"`
	// MissingReadGrants are read grants naming nothing here. A note, not a verdict:
	// runnable stays true beside them, and --strict does not fail on them.
	MissingReadGrants []string `json:"missing_read_grants,omitempty"`
	// FileishWriteGrants are write grants naming nothing here that are spelled like a
	// file. A note beside missing_read_grants and read the same way: runnable stays true
	// and --strict does not fail on it.
	FileishWriteGrants []string `json:"fileish_write_grants,omitempty"`
}

// setRunnable folds the host's verdict into the envelope, leaving every field absent
// where the host could not answer.
func (o *policyJSON) setRunnable(r runnability) {
	if r.unresolved {
		return
	}
	ok := len(r.problems) == 0
	o.Runnable = &ok
	o.RunnableProblems = r.problems
	o.MissingReadGrants = r.missingReads
	o.FileishWriteGrants = r.fileishWrites
}

type limitsJSON struct {
	Memory string `json:"memory,omitempty"`
	CPU    string `json:"cpu,omitempty"`
	PIDs   int    `json:"pids,omitempty"`
}

// blockedHosts is the manifest's record of the destinations the profiling run's egress
// guard refused, the same provenance the human summary marks its network rules with.
// networkKeys renders network rules in the host:port spelling every reader of a policy
// uses, so the summary, the envelope and profile's merge diff agree on one form.
func networkKeys(rules []policy.NetworkRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Host+":"+r.Port)
	}
	return out
}

func toPolicyJSON(p, resolved *policy.Policy, blockedHosts []string) policyJSON {
	out := policyJSON{
		Entrypoint:  p.Entrypoint,
		Interpreter: p.Interpreter,
		Args:        p.Args,
		Env:         p.Env,
		Read:        p.Read,
		Write:       p.Write,
		Exec:        string(p.Exec),
		Network:     networkKeys(p.Network),
	}
	// Rendered in the same spelling as the network field above, so a consumer can match
	// an entry back to the rule it marks without re-deriving the join.
	covering, unreadable := rulesCoveringBlockedHost(p, blockedHosts)
	if len(covering) > 0 {
		out.NetworkBlocked = networkKeys(covering)
	}
	out.NetworkBlockedUnreadable = unreadable
	if !p.Limits.IsZero() {
		out.Limits = &limitsJSON{Memory: p.Limits.Memory, CPU: p.Limits.CPU, PIDs: p.Limits.PIDs}
	}
	// A host that could not resolve the grants (an unusable $HOME) yields nil here, the
	// same degradation the human summary makes: the approval verdict this command exists
	// to give is a property of the manifest and must not start depending on the host.
	if resolved != nil {
		out.ResolvedRead = toGrantTargetsJSON(p.Read, resolved.Read)
		out.ResolvedWrite = toGrantTargetsJSON(p.Write, resolved.Write)
		// An error is dropped for the same reason a failed resolve is: the verdict this
		// command exists to give is a property of the manifest. It leaves the field absent
		// beside a resolved_read that is also absent, which is the pair a consumer reads
		// as "this host could not answer" - the human summary says it in words.
		out.ShieldedGrants, _ = explicitShieldGrants(resolved.Read)
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
	shieldGrants, shieldErr := explicitShieldGrants(resolvedRead)
	for _, g := range shieldGrants {
		fmt.Fprintf(w, "  note: this grant names a credential store bento shields on every run, exactly\n")
		fmt.Fprintf(w, "        and not merely under it: %q. bento honors that as a\n", g)
		fmt.Fprintf(w, "        deliberate read-only exception rather than refusing, so the script can\n")
		fmt.Fprintf(w, "        read the credentials in it. Remove the grant unless it needs them.\n")
	}
	// The error is dropped on both: it is the same failure to anchor the shields that
	// shieldErr carries, and the footer below reports it once in words rather than twice
	// as an empty list.
	readRefusals, _ := shieldedReadProblems(resolvedRead)
	writeShieldRefusals(w, readRefusals)
	fmt.Fprintf(w, "write:        %s\n", orNone(p.Write))
	writeResolvedGrants(w, p.Write, resolvedWrite)
	writeRefusals, _ := shieldedWriteProblems(resolvedWrite)
	writeShieldRefusals(w, writeRefusals)
	fmt.Fprintf(w, "env:          %s\n", orNone(p.Env))
	writeSandboxHome(w, p)

	if len(p.Network) == 0 {
		fmt.Fprintf(w, "network:      denied (no egress)\n")
	} else {
		fmt.Fprintf(w, "network:      %v\n", networkKeys(p.Network))
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

	// The footer asserts the shields hold over everything above it, so anything that
	// unsettles that has to be named here too: the unqualified sentence is the last thing
	// the approve prompt prints before asking, and printing it over a grant that lifts a
	// shield says the opposite of what is about to be stamped.
	if shieldErr != nil {
		fmt.Fprintf(w, "\nEverything not listed above is denied, but bento could not work out where the\n")
		fmt.Fprintf(w, "credential shields anchor on this host (%v), so nothing above was\n", shieldErr)
		fmt.Fprintf(w, "checked against them - and a run here is refused for the same reason.\n")
		return
	}
	if len(shieldGrants) > 0 {
		fmt.Fprintf(w, "\nEverything not listed above is denied, and credentials, SSH keys, and shell\n")
		fmt.Fprintf(w, "profiles are shielded - EXCEPT the %d credential store(s) noted above, which\n", len(shieldGrants))
		fmt.Fprintf(w, "a read grant names exactly and so opts back in.\n")
		return
	}
	fmt.Fprintf(w, "\nEverything not listed above is denied. Credentials, SSH keys, and shell\n")
	fmt.Fprintf(w, "profiles are shielded even if a path above would otherwise expose them.\n")
}

// writeShieldRefusals prints the grants a run refuses over the shields, beside the list
// they were spelled in. Beside, and not only in the runnability block below, because the
// footer under that list asserts the shields hold over everything above it - which reads
// as confirmation that the grant right above it is safe, when it is the one grant here
// that will not be honored at all.
//
// The sentence is run's own (grantrefusal), unwrapped: it names paths, and wrapping it to
// the note width would break a path across lines just where the reader wants to copy it.
// It appears twice on a human screen - here, and below as the reason `runnable: NO` gives
// - which is the price of the two jobs it does: the reader scanning the grants needs it at
// the grant, and the reader who skipped to the verdict needs the verdict to say why.
func writeShieldRefusals(w io.Writer, problems []string) {
	for _, p := range problems {
		fmt.Fprintf(w, "  REFUSED: %s\n", p)
	}
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
	writeSandboxHomeNote(w, "  ")
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
