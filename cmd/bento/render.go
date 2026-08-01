package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/policy"
)

// The JSON shapes below are the machine-readable contract for agents and CI.
// They are defined here, in the frontend, so the core stays free of wire-format
// concerns - and they use explicit strings rather than the core's enum values, so
// reordering a Go constant can never silently change the contract.
//
// Every path field below is a Go string encoded as JSON, so a path carrying bytes that
// are not valid UTF-8 arrives with those bytes replaced by U+FFFD and no longer names an
// openable file. A consumer that must open what it reads has to treat a path field as a
// display name on such a host; nothing here re-encodes them, because no credential store
// bento shields has a non-UTF-8 name in practice and a base64 sibling on every path field
// would cost every consumer to serve none of them.

type layerJSON struct {
	Layer  string `json:"layer"`
	Tier   string `json:"tier"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type reportJSON struct {
	Layers []layerJSON `json:"layers"`
	// FullyEnforced is true only when every layer in this report is enforced. It is not
	// the host-readiness gate: a host can run a manifest whose layers all hold while a
	// different layer here falls short, so a CI caller gates on doctor's exit code or
	// doctorJSON.Ready, not on this.
	FullyEnforced bool `json:"fully_enforced"`
}

// refusalJSON is the envelope for a run bento would not perform. It is the one shape
// every refusal uses - the enforcement layer's own and the frontend's alike - so a
// machine consumer never has to tell an empty stdout from a crash.
type refusalJSON struct {
	Refused bool       `json:"refused"`
	Reason  string     `json:"reason"`
	Report  reportJSON `json:"report"`
}

// noReport is the report for a refusal raised before any sandbox was built, where no
// layer was ever evaluated. toReportJSON of a zero Report would answer
// fully_enforced:true - literally "no layer degraded" - which reads as a clean posture
// on a run that never had one.
var noReport = reportJSON{Layers: []layerJSON{}, FullyEnforced: false}

// doctorJSON is the doctor command's machine-readable output: the full host report
// plus a readiness bool that mirrors doctor's exit code, so a CI consumer can gate on
// one field rather than the process status or the matrix.
type doctorJSON struct {
	reportJSON
	// Ready is true when every guarantee a manifest needs regardless of its contents is
	// enforced here - the same condition as exit 0. It can be true while FullyEnforced
	// is false: a host missing only a conditionally-required (network egress) or
	// hardening layer still runs every manifest that does not need that layer.
	Ready bool `json:"ready"`
}

func toReportJSON(r enforce.Report) reportJSON {
	out := reportJSON{Layers: make([]layerJSON, 0, len(r.Layers)), FullyEnforced: !r.HasDegradation()}
	for _, l := range r.Layers {
		out.Layers = append(out.Layers, layerJSON{
			Layer:  string(l.Layer),
			Tier:   l.Layer.Tier().String(),
			State:  l.State.String(),
			Detail: l.Reason,
		})
	}
	return out
}

// accessNoteJSON is one decision a profiling run made about an access it observed,
// for `bento profile --json`. It carries the two lists that decision can land in - the
// accesses profiling declined to propose, and the grants it proposed but wants a
// reviewer to weigh - because both answer the same question a harness has to ask: what
// did profiling do about this path, and why.
//
// A note about a grant the manifest carries is spelled the way the manifest spells it,
// so a consumer can look it up in Policy; a withheld note names the host path profiling
// observed, which is not a grant and has no spelling in the file to be given.
//
// Reason is a stable code rather than the prose the same decision writes to stderr. The
// prose exists to be read once and reworded when it reads badly; a machine gate that
// matched on it would break on that rewording. Path and Host/Port are alternatives: a
// filesystem note carries the first, an egress one the second.
type accessNoteJSON struct {
	// Kind is "read", "write", or "network".
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
	Port string `json:"port,omitempty"`
	// Reason is one of: system-tree, sandbox-scratch, unix-socket, unrepresentable,
	// shielded-credential, write-shielded, too-broad (withheld); foreign-home-shield,
	// target-steerable-tmp, whole-workdir (proposed and flagged).
	Reason string `json:"reason"`
	// Absent says nothing was found at Path, so the run only probed for it - the
	// difference between a file the script read under a name a manifest cannot hold and
	// an interpreter's search miss, which is the routine case. A pointer because unknown
	// is a third answer, as with policyJSON.Runnable, and unknown is what most notes
	// carry: it is answered only for an unrepresentable read, the one decision whose
	// wording turns on it. A write is judged at its parent directory, whose existence no
	// observation names, and a network note has no path at all.
	Absent *bool `json:"absent,omitempty"`
}

// profileJSON is `bento profile`'s machine-readable result: what it wrote, whether it
// can vouch for it, and every decision that is otherwise only prose on stderr.
//
// It is what the exit code cannot carry. A harness that generates manifests reads which
// paths profiling declined and why, which grants want review, and which hosts the egress
// guard refused - none of which a code can say, and all of which it would otherwise have
// to scrape.
type profileJSON struct {
	// Manifest is the path written, as it was passed or defaulted. It is written whether
	// or not profiling can vouch for it - see Complete.
	Manifest string `json:"manifest"`
	// Complete is false when the proposal is one profiling cannot vouch for, which is the
	// same condition as exit 4. IncompleteReason names it.
	Complete         bool   `json:"complete"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	// Policy is the manifest as written - the relocatable spelling, not the absolute
	// paths profiling observed - so a consumer comparing it against the file agrees. It
	// is validate's own shape, so a harness reads a manifest the same way whether it was
	// just proposed or is being re-checked; the fields validate answers about a stamped
	// file (approval, runnable) are absent here, where nothing has stamped it.
	Policy policyJSON `json:"policy"`
	// Withheld are the accesses the run observed and did not propose; Flagged are grants
	// the written manifest carries that want a reviewer's attention. A flagged grant can
	// be one the merge kept from the file rather than one this run showed - it is what
	// the reviewer is about to approve either way, which is the question it answers.
	Withheld []accessNoteJSON `json:"withheld,omitempty"`
	Flagged  []accessNoteJSON `json:"flagged,omitempty"`
	// BlockedHosts are the recorded egress destinations the guard refused that the
	// written manifest nonetheless grants - the provenance block's own record.
	BlockedHosts []string `json:"blocked_hosts,omitempty"`
	// Merged is present only when there was a manifest at --out to widen, and says which
	// half of the result came from the file rather than from this run.
	Merged *mergeJSON `json:"merged,omitempty"`
}

// mergeJSON says what folding this run's proposal into an existing manifest changed. A
// consumer that treats the written file as "what this run observed" is wrong whenever
// this is present, which is why the kept grants are named rather than counted.
type mergeJSON struct {
	KeptRead    []string `json:"kept_read,omitempty"`
	KeptWrite   []string `json:"kept_write,omitempty"`
	KeptEnv     []string `json:"kept_env,omitempty"`
	KeptNetwork []string `json:"kept_network,omitempty"`
	// ExecWidened is whether the union escalated exec to `all`; ApprovalVoided whether the
	// file carried a current approval that this write dropped.
	ExecWidened    bool `json:"exec_widened"`
	ApprovalVoided bool `json:"approval_voided"`
}

// shieldJSON is one always-on shield a run engaged, for the --json envelope. Kind is
// "hidden" or "read-only"; see enforce.ShieldApplied.
type shieldJSON struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

func toShieldsJSON(shields []enforce.ShieldApplied) []shieldJSON {
	if len(shields) == 0 {
		return nil
	}
	out := make([]shieldJSON, 0, len(shields))
	for _, s := range shields {
		out = append(out, shieldJSON{Path: s.Path, Kind: s.Kind})
	}
	return out
}

// aliasJSON is one acknowledged credential alias a run read past a shield, for the --json
// envelope; see enforce.CredentialAlias.
type aliasJSON struct {
	Path       string `json:"path"`
	Credential string `json:"credential"`
}

func toAliasesJSON(aliases []enforce.CredentialAlias) []aliasJSON {
	if len(aliases) == 0 {
		return nil
	}
	out := make([]aliasJSON, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, aliasJSON{Path: a.Path, Credential: a.Credential})
	}
	return out
}

// hostPortJSON is one egress destination for the --json envelope; see enforce.HostPort.
type hostPortJSON struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

func toHostPortsJSON(dests []enforce.HostPort) []hostPortJSON {
	if len(dests) == 0 {
		return nil
	}
	out := make([]hostPortJSON, 0, len(dests))
	for _, hp := range dests {
		out = append(out, hostPortJSON{Host: hp.Host, Port: hp.Port})
	}
	return out
}

// grantTargetJSON is one grant whose name is not where it lands - the store a symlinked
// or expanded path actually reaches. It mirrors aliasJSON: a name, and what it reaches.
type grantTargetJSON struct {
	Path   string `json:"path"`
	OnHost string `json:"on_host"`
}

// grantTarget reports what a grant reaches, and whether that differs from how the
// manifest spells it. resolved is the grant after ~ and relative prefixes are expanded
// (the same path for a grant that arrives absolute); symlinks are followed on top of
// that, because a link answers "what does this reach" differently from the name.
//
// It resolves through pathresolve.Existing, the same resolver the enforcer binds by, so
// the reported target is the path the run will actually use rather than a second opinion
// about it. That matters most for a grant whose leaf does not exist yet - a plain
// EvalSymlinks fails outright there and would report the path with its symlinked
// components still unresolved, so two entries in one envelope could disagree about the
// same directory, one of them naming a link the other had just called an alias.
func grantTarget(literal, resolved string) (string, bool) {
	if filepath.IsAbs(resolved) {
		resolved = pathresolve.Existing(resolved)
	}
	return resolved, resolved != literal
}

// toShieldedTargetsJSON renders the pairs the backend resolved as it bound them.
func toShieldedTargetsJSON(targets []enforce.CredentialAlias) []grantTargetJSON {
	var out []grantTargetJSON
	for _, t := range targets {
		out = append(out, grantTargetJSON{Path: t.Path, OnHost: t.Credential})
	}
	return out
}

// toGrantTargetsJSON pairs each grant with what it reaches, for the entries where the
// two differ. The differing ones are the whole point: an agent gating on the envelope
// otherwise reads the spelling and never the store, which for a shield opt-in under a
// caller-chosen $HOME is the difference between a scratch path and a private key.
//
// This is validate's answer, resolved when the summary is written - there is no run to
// take it from, and the comment on writeResolvedGrants owns that gap. The run's own
// envelope uses toShieldedTargetsJSON instead, which carries what was actually bound.
func toGrantTargetsJSON(literal, resolved []string) []grantTargetJSON {
	if len(resolved) != len(literal) {
		return nil
	}
	var out []grantTargetJSON
	for i, lit := range literal {
		if lands, differs := grantTarget(lit, resolved[i]); differs {
			out = append(out, grantTargetJSON{Path: lit, OnHost: lands})
		}
	}
	return out
}

// explicitShieldGrants reports the read grants that name a mandatory credential shield
// (~/.ssh, ~/.gnupg, the runtime dir's agent sockets) exactly, which the backend honors
// as a deliberate, read-only exception rather than refusing. It is the pre-run answer to
// what writeShieldedGrantWarning reports after the fact, so validate and approve can
// raise the exposure while the reviewer is still deciding.
//
// It mirrors the backend's own opt-in test (explicitShieldOptIns) rather than
// approximating it: DenyAll rules only, from the built-in home and runtime lists only,
// matched by exact string equality against the anchors denylist.HomeAnchors reports. A
// grant strictly INSIDE a shield is refused at run time, not opted into, so widening
// this to containment would name it as an exposure the run will never permit. The
// anchors are taken raw, without the symlink-resolved siblings clampShieldedGrants adds:
// that widening is a proposal-quality filter, and adding it here would warn about a
// grant the run does not treat as an opt-in.
//
// reads are the policy's resolved grants (absolute, ~ expanded, symlinks NOT followed),
// which is the same spelling the backend compares. A host with no usable anchor at all
// has no shield rules to compare against, which is returned as an error rather than as
// an empty answer: the footer this feeds asserts the shields hold, and printing that
// unqualified for a host that can build none of them is the one wrong thing to say.
func explicitShieldGrants(reads []string) ([]string, error) {
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		return nil, err
	}
	var rules []denylist.Rule
	for _, h := range anchors {
		// Every anchor is passed to every call, matching homeShields: a relocation env
		// var pointing at one home must not produce a rule that swallows another.
		rules = append(rules, denylist.Home(h, anchors...)...)
	}
	rules = append(rules, denylist.Runtime(denylist.RuntimeDir(), anchors...)...)
	var out []string
	for _, r := range rules {
		if r.Deny == denylist.DenyAll && slices.Contains(reads, r.Path) && !slices.Contains(out, r.Path) {
			out = append(out, r.Path)
		}
	}
	slices.Sort(out)
	return out, nil
}

// writeShieldSummary prints one concise line confirming the boundary engaged: how many
// credential/host-service paths the run shielded, so an operator sees the sandbox is
// working without a per-path dump (the full list is in --json). It records what the
// sandbox shielded from its rule set, not what the target tried to reach, so it is
// silent when a run's grants reached no shield.
func writeShieldSummary(w io.Writer, res enforce.Result) {
	if len(res.Shields) == 0 {
		return
	}
	hidden, readonly := 0, 0
	for _, s := range res.Shields {
		if s.Kind == "read-only" {
			readonly++
		} else {
			hidden++
		}
	}
	msg := fmt.Sprintf("%d hidden", hidden)
	if readonly > 0 {
		msg += fmt.Sprintf(", %d read-only", readonly)
	}
	fmt.Fprintf(w, "[bento] sandbox engaged: %d credential/host-service path(s) shielded (%s); --json lists them\n", len(res.Shields), msg)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// textWidth is the column the human-readable prose wraps at. It is fixed rather than
// read from the terminal because this output is piped into logs and CI transcripts at
// least as often as it is read on a tty, and a report whose line breaks depend on the
// window it was produced in cannot be diffed against another run's.
const textWidth = 78

// detailInline is the longest DETAIL cell left in the table. It is looser than
// textWidth on purpose - a table is not prose, and every reason short enough to read
// at a glance stays on its row rather than costing the reader a lookup below. What it
// catches is the degraded filesystem tier's disclosure, which runs past a thousand
// characters on one line: inline that destroys the column alignment the table exists
// for and pushes the other rows off any terminal, so it moves below as a note.
const detailInline = 100

// writeReportTable renders the enforcement matrix for a human. The layer's full
// detail is never dropped, only relocated - the machine-readable --json carries it
// whole either way.
func writeReportTable(w io.Writer, r enforce.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LAYER\tTIER\tSTATE\tDETAIL")
	var notes []enforce.LayerStatus
	for _, l := range r.Layers {
		detail := l.Reason
		if len(detail) > detailInline {
			detail = "see note below"
			notes = append(notes, l)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Layer, l.Layer.Tier(), l.State, detail)
	}
	tw.Flush()
	for _, l := range notes {
		fmt.Fprintf(w, "\n%s (%s):\n", l.Layer, l.State)
		for _, line := range wrapText(l.Reason, textWidth-2) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

// wrapText breaks s into lines of at most width columns on word boundaries. A word
// longer than width keeps its own line rather than being split: these details name
// paths, sysctls and syscalls that a reader copies out, and a break inside one turns
// an actionable name into two unusable halves.
func wrapText(s string, width int) []string {
	var lines []string
	var line string
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// writeEgressHint explains a likely proxy-bypass. Bento intercepts egress
// cooperatively: a program that honors HTTP_PROXY reaches its allowlisted hosts,
// but one that ignores it and dials a raw address hits the empty network
// namespace and fails closed. When a network-using run failed and made *no*
// connections through the proxy, that bypass is the likely cause - and a bare
// "network unreachable" would leave the user with no idea why.
//
// This is a heuristic, not proof: without syscall observation we cannot tell a
// bypass from a script that simply made no network calls and failed for another
// reason, so the wording is hedged ("if it needs network") rather than asserting.
// It reports whether it said anything, so the filesystem hint below does not stack a
// second explanation of the same failure onto it.
func writeEgressHint(w io.Writer, p *policy.Policy, res enforce.Result) bool {
	if len(p.Network) == 0 || res.ExitCode == 0 || res.EgressConnections > 0 {
		return false
	}
	fmt.Fprintln(w, "[bento] the script exited non-zero and made no connections through the egress proxy.")
	fmt.Fprintln(w, "[bento] if it needs network: bento intercepts egress via HTTP_PROXY, so a program that")
	fmt.Fprintln(w, "[bento] ignores proxy settings (some static binaries) cannot reach allowlisted hosts and")
	fmt.Fprintln(w, "[bento] fails to connect. Programs that honor HTTP_PROXY (curl, requests, pip, npm) work.")
	return true
}

// writeExecHint explains exit 126 under a manifest that blocks exec. Bento has no
// observer at enforce time here either: the filter refuses execve with EPERM and the
// target reports its own error, so a shell that could not run a command exits 126 and
// nothing connects that number back to the manifest line that caused it.
//
// A heuristic like its siblings, and worded as one - 126 is the shell's code for "found
// but not executable", which a script can reach on its own (a non-executable file, a
// missing interpreter) under any exec mode. So it names the manifest setting as what
// produces that code, not as what definitely produced this one.
//
// It reports whether it said anything, so no second explanation stacks on top.
func writeExecHint(w io.Writer, p *policy.Policy, res enforce.Result) bool {
	if res.ExitCode != 126 || p.Exec == policy.ExecAll {
		return false
	}
	// The declared mode is not enough: exec-block is a hardening layer, so a run whose
	// filter never landed proceeds anyway - and writeDegradations has just said so a few
	// lines above. Blaming the manifest there both contradicts that line and sends the
	// reader to change a setting that had no part in the failure.
	if res.Report.StateOf(enforce.LayerExec) != enforce.Enforced {
		return false
	}
	// Spelled as the manifest spells it, so the reader can find the line to change. Only
	// the two blocking modes reach here, and the zero value of ExecMode is none.
	mode := policy.ExecNone
	if p.Exec == policy.ExecNoneStrict {
		mode = policy.ExecNoneStrict
	}
	fmt.Fprintln(w, "[bento] the script exited 126, the code a shell returns when it could not execute a")
	// "runs under", not "sets": exec is the deny default, so a manifest that never
	// mentions it reaches here too and a reader would grep for a line that is not there.
	fmt.Fprintf(w, "[bento] command. This manifest runs under exec: %s, which blocks subprocess execution:\n", mode)
	fmt.Fprintln(w, "[bento] an execve is refused with a permission error, and a shell reports that as 126.")
	fmt.Fprintln(w, "[bento] Set exec: all if the script needs to run other programs.")
	return true
}

// writeDenialLegend decodes the two errors the kernel reports for a bento denial, which
// the target prints itself and bento never sees.
//
// The hints above all key on a failure - a signal, exit 126, a non-zero exit with no
// egress - because each explains one. This explains none: it is the standing note that
// a script continuing past a refused write or exec exits 0, so a clean exit is not
// evidence the box let everything through. That case has no signal at all to key on,
// and it is the one that reads as success.
//
// Deliberately naming no paths. Spelling the grants back would need the manifest's own
// wording rather than the resolved absolutes this side holds, and the reader has the
// manifest open; what they do not have is the mapping from an errno string to the field
// that produced it.
func writeDenialLegend(w io.Writer, p *policy.Policy, res enforce.Result) {
	// A clean exit only. Every hint above explains a failure the target reported, and on
	// a failing run the profile hint already says the sandbox denies silently - a second
	// telling there would stack onto it and close by explaining an exit 0 that did not
	// happen. What none of them cover is the run that reported nothing.
	if res.ExitCode != 0 || res.Signal != 0 {
		return
	}
	// Each line answers for the layer that produces its errno, because the two do not
	// stand or fall together. EROFS comes from bubblewrap's read-only remount, so it is
	// what a refused write says only on the bwrap tier; the Landlock-only tier has no
	// remount and answers EACCES instead, and naming EROFS there would map an error the
	// script cannot emit - the opposite failure to the silence this exists to fix.
	//
	// Enforced, not merely "not Unavailable": the filesystem layer also reads Degraded on
	// the bwrap tier when only the Landlock backstop failed, where EROFS does still hold.
	// Requiring Enforced drops a true line in that one case, which is the safe direction
	// to be wrong in, and writeDegradations has already spoken there.
	writesAreEROFS := res.Report.StateOf(enforce.LayerFilesystem) == enforce.Enforced
	blocksExec := p.Exec != policy.ExecAll && res.Report.StateOf(enforce.LayerExec) == enforce.Enforced
	if !writesAreEROFS && !blocksExec {
		return
	}
	fmt.Fprintln(w, "[bento] a denial inside the box is reported by the script, not by bento:")
	switch {
	case !writesAreEROFS:
	case len(p.Write) == 0:
		// Naming a field the manifest does not carry sends the reader grepping for a
		// line that is not there, the same trap writeExecHint's "runs under" avoids.
		fmt.Fprintln(w, "[bento]   \"Read-only file system\" - this manifest grants no write: directory")
	default:
		fmt.Fprintln(w, "[bento]   \"Read-only file system\" - a path outside the manifest's write: grants")
	}
	if blocksExec {
		// The zero value is the empty string, not "none", so a manifest that never
		// mentions exec would name a field spelled nothing at all.
		mode := policy.ExecNone
		if p.Exec == policy.ExecNoneStrict {
			mode = policy.ExecNoneStrict
		}
		fmt.Fprintf(w, "[bento]   \"Operation not permitted\" on a command - exec: %s\n", mode)
	}
	fmt.Fprintln(w, "[bento] bento observes neither, so a script that continues past one still exits 0.")
}

// describeLimits names the declared limits the way the manifest spells them, for the
// summary and for the kill notice that has to say which caps were in play.
func describeLimits(l policy.Limits) string {
	var parts []string
	if l.Memory != "" {
		parts = append(parts, "memory "+l.Memory)
	}
	if l.CPU != "" {
		parts = append(parts, "cpu "+l.CPU)
	}
	if l.PIDs > 0 {
		parts = append(parts, fmt.Sprintf("pids %d", l.PIDs))
	}
	return strings.Join(parts, ", ")
}

// writeSignalNotice explains a run that ended on a signal rather than an exit code.
// Without it the death arrives as a bare number the reader has to decode, and the
// profile hint below reads it as a script failure and sends them to profile a script
// that was working - the shape the strict probe example ends on, where a declared
// memory cap kills the run by design.
//
// A cgroup kill reaches here two ways, both covered. Usually the target is SIGKILLed
// inside the sandbox and each wrapper relays 128+signal outward, so it arrives as an
// exit code; occasionally the scope comes down on the wrapper itself, which arrives
// signaled. Only the second is proof - a script may exit 137 of its own accord - so
// the code-only case is worded as the likelihood it is. Bento's own 124 and 125 sit
// below the range and cannot be mistaken for one.
//
// It says the RUN was killed, never the script: a scope torn down during setup arrives
// signaled too, and the script it names there was never started.
//
// It reports whether it said anything, so no second explanation stacks on top.
func writeSignalNotice(w io.Writer, p *policy.Policy, res enforce.Result) bool {
	sig, certain := signalDeath(res)
	if sig == 0 {
		return false
	}
	if certain {
		fmt.Fprintf(w, "[bento] the run did not exit: it was killed by signal %d (%s), reported as exit %d.\n",
			sig, syscall.Signal(sig), res.ExitCode)
	} else {
		fmt.Fprintf(w, "[bento] the run ended with exit %d, which is how a process killed by signal %d (%s)\n", res.ExitCode, sig, syscall.Signal(sig))
		fmt.Fprintln(w, "[bento] is reported - though a script can also exit that code on its own.")
	}
	// SIGSYS is the one death bento can usually attribute: it means a kill-mode seccomp
	// filter refused a syscall, and every kill branch in bento's own filters (strict
	// exec, egress, terminal injection, the foreign-arch guard) is the foreign-arch or
	// x32 case - a policy refusal returns EPERM and lets the target handle it. So the
	// layer is named as the likelihood it is: a target may install its own filter.
	if sig == int(syscall.SIGSYS) {
		fmt.Fprintln(w, "[bento] that signal is sent when a seccomp filter kills a process over a syscall, and the")
		fmt.Fprintln(w, "[bento] filters bento installs kill only on a foreign-architecture call - a 32-bit or")
		fmt.Fprintln(w, "[bento] x32 syscall from a 64-bit process. A permission the manifest withholds is")
		fmt.Fprintln(w, "[bento] refused with EPERM instead, so this is most likely that guard rather than a")
		fmt.Fprintln(w, "[bento] grant you can add - though a target can install a killing filter of its own.")
	}
	// Only the two signals a cgroup kill actually arrives on. Blaming the caps for any
	// signal would tell a script that took a SIGPIPE off a closed stdout, or segfaulted,
	// that it ran out of memory - a wrong explanation is worse than the bare naming
	// above, which is true whatever killed it.
	if !p.Limits.IsZero() && (sig == int(syscall.SIGKILL) || sig == int(syscall.SIGTERM)) {
		fmt.Fprintf(w, "[bento] the manifest declares limits (%s), and exceeding one kills the run exactly\n", describeLimits(p.Limits))
		fmt.Fprintln(w, "[bento] this way - so it most likely hit a cap rather than failing on its own.")
	}
	return true
}

// signalDeath reports the signal a run died on, and whether that is known rather than
// inferred. Zero means the run did not end on one.
func signalDeath(res enforce.Result) (sig int, certain bool) {
	if res.Signaled {
		return res.Signal, true
	}
	// The shell convention every wrapper in the chain already follows. The upper bound
	// keeps an ordinary exit code in the 190s from being read as a signal number no
	// Linux host issues.
	if res.ExitCode > 128 && res.ExitCode <= 128+31 {
		return res.ExitCode - 128, false
	}
	return 0, false
}

// writeProfileHint points at profiling when a run fails, because a denied path is silent
// by construction: there is no observer at enforce time, and a script that fails closed on
// a file it needed reports its OWN error and nothing else. Under a manifest that does not
// pass HOME through, the path in that error is not even one the author wrote. Nothing
// otherwise connects it back to the manifest, and the reader debugs their code.
//
// A heuristic, and worded as one - the script may simply have failed for its own reasons.
// It is silent when the egress hint already explained the same non-zero exit, and under
// --json, where the outcome is a field. It explains a code the TARGET returned, so the
// caller keeps it off a run the target never reached: a refusal returns before the output,
// a strict shortfall is reported by its own line, and a launcher that applied its layers
// and then could not exec the target gets writeTargetUnreached instead.
func writeProfileHint(w io.Writer, p *policy.Policy, res enforce.Result) {
	if res.ExitCode == 0 {
		return
	}
	fmt.Fprintf(w, "[bento] the script exited %d. It ran with %d read and %d write path(s) granted, and the\n", res.ExitCode, len(p.Read), len(p.Write))
	fmt.Fprintln(w, "[bento] sandbox denies silently - so if it failed on a missing file or a permission")
	fmt.Fprintln(w, "[bento] error, the script's own message is all you get. To see what it actually touches:")
	// Quoted: the entrypoint is manifest text, and a newline in it would otherwise forge a
	// line of this hint.
	fmt.Fprintf(w, "[bento]   bento profile %q\n", p.Entrypoint)
}

// writeRefusal prints a pre-run refusal in the shape main's generic error printer gives
// every other one - the "bento: " prefix it writes in main.go and the reason - but wrapped, and with each layer that fell
// short on its own indented lines. The generic printer cannot do this itself: a manifest
// parse error carries caret alignment that wrapping would mangle, so only the caller that
// knows it holds a refusal can wrap it.
//
// lead names what is being refused ("refusing to run", "refusing to profile"). It is the
// caller's word rather than Refusal.Error()'s because the same host shortfall reaches
// two commands, and a profiling session told it is refusing to run sends the reader
// looking for a manifest they never invoked.
func writeRefusal(w io.Writer, lead string, r *enforce.Refusal) {
	const prefix = "bento: "
	for i, line := range wrapText(lead+": "+r.Reason, textWidth-len(prefix)) {
		if i == 0 {
			fmt.Fprintf(w, "%s%s\n", prefix, line)
			continue
		}
		fmt.Fprintf(w, "%*s%s\n", len(prefix), "", line)
	}
	for _, l := range r.Short {
		head := fmt.Sprintf("%s (%s): %s", l.Layer, l.State, l.Reason)
		for i, line := range wrapText(head, textWidth-4) {
			if i == 0 {
				fmt.Fprintf(w, "  %s\n", line)
				continue
			}
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
}

// writeTargetUnreached says what an exit code alone cannot: the sandbox came up and the
// target never ran, so the code is bento's rather than the script's. It stands in for the
// profile and HOME hints on that path - both explain a failure the script reported, and a
// script that never started reported nothing. The layer lines above carry the launcher's
// own error; this says what it means for the code the run ended with.
func writeTargetUnreached(w io.Writer, res enforce.Result) {
	notice := fmt.Sprintf("the sandbox applied its layers but could not start the target, so the script "+
		"never ran and exit %d is bento's, not its own. Check that the entrypoint and interpreter "+
		"name a program this host can execute (`bento validate` reports both).", res.ExitCode)
	for _, line := range wrapText(notice, textWidth-len("[bento] ")) {
		fmt.Fprintf(w, "[bento] %s\n", line)
	}
}

// writeSandboxHomeNote states what HOME is inside the box and what that does to a `~`
// the script expands itself. Both callers say it about the same manifest at different
// moments - validate while the reader reviews the grants, run once a `~` has already
// sent the script at the wrong path - so the wording lives here rather than in two
// copies that drift. prefix opens each line: the continuation lines align under the
// first word after it.
func writeSandboxHomeNote(w io.Writer, prefix string) {
	fmt.Fprintf(w, "%snote: HOME is not passed through, so inside the sandbox it is %s and `~`\n", prefix, enforce.SandboxHome)
	fmt.Fprintf(w, "%s      expands there, not to your home directory. The manifest's grants are\n", prefix)
	fmt.Fprintf(w, "%s      matched against host paths, so a script resolving ~ itself will miss\n", prefix)
	fmt.Fprintf(w, "%s      them - write the paths it opens absolute, or allowlist HOME in env:.\n", prefix)
}

// writeSandboxHomeMiss repeats the HOME note when a failed run has every mark of having
// tripped it: the manifest grants something under the caller's own home but does not pass
// HOME through, so a `~` the script expanded landed in the sandbox's home instead and the
// grant it was meant to reach never matched. The script reports its own missing-file error
// against a path nobody wrote, and the profile hint below sends the reader around the loop
// to reproduce exactly that path. bento holds all three facts here, so it says so.
//
// A heuristic like the profile hint, and silent on a clean exit: a manifest can grant a
// path under $HOME and open it absolutely, in which case nothing was missed.
func writeSandboxHomeMiss(w io.Writer, p *policy.Policy, res enforce.Result) {
	if res.ExitCode == 0 || slices.Contains(p.Env, "HOME") {
		return
	}
	// os.UserHomeDir returns $HOME verbatim, so a relative or unset value names no tree
	// a grant can be under - there is nothing to conclude from it either way.
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return
	}
	home = filepath.Clean(home)
	if !slices.ContainsFunc(slices.Concat(p.Read, p.Write), func(g string) bool { return underHome(g, home) }) {
		return
	}
	writeSandboxHomeNote(w, "[bento] ")
}

// underHome reports whether an already-resolved grant lies in the host home tree.
func underHome(grant, home string) bool {
	rel, err := filepath.Rel(home, grant)
	if err != nil {
		return false
	}
	// Not a plain ".." prefix test: a grant named "$HOME/..cache" is inside the tree and
	// relativizes to "..cache", which such a test reads as an escape.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// writeBlockedHostNotes marks the rules whose destination the profiling run already
// found the egress guard refusing. It runs before the script does, not after: the guard
// refuses at connect time and the target meets that as a 502 from the proxy, with
// nothing tying it back to the rule it was granted under. The manifest carries the
// answer, so it is said while the reader is still looking at the manifest they passed.
//
// It is a note, never a refusal. The record is provenance rather than permission - a
// hand-edited manifest can carry any of it - and the run refuses the destination itself
// when it comes to it, which is where the enforcement belongs.
func writeBlockedHostNotes(w io.Writer, p *policy.Policy, blockedHosts []string) {
	covering, unreadable := rulesCoveringBlockedHost(p, blockedHosts)
	for _, r := range covering {
		fmt.Fprintf(w, "[bento] note: network %q port %q covers a destination the profiling run reached and bento's\n", r.Host, r.Port)
		fmt.Fprintf(w, "[bento] egress guard refused - it resolved to loopback, private space, or cloud metadata.\n")
		fmt.Fprintf(w, "[bento] This run refuses it the same way; the rule does not widen it.\n")
	}
	for _, key := range unreadable {
		fmt.Fprintf(w, "[bento] note: the manifest records %q as a destination profiling was refused, but that is\n", key)
		fmt.Fprintf(w, "[bento] not a host:port anything can match against the rules above - it was hand-edited.\n")
	}
}

// missingReadGrants returns the already-resolved read grants naming nothing on this
// host, in the order they were declared. Only a path that is absent is worth reporting:
// a grant bento cannot stat for any other reason - a directory above it the invoker
// cannot traverse - says nothing about whether the sandbox will reach it, since the
// sandbox binds it as a different user's view of the tree.
//
// Read grants only. A write grant that names nothing is created by the backend, so its
// absence before the run is not a miss.
func missingReadGrants(read []string) []string {
	var missing []string
	for _, g := range read {
		if _, err := os.Stat(g); errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, g)
		}
	}
	return missing
}

// writeMissingReadNotes says before the script starts what validate says while the
// reader is looking at the manifest: a read grant naming nothing grants nothing, and the
// sandbox then denies that path silently. An approved manifest is not re-validated - the
// stamp covers the policy, which has not changed when the directory it names is deleted -
// so run is the only place left to notice.
//
// Said on the way in rather than in the epilogue, so it is already on screen when the
// script dies on the file it could not open.
func writeMissingReadNotes(w io.Writer, missing []string) {
	for _, g := range missing {
		fmt.Fprintf(w, "[bento] note: the read grant %q names nothing on this host, so it grants nothing and\n", g)
		fmt.Fprintln(w, "[bento] the sandbox denies that path without saying why. Fine if the script creates it;")
		fmt.Fprintln(w, "[bento] otherwise it is a typo or a moved directory that will read as a permission bug.")
	}
}

// writeGuardBlockedWarning names the destinations the allowlist permitted but the
// egress guard refused to dial, because the name resolved somewhere the sandbox must
// not reach. The script saw only "could not reach", deliberately - telling it apart
// from a dial failure would let it classify names against the host's internal DNS -
// so without this the routine case (an allowlisted name that resolves into private
// space on a corporate network) presents as an unexplained connection failure.
//
// The hosts came from the sandbox's own CONNECT requests, so they are quoted: a
// crafted hostname carries whatever bytes the target chose, including a newline that
// would otherwise forge a line of this report.
func writeGuardBlockedWarning(w io.Writer, res enforce.Result) {
	if len(res.GuardBlocked) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] the egress guard refused to connect to these allowed destinations, because")
	fmt.Fprintln(w, "[bento] each resolved to an address the sandbox must not reach:")
	for _, hp := range res.GuardBlocked {
		fmt.Fprintf(w, "[bento]   %q port %q\n", hp.Host, hp.Port)
	}
	// The guard blocks three shapes - host-reserved space, private space with no
	// literal rule, and an address it could not classify - and the report cannot say
	// which (naming the resolved address is the disclosure the 502 exists to avoid), so
	// the likeliest cause is offered as a cause and not asserted. Widening the
	// allowlist cannot fix any of them, which is the part an operator most needs told.
	fmt.Fprintln(w, "[bento] usually a name that resolves into private space (a split-horizon or corporate DNS).")
	fmt.Fprintln(w, "[bento] adding the name to the allowlist will not help: to reach a private address, list")
	fmt.Fprintln(w, "[bento] that address itself as an explicit IP rule. Loopback and cloud metadata can never")
	fmt.Fprintln(w, "[bento] be reached, by any rule.")
}

// writeDeniedWarning names the destinations the allowlist refused. The target met the
// refusal as a 403 from the proxy, buried in whatever its HTTP client made of it, with
// nothing naming the manifest - so a rule with one letter wrong presents as the script
// being broken. This is the only place the destination it actually asked for is said.
//
// The hosts came from the sandbox's own CONNECT requests, so they are quoted for the same
// reason writeGuardBlockedWarning quotes its own.
//
// It reports whether it said anything, so no second explanation of the same failure
// stacks on top of it.
func writeDeniedWarning(w io.Writer, p *policy.Policy, res enforce.Result) bool {
	if len(res.Denied) == 0 {
		return false
	}
	fmt.Fprintln(w, "[bento] the egress allowlist refused these destinations - no network rule covers them:")
	for _, hp := range res.Denied {
		fmt.Fprintf(w, "[bento]   %q port %q\n", hp.Host, hp.Port)
	}
	fmt.Fprintln(w, "[bento] the script saw only a 403 from the proxy. To allow one, add it under network: in")
	fmt.Fprintln(w, "[bento] the manifest and re-approve. To rediscover them, profile with egress forwarded -")
	// Quoted for the reason writeProfileHint quotes it: the entrypoint is manifest text.
	fmt.Fprintf(w, "[bento]   bento profile %q --allow-network\n", p.Entrypoint)
	fmt.Fprintln(w, "[bento] the default records destinations without forwarding them, so a plain re-profile")
	fmt.Fprintln(w, "[bento] reproduces this same failure.")
	return true
}

// writeShieldedGrantWarning tells the user that the policy granted a path bento would
// otherwise shield as a credential store, so the backend honored the grant and exposed
// it to the script. This is a deliberate opt-in bento does not refuse, so the notice is
// the only thing that keeps the exposure from being silent.
func writeShieldedGrantWarning(w io.Writer, res enforce.Result) {
	if len(res.ShieldedGrants) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] WARNING: the policy explicitly grants these paths bento normally shields as")
	fmt.Fprintln(w, "[bento] credential stores, so the script could read them - review that this is intended:")
	// A grant matches a shield by the name the deny-list gives it, and those names are
	// built from $HOME - so where $HOME reaches the real home through a symlink, the grant
	// names one path and the script reads another. Naming the store the exposure landed on
	// is the difference between reviewing a path and reviewing a credential. The backend
	// resolved these as it bound them; re-resolving here would name whatever the path
	// points at now, which a run that moved a symlink underneath itself has changed.
	//
	// Both lines are quoted, matching writeAcceptedAliasWarning. Neither is manifest text:
	// the grant is the deny-list's name for the shield it matched, built from $HOME, and
	// the target is enumerated from the filesystem - so a directory (or a $HOME) whose name
	// holds a newline would otherwise print as a second line and forge a summary line of
	// its own, in the block that exists to make an exposure impossible to miss.
	lands := make(map[string]string, len(res.ShieldedGrantTargets))
	for _, t := range res.ShieldedGrantTargets {
		lands[t.Path] = t.Credential
	}
	for _, g := range res.ShieldedGrants {
		fmt.Fprintf(w, "[bento]   %q\n", g)
		if target, ok := lands[g]; ok {
			fmt.Fprintf(w, "[bento]     on this host: %q\n", target)
		}
	}
}

// writeAcceptedAliasWarning names the credential aliases this run was allowed to read
// past a shield. A run that proceeds over an acknowledged gap must say so every time:
// the acknowledgement is per-invocation and easy to leave in a wrapper script, and a
// silent one would let a real leak hide behind a flag added for a backup directory. The
// paths are host-enumerated, so they are quoted.
func writeAcceptedAliasWarning(w io.Writer, res enforce.Result) {
	if len(res.AcceptedAliases) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] WARNING: these paths were readable as a second name for a shielded")
	fmt.Fprintln(w, "[bento] credential, and you acknowledged the tree they sit in:")
	for _, a := range res.AcceptedAliases {
		fmt.Fprintf(w, "[bento]   %q aliases %q\n", a.Path, a.Credential)
	}
}

// writeShieldAnchors names the home directories the credential shields will anchor on
// here, and says whether the passwd entry corroborated $HOME.
//
// The anchor set is a host fact an operator cannot recover from a run: the shield count
// looks the same whether both anchors agreed or the passwd lookup found nothing and left
// $HOME - a value whoever launches bento chooses - as the only thing deciding where the
// shields land. doctor is where that belongs; per-run it would be noise on every host
// that is configured normally.
func writeShieldAnchors(w io.Writer) {
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		fmt.Fprintf(w, "Credential shields: %v, so they cannot be anchored at all and runs are refused.\n", err)
		fmt.Fprintf(w, "Set $HOME to an absolute path, or give this uid a passwd entry.\n\n")
		return
	}
	// Quoted for the reason the shield warnings are: an anchor is $HOME or a passwd entry,
	// so its bytes are the host's and a newline in one would forge a line of this report.
	quoted := make([]string, len(anchors))
	for i, a := range anchors {
		quoted[i] = strconv.Quote(a)
	}
	fmt.Fprintf(w, "Credential shields anchor on: %s\n", strings.Join(quoted, ", "))
	if denylist.PasswdHome() == "" {
		fmt.Fprintf(w, "  No passwd entry for uid %d, so $HOME is the only anchor - whoever sets the\n", os.Getuid())
		fmt.Fprintf(w, "  environment decides where the shields land. Normally the passwd home anchors\n")
		fmt.Fprintf(w, "  them too, which is what a caller-chosen $HOME cannot move.\n")
	}
	fmt.Fprintln(w)
}

// writeExposedWarning tells the user which credential and persistence paths a full
// bwrap run would have shielded but this degraded run left exposed, so a run on a
// tier that cannot shield is not silent about what it exposed. The full tier's shield
// summary confirms the boundary engaged; this is its counterpart when the boundary
// could not. The paths carry host-enumerated names (submodule directories), so they
// are quoted.
func writeExposedWarning(w io.Writer, res enforce.Result) {
	if len(res.Exposed) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] WARNING: this host cannot shield credentials or persistence surfaces, so these paths")
	fmt.Fprintln(w, "[bento] a normal run would hide or make read-only were left exposed to the script - review:")
	for _, s := range res.Exposed {
		fmt.Fprintf(w, "[bento]   %q (%s)\n", s.Path, s.Kind)
	}
}

// writeDegradations tells the user exactly which guarantees this host is not
// delivering. In a non-JSON run the target's own streams are live during the run, so
// this prints after the script's output; a pre-run refusal is what --strict and
// doctor are for. Nothing that weakens a requested guarantee is ever silent - that
// was the failure this tool exists to prevent.
func writeDegradations(w io.Writer, r enforce.Report) {
	short := r.Degradations()
	if len(short) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] this host does not enforce everything your policy asked for:")
	for _, l := range short {
		// Wrapped, not one line: the degraded filesystem tier's reason is a
		// thousand-character paragraph, and a disclosure the reader scrolls past
		// sideways discloses nothing.
		head := fmt.Sprintf("%s (%s tier): %s - %s", l.Layer, l.Layer.Tier(), l.State, l.Reason)
		for _, line := range wrapText(head, textWidth-len("[bento]   ")) {
			fmt.Fprintf(w, "[bento]   %s\n", line)
		}
	}
	// The sharpest consequence of the degraded filesystem tier is not in the layer line
	// above: it never scans for aliases at all, so an alias inside a granted tree was
	// readable and nothing counted it. The guarantee is absent rather than waived, which
	// is also why --accept-alias cannot cover it. Keyed on the probed layer state, not on
	// --allow-degraded: the flag on a host where bwrap works still scans.
	if r.StateOf(enforce.LayerFilesystem) == enforce.Degraded {
		fmt.Fprintln(w, "[bento]   this tier never scans for credential aliases, so a second name for a shielded")
		fmt.Fprintln(w, "[bento]   credential under a granted tree was exposed rather than acknowledged.")
	}
	fmt.Fprintln(w, "[bento] run `bento doctor` for the full picture, or --strict to refuse rather than degrade.")
}
