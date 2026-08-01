package main

import (
	"encoding/json"
	"fmt"
	"io"
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

// writeReportTable renders the enforcement matrix for a human.
func writeReportTable(w io.Writer, r enforce.Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LAYER\tTIER\tSTATE\tDETAIL")
	for _, l := range r.Layers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Layer, l.Layer.Tier(), l.State, l.Reason)
	}
	tw.Flush()
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
// --json, where the outcome is a field. Bento's own 125 and 124 never reach here: a
// refusal returns before the output, and a strict shortfall is reported by its own line.
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
		fmt.Fprintf(w, "[bento]   %s (%s tier): %s - %s\n", l.Layer, l.Layer.Tier(), l.State, l.Reason)
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
