package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/whiskeyjimbo/bento-v2/enforce"
	"github.com/whiskeyjimbo/bento-v2/policy"
)

// The JSON shapes below are the machine-readable contract for agents and CI.
// They are defined here, in the frontend, so the core stays free of wire-format
// concerns - and they use explicit strings rather than the core's enum values, so
// reordering a Go constant can never silently change the contract.

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
func writeEgressHint(w io.Writer, p *policy.Policy, res enforce.Result) {
	if len(p.Network) == 0 || res.ExitCode == 0 || res.EgressConnections > 0 {
		return
	}
	fmt.Fprintln(w, "[bento] the script exited non-zero and made no connections through the egress proxy.")
	fmt.Fprintln(w, "[bento] if it needs network: bento intercepts egress via HTTP_PROXY, so a program that")
	fmt.Fprintln(w, "[bento] ignores proxy settings (some static binaries) cannot reach allowlisted hosts and")
	fmt.Fprintln(w, "[bento] fails to connect. Programs that honor HTTP_PROXY (curl, requests, pip, npm) work.")
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
	for _, g := range res.ShieldedGrants {
		fmt.Fprintf(w, "[bento]   %s\n", g)
	}
}

// writeHardlinkWarning tells the user that a shielded credential has an extra hardlink
// on the host. The shield hides the credential's own path, but a second name for the
// same inode inside a granted tree stays readable past it. bento cannot tell whether
// this run's grants actually expose that alias, so it warns rather than refuses. The
// paths carry host-enumerated file names, so they are quoted.
func writeHardlinkWarning(w io.Writer, res enforce.Result) {
	if len(res.HardlinkedShields) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] WARNING: these shielded credentials have extra hardlinks; a grant that exposes")
	fmt.Fprintln(w, "[bento] another name for the same file would leak it past the shield - review:")
	for _, p := range res.HardlinkedShields {
		fmt.Fprintf(w, "[bento]   %q\n", p)
	}
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
	fmt.Fprintln(w, "[bento] WARNING: this host cannot shield credentials, so these paths a normal run would")
	fmt.Fprintln(w, "[bento] hide or make read-only were left exposed to the script - review that this is intended:")
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
	fmt.Fprintln(w, "[bento] run `bento doctor` for the full picture, or --strict to refuse rather than degrade.")
}
