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
	// FullyEnforced is false when any layer fell short, so a caller can gate on
	// one field instead of interpreting the matrix.
	FullyEnforced bool `json:"fully_enforced"`
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
