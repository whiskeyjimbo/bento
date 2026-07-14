package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/whiskeyjimbo/bento-v2/internal/enforce"
)

// The JSON shapes below are the machine-readable contract for agents and CI.
// They are defined here, in the frontend, so the core stays free of wire-format
// concerns — and they use explicit strings rather than the core's enum values, so
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

// writeDegradations tells the user, before their script's own output, exactly
// which guarantees this host is not delivering. Nothing that weakens a requested
// guarantee is ever silent — that was the failure this tool exists to prevent.
func writeDegradations(w io.Writer, r enforce.Report) {
	short := r.Degradations()
	if len(short) == 0 {
		return
	}
	fmt.Fprintln(w, "[bento] this host does not enforce everything your policy asked for:")
	for _, l := range short {
		fmt.Fprintf(w, "[bento]   %s (%s tier): %s — %s\n", l.Layer, l.Layer.Tier(), l.State, l.Reason)
	}
	fmt.Fprintln(w, "[bento] run `bento doctor` for the full picture, or --strict to refuse rather than degrade.")
}
