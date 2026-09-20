package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// LayerStatus.Disclosure's doc asserts a property over EVERY frontend that describes a
// layer: it either prints both halves or points at the one that does. Nothing enforced
// that, and the halves are joined by hand in more than one place, so a writer that drops
// Consequences compiles and ships - which is what happened to the host-shortfall note
// before it grew its pointer to doctor. This is the table that fails instead.
//
// Consequences is the half that goes missing, because it is the one an Enforced layer can
// also carry and so reads as optional. It is not: on a degraded host it is the entire
// account of what the fallback tier does not confine.
func TestEveryLayerFrontendDisclosesOrPointsAtOneThatDoes(t *testing.T) {
	const (
		reason       = "user namespaces are blocked here"
		consequences = "It confines filesystem read/write/exec, nothing more: no mount namespace."
	)
	degraded := enforce.LayerStatus{
		Layer:        enforce.LayerFilesystem,
		State:        enforce.Degraded,
		Reason:       reason,
		Consequences: consequences,
	}
	report := enforce.Report{Layers: []enforce.LayerStatus{degraded}}
	// Every policy requires the filesystem layer, so the note speaks about this one.
	bare := &policy.Policy{Entrypoint: "./x", Exec: policy.ExecAll}

	for _, tc := range []struct {
		name  string
		write func(w *bytes.Buffer)
	}{
		// Doctor's two writers are one surface: the summary names which layers fell
		// short and the table above it carries their notes, so neither is asked to
		// disclose on its own.
		{"doctor", func(w *bytes.Buffer) {
			writeReportTable(w, report)
			writeDegradedSummary(w, []enforce.LayerStatus{degraded})
		}},
		{"the run's degradation notice", func(w *bytes.Buffer) { writeDegradations(w, report) }},
		{"validate's host note", func(w *bytes.Buffer) { writeHostPosture(w, hostPosture(report, bare)) }},
		// The --json field, not the envelope around it: a consequence that reached the
		// blob through some neighbouring key would satisfy a whole-envelope match while
		// the field a consumer reads still carried half the disclosure. A machine has
		// nowhere to be sent, so for this surface the pointer half of the contract is not
		// available and only the consequences satisfy it.
		{"validate's --json host note", func(w *bytes.Buffer) {
			var o policyJSON
			o.setHostUnenforcedLayers(hostPosture(report, bare))
			if err := json.NewEncoder(w).Encode(o.HostUnenforcedLayers); err != nil {
				panic(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			tc.write(&b)
			// Every one of these wraps to the terminal width, so a disclosure arrives
			// broken across lines and survives only a comparison made on one line.
			out := strings.Join(strings.Fields(b.String()), " ")
			if out == "" {
				t.Fatalf("a frontend given a degraded layer printed nothing")
			}
			if !strings.Contains(out, reason) {
				t.Errorf("the diagnosis is missing; got:\n%s", out)
			}
			// Either half of the contract satisfies it. A frontend that sends the reader
			// to doctor has disclosed by reference, which is what Disclosure's doc allows
			// and why the note can stay short.
			if strings.Contains(out, consequences) || strings.Contains(out, "bento doctor") {
				return
			}
			t.Errorf("this frontend neither prints the consequences nor points at doctor, so what the\n"+
				"degraded tier does not confine reaches nobody through it; got:\n%s", out)
		})
	}
}
