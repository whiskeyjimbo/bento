package main

import (
	"bytes"
	"encoding/json"
	"reflect"
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

// hostFactRow is one fact doctor reports about this host that no LayerStatus can carry,
// and either the validate --json key carrying the same fact or the reason validate has
// none. The layer model is the two commands' shared answer and stays out: what is listed
// here is everything OUTSIDE it.
type hostFactRow struct {
	key      string
	validate string
	exempt   string
}

// The host facts as of the fifth one landing. bv2-tpcnb's finding was not any single row
// but the trend: doctor learns a host fact outside the layer model, validate does not, and
// nothing notices - five times over, each in its own commit. This is what notices. A new
// field on doctor's envelope fails the test until it is classified here, which is the
// decision that kept being made by omission.
var doctorHostFacts = []hostFactRow{
	{key: "shield_anchors", validate: "shields_unknown"},
	{key: "shield_anchor_homes", exempt: "where a healthy host's shields land is not a verdict on a manifest; validate reports the anchors only when they fail, as shields_unknown"},
	{key: "no_usable_passwd_home", exempt: "who decides where the shields land; the same anchors validate checks the grants against, and it reports what they refused rather than how they were chosen"},
	{key: "libc_nss_passwd_lookup", exempt: "a property of this build, not of this host or this manifest"},
	{key: "unshieldable_runtime_dir", validate: "unshieldable_runtime_dir"},
	{key: "unshieldable_relocations", exempt: "which built-in shields this host's environment moved out of reach; validate answers the manifest's own grants against the set that remains, as refused_grants and shielded_grants"},
	{key: "nested_anchors", exempt: "the shape of this host's homes, which no grant in a manifest can change"},
	{key: "relocated_shields", exempt: "where this host's environment moved a shield to; the grants are checked against the moved set, so validate's answer already accounts for it"},
	{key: "truncated_stores", exempt: "a store the shield walk did not cover whole, which narrows no grant this manifest names - it is a caution about the stores themselves"},
}

// The property: every host fact doctor's machine surface carries either reaches validate's
// or is exempted here with a reason. Both commands answer about the same host, and a gate
// that reads only validate gets the layer model plus whatever this table says it gets.
func TestEveryHostFactOutsideTheLayerModelIsClassified(t *testing.T) {
	inLayerModel := jsonKeys(reflect.TypeOf(reportJSON{}))
	// doctor's own meta: what it is answering about and whether it answered.
	meta := map[string]bool{"ready": true, "platform": true, "platform_verified": true, "reason": true}

	rows := map[string]hostFactRow{}
	for _, r := range doctorHostFacts {
		rows[r.key] = r
	}
	validateKeys := jsonKeys(reflect.TypeOf(policyJSON{}))

	for key := range jsonKeys(reflect.TypeOf(doctorOutputJSON{})) {
		if inLayerModel[key] || meta[key] {
			continue
		}
		row, ok := rows[key]
		if !ok {
			t.Errorf("doctor reports %q about this host and no LayerStatus carries it, so nothing takes it to validate.\n"+
				"Name the validate --json key that carries the same fact, or say in doctorHostFacts why validate has none.", key)
			continue
		}
		if row.exempt == "" && !validateKeys[row.validate] {
			t.Errorf("%q is said to reach validate as %q, which validate --json has no field for", key, row.validate)
		}
	}
	for key := range rows {
		if !inLayerModel[key] && !meta[key] {
			continue
		}
		t.Errorf("%q is part of the layer model both commands share, not a host fact outside it", key)
	}
}

// jsonKeys is every key a struct marshals to, following embedded structs as encoding/json
// does, so a fact inherited from doctorJSON counts as doctor's.
func jsonKeys(t reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for k := range jsonKeys(f.Type) {
				keys[k] = true
			}
			continue
		}
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}
