package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// populatedResult is a Result with every honesty field non-empty, so one call to
// writeResult exercises every surface. The paths carry a terminal escape and a quote:
// a Result's paths can hold bytes a previous run influenced (a git submodule directory
// name), and enforce.ShieldApplied's own documentation says a consumer rendering one to
// a terminal must quote it.
func populatedResult() (enforce.Result, *policy.Policy) {
	var report enforce.Report
	report.Set(enforce.LayerNetwork, enforce.Degraded, "the egress proxy stopped accepting mid-run")

	res := enforce.Result{
		ExitCode:          3,
		Report:            report,
		EgressConnections: 0, // with p.Network below and a non-zero exit, the bypass hint fires
		GateAdmitted:      []enforce.HostPort{{Host: "ads.example", Port: "443"}},
		AcceptedAliases:   []enforce.CredentialAlias{{Path: "/backup/\x1b[2Kid_rsa", Credential: "/home/u/.ssh"}},
		ShieldedGrants:    []string{"/home/u/.ssh"},
		Shields:           []enforce.ShieldApplied{{Path: "/home/u/.gnupg", Kind: "hidden"}},
		Exposed:           []enforce.ShieldApplied{{Path: "/home/u/.aws\"", Kind: "read-only"}},
	}
	return res, &policy.Policy{Network: []policy.NetworkRule{{Host: "ok.example", Port: "443"}}}
}

// An embedder copies this example, so a field it never reads becomes a silence
// downstream: the operator sees no warning and reads that as nothing to report. Every
// honesty field must reach the output.
func TestWriteResultSurfacesEveryHonestyField(t *testing.T) {
	res, p := populatedResult()
	var out strings.Builder
	writeResult(&out, p, res)
	got := out.String()

	for _, want := range []string{
		"the egress proxy stopped accepting mid-run", // Report.Degradations
		"ads.example:443", // GateAdmitted
		"1 credential/host-service path(s) shielded", // Shields
		`"/home/u/.ssh"`, // ShieldedGrants
		"second name for the shielded credential", // AcceptedAliases
		"read-only",                              // Exposed
		"no connection through the egress proxy", // EgressConnections read as a bypass
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q; a field left unprinted is a silence an operator reads as nothing to report.\ngot:\n%s", want, got)
		}
	}
}

// A path in a Result can carry bytes a previous run chose, so rendering one raw lets it
// move the cursor or forge a line of the report around it.
func TestWriteResultQuotesPathsFromTheHost(t *testing.T) {
	res, p := populatedResult()
	var out strings.Builder
	writeResult(&out, p, res)

	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("an escape byte from a Result path reached the terminal unquoted: %q", out.String())
	}
	if !strings.Contains(out.String(), `"/home/u/.aws\""`) {
		t.Errorf("the exposed path was not quoted; got %q", out.String())
	}
}

// The completeness guard. Adding a field to enforce.Result must not leave this example
// silently unaware of it: a new honesty surface that no frontend prints is exactly the
// hole the printed ones exist to close. Either print it in writeResult and name it
// here, or record why it needs no warning.
func TestWriteResultSurfacesEveryField(t *testing.T) {
	// The two fields writeResult does not warn about, and why.
	notWarnings := map[string]string{
		"ExitCode": "the target's own code, passed through by run() rather than reported",
		"Report":   "warned about through Degradations(), which is the part that fell short",
	}
	warned := map[string]bool{
		"EgressConnections": true, "GateAdmitted": true, "AcceptedAliases": true,
		"ShieldedGrants": true, "Shields": true, "Exposed": true,
	}

	for _, f := range reflect.VisibleFields(reflect.TypeFor[enforce.Result]()) {
		if !f.IsExported() {
			continue
		}
		if len(f.Index) > 1 {
			continue // a field of an embedded struct; the outer field carries the surface
		}
		if !warned[f.Name] && notWarnings[f.Name] == "" {
			t.Errorf("enforce.Result.%s is new: print it in writeResult and add it to warned, "+
				"or record in notWarnings why it needs no warning. An unread honesty field is a "+
				"frontend that is silent about it.", f.Name)
		}
	}
}
