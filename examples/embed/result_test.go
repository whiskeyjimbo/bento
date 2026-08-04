package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// populatedResult is a Result with every honesty field non-empty, so one call to
// writeResult exercises every surface. Every host- or target-supplied string in it
// carries a terminal escape or a quote: a Result's paths can hold bytes a previous run
// influenced (a git submodule directory name) and enforce.ShieldApplied's own
// documentation says a consumer rendering one must quote it, while the gate-admitted
// host is chosen by the target outright. A clean value in any of these fields would let
// an unquoted render pass the escape scan below.
func populatedResult() (enforce.Result, *policy.Policy) {
	var report enforce.Report
	report.Set(enforce.LayerNetwork, enforce.Degraded, "the egress proxy stopped accepting mid-run")

	res := enforce.Result{
		ExitCode: 3,
		// The target ran and exited 3, so every field below accounts for a run that
		// happened. A setup that never reached the target is its own case: it reports
		// the opposite and suppresses the bypass hint.
		Setup:             enforce.SetupAttested,
		Report:            report,
		EgressConnections: 0, // with p.Network below and a non-zero exit, the bypass hint fires
		GateAdmitted:      []enforce.HostPort{{Host: "ads.example\x1b[2K", Port: "443"}},
		GuardBlocked:      []enforce.HostPort{{Host: "internal.example\x1b[2K", Port: "443"}},
		Denied:            []enforce.HostPort{{Host: "api.githb.example\x1b[2K", Port: "443"}},
		AcceptedAliases:   []enforce.CredentialAlias{{Path: "/backup/\x1b[2Kid_rsa", Credential: "/home/u/.ssh"}},
		// OnHost is the store the grant landed on, enumerated from the host filesystem.
		ShieldedGrants: []enforce.ShieldedGrant{{Path: "/home/u/.ssh", OnHost: "/home/u/real\x1b[2K/.ssh", Holds: "credentials"}},
		Shields:        []enforce.ShieldApplied{{Path: "/home/u/.gnupg", Kind: "hidden"}},
		Exposed:        []enforce.ShieldApplied{{Path: "/home/u/.aws\"", Kind: "read-only"}},
	}
	return res, &policy.Policy{Network: []policy.NetworkRule{{Host: "ok.example", Port: "443"}}}
}

// An embedder copies this example, so a field it never reads becomes a silence
// downstream: the operator sees no warning and reads that as nothing to report. Every
// honesty field must reach the output.
func TestWriteResultSurfacesEveryHonestyField(t *testing.T) {
	res, p := populatedResult()
	var out strings.Builder
	writeResult(&out, p, true, res)
	got := out.String()

	for _, want := range []string{
		"the egress proxy stopped accepting mid-run",           // Report.Degradations
		`"ads.example\x1b[2K"`,                                 // GateAdmitted, quoted
		`"internal.example\x1b[2K"`,                            // GuardBlocked, quoted
		"the egress guard refused",                             // GuardBlocked
		`"api.githb.example\x1b[2K"`,                           // Denied, quoted
		"was refused: no network rule covers it",               // Denied
		"1 credential/host-service path(s) shielded",           // Shields
		`"/home/u/.ssh"`,                                       // ShieldedGrants
		`on this host that path is "/home/u/real\x1b[2K/.ssh"`, // ShieldedGrants OnHost, quoted
		"second name for the shielded credential",              // AcceptedAliases
		"read-only",                              // Exposed
		"no connection through the egress proxy", // EgressConnections read as a bypass
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q; a field left unprinted is a silence an operator reads as nothing to report.\ngot:\n%s", want, got)
		}
	}
}

// A sandbox killed by a signal did not choose its exit code, and the hints below it are
// written for a target that reached its own conclusion. The kill is named, and the
// bypass hint - which would blame the network for a run the host ended - stays quiet.
func TestWriteResultReportsASignalKill(t *testing.T) {
	res, p := populatedResult()
	res.ExitCode, res.Signaled, res.Signal = 137, true, 9
	p.Limits = policy.Limits{Memory: "128M"}

	var out strings.Builder
	writeResult(&out, p, true, res)
	got := out.String()

	for _, want := range []string{"killed by signal 9", "exit 137", "resource limits"} {
		if !strings.Contains(got, want) {
			t.Errorf("a signal kill must say %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "no connection through the egress proxy") {
		t.Errorf("the bypass hint must not fire on a run the host killed; got:\n%s", got)
	}
}

// A path in a Result can carry bytes a previous run chose, so rendering one raw lets it
// move the cursor or forge a line of the report around it.
func TestWriteResultQuotesPathsFromTheHost(t *testing.T) {
	res, p := populatedResult()
	var out strings.Builder
	writeResult(&out, p, true, res)

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
//
// What it does NOT cover, so it is not read as more than it is: a field added to a
// nested type (ShieldApplied, ShieldedGrant, CredentialAlias, Report) is invisible to it, as is an
// exported field promoted from an UNEXPORTED embedded struct. Naming a field in warned
// without printing it also passes here - TestWriteResultSurfacesEveryHonestyField is
// what catches that, since a field named but unprinted fails its output assertions.
func TestWriteResultSurfacesEveryField(t *testing.T) {
	// The two fields writeResult does not warn about, and why.
	notWarnings := map[string]string{
		"ExitCode": "the target's own code, passed through by run() rather than reported",
		"Report":   "warned about through Degradations(), which is the part that fell short",
	}
	warned := map[string]bool{
		"EgressConnections": true, "GateAdmitted": true, "GuardBlocked": true, "Denied": true, "AcceptedAliases": true,
		"ShieldedGrants": true, "Shields": true, "Exposed": true,
		"Setup": true, "Signaled": true, "Signal": true,
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

// A stage that never reached the target must say so and must NOT print the bypass hint:
// a setup failure makes no connection either, and the hint would point an operator at a
// network problem that does not exist.
func TestWriteResultReportsSetupFailure(t *testing.T) {
	for name, setup := range map[string]enforce.SetupState{
		"silent":           enforce.SetupSilent,
		"target unreached": enforce.SetupTargetUnreached,
	} {
		t.Run(name, func(t *testing.T) {
			res, pol := populatedResult()
			res.Setup, res.ExitCode, res.EgressConnections = setup, 125, 0

			var out strings.Builder
			writeResult(&out, pol, true, res)
			got := out.String()

			if !strings.Contains(got, "the sandbox did not reach the target ("+setup.String()+")") {
				t.Errorf("a non-attested setup was not reported by name; got:\n%s", got)
			}
			if !strings.Contains(got, "exit code 125 is bento's, not the target's") {
				t.Errorf("the output did not disown the exit code; got:\n%s", got)
			}
			if strings.Contains(got, "no connection through the egress proxy") {
				t.Errorf("the bypass hint fired for a run that never reached the target; got:\n%s", got)
			}
		})
	}
}
