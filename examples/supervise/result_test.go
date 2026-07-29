package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
)

// populatedResult is a Result with every honesty field non-empty, so one call to
// writeSummary exercises every surface. Every host- or target-supplied string in it
// carries a terminal escape or a quote: a Result's paths can hold bytes a previous run
// influenced (a git submodule directory name) and enforce.ShieldApplied's own
// documentation says a consumer rendering one must quote it, while the gate-admitted
// host is chosen by the target outright. A clean value in any of these fields would let
// an unquoted render pass the escape scan below.
func populatedResult() enforce.Result {
	var report enforce.Report
	report.Set(enforce.LayerNetwork, enforce.Degraded, "the egress proxy stopped accepting mid-run")

	return enforce.Result{
		ExitCode:          3,
		Report:            report,
		EgressConnections: 0, // with a non-zero exit, the bypass hint fires
		GateAdmitted:      []enforce.HostPort{{Host: "ads.example\x1b[2K", Port: "443"}},
		GuardBlocked:      []enforce.HostPort{{Host: "internal.example\x1b[2K", Port: "443"}},
		AcceptedAliases:   []enforce.CredentialAlias{{Path: "/backup/\x1b[2Kid_rsa", Credential: "/home/u/.ssh"}},
		ShieldedGrants:    []string{"/home/u/.ssh"},
		// Keyed to the ShieldedGrants entry above, which is what pairs the two in the
		// output; the store it lands on is enumerated from the host filesystem.
		ShieldedGrantTargets: []enforce.CredentialAlias{{Path: "/home/u/.ssh", Credential: "/home/u/real\x1b[2K/.ssh"}},
		Shields:              []enforce.ShieldApplied{{Path: "/home/u/.gnupg", Kind: "hidden"}},
		Exposed:              []enforce.ShieldApplied{{Path: "/home/u/.aws\"", Kind: "read-only"}},
	}
}

// The human just answered a prompt, so a field the summary never reads is worse here
// than in a batch frontend: silence reads as confirmation that what they approved is
// all that happened. Every honesty field must reach the output.
func TestWriteSummarySurfacesEveryHonestyField(t *testing.T) {
	var out strings.Builder
	writeSummary(&out, theme{}, populatedResult())
	got := out.String()

	for _, want := range []string{
		"the egress proxy stopped accepting mid-run", // Report.Degradations
		"shielded 1 credential/host-service path(s)", // Shields
		`"ads.example\x1b[2K" port 443`,              // GateAdmitted, quoted
		"the live gate admitted egress",              // GateAdmitted
		`"internal.example\x1b[2K" port 443`,         // GuardBlocked, quoted
		"the egress guard refused",                   // GuardBlocked
		`"/home/u/.ssh"`,                             // ShieldedGrants
		`on this host: "/home/u/real\x1b[2K/.ssh"`,   // ShieldedGrantTargets, quoted
		`"/backup/\x1b[2Kid_rsa" aliases`,            // AcceptedAliases, quoted
		"read-only on a host that can shield",        // Exposed
		"no connection through the egress proxy",     // EgressConnections read as a bypass
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q; a field left unprinted is a silence the human reads as nothing to report.\ngot:\n%s", want, got)
		}
	}
}

// A path in a Result can carry bytes a previous run chose, so rendering one raw lets it
// move the cursor or forge a line of the summary around it. theme{} is the no-color
// theme, so the only escape that can reach the scan is one from the Result.
func TestWriteSummaryQuotesPathsFromTheHost(t *testing.T) {
	var out strings.Builder
	writeSummary(&out, theme{}, populatedResult())

	if strings.ContainsRune(out.String(), '\x1b') {
		t.Errorf("an escape byte from a Result path reached the terminal unquoted: %q", out.String())
	}
	if !strings.Contains(out.String(), `"/home/u/.aws\""`) {
		t.Errorf("the exposed path was not quoted; got %q", out.String())
	}
}

// The completeness guard, the same one examples/embed carries. Adding a field to
// enforce.Result must not leave this wrapper silently unaware of it: supervise is the
// gate-driven frontend, so a new honesty surface it does not print is one the human is
// least equipped to notice the absence of. Either print it in writeSummary and name it
// here, or record why it needs no warning.
//
// What it does NOT cover, so it is not read as more than it is: a field added to a
// nested type (ShieldApplied, CredentialAlias, Report) is invisible to it, as is an
// exported field promoted from an UNEXPORTED embedded struct. Naming a field in warned
// without printing it also passes here - TestWriteSummarySurfacesEveryHonestyField is
// what catches that, since a field named but unprinted fails its output assertions.
func TestWriteSummarySurfacesEveryField(t *testing.T) {
	// The two fields writeSummary does not warn about, and why.
	notWarnings := map[string]string{
		"ExitCode": "the script's own code, returned by run() rather than reported",
		"Report":   "warned about through Degradations(), which is the part that fell short",
	}
	warned := map[string]bool{
		"EgressConnections": true, "GateAdmitted": true, "GuardBlocked": true, "AcceptedAliases": true,
		"ShieldedGrants": true, "ShieldedGrantTargets": true, "Shields": true, "Exposed": true,
	}

	for _, f := range reflect.VisibleFields(reflect.TypeFor[enforce.Result]()) {
		if !f.IsExported() {
			continue
		}
		if len(f.Index) > 1 {
			continue // a field of an embedded struct; the outer field carries the surface
		}
		if !warned[f.Name] && notWarnings[f.Name] == "" {
			t.Errorf("enforce.Result.%s is new: print it in writeSummary and add it to warned, "+
				"or record in notWarnings why it needs no warning. An unread honesty field is a "+
				"frontend that is silent about it.", f.Name)
		}
	}
}
