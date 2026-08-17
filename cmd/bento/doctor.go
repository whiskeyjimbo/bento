package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
)

func newDoctorCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what this host can actually enforce",
		Long: "doctor is the single place that tells the whole truth about this host.\n\n" +
			"Each layer is reported as enforced, degraded, or unavailable, with the reason.\n" +
			"Core layers are the guarantees bento makes everywhere; a core layer that falls\n" +
			"short refuses a run by default. Hardening layers have no equivalent on every\n" +
			"platform - when one is unavailable, runs proceed and say so.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A host with no backend has no layers to report, which is doctor's own
			// answer rather than a foreign refusal envelope: a CI gate reading `ready`
			// gets false because doctor said so, not because the key went missing.
			if err := checkPlatform(); err != nil {
				// The envelope is written first so a machine consumer still gets a
				// parseable answer on stdout, and the refusal then goes to stderr and
				// the same exit as the human mode's, exactly as validate's does.
				if asJSON {
					envelope := doctorJSON{
						reportJSON:       noReport,
						Platform:         platformName(),
						PlatformVerified: platformVerified(),
						Reason:           err.Error(),
					}
					if err := writeJSON(os.Stdout, envelope); err != nil {
						return err
					}
				}
				return err
			}
			e, err := backend.New()
			if err != nil {
				return err
			}
			report := e.Probe(cmd.Context())

			// A host that cannot anchor its shields refuses every run, and no layer status
			// carries that: newSandbox fails before any tier is chosen, so Probe never sees
			// it. Asked here so the machine surface and the exit code say what the human
			// output on the same invocation already does.
			_, anchorErr := denylist.HomeAnchors()

			// doctor exits non-zero only for a shortfall in a guarantee EVERY run needs,
			// so a CI wrapper can gate on baseline host readiness without parsing output.
			// A conditionally-required core layer (network egress control) and the
			// hardening layers let runs proceed, so they are reported but stay exit 0.
			//
			// Not because a run needing one is refused at run time: enforce.Run refuses a
			// non-degraded run on an Unavailable network layer whether or not the manifest
			// declared any egress (run.go's "no network namespace to fence egress into"),
			// so a ready verdict here would be a ready verdict for a host that runs
			// nothing. What actually holds it is the Linux probe: it ties LayerNetwork
			// Unavailable to the same missing namespace that makes filesystemLayer report
			// Degraded or Unavailable, and filesystem IS in the baseline, so the gate below
			// fires anyway. That is one fact in another package, and nothing here would stop
			// compiling if it moved, so it is pinned where it lives - internal/linux's
			// TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced.
			shortfall := len(gatedShortfall(report)) > 0

			if asJSON {
				if err := writeJSON(os.Stdout, toDoctorJSON(report, anchorErr)); err != nil {
					return err
				}
				if shortfall || anchorErr != nil {
					return &exitError{code: doctorCoreShortfall}
				}
				return nil
			}

			writePlatform(os.Stdout)
			writeReportTable(os.Stdout, report)
			fmt.Println()
			writeShieldAnchors(os.Stdout)
			// Before the layer verdict, because this refuses every run whatever the layers
			// say, and unlike a core-layer shortfall there is no flag that opts into it.
			if anchorErr != nil {
				fmt.Println("Runs are refused here until the shields can be anchored. --allow-degraded")
				fmt.Println("does not help: the anchors decide where the shields land, not how they hold.")
				return &exitError{code: doctorCoreShortfall}
			}
			if shortfall {
				fmt.Println("A core guarantee every run needs is not fully enforced here. Runs are refused")
				fmt.Println("by default; --allow-degraded opts into a weaker sandbox, knowingly.")
				return &exitError{code: doctorCoreShortfall}
			}
			if short := report.Degradations(); len(short) > 0 {
				writeDegradedSummary(os.Stdout, short)
				return nil
			}
			fmt.Println("This host enforces every layer.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the enforcement matrix as JSON")
	return cmd
}

// gatedShortfall returns the shortfalls doctor fails its exit code on: the guarantees
// every manifest needs regardless of its contents. It derives that set from
// enforce.BaselineLayers rather than naming a layer here, so the gate cannot drift from
// what admission actually requires - a conditionally-required layer like network egress
// (needed only by a manifest that declares egress) is reported in the table but does not
// gate.
//
// A host whose network layer is Unavailable does NOT still run the manifests that never
// asked for egress: enforce.Run refuses those too, because there is no namespace to fence
// egress into and only the degraded tier substitutes anything for one. This gate stays in
// sync with it through the Linux probe's coupling rather than through the predicate - see
// the exit-code comment in newDoctorCmd.
func gatedShortfall(r enforce.Report) []enforce.LayerStatus {
	gate := make(map[enforce.Layer]bool)
	for _, l := range enforce.BaselineLayers() {
		gate[l] = true
	}
	var out []enforce.LayerStatus
	for _, l := range r.Degradations() {
		if gate[l.Layer] {
			out = append(out, l)
		}
	}
	return out
}

// toDoctorJSON builds the doctor JSON output. Ready derives from the same
// gatedShortfall and anchor error as the exit code, so the field a JSON consumer reads
// and the process status a shell caller reads can never disagree.
func toDoctorJSON(r enforce.Report, anchorErr error) doctorJSON {
	var anchors string
	if anchorErr != nil {
		anchors = anchorErr.Error()
	}
	return doctorJSON{
		reportJSON:       toReportJSON(r),
		Ready:            len(gatedShortfall(r)) == 0 && anchorErr == nil,
		ShieldAnchors:    anchors,
		Platform:         platformName(),
		PlatformVerified: platformVerified(),
	}
}
