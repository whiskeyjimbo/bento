package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/backend"
	"github.com/whiskeyjimbo/bento-v2/enforce"
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
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, err := backend.New()
			if err != nil {
				return err
			}
			report := e.Probe(cmd.Context())

			// doctor exits non-zero only for a shortfall in a guarantee EVERY run needs,
			// so a CI wrapper can gate on baseline host readiness without parsing output.
			// A conditionally-required core layer (network egress control) and the
			// hardening layers let runs proceed - a run that actually needs one is refused
			// at run time - so they are reported but stay exit 0.
			shortfall := len(gatedShortfall(report)) > 0

			if asJSON {
				if err := writeJSON(os.Stdout, toReportJSON(report)); err != nil {
					return err
				}
				if shortfall {
					return &exitError{code: doctorCoreShortfall}
				}
				return nil
			}

			writeReportTable(os.Stdout, report)
			fmt.Println()
			if shortfall {
				fmt.Println("A core guarantee every run needs is not fully enforced here. Runs are refused")
				fmt.Println("by default; --allow-degraded opts into a weaker sandbox, knowingly.")
				return &exitError{code: doctorCoreShortfall}
			}
			if report.HasDegradation() {
				fmt.Println("Baseline confinement holds on this host, so manifests run by default. Some")
				fmt.Println("layers below fall short; whether a run is affected depends on what its manifest")
				fmt.Println("needs. Egress control and a requested resource limit are refused by default when")
				fmt.Println("needed; other hardening gaps run with the gap reported. --strict refuses any.")
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
// (needed only by a manifest that declares egress) is reported in the table but does
// not gate, because a host without it still runs every manifest that never asked for it.
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
