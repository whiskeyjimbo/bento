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

			// A core shortfall means runs are refused by default, so doctor exits
			// non-zero for it (in both render modes) - the one place a CI wrapper can
			// gate on host readiness without parsing output. Hardening gaps let runs
			// proceed, so they stay exit 0.
			shortfall := len(coreShortfall(report)) > 0

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
				fmt.Println("A core guarantee is not fully enforced here. Runs that need it are refused by")
				fmt.Println("default; --allow-degraded opts into a weaker sandbox, knowingly.")
				return &exitError{code: doctorCoreShortfall}
			}
			if report.HasDegradation() {
				fmt.Println("Core guarantees hold on this host. Some hardening layers are unavailable -")
				fmt.Println("runs proceed and report the gap; --strict refuses instead.")
				return nil
			}
			fmt.Println("This host enforces every layer.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the enforcement matrix as JSON")
	return cmd
}

func coreShortfall(r enforce.Report) []enforce.LayerStatus {
	var out []enforce.LayerStatus
	for _, l := range r.Degradations() {
		if l.Layer.Tier() == enforce.TierCore {
			out = append(out, l)
		}
	}
	return out
}
