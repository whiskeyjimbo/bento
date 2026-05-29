package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/whiskeyjimbo/bento"
)

var (
	doctorSkipNetwork bool
	doctorFailFast    bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check the host for required and optional sandboxing primitives",
	Run: func(cmd *cobra.Command, args []string) {
		var opts []bento.CheckOption
		if doctorSkipNetwork {
			opts = append(opts, bento.WithSkipNetwork())
		}
		if doctorFailFast {
			opts = append(opts, bento.WithFailFast())
		}
		if bento.Doctor(os.Stdout, opts...) {
			os.Exit(0)
		}
		os.Exit(1)
	},
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorSkipNetwork, "skip-network", false, "omit network-dependent checks (faster CI)")
	doctorCmd.Flags().BoolVar(&doctorFailFast, "fail-fast", false, "stop at the first FAIL")
}
