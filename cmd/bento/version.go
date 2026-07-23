package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func versionInfo() string {
	if commit != "none" && date != "unknown" {
		return fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
	}
	return version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print bento version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("bento %s\n", versionInfo())
		},
	}
}
