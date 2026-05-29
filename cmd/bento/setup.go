package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/whiskeyjimbo/bento"
)

var (
	setupDryRun bool
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install/configure host bits (AppArmor profile, etc.) where needed",
	Run: func(cmd *cobra.Command, args []string) {
		runSetup()
	},
}

var initCmd = &cobra.Command{
	Use:    "init",
	Short:  "Legacy alias for setup (deprecated)",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		runSetup()
	},
}

func runSetup() {
	var opts []bento.InitOption
	if setupDryRun {
		opts = append(opts, bento.WithDryRun())
	}
	_, err := bento.Init(context.Background(), os.Stdout, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func init() {
	setupCmd.Flags().BoolVar(&setupDryRun, "dry-run", false, "print plan without making changes")
	initCmd.Flags().BoolVar(&setupDryRun, "dry-run", false, "print plan without making changes")
}
