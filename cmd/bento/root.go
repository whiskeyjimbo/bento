package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bento",
	Short: "CLI for invoking the bento sandbox",
	SilenceUsage:  true,
	SilenceErrors: true,
	Run: func(cmd *cobra.Command, args []string) {
		usage()
		os.Exit(0)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of bento",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("bento", bentoVersionTag())
		os.Exit(0)
	},
}

func init() {
	rootCmd.SetVersionTemplate("bento {{.Version}}\n")
	rootCmd.Version = bentoVersionTag()
	
	// Add custom version shorthand flag -V to match exact original CLI behavior
	rootCmd.Flags().BoolP("version", "V", false, "print the version")

	// Add subcommands
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute() {
	// 1. Handle version flags and arguments manually to match exact original CLI dispatch
	for _, arg := range os.Args[1:] {
		if arg == "-V" || arg == "--version" {
			fmt.Println("bento", bentoVersionTag())
			os.Exit(0)
		}
	}

	// 2. Handle strict no-args validation (exit 1)
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// 3. Command manual help check (only when exactly help, -h, --help)
	arg := os.Args[1]
	if arg == "-h" || arg == "--help" || arg == "help" {
		if len(os.Args) == 2 {
			usage()
			os.Exit(0)
		}
		// If len(os.Args) > 2 (e.g. bento help run), let Cobra handle nested help!
	}

	// 4. Handle init migration notice manually to match exact original CLI behavior
	if arg == "init" {
		fmt.Fprintln(os.Stderr, "[bento] note: `bento init` is now `bento setup` (host-readiness check).")
		fmt.Fprintln(os.Stderr, "[bento]       For 'generate a starter manifest' use `bento profile <script>`.")
	}

	// 5. Strict subcommand validation (prevent flag placement before subcommands)
	validCmds := map[string]bool{
		"doctor":   true,
		"run":      true,
		"validate": true,
		"setup":    true,
		"init":     true,
		"profile":  true,
		"version":  true,
		"help":     true,
	}

	if !validCmds[arg] {
		if strings.HasPrefix(arg, "-") {
			// Invalid flag placement (e.g. bento --timeout=30s run)
			usage()
			os.Exit(2)
		} else {
			// Typo or unrecognized command (e.g. bento runn)
			// Let Cobra print standard error and suggestions, but exit with code 2.
			rootCmd.SilenceErrors = false
			_ = rootCmd.Execute()
			os.Exit(2)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
