package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// readBuildInfo is swappable so a test can watch the fallback answer a binary Go stamped
// and one it did not. The test binary carries its own build info and nothing else can
// vary it, so the branch is otherwise unobservable.
var readBuildInfo = debug.ReadBuildInfo

func versionInfo() string {
	if commit != "none" && date != "unknown" {
		return fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)
	}
	// Only make build passes the ldflags stamp, but go install and a plain go build are
	// both documented install paths and Go stamps the module version into each - a
	// release tag for the former, a VCS pseudo-version for the latter. Preferring that
	// over the "dev" default is what lets a CI pin or an audit record say which bento ran.
	if v := moduleVersion(); v != "" {
		return v
	}
	return version
}

// moduleVersion is the version Go recorded for the main module, or "" when there is
// none to trust: a binary built with -buildvcs=false outside a module release reports
// "(devel)", which says less than the default does.
func moduleVersion() string {
	bi, ok := readBuildInfo()
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return ""
	}
	return bi.Main.Version
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
