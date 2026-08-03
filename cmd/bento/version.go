package main

import (
	"fmt"
	"runtime/debug"
	"strings"

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
			fmt.Fprint(cmd.OutOrStdout(), versionBanner())
		},
	}
}

// versionBanner is the build and what it can enforce. Both the subcommand and the root's
// --version answer with it, since an operator asking either question is asking the same
// one.
//
// The platform is here and not only in doctor because a build for a platform with no
// backend cannot get an answer out of doctor: cross-compiling for darwin succeeds
// silently, and doctor refuses there like the other two (only its --json envelope still
// says the platform). So until the operator tries a run there is nothing telling them the
// binary they just produced validates and approves but never confines. version is the one
// command every build answers, so it is where that has to be said.
func versionBanner() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bento %s\n", versionInfo())
	fmt.Fprintf(&b, "Platform: %s\n", platformName())
	switch {
	case checkPlatform() != nil:
		b.WriteString("  No sandbox backend here: validate and approve work; run, profile and doctor refuse.\n")
		b.WriteString("  Enforcement is Linux-only; macOS support is planned.\n")
	case !platformVerified():
		fmt.Fprintf(&b, "  Support for %s is planned, not verified. The sandbox builds and probes a real\n", platformName())
		fmt.Fprintf(&b, "  kernel here; that the layers mean what they mean on %s is untested.\n", verifiedPlatform)
	}
	return b.String()
}
