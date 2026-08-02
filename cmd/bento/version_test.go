package main

import (
	"runtime/debug"
	"testing"
)

// stubBuildInfo makes readBuildInfo answer with a given main-module version, so the
// fallback can be watched on a binary Go stamped and one it did not. The test binary
// carries a single build info of its own and nothing can vary it.
func stubBuildInfo(t *testing.T, mainVersion string, ok bool) {
	t.Helper()
	saved := readBuildInfo
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		if !ok {
			return nil, false
		}
		return &debug.BuildInfo{Main: debug.Module{Version: mainVersion}}, true
	}
	t.Cleanup(func() { readBuildInfo = saved })
}

// stubStamp sets the ldflags-stamped globals for one test.
func stubStamp(t *testing.T, v, c, d string) {
	t.Helper()
	savedV, savedC, savedD := version, commit, date
	version, commit, date = v, c, d
	t.Cleanup(func() { version, commit, date = savedV, savedC, savedD })
}

// The two install paths the README documents - go install and a plain go build - carry no
// ldflags stamp, and used to report "dev" for both a tagged release and a local build. Go
// records a version for each, so that is what the unstamped binary must answer with.
func TestVersionInfoFallsBackToTheModuleVersion(t *testing.T) {
	tests := []struct {
		name        string
		mainVersion string
		haveInfo    bool
		want        string
	}{
		{"go install of a tag", "v0.1.1", true, "v0.1.1"},
		{"plain go build in a checkout", "v0.1.2-0.20260802044404-312ea34b73cb", true, "v0.1.2-0.20260802044404-312ea34b73cb"},
		{"no module version to trust", "(devel)", true, "dev"},
		{"no build info at all", "", false, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubStamp(t, "dev", "none", "unknown")
			stubBuildInfo(t, tt.mainVersion, tt.haveInfo)
			if got := versionInfo(); got != tt.want {
				t.Errorf("versionInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

// make build stamps the version, commit and date it derived from the source, and that
// stamp is the more specific answer - it names the commit, which the module version does
// not. The fallback must not displace it.
func TestVersionInfoPrefersTheBuildStamp(t *testing.T) {
	stubStamp(t, "0.1.0-dev", "126ded7", "2026-08-02T02:18:22Z")
	stubBuildInfo(t, "v0.1.1", true)
	want := "0.1.0-dev (commit: 126ded7, built: 2026-08-02T02:18:22Z)"
	if got := versionInfo(); got != want {
		t.Errorf("versionInfo() = %q, want %q", got, want)
	}
}
