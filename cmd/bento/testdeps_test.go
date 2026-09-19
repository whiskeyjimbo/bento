package main

import (
	"os"
	"testing"
)

// skipMissingDep skips for a missing host dependency, or fails when
// BENTO_REQUIRE_TEST_DEPS is set. A behavioral test that self-skips reports a pass having
// asserted nothing, so on a host without bwrap or unprivileged user namespaces a run is
// indistinguishable from one that exercised the shield; the variable is how a host that
// is supposed to have them - CI, and `make test` - says so.
func skipMissingDep(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BENTO_REQUIRE_TEST_DEPS") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}
