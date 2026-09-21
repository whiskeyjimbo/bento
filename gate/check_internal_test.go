package gate

import (
	"errors"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// A host that cannot anchor its shields still answers the refusals the shield set has no
// part in, since validate's summary prints them REFUSED on that same host and --json
// carrying none would read as a manifest with nothing to refuse.
func TestCheckStillRefusesUnshieldedClassesWithoutAnchors(t *testing.T) {
	saved := shieldSet
	shieldSet = func() (shield.Set, error) { return shield.Set{}, errors.New("denylist: no usable home directory") }
	t.Cleanup(func() { shieldSet = saved })

	r := Check(&policy.Policy{Entrypoint: t.TempDir(), Write: []string{"/"}})
	if !r.ShieldsUnknown {
		t.Fatal("ShieldsUnknown = false on a host whose shield set errored")
	}
	// The reason and not only the verdict: doctor prints the anchoring failure's own words
	// and validate had nothing to print, so a reader whose host cannot anchor was told to
	// go run the other command to learn what broke.
	if r.ShieldsUnknownReason != "denylist: no usable home directory" {
		t.Errorf("ShieldsUnknownReason = %q, want the anchoring failure's own words", r.ShieldsUnknownReason)
	}
	want := RootWriteProblems([]string{"/"})
	if len(want) == 0 {
		t.Fatal("RootWriteProblems refuses nothing for a write grant of /; the fixture no longer exercises a refusal")
	}
	if strings.Join(r.Refusals, "\n") != strings.Join(want, "\n") {
		t.Errorf("Refusals = %q, want the root-write refusal %q", r.Refusals, want)
	}
}
