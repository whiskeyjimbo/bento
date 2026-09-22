//go:build unix

package gate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The anchor scan is the half of the credential-alias walk the budget did not reach: it
// runs before there is anything to want, so a home whose store is large paid for every
// entry in it and then answered "nothing found" - a scan that was cut short reading as one
// that finished. One allowance covers both walks, and a walk that stops short says so.
func TestAnchorWalkStopsOnItsBudget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store := filepath.Join(home, ".gnupg")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if err := os.WriteFile(filepath.Join(store, fmt.Sprintf("k%d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	budget := 5
	_, _, _, stopped := aliasableCredentials(hostSet(t), nil, &budget)
	if !stopped {
		t.Error("an anchor holding more entries than the budget must be reported as stopped short")
	}
	if budget > 0 {
		t.Errorf("the anchor walk must spend its budget; %d left", budget)
	}
}
