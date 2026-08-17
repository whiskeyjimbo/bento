//go:build linux && !bentoprobe

package main

import "errors"

// The shipped build of this probe cannot swap a preset. A test that asks for one without
// the bentoprobe tag would otherwise measure the host's own ABI and pass as low-ABI
// coverage it never got.
func setScopedIPCPreset(string) error {
	return errors.New("probe: preset swapping needs -tags bentoprobe")
}

func setTierPreset(string) error {
	return errors.New("probe: preset swapping needs -tags bentoprobe")
}
