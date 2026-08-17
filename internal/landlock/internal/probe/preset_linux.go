//go:build linux && bentoprobe

package main

import "github.com/whiskeyjimbo/bento/internal/landlock"

func setScopedIPCPreset(name string) error { return landlock.SetScopedIPCPreset(name) }
