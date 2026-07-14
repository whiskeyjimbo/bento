// Command probe confines itself to a single directory with Landlock, then
// reports whether an inside and an outside path are readable, so a test can
// observe Landlock's real effect in a fresh process (Landlock is irreversible
// for the process that applies it).
//
// Usage: probe <allowed-dir> <inside-path> <outside-path>
// Prints "inside=OK|DENIED outside=OK|DENIED".
package main

import (
	"fmt"
	"os"

	"github.com/whiskeyjimbo/bento-v2/internal/landlock"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: probe <allowed-dir> <inside-path> <outside-path>")
		os.Exit(2)
	}
	allowed := os.Args[1]
	if err := landlock.RestrictTo([]string{allowed}, []string{allowed}); err != nil {
		fmt.Fprintln(os.Stderr, "restrict:", err)
		os.Exit(2)
	}
	fmt.Printf("inside=%s outside=%s\n", readable(os.Args[2]), readable(os.Args[3]))
}

func readable(path string) string {
	if _, err := os.ReadFile(path); err != nil {
		return "DENIED"
	}
	return "OK"
}
