// Command credhunt scans the running user's home directories for credential-shaped files
// bento does not shield, and prints them for a human to classify.
//
// It is run deliberately, never as a gate: see the internal/credhunt package doc for why
// wiring a per-host shape scan into CI would either flood it or force a suppression list.
// It always exits 0 - findings are leads to read, not a build verdict - so that nobody is
// tempted to put it in `make check` and read its status.
//
//	GOWORK=off go run ./cmd/credhunt
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/credhunt"
	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// maxFileSize bounds how much of each candidate's head the content sniff reads, not which
// files it will open. A credential sits in the first few KB of the file that holds it,
// whatever that file grows to behind it: ~/.claude.json reaches ~96 KB on a working host
// and the shell histories go further, and reading every byte of those to re-find a token
// already seen would cost a full-tree read for nothing.
const maxFileSize = 64 << 10

// machineStores are the package and build caches under home. They hold content-addressed
// artifacts rather than the user's own files, so a shape hit inside one is never an entry
// the deny-list would gain - and the Go module cache writes 0600, which on its own
// accounted for the great majority of a real home's hits. Hunt reports how many it pruned
// so this stays visible rather than becoming a silent suppression list.
func machineStores(home string) []string {
	rel := []string{".cache", "go/pkg/mod", ".go/pkg/mod", ".cargo/registry", ".npm", ".m2/repository", ".gradle/caches"}
	out := make([]string, 0, len(rel)+1)
	for _, r := range rel {
		out = append(out, filepath.Join(home, r))
	}
	if c := os.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(c) {
		out = append(out, filepath.Clean(c))
	}
	return out
}

// denseTreeLimit is the hit count past which a single subtree is summarized as one line
// rather than listed. A developer home carries installed-tool trees (a toolchain manager's
// store, an editor server's extensions, a vendored SDK) that vary per host, so enumerating
// them here would be a per-host list that goes stale; counting them instead lets the
// operator see what is drowning the report and decide whether it is a machine store.
const denseTreeLimit = 20

type denseTree struct {
	prefix string
	count  int
}

// summarize splits findings into the ones worth reading path by path and the subtrees
// dense enough that listing them would bury the rest. Nothing is dropped: a dense tree is
// reported by prefix and count, so the operator sees exactly what was folded up and can
// prune it deliberately or go look. Grouping is on the first three path components, which
// is where an installed-tool tree separates from the home's own config files.
//
// A file sitting directly at the home root is its own group, so it is always listed
// however many of its siblings there are. The dotfiles and editor leavings there are the
// class this tool is most for, and folding them under one line would hide exactly what it
// went looking for.
func summarize(home string, found []credhunt.Finding) ([]credhunt.Finding, []denseTree) {
	prefixOf := func(p string) string {
		parts := strings.Split(strings.TrimPrefix(p, home+string(filepath.Separator)), string(filepath.Separator))
		if len(parts) > 3 {
			parts = parts[:3]
		} else if len(parts) > 1 {
			parts = parts[:len(parts)-1]
		}
		return filepath.Join(home, filepath.Join(parts...))
	}
	count := map[string]int{}
	for _, f := range found {
		count[prefixOf(f.Path)]++
	}
	var leads []credhunt.Finding
	var dense []denseTree
	seen := map[string]bool{}
	for _, f := range found {
		p := prefixOf(f.Path)
		if count[p] <= denseTreeLimit {
			leads = append(leads, f)
			continue
		}
		if !seen[p] {
			seen[p] = true
			dense = append(dense, denseTree{prefix: p, count: count[p]})
		}
	}
	return leads, dense
}

func main() {
	homes, err := denylist.HomeAnchors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "credhunt: %v\n", err)
		os.Exit(1)
	}
	os.Exit(run(os.Stdout, os.Stderr, homes))
}

// run hunts each home and reports what it found. Its status is 0 whether or not there
// were leads - see the package doc: findings are leads for a human to classify, and a
// nonzero status on them is the thing that would let somebody gate on this tool. Only a
// home that could not be walked, where zero findings would read as a clean home, is an
// error.
func run(stdout, stderr io.Writer, homes []string) int {
	rules := denylist.Runtime(denylist.RuntimeDir(), homes...)
	for _, h := range homes {
		rules = append(rules, denylist.Home(h, homes...)...)
	}

	for _, h := range homes {
		fmt.Fprintf(stdout, "scanning %q against %d shields\n", h, len(rules))
		found, pruned, err := credhunt.Hunt(credhunt.Options{
			Home:          h,
			Rules:         rules,
			MachineStores: machineStores(h),
			MaxFileSize:   maxFileSize,
		})
		if err != nil {
			// Quoted for the reason the leads below are: a walk error is an fs.PathError
			// carrying the name that failed, which is a name off the tree being scanned.
			fmt.Fprintf(stderr, "credhunt: walking %s: %q\n", h, err)
			return 1
		}
		// Every path below is a name off the walked tree, quoted for the reason bento's
		// own reports quote one: a filename carries whatever bytes whoever wrote it chose,
		// and this output is what a human reads to decide whether a lead is a credential -
		// a name with escapes in it could rewrite the lines around itself on a terminal.
		leads, dense := summarize(h, found)
		for _, f := range leads {
			fmt.Fprintf(stdout, "  %-70q %04o  %s\n", f.Path, f.Mode, strings.Join(f.Signals, ","))
		}
		for _, d := range dense {
			fmt.Fprintf(stdout, "  %-70q %d hits, not listed - an installed-tool tree? add it to machineStores\n", d.prefix+"/...", d.count)
		}
		fmt.Fprintf(stdout, "%d lead(s) and %d dense tree(s) under %q that no shield covers (%d tree(s) pruned)\n\n", len(leads), len(dense), h, pruned)
	}
	fmt.Fprintln(stdout, "These are LEADS, not gaps: read each one and decide whether it belongs in denylist.go.")
	fmt.Fprintln(stdout, "A name/suffix hit alone is weak; private-mode plus a content shape is close to certain.")
	return 0
}
