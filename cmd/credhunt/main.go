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
	"os"
	"path/filepath"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/credhunt"
	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// maxFileSize bounds the content sniff. A credential file is a few KB at most; past that
// the file is a dataset or a binary, and the shape this hunts is not in it.
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
	rules := denylist.Runtime(denylist.RuntimeDir(), homes...)
	for _, h := range homes {
		rules = append(rules, denylist.Home(h, homes...)...)
	}

	for _, h := range homes {
		fmt.Printf("scanning %s against %d shields\n", h, len(rules))
		found, pruned, err := credhunt.Hunt(credhunt.Options{
			Home:          h,
			Rules:         rules,
			MachineStores: machineStores(h),
			MaxFileSize:   maxFileSize,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "credhunt: walking %s: %v\n", h, err)
			os.Exit(1)
		}
		leads, dense := summarize(h, found)
		for _, f := range leads {
			fmt.Printf("  %-70s %04o  %s\n", f.Path, f.Mode, strings.Join(f.Signals, ","))
		}
		for _, d := range dense {
			fmt.Printf("  %-70s %d hits, not listed - an installed-tool tree? add it to machineStores\n", d.prefix+"/...", d.count)
		}
		fmt.Printf("%d lead(s) and %d dense tree(s) under %s that no shield covers (%d tree(s) pruned)\n\n", len(leads), len(dense), h, pruned)
	}
	fmt.Println("These are LEADS, not gaps: read each one and decide whether it belongs in denylist.go.")
	fmt.Println("A name/suffix hit alone is weak; private-mode plus a content shape is close to certain.")
}
