// Command fuzz-sarif turns the crashers a `make fuzz` run left behind into a SARIF
// report, so a nightly fuzz finding lands in GitHub's security panel rather than only
// in a workflow artifact nobody opens.
//
// It identifies a finding as an UNTRACKED file under a testdata/fuzz directory, which is
// exactly what `go test -fuzz` writes when it finds one: the corpus entries already
// committed as regression seeds are tracked, so they do not report every night forever.
// Walking the directory instead would file one alert per committed seed, which is how
// the crashers artifact behaves and why it is read by hand.
//
// The case this deliberately does not cover is a seed that is committed and still
// failing, where the replay fails before anything new is written. That is a broken main
// branch, and `make test` is red for it on every pull request - a louder signal than a
// nightly alert, and one no fuzzing budget has to catch.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A crasher path is <pkg dir>/testdata/fuzz/<FuzzTarget>/<hash>, which is where the
// target name comes from - the run's own failure summary names the target but not which
// seed belongs to it, and a nightly run can lose more than one.
var crasherPath = regexp.MustCompile(`(?:^|/)testdata/fuzz/(Fuzz[A-Za-z0-9_]*)/[^/]+$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fuzz-sarif: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	out, err := exec.Command("git", "ls-files", "--others", "--exclude-standard").Output()
	if err != nil {
		return fmt.Errorf("listing untracked files: %w", err)
	}
	report, err := sarif(strings.Split(strings.TrimSpace(string(out)), "\n"))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// sarif builds the report for the crashers among paths. A run that found nothing still
// produces a report, with no results: uploading it is what retires the alerts from the
// night before, so a fixed target stops being reported without anyone closing it by hand.
func sarif(paths []string) (map[string]any, error) {
	seeds := map[string][]string{}
	for _, p := range paths {
		if m := crasherPath.FindStringSubmatch(p); m != nil {
			seeds[m[1]] = append(seeds[m[1]], p)
		}
	}

	targets := make([]string, 0, len(seeds))
	for t := range seeds {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	rules := []any{}
	results := []any{}
	for _, target := range targets {
		sort.Strings(seeds[target])
		rules = append(rules, map[string]any{
			"id":                   target,
			"name":                 target,
			"shortDescription":     map[string]any{"text": "Fuzzing found a failing input for " + target},
			"defaultConfiguration": map[string]any{"level": "error"},
		})
		for _, seed := range seeds[target] {
			results = append(results, map[string]any{
				"ruleId":  target,
				"level":   "error",
				"message": map[string]any{"text": message(target, seed)},
				// The seed rather than the target's declaration: it is a real file at a
				// real path, and it is the artifact a reader needs to reproduce - the
				// `go test -run` line in the message replays exactly this one.
				"locations": []any{map[string]any{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": seed},
						"region":           map[string]any{"startLine": 1},
					},
				}},
			})
		}
	}

	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "go test -fuzz",
				"informationUri": "https://go.dev/doc/security/fuzz/",
				"rules":          rules,
			}},
			"results": results,
		}},
	}, nil
}

func message(target, seed string) string {
	pkg := strings.TrimSuffix(seed, "/testdata/fuzz/"+target+"/"+filepath.Base(seed))
	if pkg == "" || pkg == seed {
		pkg = "."
	}
	return fmt.Sprintf("%s found a failing input. Commit %s as a regression seed and reproduce it with: go test ./%s -run=%s/%s",
		target, seed, pkg, target, filepath.Base(seed))
}
