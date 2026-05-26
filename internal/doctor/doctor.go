// Package doctor probes the environment for sandbox prerequisites.
// Exposes a single Run() that returns CheckResults; callers format
// them however they like.
package doctor

import (
	"fmt"
	"io"
	"runtime"
)

// CheckResult is a single line in the doctor report.
type CheckResult struct {
	Name        string
	Status      Status
	Detail      string
	Remediation string
}

// Status is the outcome of a doctor check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Run executes all platform-appropriate checks (plus any added via
// WithCheck) and returns the results. Filtering (WithSkipNetwork) and
// short-circuiting (WithFailFast) apply uniformly to built-ins and
// custom checks.
func Run(opts ...Option) []CheckResult {
	c := applyOptions(opts)
	registry := append(platformRegistry(c), c.extra...)

	var results []CheckResult
	for _, check := range registry {
		if c.skipNetwork && check.category == CategoryNetwork {
			continue
		}
		r := check.run()
		results = append(results, r)
		if c.failFast && r.Status == StatusFail {
			return results
		}
	}
	return results
}

// Format writes a human-readable report of checks to w. Returns true
// iff all checks passed (no FAIL).
func Format(w io.Writer, checks []CheckResult) bool {
	fmt.Fprintf(w, "bento doctor (%s)\n\n", runtime.GOOS)
	allPass := true
	for _, c := range checks {
		fmt.Fprintf(w, "  [%s] %s", c.Status, c.Name)
		if c.Detail != "" {
			fmt.Fprintf(w, " — %s", c.Detail)
		}
		fmt.Fprintln(w)
		if c.Status == StatusFail {
			allPass = false
			if c.Remediation != "" {
				fmt.Fprintf(w, "         fix: %s\n", c.Remediation)
			}
		} else if c.Status == StatusWarn && c.Remediation != "" {
			fmt.Fprintf(w, "         note: %s\n", c.Remediation)
		}
	}
	fmt.Fprintln(w)
	if allPass {
		fmt.Fprintln(w, "all checks passed")
	} else {
		fmt.Fprintln(w, "one or more checks failed — see above")
	}
	return allPass
}
