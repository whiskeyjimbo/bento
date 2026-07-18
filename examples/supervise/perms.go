package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/whiskeyjimbo/bento-v2/policy"
)

// perms inspects and edits the permission store from the command line, so a
// remembered decision can be cleared without hand-editing JSON. It is the escape
// hatch for the deny-wins footgun: a stored deny applies silently to a later run
// with no prompt, so there must be a way to see it (list) and clear it (forget /
// reset). Every store-derived string is quoted on display - keys are attacker-
// influenced (a hostname or filename the sandboxed target chose), the same
// terminal-escape risk the approval and gate prompts neutralize.
func perms(args []string, in io.Reader, out io.Writer) int {
	s, err := loadStore()
	if err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	if len(args) == 0 {
		permsUsage(out)
		return 2
	}
	switch args[0] {
	case "list":
		listPerms(s, out)
		return 0
	case "forget":
		return forgetPerms(s, args[1:], out)
	case "reset":
		return resetPerms(s, in, out)
	default:
		permsUsage(out)
		return 2
	}
}

func permsUsage(w io.Writer) {
	fmt.Fprint(w, `supervise perms - inspect and edit the permission store

Usage:
  supervise perms list                     show the effective remembered decisions
  supervise perms forget app <handle>      forget one app's decisions (handle from list)
  supervise perms forget global [host:port]  forget one global rule, or all of them
  supervise perms reset                    clear the entire store (asks to confirm)
`)
}

// listPerms prints the effective decisions: global rules first (a global deny is
// the footgun - it blocks a host for every app with no prompt, so it must be
// visible to be cleared), then each app with its network decisions resolved
// through the deny-wins lattice.
func listPerms(s *store, out io.Writer) {
	fmt.Fprintln(out, "Global rules (apply to every app):")
	if len(s.Global.Network) == 0 {
		fmt.Fprintln(out, "  (none)")
	} else {
		for _, k := range sortedKeys(s.Global.Network) {
			fmt.Fprintf(out, "  reach  %-34s %s\n", quoteNetKey(k), s.Global.Network[k])
		}
	}

	if len(s.Apps) == 0 {
		fmt.Fprintln(out, "\nApps: (none)")
		return
	}
	fmt.Fprintln(out, "\nApps:")
	for _, key := range sortedAppKeys(s.Apps) {
		a := s.Apps[key]
		interp := ""
		if a.Interpreter != "" {
			interp = " (" + strconv.Quote(a.Interpreter) + ")"
		}
		fmt.Fprintf(out, "  app %s  %s%s\n", shortKey(key), quotePath(a.Entrypoint), interp)
		for _, p := range sortedKeys(a.Read) {
			fmt.Fprintf(out, "    read   %-34s %s\n", quotePath(p), a.Read[p])
		}
		for _, p := range sortedKeys(a.Write) {
			fmt.Fprintf(out, "    write  %-34s %s\n", quotePath(p), a.Write[p])
		}
		if a.Exec != "" {
			d := allow
			if a.Exec != string(policy.ExecAll) {
				d = deny
			}
			fmt.Fprintf(out, "    exec   %-34s %s\n", "run subprocesses", d)
		}
		for _, k := range sortedKeys(a.Network) {
			// Show the effective decision, and mark any host a global DENY blocks - the
			// footgun - so the operator knows to clear the global layer, not the app's.
			// This covers a global deny over an app allow and over an app deny alike;
			// clearing only the app leaves the second still blocked.
			eff, _ := resolveLattice(s.Global.Network[k], a.Network[k])
			note := ""
			if s.Global.Network[k] == deny {
				note = " (global)"
			}
			fmt.Fprintf(out, "    reach  %-34s %s%s\n", quoteNetKey(k), eff, note)
		}
	}
}

func forgetPerms(s *store, args []string, out io.Writer) int {
	if len(args) == 0 {
		permsUsage(out)
		return 2
	}
	switch args[0] {
	case "app":
		if len(args) != 2 {
			permsUsage(out)
			return 2
		}
		key, err := s.resolveAppPrefix(args[1])
		if err != nil {
			fmt.Fprintf(out, "supervise: %v\n", err)
			return 1
		}
		ent := s.Apps[key].Entrypoint
		delete(s.Apps, key)
		if err := s.overwrite(); err != nil {
			fmt.Fprintf(out, "supervise: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "forgot app %s  %s\n", shortKey(key), quotePath(ent))
		return 0
	case "global":
		if len(args) > 2 {
			permsUsage(out)
			return 2
		}
		if len(args) == 2 {
			k := args[1]
			if _, ok := s.Global.Network[k]; !ok {
				fmt.Fprintf(out, "supervise: no global rule %s\n", quoteNetKey(k))
				return 1
			}
			delete(s.Global.Network, k)
			if err := s.overwrite(); err != nil {
				fmt.Fprintf(out, "supervise: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "forgot global rule %s\n", quoteNetKey(k))
			return 0
		}
		s.Global.Network = nil
		if err := s.overwrite(); err != nil {
			fmt.Fprintf(out, "supervise: %v\n", err)
			return 1
		}
		fmt.Fprintln(out, "forgot all global rules")
		return 0
	default:
		permsUsage(out)
		return 2
	}
}

func resetPerms(s *store, in io.Reader, out io.Writer) int {
	if len(s.Apps) == 0 && len(s.Global.Network) == 0 {
		fmt.Fprintln(out, "the permission store is already empty")
		return 0
	}
	fmt.Fprintf(out, "clear the entire permission store (%d app(s), %d global rule(s))? [y/N] ", len(s.Apps), len(s.Global.Network))
	if !confirmed(in) {
		fmt.Fprintln(out, "cancelled")
		return 0
	}
	s.Apps = map[string]*appPerms{}
	s.Global.Network = nil
	if err := s.overwrite(); err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "cleared the permission store")
	return 0
}

// confirmed reads one line and reports whether it is an explicit yes; anything
// else (including EOF) is a no, so a piped-in blank never wipes the store.
func confirmed(in io.Reader) bool {
	buf := make([]byte, 0, 8)
	b := make([]byte, 1)
	for {
		n, err := in.Read(b)
		if n > 0 && b[0] != '\n' {
			buf = append(buf, b[0])
		}
		if n == 0 || err != nil || (n > 0 && b[0] == '\n') {
			break
		}
	}
	switch strings.ToLower(strings.TrimSpace(string(buf))) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// quoteNetKey quotes the host of a "host:port" store key while leaving the port
// unquoted, so an attacker-chosen hostname cannot carry a terminal escape onto
// the operator's screen. The key always has a final ":port" (netKey builds it).
func quoteNetKey(k string) string {
	if i := strings.LastIndex(k, ":"); i >= 0 {
		return strconv.Quote(k[:i]) + ":" + k[i+1:]
	}
	return strconv.Quote(k)
}

func sortedKeys(m map[string]decision) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedAppKeys(m map[string]*appPerms) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
