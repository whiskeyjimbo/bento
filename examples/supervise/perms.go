package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
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
		// reset is the recovery path, so it must survive the state it recovers from: a
		// corrupt or unreadable store is exactly when a human needs to clear it, and
		// refusing here would leave `rm` as the only way out of a state the code
		// deliberately fails closed on. It discards the file wholesale by design, so it
		// needs nothing from the unreadable contents. Every other subcommand reads what
		// is there and must not act on bytes it could not parse.
		if len(args) == 0 || args[0] != "reset" {
			fmt.Fprintf(out, "supervise: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "supervise: %v\n", err)
		fmt.Fprintln(out, "supervise: clearing it is the way out of this - reset does not need to read it.")
		s, err := emptyStore()
		if err != nil {
			fmt.Fprintf(out, "supervise: %v\n", err)
			return 1
		}
		return resetPerms(s, in, out, true)
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
		return resetPerms(s, in, out, false)
	case "export":
		return exportPerms(s, args[1:], out)
	case "import":
		return importPerms(s, args[1:], in, out)
	case "global":
		return globalPermsCmd(s, args[1:], out)
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
  supervise perms export <handle> [-o f]   write an app's approvals as a bento manifest
  supervise perms import <manifest.yaml>   seed an app's approvals from a manifest
  supervise perms global allow|deny <net host:port | read|write path | exec>
                                           set a standing rule for every script
`)
}

// listPerms prints the effective decisions: global rules first (a global deny is
// the footgun - it blocks a host for every app with no prompt, so it must be
// visible to be cleared), then each app with its network decisions resolved
// through the deny-wins lattice.
func listPerms(s *store, out io.Writer) {
	fmt.Fprintln(out, "Global rules (apply to every app):")
	g := s.Global
	if len(g.Read) == 0 && len(g.Write) == 0 && g.Exec == "" && len(g.Network) == 0 {
		fmt.Fprintln(out, "  (none)")
	} else {
		for _, p := range sortedKeys(g.Read) {
			fmt.Fprintf(out, "  read   %-34s %s\n", quotePath(p), g.Read[p])
		}
		for _, p := range sortedKeys(g.Write) {
			fmt.Fprintf(out, "  write  %-34s %s\n", quotePath(p), g.Write[p])
		}
		if d := execDecision(g.Exec); d != "" {
			fmt.Fprintf(out, "  exec   %-34s %s\n", "run subprocesses", d)
		}
		for _, k := range sortedKeys(g.Network) {
			fmt.Fprintf(out, "  reach  %-34s %s\n", quoteNetKey(k), g.Network[k])
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
		// mark tags a line "(global)" when a global DENY is the reason - the footgun -
		// so the operator clears the global layer, not the app's. It fires for a global
		// deny over an app allow and over an app deny alike; clearing only the app would
		// leave the second still blocking.
		mark := func(globalDenies bool) string {
			if globalDenies {
				return " (global)"
			}
			return ""
		}
		for _, p := range sortedKeys(a.Read) {
			eff, _ := s.decidePath(key, "read", p)
			gd, ok := longestPrefixMatch(s.Global.Read, p)
			fmt.Fprintf(out, "    read   %-34s %s%s\n", quotePath(p), eff, mark(ok && gd == deny))
		}
		for _, p := range sortedKeys(a.Write) {
			eff, _ := s.decidePath(key, "write", p)
			gd, ok := longestPrefixMatch(s.Global.Write, p)
			fmt.Fprintf(out, "    write  %-34s %s%s\n", quotePath(p), eff, mark(ok && gd == deny))
		}
		if a.Exec != "" {
			eff, _ := s.decideExec(key)
			fmt.Fprintf(out, "    exec   %-34s %s%s\n", "run subprocesses", eff, mark(execDecision(s.Global.Exec) == deny))
		}
		for _, k := range sortedKeys(a.Network) {
			eff, _ := resolveLattice(s.Global.Network[k], a.Network[k])
			fmt.Fprintf(out, "    reach  %-34s %s%s\n", quoteNetKey(k), eff, mark(s.Global.Network[k] == deny))
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
			removed := false
			if k == "exec" && s.Global.Exec != "" {
				s.Global.Exec = ""
				removed = true
			}
			for _, m := range []map[string]decision{s.Global.Network, s.Global.Read, s.Global.Write} {
				if _, ok := m[k]; ok {
					delete(m, k)
					removed = true
				}
			}
			if !removed {
				fmt.Fprintf(out, "supervise: no global rule %s\n", quoteNetKey(k))
				return 1
			}
			if err := s.overwrite(); err != nil {
				fmt.Fprintf(out, "supervise: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "forgot global rule %s\n", quoteNetKey(k))
			return 0
		}
		s.Global = globalPerms{}
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

// globalPermsCmd sets a standing rule that applies to every script. It is the
// deliberate way to establish a cross-script allow or deny, kept out of the routine
// approval prompt so "for every app" is never one keystroke away from a per-script
// yes. The live gate still offers a network block-everywhere in the moment; this
// command covers the rest (a global allow, or a read/write/exec rule).
func globalPermsCmd(s *store, args []string, out io.Writer) int {
	if len(args) < 2 {
		permsUsage(out)
		return 2
	}
	var d decision
	switch args[0] {
	case "allow":
		d = allow
	case "deny":
		d = deny
	default:
		permsUsage(out)
		return 2
	}
	var target string
	switch args[1] {
	case "net":
		if len(args) != 3 {
			permsUsage(out)
			return 2
		}
		host, port := splitNetKey(args[2])
		if host == "" || port == "" {
			fmt.Fprintln(out, "supervise: a net rule needs host:port")
			return 1
		}
		s.rememberNetwork("", host, port, d, true)
		target = "reach " + quoteNetKey(netKey(host, port))
	case "read", "write":
		if len(args) != 3 {
			permsUsage(out)
			return 2
		}
		if !filepath.IsAbs(args[2]) {
			fmt.Fprintf(out, "supervise: %s path must be absolute\n", args[1])
			return 1
		}
		s.rememberPath("", args[1], args[2], d, true)
		target = args[1] + " " + quotePath(args[2])
	case "exec":
		if len(args) != 2 {
			permsUsage(out)
			return 2
		}
		s.rememberExec("", d, true)
		target = "exec"
	default:
		permsUsage(out)
		return 2
	}
	// An explicit `global allow` uses the non-folding write so it sticks, the same as
	// forget and reset: the concurrent-merge deny-preference would otherwise override
	// the allow the operator just typed. A deny has no such conflict - the merge is
	// deny-preferring, so folding it in gets the operator's rule AND keeps a
	// concurrent run's recorded block, which overwrite would clobber.
	write := s.overwrite
	if d == deny {
		write = s.save
	}
	if err := write(); err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "set global %s %s\n", d, target)
	return 0
}

// unreadable says the store on disk could not be parsed, so s is a stand-in empty one
// rather than its contents. Reset still has work to do then - the file itself is what
// is being discarded - and there is nothing to count, so the usual empty-store
// shortcut and the itemized confirmation both have to give way.
func resetPerms(s *store, in io.Reader, out io.Writer, unreadable bool) int {
	globals := globalCount(s)
	if !unreadable && len(s.Apps) == 0 && globals == 0 {
		fmt.Fprintln(out, "the permission store is already empty")
		return 0
	}
	if unreadable {
		fmt.Fprint(out, "replace the unreadable permission store with an empty one? [y/N] ")
	} else {
		fmt.Fprintf(out, "clear the entire permission store (%d app(s), %d global rule(s))? [y/N] ", len(s.Apps), globals)
	}
	if !confirmed(in) {
		fmt.Fprintln(out, "cancelled")
		return 0
	}
	s.Apps = map[string]*appPerms{}
	s.Global = globalPerms{}
	if err := s.overwrite(); err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	fmt.Fprintln(out, "cleared the permission store")
	return 0
}

// exportPerms graduates an app's remembered approvals into a bento manifest, so
// the same script can run under plain `bento run` once a human attests it with
// `bento approve`. It exports the EFFECTIVE decision (a globally-denied host never
// leaks into the allowlist) and refuses a deny nested under an allowed dir, which a
// pure-allowlist manifest cannot express. Like `bento profile` it leaves the
// provenance unattested: graduating store memory into a declared policy is honest,
// but the attestation is a separate deliberate step.
func exportPerms(s *store, args []string, out io.Writer) int {
	handle, outPath := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			if i+1 >= len(args) {
				permsUsage(out)
				return 2
			}
			i++
			outPath = args[i]
		default:
			if handle != "" {
				permsUsage(out)
				return 2
			}
			handle = args[i]
		}
	}
	if handle == "" {
		permsUsage(out)
		return 2
	}
	key, err := s.resolveAppPrefix(handle)
	if err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	a := s.Apps[key]

	// Export the EFFECTIVE decision, folding the global layer in: a globally-denied
	// path never reaches the allowlist, and a global deny still counts for the
	// refusal below.
	readAllows, readDenies := s.effectivePaths(key, "read")
	writeAllows, writeDenies := s.effectivePaths(key, "write")

	// A deny under an allowed dir cannot survive the round-trip: the manifest grants
	// the dir and would re-expose the denied child. Refuse rather than silently
	// over-grant (drop the deny) or under-grant (drop the allow).
	offending := append(
		deniesUnderAllows(readGrants(readAllows, writeAllows), readDenies, "read"),
		deniesUnderAllows(writeAllows, writeDenies, "write")...,
	)
	if len(offending) > 0 {
		for _, c := range offending {
			fmt.Fprintf(out, "supervise: cannot export: %s %s is denied but lies under the allowed %s; a manifest is a pure allowlist and cannot express the sub-deny. forget one of them first.\n",
				c.kind, quotePath(c.deny), quotePath(c.allow))
		}
		return 1
	}

	pol := &policy.Policy{
		Entrypoint:  a.Entrypoint,
		Interpreter: a.Interpreter,
		Read:        readAllows,
		Write:       writeAllows,
		Exec:        policy.ExecNone,
	}
	if eff, ok := s.decideExec(key); ok && eff == allow {
		pol.Exec = policy.ExecAll
	}
	// Include global network allows too, not just the app's own - the same way the
	// path fields fold the global layer in via effectivePaths. A manifest has no
	// global concept, so a host the app reaches only through a global allow must be
	// baked in, or the exported manifest is not self-contained and drift-warns at once.
	for _, k := range storeNetKeys(s, key) {
		host, port := splitNetKey(k)
		if eff, ok := s.decideNetwork(key, host, port); !ok || eff != allow {
			continue // effective deny (or unknown): keep it out of the allowlist
		}
		pol.Network = append(pol.Network, policy.NetworkRule{Host: host, Port: port})
	}

	// A relative grant cannot be exported, because the two ends anchor it differently:
	// supervise resolves it against its own working directory, while `bento run`
	// resolves a manifest's relative path against the manifest's directory. The store
	// shield below would then judge a different path than the one the manifest grants -
	// so a grant that misses the store from here can reach it from there. Refuse rather
	// than pick one anchor and be wrong about the other.
	for _, kind := range []struct {
		name  string
		paths []string
	}{{"read", pol.Read}, {"write", pol.Write}} {
		for _, p := range kind.paths {
			if !filepath.IsAbs(p) {
				fmt.Fprintf(out, "supervise: cannot export: the %s grant %s is relative; a manifest resolves it against its own directory, not the one you remembered it from. forget it and re-approve the absolute path.\n", kind.name, quotePath(p))
				return 1
			}
		}
	}

	// Export is where a store decision leaves the wrapper's own shielding: under plain
	// `bento run` there is no approve() refusal and no enforced-run backstop, so a
	// remembered allow covering the store would graduate into a real grant. Refuse with
	// the same predicate the other two use, before anything is written.
	if err := assertStoreShielded(pol, s.dir); err != nil {
		fmt.Fprintf(out, "supervise: cannot export: %v; forget it first.\n", err)
		return 1
	}

	if err := pol.Validate(); err != nil {
		fmt.Fprintf(out, "supervise: exported policy is invalid: %v\n", err)
		return 1
	}
	data, err := manifest.Marshal(pol, manifest.Provenance{
		GeneratedBy: "bento-supervise",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	if outPath == "" {
		outPath = a.Entrypoint + ".manifest.yaml"
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	// The descriptive path is prettied for reading; the runnable command uses the
	// raw path, since a ~-shortened path does not expand inside the shell.
	fmt.Fprintf(out, "wrote %s - review it, then run: bento approve %s\n", quotePath(outPath), outPath)
	return 0
}

// importPerms seeds the store for an app from an existing manifest, so a declared
// policy becomes the wrapper's remembered answers. It keys the app by the CURRENT
// bytes of the manifest's entrypoint and requires explicit consent: bento's
// fingerprint attests the policy, not the code, so the file on disk may not be what
// the manifest was written for. A pre-existing deny is kept (only `forget` clears a
// deny), and a wildcard/range network rule is skipped - the store holds only
// literal host:port keys, so those are left to prompt at runtime.
func importPerms(s *store, args []string, in io.Reader, out io.Writer) int {
	if len(args) != 1 {
		permsUsage(out)
		return 2
	}
	f, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	defer f.Close()
	pol, err := manifest.Load(f)
	if err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	key, err := appKey(pol.Entrypoint)
	if err != nil {
		fmt.Fprintf(out, "supervise: cannot hash the manifest's entrypoint: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "seed the store from %s for %s (hashing its current bytes)?\n", quotePath(args[0]), quotePath(pol.Entrypoint))
	fmt.Fprint(out, "bento's fingerprint attests the policy, not the code, so confirm the file is what you expect. [y/N] ")
	if !confirmed(in) {
		fmt.Fprintln(out, "cancelled")
		return 0
	}

	a := s.app(key)
	a.Entrypoint = pol.Entrypoint
	a.Interpreter = pol.Interpreter
	for _, p := range pol.Read {
		seedPath(s, key, "read", p, out)
	}
	for _, p := range pol.Write {
		seedPath(s, key, "write", p, out)
	}
	if pol.Exec == policy.ExecAll {
		// A recorded exec deny (per-app ExecNone or a global exec deny) is not an unset
		// default, so keep it: only forget clears a deny, the same rule the path and
		// network loops honor.
		if eff, ok := s.decideExec(key); ok && eff == deny {
			fmt.Fprintln(out, "  kept the existing exec deny - forget it first if you want the manifest's allow")
		} else {
			a.Exec = string(policy.ExecAll)
		}
	}
	for _, r := range pol.Network {
		if isWildcardRule(r) {
			fmt.Fprintf(out, "  skipped %s:%s - a wildcard/range rule has no literal store key; it stays a runtime prompt\n", strconv.Quote(r.Host), r.Port)
			continue
		}
		k := netKey(r.Host, r.Port)
		if s.Global.Network[k] == deny || a.Network[k] == deny {
			fmt.Fprintf(out, "  kept the existing deny for %s - forget it first if you want the manifest's allow\n", quoteNetKey(k))
			continue
		}
		s.rememberNetwork(key, r.Host, r.Port, allow, false)
	}
	if err := s.save(); err != nil {
		fmt.Fprintf(out, "supervise: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "seeded app %s from the manifest\n", shortKey(key))
	return 0
}

// seedPath records a manifest path as an allow, unless a deny is already stored for
// it: only `forget` clears a deny, so import must never flip one to allow.
func seedPath(s *store, key, kind, path string, out io.Writer) {
	if d, ok := s.decidePath(key, kind, path); ok && d == deny {
		fmt.Fprintf(out, "  kept the existing %s deny covering %s - forget it first if you want the manifest's allow\n", kind, quotePath(path))
		return
	}
	s.rememberPath(key, kind, path, allow, false)
}

// effectivePaths partitions the paths an app is judged on for one kind into the
// effectively-allowed and effectively-denied sets, folding the global and per-app
// layers deny-wins. Export uses it so a globally-denied path never reaches the
// manifest allowlist, while a global deny still counts for the deny-under-allow
// refusal.
func (s *store) effectivePaths(key, kind string) (allows, denies []string) {
	globalM, appM := s.Global.Read, map[string]decision(nil)
	if kind == "write" {
		globalM = s.Global.Write
	}
	if a := s.Apps[key]; a != nil {
		appM = a.Read
		if kind == "write" {
			appM = a.Write
		}
	}
	seen := map[string]bool{}
	for _, m := range []map[string]decision{globalM, appM} {
		for p := range m {
			if seen[p] {
				continue
			}
			seen[p] = true
			eff, ok := s.decidePath(key, kind, p)
			if !ok {
				continue
			}
			if eff == allow {
				allows = append(allows, p)
			} else {
				denies = append(denies, p)
			}
		}
	}
	sort.Strings(allows)
	sort.Strings(denies)
	return
}

// isWildcardRule reports whether a network rule cannot become a literal store key:
// "*" or a ".suffix" host, or a "*"/range port. Those stay runtime prompts.
func isWildcardRule(r policy.NetworkRule) bool {
	return r.Host == "*" || strings.HasPrefix(r.Host, ".") ||
		r.Port == "*" || strings.Contains(r.Port, "-")
}

// globalCount is how many standing rules the store holds across all dimensions,
// counting the exec field as one when set.
func globalCount(s *store) int {
	n := len(s.Global.Read) + len(s.Global.Write) + len(s.Global.Network)
	if s.Global.Exec != "" {
		n++
	}
	return n
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
