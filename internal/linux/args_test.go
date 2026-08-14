//go:build linux

package linux

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/policy"
)

// The argv compiler: the base flags, the system mounts and the interpreter's, the
// environment, the command, and the fake filesystem every test in the package builds on.
// The two concerns that grew their own source files have their own test files beside
// them - what a run shields in shields_test.go, what it refuses in grants_test.go.

// testSandbox compiles argv against a hypothetical filesystem, so the
// security-critical argv decisions can be asserted without launching anything.
func testSandbox(existing ...string) sandbox {
	set := make(map[string]bool, len(existing))
	for _, p := range existing {
		set[p] = true
	}
	return sandbox{
		homes:      []string{"/home/u"},
		emptyFile:  "/tmp/shield",
		entrypoint: "/work/run.py",
		exists:     func(p string) bool { return set[p] },
		// The hypothetical filesystem is the invoking user's own throughout.
		writable: func(string) bool { return true },
		// A path is a directory if the fake filesystem has an entry strictly under
		// it; a leaf entry is a file. This lets a write grant that is a project
		// directory get its workspace shields while a plain-file grant does not.
		isDir: func(p string) bool {
			for e := range set {
				if e != p && policy.CoversResolved(p, e) {
					return true
				}
			}
			return false
		},
		rootDirs: func() ([]string, error) { return []string{"/usr", "/home", "/etc"}, nil },
		// The hypothetical filesystem has no symlinks, so shields bind in place.
		resolve: func(p string) string { return p },
		// listDir returns the immediate SUBDIRECTORY names of p implied by the fake
		// entries (a segment with something under it), matching hostListDir, which
		// reports files nowhere and symlinks as links. ok is true when p is a directory (has any entry
		// under it); the fake has no unreadable directories. A bare leaf entry directly
		// under p is a file. The fake filesystem has no symlinks, so links is always nil.
		listDir: func(p string) (names, links []string, ok bool) {
			prefix := p + "/"
			seen := map[string]bool{}
			isDir := false
			for e := range set {
				if !strings.HasPrefix(e, prefix) {
					continue
				}
				isDir = true
				rest := e[len(prefix):]
				before, _, ok := strings.Cut(rest, "/")
				if !ok {
					continue // a leaf directly under p is a file, not a subdirectory
				}
				if name := before; !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
			return names, nil, isDir
		},
		// The fake filesystem has no aliased credentials by default; the alias-scan
		// tests override these seams to plant one.
		fileIDs:      func(string) ([]identifiedFile, error) { return nil, nil },
		aliasesUnder: func(string, map[fileID]string) ([]credentialAlias, error) { return nil, nil },
		mountpoints:  func([]uint64) ([]mountPoint, error) { return nil, nil },
		statID:       func(string) (fileID, bool) { return fileID{}, false },
	}
}

func compileOrFail(t *testing.T, p *policy.Policy, sb sandbox) []string {
	t.Helper()
	args, _, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return args
}

// pairIndex returns the index of the first occurrence of `flag target` in args.
func pairIndex(args []string, flag, target string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == target {
			return i
		}
	}
	return -1
}

func has(args []string, flag, target string) bool { return pairIndex(args, flag, target) >= 0 }

// lastPairIndex returns the index of the last occurrence of `flag target`, for
// asserting that a re-bind of a path wins over an earlier bind of the same path.
func lastPairIndex(args []string, flag, target string) int {
	last := -1
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == target {
			last = i
		}
	}
	return last
}

func containsStr(ss []string, s string) bool {
	return slices.Contains(ss, s)
}

func TestNoNetworkRulesUnsharesNetwork(t *testing.T) {
	args := compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py"}, testSandbox())
	found := false
	for _, a := range args {
		if a == "--unshare-net" {
			found = true
		}
	}
	if !found {
		t.Error("a policy with no network rules must unshare the network namespace")
	}
}

func TestGrantsAreBound(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/data"}, Write: []string{"/out"}}
	args := compileOrFail(t, p, testSandbox())

	if !has(args, "--ro-bind-try", "/data") {
		t.Error("read grant not bound read-only")
	}
	if !has(args, "--bind-try", "/out") {
		t.Error("write grant not bound")
	}
}

// A "/" read grant must bind the root's children individually, never the host
// root onto the sandbox root - and never the mounts baseFlags manages, or the
// host's /proc, /dev, /tmp would overmount the sandbox's own.
func TestRootReadGrantExpandsToChildren(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}
	args := compileOrFail(t, p, testSandbox())

	if has(args, "--ro-bind-try", "/") {
		t.Error("a \"/\" read grant must not bind the host root onto the sandbox root")
	}
	if !has(args, "--ro-bind-try", "/home") {
		t.Error("a \"/\" read grant must bind the root's children individually")
	}
	for _, managed := range []string{"/proc", "/dev", "/tmp"} {
		if has(args, "--ro-bind-try", managed) {
			t.Errorf("%s is managed by baseFlags and must not be overmounted from the host", managed)
		}
	}
}

// A root the host cannot enumerate must refuse the run. Expanding it to nothing binds
// nothing while the deny-list still emits shields for the paths a "/" grant reaches, so
// the run would exit 0 reporting confinement over a filesystem it never mounted.
func TestRootReadGrantRefusesAnUnreadableRoot(t *testing.T) {
	sb := testSandbox()
	sb.rootDirs = func() ([]string, error) { return nil, errors.New("permission denied") }
	p := &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}

	if _, _, err := compile(p, enforce.Process{}, sb); err == nil {
		t.Error("a \"/\" read grant whose expansion fails must refuse the run, not bind nothing")
	}
}

// The expansion feeds both the binds and the symlink decision, so it must be read once:
// a second enumeration can disagree with the first, leaving a name bound that the
// symlink pass never accounted for.
func TestRootReadGrantEnumeratesTheRootOnce(t *testing.T) {
	sb := testSandbox()
	calls := 0
	sb.rootDirs = func() ([]string, error) {
		calls++
		return []string{"/usr", "/home", "/etc"}, nil
	}
	compileOrFail(t, &policy.Policy{Entrypoint: "/work/run.py", Read: []string{"/"}}, sb)

	if calls != 1 {
		t.Errorf("the root expansion must be read once and carried; got %d reads", calls)
	}
}

// The exec-block is a hardening layer: on a host without seccomp the launcher must
// run the target without the filter (matching the LayerExec=Unavailable warning),
// never hard-refuse to install one it cannot. StrictBlock always implies Block.
func TestExecBlockFlagsGatedOnSeccomp(t *testing.T) {
	for _, mode := range []policy.ExecMode{policy.ExecNone, policy.ExecNoneStrict, policy.ExecAll} {
		if b, s := execBlockFlags(mode, false); b || s {
			t.Errorf("execBlockFlags(%q, seccomp=false) = %v,%v; want false,false - a hardening gap proceeds unblocked", mode, b, s)
		}
	}
	cases := []struct {
		mode          policy.ExecMode
		block, strict bool
	}{
		{policy.ExecNone, true, false},
		{policy.ExecNoneStrict, true, true},
		{policy.ExecAll, false, false},
	}
	for _, c := range cases {
		if b, s := execBlockFlags(c.mode, true); b != c.block || s != c.strict {
			t.Errorf("execBlockFlags(%q, seccomp=true) = %v,%v; want %v,%v", c.mode, b, s, c.block, c.strict)
		}
	}
}

// compile must gate the exec-block on the real seccomp check, not on the seccomp
// every development host has. The pure decision above proves the gating; this proves
// compile consults the check at all, which a host WITH seccomp cannot otherwise
// exercise: a compile that hardcoded seccomp support would encode a none-strict
// launch the launcher then cannot deliver.
func TestCompileReadsTheRealSeccompCheck(t *testing.T) {
	sb := testSandbox("/work/run.py")
	p := &policy.Policy{Entrypoint: "/work/run.py", Exec: policy.ExecNoneStrict}

	// A positive control: with seccomp present this host must encode the strict
	// block, or the fallback below would not be caused by losing the capability.
	args, _, err := compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--exec", "none-strict") {
		t.Skipf("this host does not encode a none-strict launch to begin with: %v", args)
	}

	swap(t, &seccompSupported, false)
	args, _, err = compile(p, enforce.Process{}, sb)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--exec", "all") {
		t.Errorf("without seccomp compile still encodes a blocking exec mode: %v - it is not reading the check", args)
	}
}

// hasFlagValue reports whether args carries flag immediately followed by value.
func hasFlagValue(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestEnvIsClearedAndAllowlistApplied(t *testing.T) {
	proc := enforce.Process{Env: map[string]string{"LANG": "C", "TOKEN": "abc"}}
	args, _, err := compile(&policy.Policy{Entrypoint: "/work/run.py"}, proc, testSandbox())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if args[0] != "--die-with-parent" {
		t.Errorf("argv should start with the isolation flags, got %q", args[0])
	}
	cleared := false
	for _, a := range args {
		if a == "--clearenv" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the inherited environment must be cleared")
	}
	if !has(args, "--setenv", "LANG") || !has(args, "--setenv", "TOKEN") {
		t.Error("allowlisted env values were not passed through")
	}
	// HOME must never point at the host's home directory.
	i := pairIndex(args, "--setenv", "HOME")
	if i < 0 || args[i+2] != "/tmp" {
		t.Error("HOME inside the sandbox must not be the host home directory")
	}
}

func TestEntrypointBoundReadOnly(t *testing.T) {
	p := &policy.Policy{Entrypoint: "/work/run.py", Write: []string{"/work"}}
	args := compileOrFail(t, p, testSandbox())

	entry := -1
	grant := pairIndex(args, "--bind-try", "/work")
	for j := 0; j+2 < len(args); j++ {
		if args[j] == "--ro-bind" && args[j+1] == "/work/run.py" && args[j+2] == "/work/run.py" {
			entry = j
		}
	}
	if entry < 0 {
		t.Fatal("entrypoint must be bound read-only")
	}
	if entry < grant {
		t.Error("a write grant covering the script's directory would leave the script itself writable")
	}
}

func TestCommandUsesInterpreterWhenSet(t *testing.T) {
	sb := testSandbox()
	sb.interpreter = "/usr/bin/python3"
	p := &policy.Policy{Entrypoint: "/work/run.py", Args: []string{"--flag"}}
	args := compileOrFail(t, p, sb)

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 {
		t.Fatal("argv must contain the -- separator")
	}
	got := strings.Join(args[sep+1:], " ")
	if got != "/usr/bin/python3 /work/run.py --flag" {
		t.Errorf("command = %q", got)
	}
}

func TestCompiledBinaryRunsItself(t *testing.T) {
	sb := testSandbox()
	sb.entrypoint = "/work/tool"
	p := &policy.Policy{Entrypoint: "/work/tool"}
	args := compileOrFail(t, p, sb)

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if got := strings.Join(args[sep+1:], " "); got != "/work/tool" {
		t.Errorf("a binary with no interpreter should run itself, got %q", got)
	}
}

func TestInterpreterPrefix(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/python3":                    "",
		"/home/u/.pyenv/versions/3.12/bin/py": "/home/u/.pyenv/versions/3.12",
		"":                                    "",
	}
	for in, want := range cases {
		if got := interpreterPrefix(in); got != want {
			t.Errorf("interpreterPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// An interpreter directly under the home directory (a hand-written ~/bin/python3
// wrapper) would make the prefix the whole of $HOME. Binding that would hand a
// policy that granted only /work every file in the home directory - the shields
// cover the deny-list, but nothing covers ~/.bash_history or another project's
// .env. Only the interpreter itself is bound.
func TestInterpreterUnderHomeBindsOnlyItself(t *testing.T) {
	sb := testSandbox("/home/u", "/home/u/bin", "/home/u/bin/python3", "/home/u/notes.txt", "/work")
	sb.interpreter = "/home/u/bin/python3"
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if has(args, "--ro-bind", "/home/u") {
		t.Errorf("$HOME must never be bound as an interpreter prefix; got %v", args)
	}
	if !has(args, "--ro-bind", "/home/u/bin/python3") {
		t.Errorf("the interpreter itself must be bound so the run can exec it; got %v", args)
	}
}

// A write grant covering the interpreter's directory (write: ~/bin over a
// ~/bin/python3 wrapper) would overmount the interpreter's read-only bind with a
// read-write one - letting the target rewrite the binary it is running, host
// persistence. The interpreter must be re-bound read-only after the write grant, so
// the shield wins by argv order, just as the entrypoint is.
// The interpreter sits in a project virtualenv rather than ~/bin: ~/bin is itself a
// write-shielded $PATH directory, so a write grant naming it is refused outright and
// never reaches the ordering this test is about. A venv is the case where the grant is
// legitimate and the re-bind is the only thing protecting the binary.
func TestWriteGrantDoesNotLeaveInterpreterWritable(t *testing.T) {
	sb := testSandbox("/work", "/work/venv/bin", "/work/venv/bin/python3")
	sb.interpreter = "/work/venv/bin/python3"
	args := compileOrFail(t, &policy.Policy{Write: []string{"/work/venv/bin"}}, sb)

	rw := pairIndex(args, "--bind-try", "/work/venv/bin")
	ro := lastPairIndex(args, "--ro-bind", "/work/venv/bin/python3")
	if rw < 0 {
		t.Fatalf("the write grant should bind /work/venv/bin read-write; got %v", args)
	}
	if ro < 0 {
		t.Fatalf("the interpreter must be re-bound read-only; got %v", args)
	}
	if ro < rw {
		t.Errorf("the interpreter re-bind (at %d) must come after the write grant (at %d) so it wins", ro, rw)
	}
}

// The re-bind protects the interpreter binary for a version-managed runtime too,
// where the whole install prefix is bound and a write grant over it (write: ~/.pyenv)
// would otherwise make the binary itself writable.
func TestWriteGrantDoesNotLeavePyenvInterpreterWritable(t *testing.T) {
	interp := "/home/u/.pyenv/versions/3.12/bin/python3"
	sb := testSandbox("/home/u/.pyenv", "/home/u/.pyenv/versions/3.12", interp, "/work")
	sb.interpreter = interp
	args := compileOrFail(t, &policy.Policy{Write: []string{"/home/u/.pyenv"}}, sb)

	rw := pairIndex(args, "--bind-try", "/home/u/.pyenv")
	ro := lastPairIndex(args, "--ro-bind", interp)
	if rw < 0 || ro < 0 {
		t.Fatalf("want both a write bind of the prefix and a read-only re-bind of the interpreter; got %v", args)
	}
	if ro < rw {
		t.Errorf("the interpreter re-bind (at %d) must come after the write grant (at %d)", ro, rw)
	}
}

// On a host where the home directory is reached through a symlink (/home ->
// var/home on Silverblue, or a relocated home) the interpreter resolves to the real
// tree while os.UserHomeDir still reports the linked name. The floor must compare
// the two on the same footing, or it misses and binds the whole home tree.
func TestInterpreterUnderSymlinkedHomeBindsOnlyItself(t *testing.T) {
	sb := testSandbox("/var/home/u", "/var/home/u/bin", "/var/home/u/bin/python3", "/work")
	sb.homes = []string{"/home/u"}
	sb.interpreter = "/var/home/u/bin/python3"
	sb.resolve = func(p string) string {
		if p == "/home/u" || policy.CoversResolved("/home/u", p) {
			return filepath.Join("/var", p)
		}
		return p
	}
	args := compileOrFail(t, &policy.Policy{Read: []string{"/work"}}, sb)

	if has(args, "--ro-bind", "/var/home/u") {
		t.Errorf("a symlinked $HOME must never be bound as an interpreter prefix; got %v", args)
	}
	if !has(args, "--ro-bind", "/var/home/u/bin/python3") {
		t.Errorf("the interpreter itself must be bound so the run can exec it; got %v", args)
	}
}

// What systemMountPaths binds for an interpreter is what exposedPaths hands the
// deny-list, so each layout must bind exactly what the interpreter needs and no
// user data beyond it.
func TestSystemMountPathsForInterpreter(t *testing.T) {
	cases := []struct {
		name        string
		interpreter string
		existing    []string
		want        string // the interpreter-driven mount, "" for none beyond the system paths
		unwanted    string
	}{
		{"pip --user prefix", "/home/u/.local/bin/python3", []string{"/home/u/.local"}, "/home/u/.local", ""},
		{"pyenv", "/home/u/.pyenv/versions/3.12/bin/py", []string{"/home/u/.pyenv/versions/3.12"}, "/home/u/.pyenv/versions/3.12", ""},
		{"home wrapper binds the file, never $HOME", "/home/u/bin/python3", []string{"/home/u", "/home/u/bin/python3"}, "/home/u/bin/python3", "/home/u"},
		{"nix binds the store, not the package prefix", "/nix/store/abc/bin/python3", []string{"/nix/store", "/nix/store/abc"}, "/nix/store", "/nix/store/abc"},
		{"system interpreter", "/usr/bin/python3", []string{"/usr"}, "", ""},
		{"prefix absent from the host", "/opt/py/bin/python3", nil, "", "/opt/py"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox(tc.existing...)
			sb.interpreter = tc.interpreter
			got := systemMountPaths(sb)
			if tc.want != "" && !containsStr(got, tc.want) {
				t.Errorf("systemMountPaths(%q) = %v, want it to bind %q", tc.interpreter, got, tc.want)
			}
			if tc.unwanted != "" && containsStr(got, tc.unwanted) {
				t.Errorf("systemMountPaths(%q) = %v, must not bind %q", tc.interpreter, got, tc.unwanted)
			}
		})
	}
}

// The interpreter can come from the target script's shebang, so its install prefix is
// adversary-influenced. A prefix that covers a top-level host directory or another
// user's home must narrow the run to the interpreter file rather than exposing the
// tree - nothing under /srv, /opt, or an alien home is covered by any deny-list rule,
// which is anchored on the running user's home.
func TestInterpreterReadPathRefusesABroadPrefix(t *testing.T) {
	cases := []struct {
		name string
		// broad is the tree the unfloored prefix would have exposed. It is present in
		// the fake filesystem, so a missing floor binds it rather than failing the
		// exists check for an unrelated reason.
		interp, broad, want string
	}{
		{"top-level dir", "/srv/bin/python3", "/srv", "/srv/bin/python3"},
		{"root itself", "/python3", "/", "/python3"},
		{"another user's home", "/home/other/bin/python3", "/home/other", "/home/other/bin/python3"},
		{"alien home on another base", "/var/home/other/bin/python3", "/var/home/other", "/var/home/other/bin/python3"},
		{"own home", "/home/u/bin/python3", "/home/u", "/home/u/bin/python3"},
		{"a genuine install root", "/opt/toolchains/py/3.12/bin/python3", "", "/opt/toolchains/py/3.12"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb := testSandbox(tc.interp, tc.want, tc.broad)
			sb.interpreter = tc.interp
			if got := interpreterReadPath(sb); got != tc.want {
				t.Errorf("interpreterReadPath(%q) = %q, want %q", tc.interp, got, tc.want)
			}
		})
	}

	// As root the home is /root, so a floor that only compared against the running
	// user's home base would never fire for anything under /home - the case where an
	// alien home's credentials are least protected, since the deny-list is anchored on
	// /root and shields nothing under /home/other.
	t.Run("alien home while running as root", func(t *testing.T) {
		sb := testSandbox("/home/other/bin/python3", "/home/other")
		sb.homes = []string{"/root"}
		sb.interpreter = "/home/other/bin/python3"
		if got := interpreterReadPath(sb); got != "/home/other/bin/python3" {
			t.Errorf("interpreterReadPath = %q, want the interpreter file alone, not another user's home", got)
		}
	})

	// With no home there is no deny-list anchor either, so nothing shields whatever a
	// prefix contains. The ratchet has to close, not open, at that point.
	t.Run("no home at all", func(t *testing.T) {
		sb := testSandbox("/srv/rt/py/bin/python3", "/srv/rt/py")
		sb.homes = nil
		sb.interpreter = "/srv/rt/py/bin/python3"
		if got := interpreterReadPath(sb); got != "/srv/rt/py/bin/python3" {
			t.Errorf("interpreterReadPath = %q, want the interpreter file alone when there is no home to anchor shields on", got)
		}
	})
}

// The one arm of the too-broad floor that binds nothing at all: the interpreter itself
// is gone by the time compile asks. newSandbox already LookPath'd and resolved it, and
// compile re-guards with sb.exists, so this needs the file to vanish between the two -
// real, and the safe direction (bind nothing rather than fall back to the broad prefix
// the floor just refused), but until now unmeasured.
func TestInterpreterReadPathBindsNothingWhenTheInterpreterVanished(t *testing.T) {
	// The broad prefix is on the fake filesystem and the interpreter is not, which is
	// exactly the ordering that would let a regression bind /srv.
	sb := testSandbox("/srv")
	sb.interpreter = "/srv/bin/python3"
	if got := interpreterReadPath(sb); got != "" {
		t.Errorf("interpreterReadPath = %q, want nothing bound: the floor refused the prefix and the interpreter is no longer there", got)
	}
}

// prefixTooBroad compares the prefix against each home run through sb.resolve, and used
// to carry a guard for that seam answering empty. It cannot: hostResolve returns its
// input unchanged on any resolution error, so a non-empty path in is a non-empty path
// out. The guard was fail-closed and cost only a reader's time, but it invited the
// belief that the seam can answer empty - and a later caller acting on that belief is
// the real cost. This is what makes deleting it safe, so it is pinned rather than
// argued.
func TestHostResolveNeverAnswersEmpty(t *testing.T) {
	for _, p := range []string{
		"/nonexistent-" + t.Name(),
		"/nonexistent-" + t.Name() + "/deeper/still",
		"/",
		"relative/path",
		"/proc/self/root",
	} {
		if got := hostResolve(p); got == "" {
			t.Errorf("hostResolve(%q) = \"\": the resolve seam must answer a path or the input, never nothing", p)
		}
	}
}

// The interpreter's own options go before the entrypoint, which is the only place the
// interpreter reads them: after it they would be the script's argv, and `python3 -u`
// would become `python3 script -u`.
func TestCommandPutsInterpreterArgsBeforeTheEntrypoint(t *testing.T) {
	sb := testSandbox()
	sb.interpreter = "/bin/sh"
	p := &policy.Policy{Entrypoint: "/work/run.py", InterpreterArgs: []string{"-eu"}, Args: []string{"--flag"}}
	args := compileOrFail(t, p, sb)

	// The last separator, as its neighbour above does: bwrap's own "--" comes first
	// and the launcher's is the one the target's argv follows.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 {
		t.Fatal("argv must contain the -- separator")
	}
	if got := strings.Join(args[sep+1:], " "); got != "/bin/sh -eu /work/run.py --flag" {
		t.Errorf("command = %q", got)
	}
}

// The two tiers build the target's environment through different mechanisms - bwrap
// --setenv arguments and a plain KEY=VALUE slice - and the defaults have to survive
// both, or a `~` expansion works under bwrap and fails under --allow-degraded.
func TestBothTiersDefaultHomeAndPath(t *testing.T) {
	proc := enforce.Process{Env: map[string]string{"LANG": "C"}}

	args := envArgs(proc)
	if i := pairIndex(args, "--setenv", "HOME"); i < 0 || args[i+2] != enforce.SandboxHome {
		t.Errorf("bwrap tier HOME = %v, want %s", args, enforce.SandboxHome)
	}
	if i := pairIndex(args, "--setenv", "PATH"); i < 0 || args[i+2] != enforce.SandboxPath {
		t.Errorf("bwrap tier PATH = %v, want %s", args, enforce.SandboxPath)
	}

	// The degraded tier's own default is its scratch directory, not enforce.SandboxHome:
	// with no mount namespace /tmp is the host's, and it is in neither the Landlock read
	// set nor the write set, so a target given it as HOME cannot write $HOME/.cache where
	// the bwrap tier can. The stand-in for the tmpfs is what makes HOME mean the same
	// thing on both tiers.
	env := envSlice(sandboxEnv(proc.Env, "/run/scratch"))
	if !slices.Contains(env, "HOME=/run/scratch") || !slices.Contains(env, "PATH="+enforce.SandboxPath) {
		t.Errorf("degraded tier env = %v, want HOME and PATH defaulted", env)
	}

	// A policy that passes either through keeps its own value on both tiers.
	got := sandboxEnv(map[string]string{"HOME": "/work", "PATH": "/opt/bin"}, "/run/scratch")
	if got["HOME"] != "/work" || got["PATH"] != "/opt/bin" {
		t.Errorf("declared values were overwritten: %v", got)
	}
}

// The $HOME tmpfs a profiling run adds goes on before the grants, the system mounts and
// the deny-list, so it undoes no shield - but a tmpfs over / or over the base /tmp makes
// the run observe a host the operator did not think it was observing. Both are named as
// skipped, and both are reachable by spelling HOME differently.
func TestObserveHomeTmpfsSkipsRootAndBaseTmpfs(t *testing.T) {
	for _, tc := range []struct {
		home string
		want string
	}{
		{"/home/u", "/home/u"},
		{"/home/u/", "/home/u"},
		{"/", ""},
		{"/.", ""},
		{"//", ""},
		{"/tmp", ""},
		{"/tmp/", ""},
		{"", ""},
		{"relative", ""},
	} {
		proc := enforce.Process{Env: map[string]string{"HOME": tc.home}}
		if got := observeHomeTmpfs(proc, sandbox{observe: true}); got != tc.want {
			t.Errorf("observeHomeTmpfs(HOME=%q) = %q, want %q", tc.home, got, tc.want)
		}
	}

	// Only profiling adds it: an enforced run's HOME is the base /tmp or built from the
	// grants, and an empty overlay would shadow the granted content.
	proc := enforce.Process{Env: map[string]string{"HOME": "/home/u"}}
	if got := observeHomeTmpfs(proc, sandbox{}); got != "" {
		t.Errorf("an enforced run got a $HOME tmpfs at %q", got)
	}
}
