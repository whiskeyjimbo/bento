package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/gate"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/policy"
	"github.com/whiskeyjimbo/bento/profile"
)

// hostShieldSet is the set clampProposal would clamp against on this host, off the $HOME
// the case relocated. Asked per call rather than once, because a case that moves HOME
// must get the new one - which is what gate.ShieldSet walking fresh gives it, and what
// commandShieldSet's environment key preserves for the command path clampProposal takes.
func hostShieldSet(t *testing.T) shield.Set {
	t.Helper()
	set, err := gate.ShieldSet()
	if err != nil {
		t.Fatalf("gate.ShieldSet: %v", err)
	}
	return set
}

// The clamp order is load-bearing - DropCovered must run LAST,
// after the broad-write clamp, so a read under a write that gets dropped as too broad
// is NOT swallowed by that write but surfaces as its own read grant. This fails if
// DropCovered is reordered ahead of partitionBroad (the shape of the original bug).
func TestClampProposalDedupsReadsOnlyAfterDroppingBroadWrites(t *testing.T) {
	p := &policy.Policy{
		Read:  []string{"/srv/app/config", "/etc/thing/data"},
		Write: []string{"/srv/app", "/etc"}, // /srv/app is narrow (kept); /etc is top-level (dropped)
	}
	_, _, _, broadWrites := clampProposal(p)

	if !slices.Contains(broadWrites, "/etc") {
		t.Fatalf("the top-level /etc write must be surfaced as too broad, got %v", broadWrites)
	}
	// The read under the KEPT narrow write is deduped away...
	if slices.Contains(p.Read, "/srv/app/config") {
		t.Errorf("a read under the surviving narrow write /srv/app must be deduped, got Read=%v", p.Read)
	}
	// ...but the read under the DROPPED broad /etc write survives (DropCovered ran
	// after the broad clamp, so /etc no longer covers it). If DropCovered ran first,
	// /etc would have swallowed it and it would be silently gone - the bug.
	if !slices.Contains(p.Read, "/etc/thing/data") {
		t.Errorf("a read under a dropped broad write must survive as its own grant, got Read=%v", p.Read)
	}
}

// A broad READ grant (~, /, or a top-level dir) must be dropped from the proposal and
// surfaced, symmetric to the broad-write clamp. Without this, a script that lists its
// home or the root produces read: ~ / read: /, which - once approved - binds the whole
// tree minus only the enumerated shields, re-opening a fail-open the clamp closed. The
// specific sub-paths the script read must still survive as their own grants.
func TestClampProposalDropsBroadReads(t *testing.T) {
	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home directory on this host")
	}
	underHome := home + "/.config/app/config" // a specific path the script really read
	p := &policy.Policy{Read: []string{home, "/", "/etc", underHome, "/srv/app/data"}}

	_, _, broadReads, _ := clampProposal(p)

	for _, want := range []string{home, "/", "/etc"} {
		if !slices.Contains(broadReads, want) {
			t.Errorf("%q must be surfaced as a too-broad read; broadReads=%v", want, broadReads)
		}
		if slices.Contains(p.Read, want) {
			t.Errorf("%q must be dropped from the proposed reads; Read=%v", want, p.Read)
		}
	}
	// The specific access and an ordinary deep directory survive.
	for _, keep := range []string{underHome, "/srv/app/data"} {
		if !slices.Contains(p.Read, keep) {
			t.Errorf("the specific read %q must survive; Read=%v", keep, p.Read)
		}
	}
}

// A credential path under a home OTHER than the profiler's (sudo: HOME=/root, script
// reads /home/u/.ssh) is not caught by clampShieldedGrants, which builds shields from
// the profiler's home only. The user chose to warn, not drop: the path SURVIVES the
// proposal (dropping on a home-shaped guess would gut legitimate cross-home data grants)
// and is instead surfaced by foreignHomeShields. An ordinary data path under the foreign
// home, the profiler's own credential path, and an unconventional home location must not
// warn.
func TestForeignHomeShieldsWarnsButKeeps(t *testing.T) {
	t.Setenv("HOME", "/root")

	foreignSSH := "/home/realuser/.ssh"
	p := &policy.Policy{
		Read: []string{foreignSSH, "/home/realuser/project/data", "/root/.ssh", "/srv/app"},
	}
	clampProposal(p)

	// Warn, don't drop: the foreign credential grant is still in the proposal.
	if !slices.Contains(p.Read, foreignSSH) {
		t.Errorf("a credential path under a foreign home must SURVIVE the proposal (warn, not drop); Read=%v", p.Read)
	}

	// The same path arriving as both a read and a write must warn once, not twice.
	warned := foreignHomeShields([]string{foreignSSH, "/home/realuser/project/data", "/root/.ssh", "/srv/app", foreignSSH})
	if !slices.Equal(warned, []string{foreignSSH}) {
		t.Errorf("foreignHomeShields = %v, want exactly [%q] (deduped, only the credential shield under a foreign home)", warned, foreignSSH)
	}

	// A grant that ENCLOSES a foreign shield must warn too: Synthesize collapses a file
	// write to its directory, so a script writing /home/realuser/notes.txt proposes
	// write: /home/realuser - which sweeps in ~/.ssh yet is neither at nor under it. The
	// enforced run shields only the home it runs as, so a foreign home stays exposed.
	for _, g := range []string{"/home/realuser", "/home/realuser/.config"} {
		if len(foreignHomeShields([]string{g})) == 0 {
			t.Errorf("%q encloses foreign credential shields and must warn", g)
		}
	}
	// A foreign DenyWrite persistence path (unshielded at run time) must warn, not just
	// DenyAll credentials.
	if len(foreignHomeShields([]string{"/home/realuser/.config/systemd/user"})) == 0 {
		t.Error("a foreign persistence path (~/.config/systemd/user) must warn")
	}
	// The profiler's own home path is clamped away by clampProposal, so it is never a
	// foreign warning; assert directly too in case the clamp changes.
	if slices.Contains(foreignHomeShields([]string{"/root/.ssh", "/var/home/u/.ssh"}), "/root/.ssh") {
		t.Error("the profiler's own credential path must not warn as foreign")
	}
	// An ostree layout is a home root like any other: converge treats "no warning" as
	// "safe to auto-accept under [a]ll", so a root this misses is a credential store
	// mounted without ever being shown.
	if len(foreignHomeShields([]string{"/var/home/u/.ssh"})) == 0 {
		t.Error("/var/home/u is a foreign home; its credential store must warn")
	}
}

// The ostree root must not warn about the profiler's OWN home, or a Silverblue host
// prompts per-path on every grant it makes - the noise that turning the blind spot into
// a warning would otherwise buy.
func TestForeignHomeShieldsQuietOnAnOstreeOwnHome(t *testing.T) {
	t.Setenv("HOME", "/var/home/u")

	if warned := foreignHomeShields([]string{"/var/home/u/.ssh", "/var/home/u"}); len(warned) != 0 {
		t.Errorf("foreignHomeShields = %v, want none: /var/home/u is this run's own home and the run shields it", warned)
	}
	if root, ok := homeRoot("/var/home/u/.ssh/id_rsa"); !ok || root != "/var/home/u" {
		t.Errorf("homeRoot = (%q, %v), want (\"/var/home/u\", true)", root, ok)
	}
}

// The half of that quiet the test above cannot reach: on a stock ostree host the anchors
// say /var/home/u while the /home -> /var/home symlink makes the same home /home/u, and a
// grant spelled through the symlink resolves to a root that is not literally an anchor.
// Without resolving the root too, every own-home grant on a Silverblue host warns as
// foreign - and converge prompts per path for each one.
//
// Built at temporary paths, since /home is not a symlink here and a test cannot make it
// one. Only the container list is stood in for; the symlink, the resolution and the
// anchors are real.
func TestForeignHomeShieldsQuietThroughAnOstreeHomeSymlink(t *testing.T) {
	root := t.TempDir()
	varHome, stockHome := filepath.Join(root, "var-home"), filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(varHome, "u", ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(varHome, stockHome); err != nil {
		t.Fatal(err)
	}
	saved := homeContainers
	homeContainers = func() []string { return []string{stockHome, varHome} }
	t.Cleanup(func() { homeContainers = saved })
	// What the anchors report on such a host: the resolved location, not the symlinked
	// spelling the grant uses.
	t.Setenv("HOME", filepath.Join(varHome, "u"))

	throughLink := filepath.Join(stockHome, "u", ".ssh")
	if warned := foreignHomeShields([]string{throughLink}); len(warned) != 0 {
		t.Errorf("foreignHomeShields(%q) = %v, want none: it is this run's own home named through the /home symlink", throughLink, warned)
	}
	// The guard must not go quiet about everything it resolves: another user's store under
	// the same symlinked container is still foreign.
	other := filepath.Join(stockHome, "other", ".ssh")
	if err := os.MkdirAll(filepath.Join(varHome, "other", ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if len(foreignHomeShields([]string{other})) == 0 {
		t.Errorf("foreignHomeShields(%q) = none, want the grant back: it is another user's credential store", other)
	}
}

// foreignHomeShields is the other half of the same consent gate, and it judges the same
// way: a grant that names a link into another user's store belongs, as spelled, to no
// home at all, and converge reads "no warning" as safe to auto-accept under [a]ll.
func TestForeignHomeShieldsResolves(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	link := filepath.Join(t.TempDir(), "link")
	// A dangling link resolves to its target all the same, which is what a target plants:
	// the store it points at belongs to an account this host need not have.
	if err := os.Symlink("/home/realuser/.ssh", link); err != nil {
		t.Fatal(err)
	}
	if warned := foreignHomeShields([]string{link}); !slices.Equal(warned, []string{link}) {
		t.Errorf("foreignHomeShields(%q) = %v, want the grant back: it lands in a foreign credential store", link, warned)
	}
	// The grant is named as the reviewer would read it in the manifest, not as resolved.
	plain := filepath.Join(t.TempDir(), "data")
	if warned := foreignHomeShields([]string{plain}); len(warned) != 0 {
		t.Errorf("foreignHomeShields(%q) = %v, want none: it reaches no home", plain, warned)
	}
}

// isBroadDir is a consent gate, not a spelling check: under [a]ll a grant it calls
// narrow is auto-accepted with no per-path prompt, so a target that steers it with a
// symlink gets the whole home mounted unseen. Both directions of the comparison have to
// resolve - the grant may name a link into the home, and the home itself may be spelled
// through one (an automounted /home -> /var/home).
func TestIsBroadDirResolves(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(work, "link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// The grant names the link the target planted; it lands on the whole home.
	if !isBroadDir(link) {
		t.Errorf("isBroadDir(%q) = false; it resolves to $HOME %q, so it binds the whole home", link, home)
	}
	if kept, dropped := partitionBroad([]string{link}); len(kept) != 0 || !slices.Contains(dropped, link) {
		t.Errorf("partitionBroad(%q) = (kept %v, dropped %v), want it dropped", link, kept, dropped)
	}
	// Discovery binds the script's own directory, so a script sitting behind such a link
	// would mount the home for the profiling run itself.
	if p := discoveryPolicy(filepath.Join(link, "run.sh"), "sh", nil, nil); len(p.Read) != 0 || len(p.Write) != 0 {
		t.Errorf("discoveryPolicy granted %v/%v for a script directory that resolves to $HOME", p.Read, p.Write)
	}
	// A directory genuinely inside the home is still narrow enough to grant.
	if isBroadDir(filepath.Join(home, "sub")) {
		t.Error("a directory inside the home is not broad")
	}
	// A container is every account at once. /home and /Users are caught as top-level
	// directories; /var/home is not, and it is the layout the home rules do know.
	for _, c := range profile.HomeContainers() {
		if !isBroadDir(c) {
			t.Errorf("isBroadDir(%q) = false; the container holds every user's home", c)
		}
	}

	// The other direction: $HOME is spelled through a link (/home -> /var/home) while the
	// observer records the resolved name, so the grant and the anchor never match
	// literally.
	real := filepath.Join(root, "real", "u")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "container")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "container", "u"))
	if !isBroadDir(real) {
		t.Errorf("isBroadDir(%q) = false; it is $HOME under the spelling the observer records", real)
	}
}

// The Solaris/NFS-automount layout, where homes live under /export/home. The enforcer's
// prefixTooBroad already refuses that shape; the proposal side reads the same list, so a
// grant of every account at once is refused here too, and the own-home logic recognises a
// home under it. The two lists having diverged is what put the container outside both.
func TestExportHomeIsAHomeContainerOnBothSides(t *testing.T) {
	if !isBroadDir("/export/home") {
		t.Error("isBroadDir(\"/export/home\") = false; the container holds every account on the host")
	}
	if root, ok := homeRoot("/export/home/u/work"); !ok || root != "/export/home/u" {
		t.Errorf("homeRoot(\"/export/home/u/work\") = (%q, %v), want (\"/export/home/u\", true)", root, ok)
	}
}

// The warning must name shields the enforced run actually carries. A KUBECONFIG under an
// anchor's own ~/.kube is covered by that anchor's directory shield, so the enforcer emits
// no interior file rule for it - and neither may this, or the reviewer is sent to check a
// rule the run has not got. Reachable where $HOME sits under another conventional home
// root, which makes homeRoot read the parent as foreign.
func TestForeignHomeShieldsFollowsTheRunsAnchors(t *testing.T) {
	t.Setenv("HOME", "/home/other/sub")
	t.Setenv("KUBECONFIG", "/home/other/sub/.kube/config")

	for _, g := range []string{"/home/other/sub/.kube", "/home/other/sub/.kube/config"} {
		if warned := foreignHomeShields([]string{g}); len(warned) != 0 {
			t.Errorf("foreignHomeShields(%q) = %v, want none: the anchor's own ~/.kube shield covers it, so the run carries no rule for it", g, warned)
		}
	}
	// The store the anchors do not cover still warns, so this has not simply gone quiet.
	if len(foreignHomeShields([]string{"/home/other/.ssh"})) == 0 {
		t.Error("a credential store under the foreign root itself must still warn")
	}
}

func TestPartitionBroad(t *testing.T) {
	home, _ := os.UserHomeDir()

	deep := "/srv/app/data" // a specific directory, safe to grant
	writes := []string{deep, "/", "/etc", "/usr"}
	if home != "" {
		writes = append(writes, home)
	}

	kept, dropped := partitionBroad(writes)

	if !slices.Equal(kept, []string{deep}) {
		t.Fatalf("kept = %v, want just the specific directory %q", kept, deep)
	}
	for _, broad := range []string{"/", "/etc", "/usr"} {
		if !slices.Contains(dropped, broad) {
			t.Errorf("%q should be dropped as too broad to grant automatically", broad)
		}
	}
	if home != "" && !slices.Contains(dropped, home) {
		t.Errorf("the home directory %q should be dropped as too broad", home)
	}
}

// The profiling policy must be default-deny: never Read:["/"], which is the
// fail-open trial that was removed. Only the script's own directory is granted; a
// grant of "/" would re-expose every credential the deny-list does not enumerate.
func TestDiscoveryPolicyIsDefaultDeny(t *testing.T) {
	p := discoveryPolicy("/home/u/tool/run.sh", "sh", nil, []string{"--flag"})

	if slices.Contains(p.Read, "/") {
		t.Fatalf("discovery policy must not grant Read:[\"/\"] (fail-open); Read=%v", p.Read)
	}
	if !slices.Equal(p.Read, []string{"/home/u/tool"}) {
		t.Errorf("discovery Read = %v, want just the script directory", p.Read)
	}
	if !slices.Equal(p.Write, []string{"/home/u/tool"}) {
		t.Errorf("discovery Write = %v, want just the script directory", p.Write)
	}
	if p.Exec != policy.ExecAll {
		t.Errorf("discovery Exec = %v, want ExecAll so the run exercises real code paths", p.Exec)
	}
	if !slices.Equal(p.Args, []string{"--flag"}) {
		t.Errorf("discovery Args = %v, want the passed-through args", p.Args)
	}
}

// A script that sits directly in $HOME must not make the discovery run grant the home
// directory: that would bind the whole home tree and re-expose the credentials beside
// the script, defeating default-deny. The run still proceeds (entrypoint bound
// regardless) with no directory grant.
func TestDiscoveryPolicyDoesNotGrantBroadScriptDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := discoveryPolicy(filepath.Join(home, "deploy.sh"), "sh", nil, nil)

	if len(p.Read) != 0 || len(p.Write) != 0 {
		t.Errorf("a script directly in $HOME must not grant the home dir; Read=%v Write=%v", p.Read, p.Write)
	}
}

// discoveryEnv passes only variables actually set on the host, and never the ones
// deliberately omitted (PWD, XDG_RUNTIME_DIR). The names it returns become the
// manifest's env allowlist, so the enforced run rebuilds the same $HOME-relative paths.
func TestDiscoveryEnv(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_CONFIG_HOME", "/home/u/.config")
	t.Setenv("USER", "")                          // set but empty: treated as unset
	t.Setenv("PWD", "/somewhere")                 // deliberately omitted
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000") // omitted: always-shielded target

	env := discoveryEnv()

	if env["HOME"] != "/home/u" || env["XDG_CONFIG_HOME"] != "/home/u/.config" {
		t.Errorf("discoveryEnv dropped a set variable: %v", env)
	}
	for _, absent := range []string{"USER", "PWD", "XDG_RUNTIME_DIR"} {
		if _, ok := env[absent]; ok {
			t.Errorf("discoveryEnv should not carry %q; got %v", absent, env)
		}
	}
}

func TestPartialRunWarning(t *testing.T) {
	if w := partialRunWarning(profile.Observation{ExitCode: 0}, ""); w != "" {
		t.Errorf("clean run should not warn, got %q", w)
	}
	if w := partialRunWarning(profile.Observation{ExitCode: 7}, ""); !strings.Contains(w, "exited with code 7") {
		t.Errorf("nonzero exit warning = %q, want it to name code 7", w)
	}
	// Signaled takes priority over the (implied nonzero) exit code.
	w := partialRunWarning(profile.Observation{Signaled: true, Signal: 9, ExitCode: 137}, "")
	if !strings.Contains(w, "signal 9") || strings.Contains(w, "exited with code") {
		t.Errorf("signaled warning = %q, want it to name signal 9 and not the exit code", w)
	}
}

// 127 from a shell is "command not found", which the generic "fix the run and profile
// again" answers with a loop that cannot terminate - the search path is what is wrong,
// and the observer drops search misses, so another round sees exactly the same thing.
func TestPartialRunWarningCommandNotFound(t *testing.T) {
	w := partialRunWarning(profile.Observation{ExitCode: 127}, "/bin/sh")
	if !strings.Contains(w, enforce.SandboxPath) {
		t.Errorf("shell 127 warning = %q, want it to name the sandbox PATH", w)
	}
	if strings.Contains(w, "profile again to widen it") {
		t.Errorf("shell 127 warning = %q, want it to replace the generic advice, not repeat it", w)
	}
	// A shell reached by bare name is the same shell.
	if w := partialRunWarning(profile.Observation{ExitCode: 127}, "bash"); !strings.Contains(w, enforce.SandboxPath) {
		t.Errorf("bare-name shell 127 warning = %q, want it to name the sandbox PATH", w)
	}
	// A compiled entrypoint has no interpreter at all, and filepath.Base("") is ".", which
	// must not read as a shell.
	if w := partialRunWarning(profile.Observation{ExitCode: 127}, ""); !strings.Contains(w, "exited with code 127 -") {
		t.Errorf("no-interpreter 127 warning = %q, want the generic nonzero-exit wording", w)
	}
	// 127 means nothing in particular in another language, so the generic warning stands.
	if w := partialRunWarning(profile.Observation{ExitCode: 127}, "python3"); !strings.Contains(w, "exited with code 127 -") {
		t.Errorf("non-shell 127 warning = %q, want the generic nonzero-exit wording", w)
	}
	// A shell that reached 127 after ATTEMPTING an exec named an absolute path, which the
	// observer recorded and proposed. Granting it is what fixes the next round, so the
	// generic advice is right and the PATH story would be false - the search is not what
	// lost the tool, and telling the reader to use an absolute path is what they just did.
	//
	// The attempt alone is the case that matters here, and it is the common one: the exec
	// of a path the profiling sandbox did not hold is exactly why the shell reached 127.
	// A gate on the spawn instead of the attempt reads false on it and prints the PATH
	// story to a script that is already calling the tool by absolute path.
	for _, obs := range []profile.Observation{
		{ExitCode: 127, ExecAttempted: true},
		{ExitCode: 127, ExecAttempted: true, Execed: true},
	} {
		w = partialRunWarning(obs, "/bin/sh")
		if !strings.Contains(w, "exited with code 127 -") || strings.Contains(w, enforce.SandboxPath) {
			t.Errorf("shell 127 warning after an exec attempt (%+v) = %q, want the generic wording and no PATH claim", obs, w)
		}
	}
}

// On a symlinked home (Fedora Silverblue's /home -> /var/home), an observed credential
// path can arrive symlink-resolved (anchored at a resolved cwd) while $HOME is the
// unresolved form. The shield clamp must drop the grant in either form, so it builds
// shields against both the home as configured and its resolved target.
func TestClampShieldedGrantsResolvesSymlinkedHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)

	resolvedSSH := filepath.Join(real, ".ssh", "id_rsa") // observed via the resolved home
	linkSSH := filepath.Join(link, ".ssh", "id_rsa")     // observed via $HOME as configured
	_, _, shielded, _ := clampShieldedGrants(hostShieldSet(t), []string{resolvedSSH, linkSSH}, nil)
	dropped := shieldGrantPaths(shielded)
	for _, p := range []string{resolvedSSH, linkSSH} {
		if !slices.Contains(dropped, p) {
			t.Errorf("%q is inside the ~/.ssh shield and must be dropped; dropped=%v", p, dropped)
		}
	}
}

// A grant withheld from the proposal is warned about by what it holds, so the drop
// carries the shield's own classification rather than calling everything a credential.
func TestClampShieldedGrantsCarriesWhatTheShieldHolds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hist := filepath.Join(home, ".local", "state", "nvim", "shada")
	_, _, shielded, _ := clampShieldedGrants(hostShieldSet(t), []string{hist}, nil)
	if len(shielded) != 1 || shielded[0].Holds != denylist.HoldsHistory {
		t.Errorf("%q is a history store and must be withheld as one; got %+v", hist, shielded)
	}
}

// The withheld note is what a harness reads instead of the prose beside it, so the
// bucket has to reach the note too - a gate that re-proposes what a run declined needs to
// tell a withheld history store from a withheld private key.
func TestProposalWarningsCarryWhatTheShieldHolds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &policy.Policy{Read: []string{filepath.Join(home, ".local", "state", "nvim")}}
	withheld, _ := printProposalWarnings(io.Discard, p)
	if len(withheld) != 1 || withheld[0].Reason != "read-shielded" || withheld[0].Holds != "history" {
		t.Errorf("withheld = %+v, want one read-shielded note holding history", withheld)
	}
}

// The enforcer shields the passwd home whatever $HOME says, so the clamp has to know
// about it too: keyed on $HOME alone, a profiling run with a relocated home proposes a
// credential grant the enforced run then refuses.
func TestClampShieldedGrantsClampsThePasswdHome(t *testing.T) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skip("no passwd entry for this uid")
	}
	t.Setenv("HOME", t.TempDir())

	ssh := filepath.Join(u.HomeDir, ".ssh", "id_rsa")
	_, _, shielded, _ := clampShieldedGrants(hostShieldSet(t), []string{ssh}, nil)
	if dropped := shieldGrantPaths(shielded); !slices.Contains(dropped, ssh) {
		t.Errorf("%q is inside the passwd home's ~/.ssh shield and must be dropped; dropped=%v", ssh, dropped)
	}
}

// mergeExisting must distinguish a missing --out (first run, write fresh) from a file
// that exists but cannot be parsed. Overwriting an unparseable manifest would silently
// discard whatever grants it held, contradicting the merge-not-overwrite contract, so
// a corrupt existing file is refused rather than clobbered.
func TestMergeExisting(t *testing.T) {
	dir := t.TempDir()
	proposed := &policy.Policy{Entrypoint: "/w/run.py", Read: []string{"/w/in.txt"}}

	// Missing file: the first run returns the proposal unchanged, ready to write.
	got, err := mergeExisting(filepath.Join(dir, "absent.yaml"), "/w/run.py", proposed)
	if err != nil {
		t.Fatalf("missing --out should not error (first run); got %v", err)
	}
	if got.policy != proposed {
		t.Errorf("missing --out should return the proposal unchanged")
	}
	if got.widened {
		t.Errorf("a first run widened nothing")
	}

	// Corrupt file: refuse, so the prior file's grants are not silently overwritten.
	corrupt := filepath.Join(dir, "corrupt.yaml")
	if err := os.WriteFile(corrupt, []byte("\tnot: [valid: yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mergeExisting(corrupt, "/w/run.py", proposed); err == nil {
		t.Errorf("a corrupt existing manifest must be refused, not overwritten")
	}

	// Valid file: its grants are merged into the proposal.
	valid := filepath.Join(dir, "valid.yaml")
	base := &policy.Policy{Entrypoint: "/w/run.py", Read: []string{"/w/prior.txt"}}
	data, err := manifest.Marshal(base, manifest.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid, data, 0o644); err != nil {
		t.Fatal(err)
	}
	merged, err := mergeExisting(valid, "/w/run.py", proposed)
	if err != nil {
		t.Fatalf("a valid existing manifest should merge; got %v", err)
	}
	if !slices.Contains(merged.policy.Read, "/w/prior.txt") || !slices.Contains(merged.policy.Read, "/w/in.txt") {
		t.Errorf("merge should union prior and proposed reads; got %v", merged.policy.Read)
	}
	// The delta is what the closing message reports: a grant the file already held and
	// this run did not show is the part the reviewer cannot infer from the session.
	if !slices.Equal(merged.keptRead, []string{"/w/prior.txt"}) {
		t.Errorf("keptRead = %v, want the grant only the existing manifest held", merged.keptRead)
	}

	// A relative grant in the existing manifest names the same path the (always
	// absolute) proposal does, so the union must not write both spellings of it.
	rel := filepath.Join(dir, "relative.yaml")
	relData, err := manifest.Marshal(&policy.Policy{Entrypoint: "run.py", Read: []string{"in.txt"}}, manifest.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rel, relData, 0o644); err != nil {
		t.Fatal(err)
	}
	same := &policy.Policy{Entrypoint: filepath.Join(dir, "run.py"), Read: []string{filepath.Join(dir, "in.txt")}}
	merged, err = mergeExisting(rel, filepath.Join(dir, "run.py"), same)
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	if len(merged.policy.Read) != 1 {
		t.Errorf("a relative grant naming the proposal's path must merge to one entry; got %v", merged.policy.Read)
	}
}

func TestClampShieldedGrants(t *testing.T) {
	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home directory on this host")
	}
	ssh := home + "/.ssh/id_rsa"   // a file inside a DenyAll shield directory
	sshDir := home + "/.ssh"       // the shield directory itself
	netrc := home + "/.netrc"      // a DenyAll shield that is itself a FILE
	ordinary := "/srv/app/config"  // no shield involved
	underHome := home + "/project" // under home but not a shield

	reads := []string{ssh, sshDir, netrc, home, ordinary, underHome}
	writes := []string{home + "/.gnupg/x", ordinary}

	keptR, keptW, shielded, _ := clampShieldedGrants(hostShieldSet(t), reads, writes)
	dropped := shieldGrantPaths(shielded)

	// A grant AT or INSIDE a shield is dropped, whether the shield is a directory
	// (~/.ssh) or a file (~/.netrc); the run refuses all of them.
	for _, d := range []string{ssh, sshDir, netrc, home + "/.gnupg/x"} {
		if !slices.Contains(dropped, d) {
			t.Errorf("%q is at/inside a DenyAll shield and must be dropped; dropped=%v", d, dropped)
		}
	}
	// The load-bearing property: a read that only CONTAINS a shield (read: ~) is
	// legitimate and kept - the run allows it, so dropping it would strip a valid grant.
	if !slices.Contains(keptR, home) {
		t.Errorf("read of the home directory %q must be KEPT (it merely contains shields); keptReads=%v", home, keptR)
	}
	if !slices.Contains(keptR, ordinary) || !slices.Contains(keptR, underHome) {
		t.Errorf("ordinary reads must be kept; keptReads=%v", keptR)
	}
	if !slices.Contains(keptW, ordinary) {
		t.Errorf("ordinary write must be kept; keptWrites=%v", keptW)
	}
}

// The profiler must not propose a write grant the enforcer hard-refuses. A DenyWrite
// shield has no opt-in, so a proposal naming one could not be approved into a working
// run - the reviewer would accept a manifest that fails at compile. This is the one
// clamp that is not merely proposal quality: it is what keeps the two halves agreeing.
func TestClampDropsWritesUnderWriteShieldButKeepsReads(t *testing.T) {
	home, _ := os.UserHomeDir()
	if home == "" {
		t.Skip("no home directory on this host")
	}
	pathBin := home + "/.local/bin"       // a $PATH plant target: DenyWrite directory
	installed := home + "/.cargo/bin/rg"  // strictly inside another one
	bashrc := home + "/.bashrc"           // a DenyWrite shield that is itself a FILE
	ordinary := home + "/project/out.txt" // no shield involved

	reads := []string{pathBin, bashrc}
	writes := []string{pathBin, installed, bashrc, ordinary}

	keptR, keptW, _, writeShielded := clampShieldedGrants(hostShieldSet(t), reads, writes)

	for _, w := range []string{pathBin, installed, bashrc} {
		if !slices.Contains(writeShielded, w) {
			t.Errorf("write %q is at/inside a DenyWrite shield and must be dropped, or the proposal cannot be approved into a working run; dropped=%v", w, writeShielded)
		}
		if slices.Contains(keptW, w) {
			t.Errorf("write %q must not survive into the proposal; keptWrites=%v", w, keptW)
		}
	}
	if !slices.Contains(keptW, ordinary) {
		t.Errorf("an ordinary write must be kept; keptWrites=%v", keptW)
	}
	// Reads of the same paths stay: a DenyWrite shield leaves its content readable, so
	// dropping the read would withhold access the shield never took.
	for _, r := range []string{pathBin, bashrc} {
		if !slices.Contains(keptR, r) {
			t.Errorf("read of write-shielded %q must be KEPT - the shield only blocks writes; keptReads=%v", r, keptR)
		}
	}
}

// The clamp must match a symlinked shield by its TARGET, because that is what both the
// observer and the enforcer see. home-manager and stow both make ~/.local/bin a symlink
// into a dotfiles tree or the nix store; a write there is observed at the resolved path,
// and the enforcer refuses it (it resolves the shield too). A clamp that only compared
// literal paths would keep the grant, propose it, and let compile reject the approved
// manifest - the exact disagreement this clamp exists to prevent.
func TestClampWriteShieldMatchesSymlinkedShieldTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store := filepath.Join(t.TempDir(), "dotfiles", "bin")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, filepath.Join(home, ".local", "bin")); err != nil {
		t.Skipf("cannot symlink on this filesystem: %v", err)
	}
	// EvalSymlinks the temp root too: on macOS and some CI images /tmp is itself a
	// symlink, so the store path the observer would record is the resolved one.
	resolvedStore, err := filepath.EvalSymlinks(store)
	if err != nil {
		t.Fatal(err)
	}

	_, kept, _, dropped := clampShieldedGrants(hostShieldSet(t), nil, []string{filepath.Join(resolvedStore, "mytool")})
	if slices.Contains(kept, filepath.Join(resolvedStore, "mytool")) {
		t.Errorf("a write observed at the symlinked shield's target must be dropped, not proposed for a manifest compile will refuse; kept=%v", kept)
	}
	if len(dropped) == 0 {
		t.Errorf("the write must be reported as write-shielded so the user is told why; dropped=%v", dropped)
	}
}

// A clean exit says nothing about whether the observer could name everything it saw, so
// the two warnings are independent: a run that is both signaled and lossy reports both,
// each on its own schedule - dropped per round, partial once the last round is known.
func TestProfileWarningsCoversDroppedAccesses(t *testing.T) {
	if got := partialRunWarning(profile.Observation{Dropped: 2}, ""); got != "" {
		t.Errorf("a lossy but clean run did not fail to finish; got %q", got)
	}
	if got := droppedWarning(2); !strings.Contains(got, "could not name 2 file access") {
		t.Errorf("dropped warning = %q, want it to name the count", got)
	}
	if got := partialRunWarning(profile.Observation{Signaled: true, Signal: 9, Dropped: 1}, ""); got == "" {
		t.Error("a signaled run must warn that it may not have finished")
	}
}

// A seccomp kill is not a partial run to warn about: the observation is missing
// everything that process did, and profiling again produces the same result. It stops
// the round rather than proposing a manifest that looks complete - and it must not be
// downgraded into one of the advisory warnings. The message names both possible causes,
// since SIGSYS alone does not distinguish bento's arch guard from a self-sandboxing
// target, and misdiagnosing the second sends that user nowhere.
func TestSeccompKilledRefusesRatherThanWarns(t *testing.T) {
	if _, err := profile.Synthesize("/w/s.py", "python3", nil, profile.Observation{Dropped: 3, Signaled: true}); err != nil {
		t.Errorf("only a seccomp kill refuses the round; got %v", err)
	}
	_, err := profile.Synthesize("/w/s.py", "python3", nil, profile.Observation{SeccompKilled: true})
	if err == nil {
		t.Fatal("a seccomp-killed run must refuse the round")
	}
	for _, want := range []string{"non-native (32-bit) syscall ABI", "its own sandbox"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %q, want it to name %q as a possible cause", err, want)
		}
	}
	if got := partialRunWarning(profile.Observation{SeccompKilled: true}, ""); got != "" {
		t.Errorf("a seccomp kill must refuse, not warn; got %q", got)
	}
}

func TestSeedGrants(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, p *policy.Policy, prov manifest.Provenance) string {
		t.Helper()
		data, err := manifest.Marshal(p, prov)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Stamp the way `bento approve` does - over the policy as parsed back from disk,
	// which is what checkApproval fingerprints.
	approve := func(path string) {
		t.Helper()
		doc, _, err := loadDocument(path)
		if err != nil {
			t.Fatal(err)
		}
		doc.Provenance.Approves = doc.Policy.Fingerprint()
		data, err := manifest.Marshal(doc.Policy, doc.Provenance)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Missing --out is the first run: nothing to resume from, and no error.
	if seed, err := seedGrants(filepath.Join(dir, "absent.yaml"), "/w/run.py", io.Discard); seed != nil || err != nil {
		t.Errorf("a missing manifest should seed nothing without error; got %v, %v", seed, err)
	}

	// A file that cannot be parsed is refused up front rather than after a whole
	// profiling session that mergeExisting would then refuse to write.
	corrupt := filepath.Join(dir, "corrupt.yaml")
	if err := os.WriteFile(corrupt, []byte("\tnot: [valid: yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := seedGrants(corrupt, "/w/run.py", io.Discard); err == nil {
		t.Errorf("an unparseable manifest at --out must be refused, not ignored")
	}

	// Unapproved: the stamp is the consent record for mounting without a prompt, so
	// without it nothing is seeded and the loop asks about every path again.
	unapproved := write("unapproved.yaml", &policy.Policy{Entrypoint: "/w/run.py", Read: []string{"/w/secret"}}, manifest.Provenance{})
	if seed, err := seedGrants(unapproved, "/w/run.py", io.Discard); err != nil || seed != nil {
		t.Errorf("an unapproved manifest must seed nothing; got %v, %v", seed, err)
	}

	// Stale: approved once, then widened. Same refusal - the stamp no longer attests
	// the grants the file now holds.
	stale := write("stale.yaml", &policy.Policy{Entrypoint: "/w/run.py"}, manifest.Provenance{})
	approve(stale)
	staleDoc, _, err := loadDocument(stale)
	if err != nil {
		t.Fatal(err)
	}
	staleDoc.Policy.Read = []string{"/w/a"} // widened after approval, stamp not refreshed
	staleData, err := manifest.Marshal(staleDoc.Policy, staleDoc.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, staleData, 0o644); err != nil {
		t.Fatal(err)
	}
	if seed, err := seedGrants(stale, "/w/run.py", io.Discard); err != nil || seed != nil {
		t.Errorf("a stale approval must seed nothing; got %v, %v", seed, err)
	}

	// Approved, but for another script: the consent was "run.py may see these paths",
	// so profiling a different target against the same --out mounts nothing.
	other := write("other.yaml", &policy.Policy{Entrypoint: "/w/run.py", Read: []string{"/w/secret"}}, manifest.Provenance{})
	approve(other)
	if seed, err := seedGrants(other, "/w/attacker.py", io.Discard); err != nil || seed != nil {
		t.Errorf("an approval for a different entrypoint must seed nothing; got %v, %v", seed, err)
	}

	// Approved: its grants seed the loop, with relative paths resolved against the
	// manifest's own directory the way run resolves them.
	path := write("approved.yaml", &policy.Policy{Entrypoint: "run.py", Read: []string{"data/in.txt"}, Write: []string{"/w/out"}}, manifest.Provenance{})
	approve(path)
	seed, err := seedGrants(path, filepath.Join(dir, "run.py"), io.Discard)
	if err != nil {
		t.Fatalf("an approved manifest should seed; got %v", err)
	}
	if !slices.Contains(seed.Read, filepath.Join(dir, "data/in.txt")) {
		t.Errorf("a relative read grant must resolve against the manifest dir; got %v", seed.Read)
	}
	if !slices.Contains(seed.Write, "/w/out") {
		t.Errorf("write grants must seed too; got %v", seed.Write)
	}
}

// A grant Synthesize floors is withheld before the proposal the clamps report on, so
// without its own message it is the one withheld class that leaves no trace: the script
// fails EACCES at enforce time and the reviewer has nothing to read. Every other
// withheld class prints; this must too.
func TestFlooredWritesAreReportedNotSilent(t *testing.T) {
	var buf bytes.Buffer
	notes := printFlooredWrites(&buf, []string{
		"/var/lib/app/state.db",
		"/var/lib/app/other.db", // same collapsed dir: reported once
		"/home/other/.bashrc",
		"/usr/lib/thing.so", // a system tree the write floor knows only as a read path
		"relative/path",     // no absolute anchor, nothing to name
		"/work/ok.txt",      // an ordinary grant, reported by the clamps instead
	})
	got := buf.String()

	// The same decision reaches --json, so the prose and the envelope cannot disagree.
	want := []accessNoteJSON{
		{Kind: "write", Path: "/var/lib/app", Reason: "system-tree"},
		{Kind: "write", Path: "/home/other", Reason: "system-tree"},
		{Kind: "write", Path: "/usr/lib", Reason: "system-tree"},
	}
	if !slices.Equal(notes, want) {
		t.Errorf("notes = %+v, want %+v", notes, want)
	}

	for _, want := range []string{`"/var/lib/app"`, `"/home/other"`} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not name the withheld grant %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/work") {
		t.Errorf("an ordinary grant must not be reported as floored:\n%s", got)
	}
	if n := strings.Count(got, "not proposing write access"); n != 3 {
		t.Errorf("printed %d messages, want 3 (the duplicate directory is reported once):\n%s", n, got)
	}
}

// The floor Synthesize applies to the resolved name is the one a report can least afford
// to miss: it fires on a directory converge already granted, so the grant's own text
// looks ordinary and nothing else in the run names the tree the write really reaches.
func TestFlooredWritesReportAWriteThroughASymlink(t *testing.T) {
	proj := t.TempDir()
	link := filepath.Join(proj, "cfg")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	notes := printFlooredWrites(&buf, []string{filepath.Join(link, "cron.d", "job")})
	got := buf.String()

	want := []accessNoteJSON{{Kind: "write", Path: filepath.Join(link, "cron.d"), Reason: "system-tree"}}
	if !slices.Equal(notes, want) {
		t.Errorf("notes = %+v, want %+v: the withheld write must reach --json too", notes, want)
	}
	// Naming only the grant's own spelling sends the reviewer to look at a directory
	// there is nothing wrong with.
	if !strings.Contains(got, `resolves to "/etc/cron.d"`) {
		t.Errorf("the message must name where the write lands:\n%s", got)
	}
}

// The provenance record exists so approve can name a rule the reader is about to stamp,
// so it carries exactly the refusals the written manifest grants: a host the guard
// refused and the proposal then dropped (an unrepresentable name, a rule the merge never
// produced) has nothing to warn about, and recording it would leave the manifest naming
// a destination the target chose that appears nowhere else in the file.
func TestBlockedHostsRecordedOnlyForRulesTheManifestGrants(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "./x",
		Network: []policy.NetworkRule{
			{Host: "example.com", Port: "443"},
			{Host: "metadata.internal", Port: "80"},
		},
	}
	got := blockedHostsGranted(p, []string{"metadata.internal:80", "dropped.example:443"})
	if !slices.Equal(got, []string{"metadata.internal:80"}) {
		t.Errorf("blockedHostsGranted = %v, want only the refusal the manifest grants", got)
	}
}

// A rule need not be spelled as the destination it admits. Matching the record against a
// rule's text lost the callout for the broad rules - a suffix wildcard, a `*` - which are
// the ones a reader most needs warned about, and then dropped the record entirely at the
// next re-profile, so the warning never came back. The record keeps the destination the
// guard refused; the rules are asked whether they reach it.
func TestBlockedHostsMatchedThroughWildcardAndSpellingRules(t *testing.T) {
	for name, r := range map[string]policy.NetworkRule{
		"suffix wildcard":   {Host: ".internal", Port: "80"},
		"any host":          {Host: "*", Port: "*"},
		"port range":        {Host: "metadata.internal", Port: "80-90"},
		"case and root dot": {Host: "Metadata.Internal.", Port: "80"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &policy.Policy{Entrypoint: "./x", Network: []policy.NetworkRule{r}}
			blocked := []string{"metadata.internal:80"}
			if got := blockedHostsGranted(p, blocked); !slices.Equal(got, blocked) {
				t.Errorf("blockedHostsGranted = %v, want the refusal kept", got)
			}
			if !grantsAnyBlockedHost(r, blocked) {
				t.Error("approve must call this rule out")
			}
		})
	}
	unrelated := policy.NetworkRule{Host: "example.com", Port: "443"}
	if grantsAnyBlockedHost(unrelated, []string{"metadata.internal:80"}) {
		t.Error("a rule that reaches no recorded refusal must not be called out")
	}
}

// An IPv6 destination carries colons of its own, so the key the record holds and the
// split that reads it back have to agree on the separator. net.JoinHostPort brackets it
// on the way in and net.SplitHostPort unbrackets it on the way out; a bare concatenation
// would make the key unsplittable and the rule unmatched.
func TestBlockedHostKeysRoundTripAnIPv6Destination(t *testing.T) {
	keys := blockedHostKeys([]profile.HostPort{{Host: "2001:db8::1", Port: "443"}})
	if !slices.Equal(keys, []string{"[2001:db8::1]:443"}) {
		t.Fatalf("blockedHostKeys = %v, want the bracketed form", keys)
	}
	r := policy.NetworkRule{Host: "2001:db8::1", Port: "443"}
	if !grantsAnyBlockedHost(r, keys) {
		t.Error("a rule naming the same address must match the recorded key")
	}
}

// A CONNECT host is target-chosen, so it can be one the manifest grammar cannot hold.
// Such a host is already withheld from the proposal, and recording it in provenance
// would fail the marshal that ends the profiling run - discarding the session's work
// over a fact about it rather than a permission in it.
func TestBlockedHostKeysDropUnrepresentableHosts(t *testing.T) {
	got := blockedHostKeys([]profile.HostPort{
		{Host: "metadata.internal", Port: "80"},
		{Host: "bad host\n", Port: "443"},
		{Host: "metadata.internal", Port: "80"},
	})
	if !slices.Equal(got, []string{"metadata.internal:80"}) {
		t.Errorf("blockedHostKeys = %v, want the representable host once", got)
	}
}

// A path under /tmp reaches a proposal by existing on the HOST - inside the box /tmp is
// an empty tmpfs, so every probe there fails identically and only real names survive
// (profile.SandboxScratch). That test is what tells a real workspace from scratch and
// cannot be dropped, so the target's ability to steer it is disclosed instead: the
// entries it can choose are named as a group.
func TestTmpGrantsNamesWhatATargetCouldHaveSteered(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "/tmp/work-1234/run.py",
		Read:       []string{"/tmp/work-1234/data", "/tmp/probed-name", "/etc/hostname"},
		Write:      []string{"/tmp/work-1234", "/tmp/other"},
	}
	got := tmpGrants(p)
	want := []string{"/tmp/other", "/tmp/probed-name"}
	if !slices.Equal(got, want) {
		t.Errorf("tmpGrants = %v, want %v - the script's own workspace is where the user put it, not a guess", got, want)
	}

	// Running out of a mktemp -d workspace is ordinary. A note on every such run is one
	// the reader learns to skip, which costs the runs where it means something.
	only := &policy.Policy{Entrypoint: "/tmp/work-1234/run.py", Write: []string{"/tmp/work-1234"}}
	if got := tmpGrants(only); len(got) != 0 {
		t.Errorf("tmpGrants = %v, want nothing for a run confined to its own temp workspace", got)
	}

	// An entrypoint sitting directly in /tmp would make the exclusion cover everything
	// under it, hiding exactly the grants this exists to name.
	loose := &policy.Policy{Entrypoint: "/tmp/run.py", Read: []string{"/tmp/probed-name"}}
	if got := tmpGrants(loose); !slices.Equal(got, []string{"/tmp/probed-name"}) {
		t.Errorf("tmpGrants = %v, want the sibling grant still named", got)
	}

	if got := tmpGrants(&policy.Policy{Entrypoint: "/srv/x", Read: []string{"/srv/data"}}); len(got) != 0 {
		t.Errorf("tmpGrants = %v, want nothing for a policy that names no /tmp path", got)
	}
	if got := tmpGrants(nil); len(got) != 0 {
		t.Errorf("tmpGrants(nil) = %v, want nothing", got)
	}
}

// The note is the one thing a hand-edited manifest most wants to dodge, and the tests
// are prefix comparisons - so they run on the cleaned spelling. Both of these name a
// path the kernel binds under /tmp while reading, uncleaned, as something else.
func TestTmpGrantsIsNotDodgedByAnUncleanSpelling(t *testing.T) {
	doubled := &policy.Policy{Entrypoint: "/srv/run.py", Read: []string{"//tmp/guessed"}}
	if got := tmpGrants(doubled); !slices.Equal(got, []string{"/tmp/guessed"}) {
		t.Errorf("tmpGrants = %v, want the doubled-slash grant named as the /tmp path it binds", got)
	}

	// Written to sit inside the entrypoint's directory, where the workspace exclusion
	// would drop it, while actually naming a sibling of that workspace.
	escaped := &policy.Policy{Entrypoint: "/tmp/work/run.py", Read: []string{"/tmp/work/../guessed"}}
	if got := tmpGrants(escaped); !slices.Equal(got, []string{"/tmp/guessed"}) {
		t.Errorf("tmpGrants = %v, want the grant that climbs out of the workspace named", got)
	}
}

// grantsBlockedHost answers an unjudgeable key with "covered" so approve's per-rule
// prompt degrades into telling the reader to look. The grouped note states a fact
// instead, so inheriting that answer would assert of every rule in the manifest that
// profiling was refused it - false for the rules that work, and printed once each.
func TestRulesCoveringBlockedHostSetsAsideAnUnjudgeableKey(t *testing.T) {
	p := &policy.Policy{
		Entrypoint: "./x",
		Network: []policy.NetworkRule{
			{Host: ".internal", Port: "80"},
			{Host: "example.com", Port: "443"},
		},
	}

	covering, unreadable := rulesCoveringBlockedHost(p, []string{"metadata.internal:80", "not-a-host-port"})
	if len(covering) != 1 || covering[0].Host != ".internal" {
		t.Errorf("covering = %v, want only the rule that reaches the judgeable refusal", covering)
	}
	if !slices.Equal(unreadable, []string{"not-a-host-port"}) {
		t.Errorf("unreadable = %v, want the key nothing can match reported as its own fact", unreadable)
	}
}

// The union keeps the base's entrypoint, so merging into a manifest written for another
// program leaves a file naming one and granting what the other did. seedGrants already
// declines to mount such a manifest, so the run that produced the proposal was not
// resuming from it either - refusing at the write says so while it can still be acted on.
func TestMergeExistingRefusesAForeignEntrypoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.py.manifest.yaml")
	data, err := manifest.Marshal(&policy.Policy{Entrypoint: "/gone/stale.py", Read: []string{"/some/other/machine/dir"}}, manifest.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(dir, "probe.py")
	_, err = mergeExisting(path, script, &policy.Policy{Entrypoint: script})
	if err == nil {
		t.Fatal("a manifest for another program must be refused, not merged")
	}
	for _, want := range []string{"/gone/stale.py", script, "--out"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

// Re-profiling per the help text's "profile again to converge" advice unions the round's
// proposal into the file, which can escalate exec and always drops the approval stamp.
// Neither is refused - both are the merge working - but the closing message used to say
// the manifest reflected only this run, which is the one thing it does not.
func TestMergeNoticeReportsWideningAndVoidedApproval(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "probe.py")
	path := filepath.Join(dir, "probe.py.manifest.yaml")
	base := &policy.Policy{
		Entrypoint: script,
		Read:       []string{filepath.Join(dir, "prior")},
		Exec:       policy.ExecNone,
	}
	data, err := manifest.Marshal(base, manifest.Provenance{Approves: base.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	merged, err := mergeExisting(path, script, &policy.Policy{Entrypoint: script, Read: []string{filepath.Join(dir, "fresh")}, Exec: policy.ExecAll})
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	var b strings.Builder
	writeMergeNotice(&b, path, merged)
	out := b.String()
	for _, want := range []string{"already existed", "unioned with what was already there", filepath.Join(dir, "prior"), "exec was widened", "its approval is gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("merge notice missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "reflects only this run") {
		t.Errorf("the merge notice must not claim the manifest reflects only this run; got:\n%s", out)
	}

	// A first run has nothing to widen, so it keeps the line that sends the user back
	// with other inputs.
	var first strings.Builder
	writeMergeNotice(&first, path, mergeOutcome{})
	if !strings.Contains(first.String(), "reflects only this run") {
		t.Errorf("a first run must keep its own closing line; got:\n%s", first.String())
	}
}

// A generated manifest must be the same artifact a hand-written one is. Profiling
// observes host paths, so emitting them verbatim produced a manifest that named one
// machine: a teammate, or CI, or the same directory after a move, got a stat failure,
// and the author's home landed in a tracked file.
func TestRelocatableRewritesPathsIntoTheManifestsVocabulary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	p := &policy.Policy{
		Entrypoint: filepath.Join(dir, "probe.py"),
		Read:       []string{filepath.Join(home, ".config", "app"), dir, "/etc/hosts"},
		Write:      []string{filepath.Join(dir, "out")},
	}
	got := relocatable(p, filepath.Join(dir, "m.yaml"))

	if got.Entrypoint != "./probe.py" {
		t.Errorf("entrypoint = %q, want ./probe.py", got.Entrypoint)
	}
	// The manifest directory wins over home for a path under both - manifests usually
	// live under home, and ~-anchoring them leaves the artifact just as unshareable.
	if want := []string{"~/.config/app", ".", "/etc/hosts"}; !slices.Equal(got.Read, want) {
		t.Errorf("read = %v, want %v", got.Read, want)
	}
	if want := []string{"./out"}; !slices.Equal(got.Write, want) {
		t.Errorf("write = %v, want %v", got.Write, want)
	}
	// The rewrite must be lossless: what run enforces has to be what profiling saw.
	back := *got
	back.Read, back.Write = slices.Clone(got.Read), slices.Clone(got.Write)
	if err := manifest.Resolve(&back, filepath.Join(dir, "m.yaml")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if back.Entrypoint != p.Entrypoint || !slices.Equal(back.Read, p.Read) || !slices.Equal(back.Write, p.Write) {
		t.Errorf("resolving the rewrite must return the observed paths; got %+v, want %+v", back, p)
	}
}

// A sibling of the anchor is not under it. A prefix test reads /home/alice-backup as
// living inside /home/alice and would emit a ../ path, which is less relocatable than
// the absolute one it replaced.
func TestRelocatableLeavesAPathOutsideBothAnchorsAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	sibling := dir + "-backup"
	p := &policy.Policy{Entrypoint: filepath.Join(dir, "x"), Read: []string{sibling, home + "-backup"}}
	got := relocatable(p, filepath.Join(dir, "m.yaml"))
	if want := []string{sibling, home + "-backup"}; !slices.Equal(got.Read, want) {
		t.Errorf("read = %v, want the absolute paths untouched (%v)", got.Read, want)
	}
}

// A path-shaped interpreter names a machine exactly as an entrypoint does, and a
// re-profile resolves an existing manifest's to an absolute path before the merge - so
// leaving the field out of the rewrite de-relativized a manifest that already had it
// right. A bare name means "the host's python3" and must survive untouched.
func TestRelocatableRewritesOnlyAPathShapedInterpreter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	m := filepath.Join(dir, "m.yaml")

	got := relocatable(&policy.Policy{
		Entrypoint:  filepath.Join(dir, "x.py"),
		Interpreter: filepath.Join(dir, "venv", "bin", "python"),
	}, m)
	if got.Interpreter != "./venv/bin/python" {
		t.Errorf("interpreter = %q, want ./venv/bin/python", got.Interpreter)
	}

	bare := relocatable(&policy.Policy{Entrypoint: filepath.Join(dir, "x.py"), Interpreter: "python3"}, m)
	if bare.Interpreter != "python3" {
		t.Errorf("interpreter = %q, want the bare name untouched", bare.Interpreter)
	}
}

// The rewrite changes spelling, not policy, so it must never produce a manifest Marshal's
// own gate refuses - that would end a whole granting session over a spelling the user
// never wrote. `write: /home/you` passes validation; `write: ~` is refused outright.
func TestRelocatableKeepsTheAbsoluteFormWhenTheRewriteWouldNotValidate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	p := &policy.Policy{Entrypoint: filepath.Join(dir, "x"), Write: []string{home}}
	got := relocatable(p, filepath.Join(dir, "m.yaml"))
	if !slices.Equal(got.Write, []string{home}) {
		t.Errorf("write = %v, want the absolute home grant kept", got.Write)
	}
	if _, err := manifest.Marshal(got, manifest.Provenance{}); err != nil {
		t.Errorf("what relocatable returns must always marshal; got %v", err)
	}
}

// A $HOME of "/" - a system account, a minimal container - is under every absolute path,
// so home-anchoring there would write the whole policy as ~/-relative and land it
// somewhere else entirely on a host whose home is a real directory.
func TestRelocatableIgnoresARootHome(t *testing.T) {
	t.Setenv("HOME", "/")
	dir := t.TempDir()

	got := relocatable(&policy.Policy{Entrypoint: filepath.Join(dir, "x"), Read: []string{"/etc/hosts"}}, filepath.Join(dir, "m.yaml"))
	if !slices.Equal(got.Read, []string{"/etc/hosts"}) {
		t.Errorf("read = %v, want /etc/hosts left absolute", got.Read)
	}
}

// The host shortfall profiling refuses on is the one doctor gates its exit code on, and
// it is worded for the command the user actually invoked - a profiling session told it
// is "refusing to run" sends the reader looking for a manifest they never named.
func TestProfileRefusalNamesProfiling(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Unavailable, "bubblewrap (bwrap) is not installed")
	if len(gatedShortfall(report)) == 0 {
		t.Fatal("a filesystem shortfall must gate, or profile has nothing to refuse on")
	}

	var out bytes.Buffer
	writeRefusal(&out, "refusing to profile", &enforce.Refusal{
		Report: report, Reason: "a core guarantee cannot be fully enforced on this host", Short: gatedShortfall(report),
	})
	got := out.String()
	if !strings.HasPrefix(got, "bento: refusing to profile: ") {
		t.Errorf("refusal = %q, want it to say what is being refused", got)
	}
	if !strings.Contains(got, "bwrap") {
		t.Errorf("refusal = %q, want the layer reason bento authored rather than bwrap's own stderr", got)
	}
}

// A proposed write directory that is missing from the host but sits inside the tree
// profiling already granted write to is one an enforced run would create, so the
// single pass retries with it created rather than reporting a correct proposal as
// unfinished. A proposal outside that tree is a path the target chose: profiling does
// not create host directories on its say-so.
func TestMissingGrantedWriteDirs(t *testing.T) {
	tree := t.TempDir()
	existing := filepath.Join(tree, "have")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "guessed")

	got := missingGrantedWriteDirs([]string{tree}, []string{existing, filepath.Join(tree, "out"), elsewhere, tree})
	want := []string{filepath.Join(tree, "out")}
	if !slices.Equal(got, want) {
		t.Errorf("missingGrantedWriteDirs = %v, want %v", got, want)
	}
}

// The retry re-runs the target, and the trigger - an unfinished round plus a missing
// write dir - does not establish that the missing directory is why the round ended. A
// target that failed for its own reasons gets a second run it did not ask for, and under
// --allow-network that second run repeats real egress with nothing out here to consent
// to it. So the dirs are still named (the proposal carries them either way) and the pass
// is refused.
func TestRetryWriteDirsStopsAtForwardedEgress(t *testing.T) {
	tree := t.TempDir()
	missing := filepath.Join(tree, "out")
	unfinished := roundStatus{unfinished: "did not finish"}

	dirs, mayRun := retryWriteDirs(unfinished, false, []string{tree}, []string{missing})
	if !slices.Equal(dirs, []string{missing}) || !mayRun {
		t.Errorf("without forwarded egress = (%v, %v), want (%v, true)", dirs, mayRun, []string{missing})
	}

	dirs, mayRun = retryWriteDirs(unfinished, true, []string{tree}, []string{missing})
	if !slices.Equal(dirs, []string{missing}) || mayRun {
		t.Errorf("under --allow-network = (%v, %v), want (%v, false)", dirs, mayRun, []string{missing})
	}

	if dirs, _ := retryWriteDirs(roundStatus{}, false, []string{tree}, []string{missing}); len(dirs) > 0 {
		t.Errorf("a finished round has nothing to retry; got %v", dirs)
	}
}

// A grant on the whole directory the script runs from is the broadest one profiling
// still proposes - isBroadDir drops the rest - and the reviewer is told so. A grant on
// a subdirectory or a sibling is not the working directory and stays quiet.
func TestPrintWorkdirGrantsNamesTheWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "s.py")

	var out bytes.Buffer
	printWorkdirGrants(&out, &policy.Policy{Read: []string{dir}, Write: []string{filepath.Join(dir, "out")}}, script)
	got := out.String()
	if !strings.Contains(got, "grants read "+strconv.Quote(dir)) {
		t.Errorf("output = %q, want the whole-workdir read called out", got)
	}
	if strings.Contains(got, "grants write") {
		t.Errorf("output = %q, want a subdirectory write left unremarked", got)
	}

	out.Reset()
	printWorkdirGrants(&out, &policy.Policy{Read: []string{filepath.Join(dir, "data")}}, script)
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing for a grant that is not the working directory", out.String())
	}
}

// The --json envelope carries what the exit code cannot: the policy as the manifest
// spells it, why the proposal cannot be vouched for, the accesses profiling declined,
// the grants it wants reviewed, and which half of a widened manifest came from the file.
func TestProfileResultJSON(t *testing.T) {
	written := &policy.Policy{
		Entrypoint: "./s.py", Interpreter: "python3", Read: []string{"./data"},
		Exec: policy.ExecNone, Env: []string{"HOME"},
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}},
	}
	status := roundStatus{
		withheld: []accessNoteJSON{{Kind: "read", Path: "/home/u/.ssh", Reason: "read-shielded", Holds: "credentials"}},
		flagged:  []accessNoteJSON{{Kind: "read", Path: "/work", Reason: "whole-workdir"}},
	}
	merge := mergeOutcome{widened: true, keptRead: []string{"./old"}, approvalVoided: true}
	doc := manifest.Provenance{BlockedHosts: []string{"metadata.internal:80"}}

	proposed := &policy.Policy{
		Entrypoint: "/work/s.py", Interpreter: "python3", Read: []string{"/work/data"},
		Exec: policy.ExecNone, Env: []string{"HOME"},
		Network: []policy.NetworkRule{{Host: "example.com", Port: "443"}},
	}

	env := profileResultJSON("s.py.manifest.yaml", proposed, written, doc, status, merge, "the profiled run did not finish")

	if env.Complete || env.IncompleteReason == "" {
		t.Errorf("complete=%v reason=%q, want an incomplete result that says why", env.Complete, env.IncompleteReason)
	}
	if env.Policy.Exec != "none" || !slices.Equal(env.Policy.Read, []string{"./data"}) {
		t.Errorf("policy = %+v, want the manifest's own spelling", env.Policy)
	}
	if !slices.Equal(env.Policy.Network, []string{"example.com:443"}) {
		t.Errorf("network = %+v, want the proposed rule", env.Policy.Network)
	}
	if !slices.Equal(env.BlockedHosts, doc.BlockedHosts) {
		t.Errorf("blocked_hosts = %v, want the provenance record %v", env.BlockedHosts, doc.BlockedHosts)
	}
	if !slices.Equal(env.Withheld, status.withheld) {
		t.Errorf("withheld = %+v, want the host paths profiling declined", env.Withheld)
	}
	if env.Merged == nil || !slices.Equal(env.Merged.KeptRead, []string{"./old"}) || !env.Merged.ApprovalVoided {
		t.Errorf("merged = %+v, want the grants kept from the file and the voided approval", env.Merged)
	}

	// No manifest to widen: the consumer is told nothing came from a file, rather than
	// reading an empty merge block as "merged, and it kept nothing".
	if got := profileResultJSON("m.yaml", proposed, written, doc, roundStatus{}, mergeOutcome{}, ""); got.Merged != nil || !got.Complete {
		t.Errorf("first-run envelope = %+v, want complete and unmerged", got)
	}
}

// A profiling refusal answers --json with the envelope every refusal uses, carrying the
// probe that judged the host - so a harness reading stdout alone sees which layer fell
// short instead of an empty stream it cannot tell from a crash.
func TestProfileRefusalJSONCarriesTheReport(t *testing.T) {
	var report enforce.Report
	report.Add(enforce.LayerFilesystem, enforce.Unavailable, "bubblewrap (bwrap) is not installed")
	refusal := &enforce.Refusal{Report: report, Reason: "a core guarantee cannot be fully enforced on this host", Short: gatedShortfall(report)}

	var stdout bytes.Buffer
	err := refuseJSON(&stdout, true, refusal)

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != bentoFailed {
		t.Fatalf("refusal = %v, want exitError{%d}", err, bentoFailed)
	}
	var env refusalJSON
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("refusal envelope is not valid JSON: %v\n%s", err, stdout.String())
	}
	if !env.Refused || env.Reason != refusal.Reason {
		t.Errorf("envelope = %+v, want refused=true with the refusal's own reason", env)
	}
	if len(env.Report.Layers) == 0 {
		t.Error("the envelope must carry the report, or a consumer cannot see which layer fell short")
	}
}

// A flagged note points at a grant the manifest holds, so it carries the manifest's own
// spelling: a consumer told to review a grant must be able to find it in the policy
// beside it. A withheld note is not a grant and keeps the host path profiling saw.
func TestProfileResultJSONRespellsFlaggedGrants(t *testing.T) {
	proposed := &policy.Policy{Entrypoint: "/work/s.py", Read: []string{"/work"}, Write: []string{"/tmp/guessed"}}
	written := &policy.Policy{Entrypoint: "./s.py", Read: []string{"."}, Write: []string{"/tmp/guessed"}}
	status := roundStatus{
		flagged: []accessNoteJSON{
			{Kind: "read", Path: "/work", Reason: "whole-workdir"},
			{Kind: "write", Path: "/tmp/guessed", Reason: "target-steerable-tmp"},
		},
		withheld: []accessNoteJSON{{Kind: "read", Path: "/home/u/.ssh", Reason: "read-shielded", Holds: "credentials"}},
	}

	env := profileResultJSON("m.yaml", proposed, written, manifest.Provenance{}, status, mergeOutcome{}, "")

	for _, n := range env.Flagged {
		if !slices.Contains(env.Policy.Read, n.Path) && !slices.Contains(env.Policy.Write, n.Path) {
			t.Errorf("flagged %+v names no grant in the policy %+v", n, env.Policy)
		}
	}
	if env.Withheld[0].Path != "/home/u/.ssh" {
		t.Errorf("withheld = %+v, want the observed host path left alone", env.Withheld[0])
	}
}

// A grant the manifest carries both ways is named both ways: kind says which access a
// note is about, so answering "write" for a path that is also read drops half of it.
func TestGrantKindsNamesBothAccesses(t *testing.T) {
	p := &policy.Policy{Read: []string{"/tmp/w", "/tmp/r"}, Write: []string{"/tmp/w"}}

	if got := grantKinds(p, "/tmp/w", "target-steerable-tmp"); !slices.Equal(got, []accessNoteJSON{
		{Kind: "read", Path: "/tmp/w", Reason: "target-steerable-tmp"},
		{Kind: "write", Path: "/tmp/w", Reason: "target-steerable-tmp"},
	}) {
		t.Errorf("grantKinds = %+v, want both accesses", got)
	}
	if got := grantKinds(p, "/tmp/r", "target-steerable-tmp"); len(got) != 1 || got[0].Kind != "read" {
		t.Errorf("grantKinds = %+v, want the read alone", got)
	}
}

// A dangling symlink is not a missing directory: Stat follows it and reports ENOENT, and
// the mkdir the retry would then make fails EEXIST on the link, turning a session that
// wrote a manifest and exited 4 into one that refuses.
func TestMissingGrantedWriteDirsSkipsADanglingSymlink(t *testing.T) {
	tree := t.TempDir()
	link := filepath.Join(tree, "link")
	if err := os.Symlink(filepath.Join(tree, "nowhere"), link); err != nil {
		t.Fatal(err)
	}

	if got := missingGrantedWriteDirs([]string{tree}, []string{link}); len(got) != 0 {
		t.Errorf("missingGrantedWriteDirs = %v, want the dangling symlink left alone", got)
	}
}

// The full warning's framing - a name made to read as something other than what it grants
// - describes a deception that needs a file behind it. When every open of the path missed,
// nothing was read and no grant of it would have meant anything, so the report says the
// run only probed. A write is judged at its parent directory, whose existence no
// observation names, so it keeps the unqualified text.
func TestUnrepresentableWarningSeparatesProbedFromResolved(t *testing.T) {
	resolved := "/data/re\u202eal.txt"
	probed := "/data/pro\u202ebed.txt"
	var buf bytes.Buffer
	notes := printUnrepresentable(&buf, profile.Observation{
		Reads:  []string{resolved, probed},
		Writes: []string{"/data/wr\u202eite/f.txt"},
		Absent: []string{probed},
	})
	got := buf.String()

	// The same distinction reaches --json, so the prose and the envelope cannot disagree.
	// The write note leaves absent unset rather than answering false: it is judged at its
	// parent directory, which no observation says the existence of.
	found, missing := false, true
	want := []struct {
		path   string
		absent *bool
	}{
		{resolved, &found},
		{probed, &missing},
		{"/data/wr\u202eite", nil},
	}
	if len(notes) != len(want) {
		t.Fatalf("notes = %+v, want one per unrepresentable path", notes)
	}
	for i, w := range want {
		n := notes[i]
		if n.Path != w.path || n.Reason != "unrepresentable" {
			t.Errorf("note %d = %+v, want %q unrepresentable", i, n, w.path)
		}
		switch {
		case w.absent == nil && n.Absent != nil:
			t.Errorf("note %d says absent=%v for a path whose existence is unknown", i, *n.Absent)
		case w.absent != nil && (n.Absent == nil || *n.Absent != *w.absent):
			t.Errorf("note %d absent = %v, want %v", i, n.Absent, *w.absent)
		}
	}
	if !strings.Contains(got, fmt.Sprintf("%q - the name carries a character a manifest path cannot hold (a control, bidi, invisible, or line-separating one, or a byte that is not valid UTF-8), which is how a path", resolved)) {
		t.Errorf("a path that resolved lost the full warning:\n%s", got)
	}
	if !strings.Contains(got, fmt.Sprintf("%q - the name carries", probed)) || !strings.Contains(got, "Nothing was found at that path, so the run only probed for it") {
		t.Errorf("a path nothing was found at did not get the probe wording:\n%s", got)
	}
	// The resolved read and the write keep it; only the probed read loses it.
	if strings.Count(got, "which is how a path is made to read as something other than what it grants") != 2 {
		t.Errorf("the deception framing was applied to a path that was only probed:\n%s", got)
	}
}

// A re-profile runs under the interpreter guessed (or given) now, not the one an older
// manifest names, so the grants it merges in are that interpreter's. Keeping the base's
// interpreter would write a manifest whose enforced run differs from the run the user
// just watched, and the swap has to be reported or it is a silent rewrite of what the
// manifest runs.
func TestMergeTakesTheInterpreterTheRunUsed(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tidy.sh")
	path := filepath.Join(dir, "tidy.sh.manifest.yaml")
	base := &policy.Policy{Entrypoint: script, Interpreter: "bash", Read: []string{filepath.Join(dir, "prior")}}
	// Approved, because that is the case with consequences: the interpreter is part of
	// the fingerprint, so swapping it is exactly what the stamp was meant to catch, and
	// the reviewer has to be told both that the approval is gone and what moved.
	data, err := manifest.Marshal(base, manifest.Provenance{Approves: base.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	merged, err := mergeExisting(path, script, &policy.Policy{Entrypoint: script, Interpreter: "/bin/sh"})
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	if merged.policy.Interpreter != "/bin/sh" {
		t.Errorf("merged interpreter = %q, want /bin/sh (the one this run profiled under)", merged.policy.Interpreter)
	}
	var b strings.Builder
	writeMergeNotice(&b, path, merged)
	for _, want := range []string{`"bash"`, `"/bin/sh"`, "its approval is gone"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the merge notice must report %s; got:\n%s", want, b.String())
		}
	}

	// An agreeing manifest is not a swap, so it draws no notice.
	same, err := mergeExisting(path, script, &policy.Policy{Entrypoint: script, Interpreter: "bash"})
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	if same.interpreterChanged {
		t.Error("no drift must be reported when the run agrees with the manifest")
	}
}

// The arguments are part of the invocation, so `sh -eu` becoming plain `sh` is the
// same silent rewrite of what runs that a changed interpreter is - and the merged
// manifest keeps the run's, not the older file's.
func TestMergeReportsAChangedInterpreterArgs(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tidy.sh")
	path := filepath.Join(dir, "tidy.sh.manifest.yaml")
	base := &policy.Policy{Entrypoint: script, Interpreter: "/bin/sh", InterpreterArgs: []string{"-eu"}}
	data, err := manifest.Marshal(base, manifest.Provenance{Approves: base.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	merged, err := mergeExisting(path, script, &policy.Policy{Entrypoint: script, Interpreter: "/bin/sh"})
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	if len(merged.policy.InterpreterArgs) != 0 {
		t.Errorf("merged interpreter_args = %q, want the run's (none)", merged.policy.InterpreterArgs)
	}
	var b strings.Builder
	writeMergeNotice(&b, path, merged)
	if !strings.Contains(b.String(), `"-eu"`) {
		t.Errorf("the merge notice must name the arguments the manifest used to carry; got:\n%s", b.String())
	}

	same, err := mergeExisting(path, script, base)
	if err != nil {
		t.Fatalf("mergeExisting: %v", err)
	}
	if same.interpreterChanged {
		t.Error("no drift must be reported when the run agrees with the manifest")
	}
	// Carried raw, not rendered: the --json envelope publishes these values, and
	// quoting them here would ship a consumer `"\"/bin/sh\""`.
	if merged.interpreterWas != "/bin/sh" || !slices.Equal(merged.interpreterArgsWas, []string{"-eu"}) {
		t.Errorf("the drift fields must carry the manifest's own values unquoted; got %q %q",
			merged.interpreterWas, merged.interpreterArgsWas)
	}
}

// The --allow-network consent gate. It forwards the target's egress while the content
// the user granted is mounted with real data, so an answer that is not an explicit yes
// must abort - a near-miss must not be read as consent to that.
func TestConfirmNetworkExfil(t *testing.T) {
	for _, tc := range []struct {
		answer   string
		proceeds bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"YES\n", true},
		{"  y  \n", true},
		{"n\n", false},
		{"no\n", false},
		{"\n", false},    // the default the prompt advertises with [y/N]
		{"", false},      // a closed stream, no newline
		{"y", true},      // a stream ending mid-line is still a complete answer
		{"yep\n", false}, // close enough to yes to be worth pinning
		{"ye\n", false},
		{"1\n", false},
	} {
		t.Run(strconv.Quote(tc.answer), func(t *testing.T) {
			var buf strings.Builder
			err := confirmNetworkExfil(t.Context(), ttyLines(strings.NewReader(tc.answer)), &buf)
			if proceeded := err == nil; proceeded != tc.proceeds {
				t.Errorf("answer %q proceeded = %v, want %v (err %v)", tc.answer, proceeded, tc.proceeds, err)
			}
			if !strings.Contains(buf.String(), "[y/N]") {
				t.Errorf("the prompt must state the default; got %q", buf.String())
			}
			// The warning is the reason the gate exists: an answer given without it is
			// not informed consent.
			if !strings.Contains(buf.String(), "exfiltrate") {
				t.Errorf("the prompt must state what is at risk; got %q", buf.String())
			}
		})
	}
}

// The DenyAll clamp must match a symlinked store by its TARGET too, for the reason its
// DenyWrite sibling does: a ~/.gnupg symlinked into a dotfiles checkout is observed at
// the target, and checkReadNotShielded resolves the rule before comparing. Keeping the
// grant drafts a manifest bento hard-refuses, and the only remedy that refusal offers -
// a read of the shielding directory itself - exposes the whole store, so the proposal
// would steer the reviewer to a broader grant than the program ever needed.
func TestClampShieldMatchesSymlinkedStoreTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store := filepath.Join(t.TempDir(), "dotfiles", "gnupg")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, filepath.Join(home, ".gnupg")); err != nil {
		t.Skipf("cannot symlink on this filesystem: %v", err)
	}
	resolvedStore, err := filepath.EvalSymlinks(store)
	if err != nil {
		t.Fatal(err)
	}

	grant := filepath.Join(resolvedStore, "pubring.kbx")
	kept, _, dropped, _ := clampShieldedGrants(hostShieldSet(t), []string{grant}, nil)
	if slices.Contains(kept, grant) {
		t.Errorf("a read observed at the symlinked store's target must be dropped, not proposed for a manifest compile will refuse; kept=%v", kept)
	}
	if len(dropped) != 1 || dropped[0].Holds != denylist.HoldsCredentials {
		t.Errorf("the drop must name what the store holds so the warning is specific; got %+v", dropped)
	}
}

// The same symlinked shield, but pointing at a store the host has not created yet - a
// dotfiles tree checked out lazily, or a nix profile link before its first activation.
// EvalSymlinks fails outright on that, which left the clamp shielding only the literal
// path while the gate and the backend (both pathresolve-backed) shielded the target, so
// the proposal kept a write the run then hard-refused.
func TestClampWriteShieldMatchesDanglingShieldTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store := filepath.Join(t.TempDir(), "dotfiles", "bin")
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, filepath.Join(home, ".local", "bin")); err != nil {
		t.Skipf("cannot symlink on this filesystem: %v", err)
	}

	grant := filepath.Join(pathresolve.Existing(store), "mytool")
	_, kept, _, dropped := clampShieldedGrants(hostShieldSet(t), nil, []string{grant})
	if slices.Contains(kept, grant) {
		t.Errorf("a write at a dangling shield's target must be dropped, not proposed for a manifest compile will refuse; kept=%v", kept)
	}
	if len(dropped) == 0 {
		t.Errorf("the write must be reported as write-shielded so the user is told why; dropped=%v", dropped)
	}
}

// A home reached through a symlink whose target does not exist yet - a container image
// that mounts the account later, or a home-manager profile before its first activation -
// is still the profiler's OWN home, and a grant under it must not be reported as
// belonging to somebody else's account. EvalSymlinks fails outright on that and made the
// anchor unrecognizable; the shields and the clamp both resolve it the way a write
// through it would land, and this has to agree with them or the reviewer is warned about
// their own credential store.
func TestForeignHomeShieldsResolvesDanglingAnchor(t *testing.T) {
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink("/home/ghostuser", link); err != nil {
		t.Skipf("cannot symlink on this filesystem: %v", err)
	}
	t.Setenv("HOME", link)

	own := "/home/ghostuser/.ssh"
	if warned := foreignHomeShields([]string{own}); len(warned) != 0 {
		t.Errorf("%q is the profiler's own home reached through a dangling link and must not be warned about as foreign; got %v", own, warned)
	}
}
