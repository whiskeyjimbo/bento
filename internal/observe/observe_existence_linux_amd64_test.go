package observe

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A path the target only stats, accesses, or readlinks - never opens - must land in the
// manifest as a read, because under enforcement an ungranted path is absent rather than
// unreadable and the stat that succeeded during profiling returns ENOENT on the enforced
// run. The mirror requirement is that a probe which already MISSED is not recorded: a
// shell's PATH search misses hundreds of times per command, and carrying those into the
// proposal would bury the paths the run needs.
func TestTraceRecordsSuccessfulExistenceProbes(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	statted := filepath.Join(dir, "config.toml")
	linked := filepath.Join(dir, "link")
	if err := os.WriteFile(statted, []byte("k = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(statted, linked); err != nil {
		t.Fatal(err)
	}
	accessed := statted
	missing := filepath.Join(dir, "absent.toml")

	script := fmt.Sprintf(`
import os
os.stat(%q)
os.access(%q, os.R_OK)
os.readlink(%q)
try:
    os.stat(%q)
except FileNotFoundError:
    pass
`, statted, accessed, linked, missing)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	for _, path := range []string{statted, linked} {
		if a, ok := find(res, path); !ok {
			t.Errorf("no access recorded for the probed path %q; accesses: %v", path, res.Accesses)
		} else if a.Write {
			t.Errorf("existence probe of %q recorded as a write, want a read", path)
		}
	}
	if _, ok := find(res, missing); ok {
		t.Errorf("a probe that returned ENOENT was recorded: %q", missing)
	}
}

// Both decoders can name the same path, and a consumer that wants to tell an access the
// program reached for from one the kernel resolved on its behalf needs to know which. A
// directory that is only stat'ed is probe-only; the same directory listed - a readdir
// opens it first - is not, and neither is one that is stat'ed and then opened.
func TestTraceMarksPathsNothingEverOpened(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	statted := filepath.Join(dir, "statted")
	listed := filepath.Join(dir, "listed")
	for _, d := range []string{statted, listed} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	script := fmt.Sprintf(`
import os
os.stat(%q)
os.stat(%q)
os.listdir(%q)
`, statted, listed, listed)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	a, ok := find(res, statted)
	if !ok {
		t.Fatalf("no access recorded for %q; accesses: %v", statted, res.Accesses)
	}
	if !a.Probed {
		t.Errorf("a directory nothing opened is not marked probe-only: %+v", a)
	}
	a, ok = find(res, listed)
	if !ok {
		t.Fatalf("no access recorded for %q; accesses: %v", listed, res.Accesses)
	}
	if a.Probed {
		t.Errorf("a directory the target listed is marked probe-only: %+v", a)
	}
}

// chdir is decoded at the entry stop, unlike the other existence syscalls, because it
// moves the directory resolveAt reads back out of /proc. A relative chdir must therefore
// be anchored at the directory the process was in BEFORE the call, not after it - the
// exit stop would name dir/sub/sub.
func TestTraceAnchorsRelativeChdirBeforeTheMove(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("import os\nos.chdir(%q)\nos.chdir('sub')\n", dir)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	if _, ok := find(res, sub); !ok {
		t.Errorf("relative chdir not anchored at %q; accesses: %v", sub, res.Accesses)
	}
	if _, ok := find(res, filepath.Join(sub, "sub")); ok {
		t.Errorf("relative chdir anchored at the post-move directory: %q", filepath.Join(sub, "sub"))
	}
}

// A failed open is still recorded - the program meant to open that file, and enforcement
// has to reproduce the same answer - but a path nothing was ever found at needs to be
// distinguishable from one that resolved, so a reporting layer can tell a search miss
// from a file the run read. The probe-then-create case is the one that decides the key:
// the two opens differ in their write bit, and letting each carry its own answer would
// report a file the run created as absent.
func TestTraceMarksPathsNothingWasFoundAt(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	if os.Geteuid() == 0 {
		t.Skip("root opens an unreadable file, so the EACCES case cannot be produced")
	}
	dir := t.TempDir()
	present := filepath.Join(dir, "there.toml")
	missing := filepath.Join(dir, "gone.toml")
	created := filepath.Join(dir, "made.toml")
	unreadable := filepath.Join(dir, "locked.toml")
	if err := os.WriteFile(present, []byte("k = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unreadable, []byte("k = 1\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf(`
import os
open(%q).close()
try:
    open(%q).close()
except FileNotFoundError:
    pass
try:
    open(%q).close()
except FileNotFoundError:
    pass
open(%q, "w").close()
try:
    open(%q).close()
except PermissionError:
    pass
`, present, missing, created, created, unreadable)

	res, err := Trace([]string{py, "-c", script}, os.Environ(), nil, nil, nil)
	if err != nil {
		t.Fatalf("Trace: %v", err)
	}
	// unreadable is here for the errno the answer turns on: it exists, and an open of it
	// fails with EACCES rather than ENOENT, so nothing was found is the wrong reading.
	for _, path := range []string{present, created, unreadable} {
		for _, a := range res.Accesses {
			if a.Path == path && a.Absent {
				t.Errorf("%q exists but is marked absent (write=%v)", path, a.Write)
			}
		}
	}
	a, ok := find(res, missing)
	if !ok {
		t.Fatalf("a failed open was not recorded: %q; accesses: %v", missing, res.Accesses)
	}
	if !a.Absent {
		t.Errorf("open of %q returned ENOENT and was not marked absent", missing)
	}
}

// negErrno is the exit stop's rax for a syscall that failed with errno: the kernel returns
// the negated value, and the sign has to survive the trip through the unsigned register.
func negErrno(errno syscall.Errno) uint64 {
	return uint64(-int64(errno))
}

// ENOTDIR and ENOENT both mean the probed path is not there, and only one of them survives
// enforcement. ENOTDIR is the kernel reporting a component that exists and is not a
// directory, so an unbound sandbox answers the probe ENOENT instead - a different branch in
// a target that tells the two apart, off a manifest that reported nothing missing.
//
// It is counted rather than recorded because the file that makes the difference is a
// component of the pathname and not the pathname itself, and which component is not
// knowable from the errno. An answer the decoder cannot give has to reach Dropped, or the
// manifest reads complete.
func TestHeldProbeCountsENOTDIRRatherThanSkippingIt(t *testing.T) {
	const probed = "/etc/passwd/x"
	regs := syscall.PtraceRegs{Orig_rax: unix.SYS_STAT, Rip: 0x1000, Rax: negErrno(syscall.ENOTDIR)}
	held := map[string]heldPath{stopKey(1, &regs): {path: probed, readOK: true}}

	var recorded []string
	dropped := 0
	recordHeldExistence(1, &regs,
		func(p string, _ bool) { recorded = append(recorded, p) },
		func(string, bool) {},
		func() { dropped++ }, held)

	if len(recorded) != 0 {
		t.Errorf("recorded %q, which the sandbox cannot bind - the path has a regular file as a component", recorded)
	}
	if dropped != 1 {
		t.Errorf("counted %d drops for an ENOTDIR probe, want 1: enforcement answers this one ENOENT, and nothing else says so", dropped)
	}
	if len(held) != 0 {
		t.Errorf("the held entry survived, and its key is one the next call at this site rebuilds: %v", held)
	}
}

// ENOMEM belongs with the restart errnos below: the kernel gave up before it resolved
// anything, so it says nothing about the path either way and must not widen the manifest.
//
// EINVAL looks like the same shape - statx with a bad mask and faccessat2 with bad flags
// are both refused before the walk - but it is pinned as RECORDED, because it is not always
// pre-resolution: readlink answers EINVAL for a file that is very much there and simply is
// not a symlink. Skipping it would drop a real access, which is the more expensive of the
// two mistakes; recording the pre-resolution cases costs one extra bind.
func TestHeldProbeSkipsENOMEMButNotEINVAL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		errno  syscall.Errno
		record bool
	}{
		{"ENOMEM", syscall.ENOMEM, false},
		{"EINVAL", syscall.EINVAL, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const probed = "/etc/hosts"
			regs := syscall.PtraceRegs{Orig_rax: unix.SYS_READLINK, Rip: 0x1000, Rax: negErrno(tc.errno)}
			held := map[string]heldPath{stopKey(1, &regs): {path: probed, readOK: true}}

			var recorded []string
			dropped := 0
			recordHeldExistence(1, &regs,
				func(p string, _ bool) { recorded = append(recorded, p) },
				func(string, bool) {},
				func() { dropped++ }, held)

			if got := len(recorded) == 1; got != tc.record {
				t.Errorf("recorded %q for a probe that failed %v, want recorded = %v", recorded, tc.errno, tc.record)
			}
			if dropped != 0 {
				t.Errorf("counted %d drops for a probe whose answer the decoder read fine", dropped)
			}
		})
	}
}

// The success filter turns on the errno, and the errnos a TRACER sees are not the ones a
// program sees. A probe interrupted mid-call returns one of the kernel's restart signals,
// which the signal machinery rewrites before userspace reads it - but the syscall-exit stop
// comes first, so this decoder gets the raw value. None of them says anything about the
// path, and each is about to be re-issued and answered properly at a stop of its own.
// Recorded as a real refusal instead, they widen the manifest with the PATH-search noise
// the filter exists to keep out, and mark it present because the path never missed; counted
// as drops, they tell the user the manifest is short when it is not.
//
// Driven directly rather than through a tracee: reproducing it live needs a probe that
// blocks (a FUSE or NFS mount) and a signal landing inside it, and the errno is the whole
// mechanism.
func TestHeldProbeSkipsTheRestartErrnos(t *testing.T) {
	for _, tc := range []struct {
		name string
		ret  int64
	}{
		{"ERESTARTSYS", -512},
		{"ERESTARTNOINTR", -513},
		{"ERESTARTNOHAND", -514},
		{"ERESTART_RESTARTBLOCK", -516},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const probed = "/etc/hosts"
			regs := syscall.PtraceRegs{Orig_rax: unix.SYS_STAT, Rip: 0x1000, Rax: uint64(tc.ret)}
			held := map[string]heldPath{stopKey(1, &regs): {path: probed, readOK: true}}

			var recorded []string
			var answered []bool
			dropped := 0
			recordHeldExistence(1, &regs,
				func(p string, _ bool) { recorded = append(recorded, p) },
				func(_ string, found bool) { answered = append(answered, found) },
				func() { dropped++ }, held)

			if len(recorded) != 0 {
				t.Errorf("recorded %q for a probe the kernel aborted; nothing was learned about the path", recorded)
			}
			if len(answered) != 0 {
				t.Errorf("answered whether %q resolved (%v) off a call that never got that far", probed, answered)
			}
			// Not a lost access either: the interrupted call is re-issued and reports at its
			// own stop, so counting it here would tell the user the manifest is short when it
			// is not.
			if dropped != 0 {
				t.Errorf("counted %d drops for a probe that is about to be re-issued and answered", dropped)
			}
			if len(held) != 0 {
				t.Errorf("the held entry survived, and its key is one the next call at this site rebuilds: %v", held)
			}
		})
	}
}

// Literal EINTR is the one value at that stop the restart argument does not cover: it is
// the call's own terminal answer, not a re-issue, so no later stop carries anything about
// this path. Skipped, the observation lands in neither Accesses nor Dropped - a manifest
// that reports no loss while the enforced run answers ENOENT where the profiling run got a
// real answer, which is the divergence this decoder exists to prevent. It is an observation
// this decoder cannot make, and Dropped is how it says so.
func TestAnInterruptedProbeIsCountedRatherThanSkipped(t *testing.T) {
	const probed = "/etc/hosts"
	ret := -int64(syscall.EINTR) // the raw negative errno the exit stop carries
	regs := syscall.PtraceRegs{Orig_rax: unix.SYS_STAT, Rip: 0x1000, Rax: uint64(ret)}
	held := map[string]heldPath{stopKey(1, &regs): {path: probed, readOK: true}}

	var recorded []string
	dropped := 0
	recordHeldExistence(1, &regs,
		func(p string, _ bool) { recorded = append(recorded, p) },
		func(string, bool) {},
		func() { dropped++ }, held)

	if len(recorded) != 0 {
		t.Errorf("recorded %q off a call that never resolved it", recorded)
	}
	if dropped != 1 {
		t.Errorf("counted %d drops for a probe the kernel aborted for good; the manifest reports no loss", dropped)
	}
	if len(held) != 0 {
		t.Errorf("the held entry survived: %v", held)
	}
}

// An exec's exit stop carries the raw restart pseudo-errnos too - execve returns
// ERESTARTNOINTR when a signal lands during de_thread - and they say nothing about the
// path. Answered as "found", a PATH-search miss would claim its target resolved, and the
// re-issue's real ENOENT could not correct it: resolved beats missed when one path is
// reached both ways, so the manifest would carry a positive false claim about a name
// nothing was ever found at.
func TestARestartedExecDoesNotClaimItsTargetResolved(t *testing.T) {
	const target = "/opt/toolchain/bin/cc"
	for _, ret := range []int64{-int64(errRestartNoIntr), -int64(syscall.EINTR)} {
		regs := syscall.PtraceRegs{Orig_rax: unix.SYS_EXECVE, Rip: 0x2000, Rax: uint64(ret)}
		held := map[string]heldPath{
			stopKey(1, &regs): {path: target, readOK: true, exec: true, complete: true},
		}

		var recorded []string
		var answered []bool
		dropped := 0
		if !releaseHeldExec(1, &regs,
			func(p string, _ bool) { recorded = append(recorded, p) },
			func(_ string, found bool) { answered = append(answered, found) },
			func() { dropped++ }, held) {
			t.Fatalf("errno %d: the held exec was not recognized at its own exit stop", -ret)
		}
		// The access itself still stands: the target meant to run that file whatever the
		// call went on to answer.
		if len(recorded) != 1 || recorded[0] != target {
			t.Errorf("errno %d: recorded %q, want the exec target", -ret, recorded)
		}
		if len(answered) != 0 {
			t.Errorf("errno %d: answered whether %q resolved (%v) off a call that never got that far", -ret, target, answered)
		}
		if dropped != 0 {
			t.Errorf("errno %d: counted %d drops for an exec whose image chain was whole", -ret, dropped)
		}
	}
}

// A syscall that names a path and reaches neither switch must still reach Dropped. The
// silent third outcome - out of Accesses and out of Dropped - is the one direction that
// channel's invariant forbids: the caller reads the run as having touched nothing there
// and synthesizes a manifest that is short with nothing to say so.
//
// chroot stands for the set. It is unprivileged only after an unshare, and this test
// makes no namespace: the call fails EPERM, which changes nothing here, because the
// count is taken at the entry stop like every other decode in this package.
//
// Measured as a delta against the same script without the call rather than against zero,
// so an unrelated drop from the interpreter's own startup cannot decide the result.
func TestTraceCountsAPathSyscallItCannotDecode(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipMissingDep(t, "python3 not available")
	}
	target := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}

	trace := func(body string) Result {
		t.Helper()
		res, err := Trace([]string{py, "-c", body}, os.Environ(), nil, nil, nil)
		if err != nil {
			t.Fatalf("Trace: %v", err)
		}
		return res
	}
	const call = `
try:
    os.chroot(%q)
except OSError:
    pass
`
	base := trace("import os")
	with := trace("import os" + fmt.Sprintf(call, target))

	if got := with.Dropped - base.Dropped; got != 1 {
		t.Errorf("chroot moved Dropped by %d, want 1 (base %d, with the call %d): a path syscall this decoder skips reached neither channel",
			got, base.Dropped, with.Dropped)
	}
	if _, ok := find(with, target); ok {
		t.Errorf("the chroot target %q was recorded as an access; counting it says the observation is short, not what it lost", target)
	}
}
