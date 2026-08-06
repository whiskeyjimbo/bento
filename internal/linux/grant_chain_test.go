//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/policy"
)

// The grant chain walk - checkGrantNotLooped's ELOOP probe and missingHop's
// os.Readlink following - runs against the real filesystem on purpose (see the
// comments on both), so the fake testSandbox cannot express a looped grant or a
// multi-hop chain at all. These drive both against real symlink trees, in-process
// and without bwrap, so the cases are pinned even where the sandbox integration
// tests are skipped for want of a usable kernel.

func TestCheckGrantNotLoopedRealFilesystem(t *testing.T) {
	d := canonTempDir(t)
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	mustLink(t, b, a)
	mustLink(t, a, b)
	mustLink(t, filepath.Join(d, "missing"), filepath.Join(d, "dangle"))

	for _, tc := range []struct {
		name    string
		p       *policy.Policy
		refused bool
	}{
		{"read loop", &policy.Policy{Read: []string{a}}, true},
		{"write loop", &policy.Policy{Write: []string{a}}, true},
		// The loop sits in a parent component, not the granted leaf: a check that
		// only followed the leaf's own link would let this through.
		{"loop in a parent component", &policy.Policy{Read: []string{filepath.Join(a, "x")}}, true},
		// A dangling symlink resolves to a target that does not exist yet, which is
		// supported - only a loop names nothing bindable.
		{"dangling leaf", &policy.Policy{Read: []string{filepath.Join(d, "dangle")}}, false},
		{"plain directory", &policy.Policy{Read: []string{d}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkGrantNotLooped(tc.p)
			if !tc.refused {
				if err != nil {
					t.Fatalf("checkGrantNotLooped: %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a looping grant was accepted")
			}
			if !strings.Contains(err.Error(), "loops through itself") {
				t.Errorf("error does not name the loop: %v", err)
			}
		})
	}
}

// A read and a write grant that loop are found at different points in the run, so
// the refusal must read the same either way.
func TestLoopedGrantErrorAgreesAcrossReadAndWrite(t *testing.T) {
	d := canonTempDir(t)
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	mustLink(t, b, a)
	mustLink(t, a, b)

	read := checkGrantNotLooped(&policy.Policy{Read: []string{a}})
	write := checkGrantNotLooped(&policy.Policy{Write: []string{a}})
	if read == nil || write == nil {
		t.Fatalf("a looping grant was accepted: read=%v write=%v", read, write)
	}
	if read.Error() != write.Error() {
		t.Errorf("read and write disagree:\n read: %v\nwrite: %v", read, write)
	}
}

// A granted symlink whose name a broader read grant already fills points, on the
// host, at a MID link that nothing else fills - so the chain breaks in the middle
// unless missingHop follows the filled name and recreates the mid name instead.
func TestGrantSymlinksMultiHopRealFilesystem(t *testing.T) {
	root := canonTempDir(t)
	other, elsewhere := filepath.Join(root, "other"), filepath.Join(root, "elsewhere")
	for _, d := range []string{other, elsewhere} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(elsewhere, "mid")
	mustLink(t, target, mid)
	head := filepath.Join(other, "head")
	mustLink(t, mid, head)

	sb := sandbox{
		homes:      []string{root},
		entrypoint: filepath.Join(root, "probe.sh"),
		exists:     hostExists,
		isDir:      hostIsDir,
		listDir:    hostListDir,
		resolve:    hostResolve,
		rootDirs:   hostRootDirs,
	}
	p := &policy.Policy{Read: []string{other, head}}
	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		t.Fatalf("resolveGrants: %v", err)
	}
	args, err := grantSymlinks(sb, p, reads, writes, nil)
	if err != nil {
		t.Fatalf("grantSymlinks: %v", err)
	}

	want := []string{"--symlink", target, mid}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("grantSymlinks = %q, want %q (the broken mid hop must be recreated, pointed at the bound target)", args, want)
	}
}

// The same tree with the mid hop already inside a grant needs no link at all: the
// bind carries the host's own entry there, and recreating it would abort bwrap.
func TestGrantSymlinksSkipsChainAlreadyMounted(t *testing.T) {
	root := canonTempDir(t)
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(other, "mid")
	mustLink(t, target, mid)
	head := filepath.Join(other, "head")
	mustLink(t, mid, head)

	sb := sandbox{
		homes:      []string{root},
		entrypoint: filepath.Join(root, "probe.sh"),
		exists:     hostExists,
		isDir:      hostIsDir,
		listDir:    hostListDir,
		resolve:    hostResolve,
		rootDirs:   hostRootDirs,
	}
	p := &policy.Policy{Read: []string{other, head}}
	reads, writes, err := resolveGrants(sb, p)
	if err != nil {
		t.Fatalf("resolveGrants: %v", err)
	}
	args, err := grantSymlinks(sb, p, reads, writes, nil)
	if err != nil {
		t.Fatalf("grantSymlinks: %v", err)
	}
	if len(args) != 0 {
		t.Fatalf("grantSymlinks = %q, want none: every hop is already inside a bound grant", args)
	}
}

// missingHop treated every os.Readlink failure as "filled and not a symlink" and
// returned "", silently dropping the --symlink and leaving the granted name absent in
// the sandbox with nothing reporting why. Only EINVAL means "not a symlink"; every other
// errno says nothing about whether the name needs recreating, so it propagates.
func TestMissingHopReadlinkErrorIsNotSwallowed(t *testing.T) {
	root := t.TempDir()
	// A component past NAME_MAX: readlink fails with ENAMETOOLONG, which is neither a
	// missing name nor a settled "not a symlink".
	abs := filepath.Join(root, strings.Repeat("n", 300))

	sb := sandbox{resolve: hostResolve}
	hop, err := missingHop(sb, abs, filepath.Join(root, "target"), []string{root})
	if err == nil {
		t.Fatalf("a readlink error other than EINVAL must propagate, not resolve to no hop; got hop=%q", hop)
	}
	if !strings.Contains(err.Error(), abs) {
		t.Errorf("the error must name the path it could not read; got %v", err)
	}

	// A real name that is simply not a symlink still settles as no hop.
	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if hop, err := missingHop(sb, plain, filepath.Join(root, "target"), []string{root}); err != nil || hop != "" {
		t.Errorf("a filled non-symlink must settle as no hop; got hop=%q err=%v", hop, err)
	}
}
