//go:build linux

package linux

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// checkGrants runs every grant-safety check that must hold before a policy's reads
// and writes are honored, whatever tier enforces them. The full (bwrap) tier and the
// degraded (Landlock-only) tier share it: a grant that names a credential shield, a
// host process, a managed pseudo-filesystem, or a symlink loop is refused the same way
// in both, so --allow-degraded can never accept a manifest the full tier hard-refuses.
// reads and writes are the resolved grants; p carries the unresolved paths the process
// and managed-mount checks re-resolve for their own diagnostics.
func checkGrants(sb sandbox, p *policy.Policy, reads, writes []string) error {
	// First: the shield checks below skip "/" and rely on it being refused already.
	if err := checkWriteNotRoot(writes); err != nil {
		return err
	}
	optInShields := shield.Targets(explicitShieldOptIns(sb, p.Read))
	// Only reads carry the opt-in: a write grant under a shield the policy also reads
	// must stay refused, so it is checked against no opt-ins at all - and refused in a
	// sentence that does not offer the read's remedy.
	if err := checkReadNotShielded(sb, reads, optInShields); err != nil {
		return err
	}
	if err := checkWriteNotShielded(sb, writes); err != nil {
		return err
	}
	// Before checkWriteNotUnderReadOnlyShield, which also consults the workspace shields
	// and compares against their RESOLVED paths: where a symlink redirects one, that
	// check fires on the target and tells the author to remove a grant that is not the
	// problem, while the remedy that works - remove the symlink - is this one's.
	if err := checkWorkspaceShieldNotRedirected(sb, writes); err != nil {
		return err
	}
	if err := checkWriteNotUnderReadOnlyShield(sb, writes); err != nil {
		return err
	}
	if err := checkWriteNotAboveShield(sb, writes); err != nil {
		return err
	}
	if err := checkGrantNotProcess(sb, p); err != nil {
		return err
	}
	if err := checkGrantNotManagedMount(sb, p); err != nil {
		return err
	}
	return checkGrantNotLooped(p)
}

// checkReadNotShielded and checkWriteNotShielded are the two kinds the check below comes
// in. They share every rule and differ only in the sentence they refuse with, because the
// read opt-in InsideShield names is read-only by construction (see explicitShieldOptIns)
// - naming it to the author of a write grant instructs them to add a line that will not
// lift their refusal.
func checkReadNotShielded(sb sandbox, reads, optInShields []string) error {
	return checkNotShielded(sb, shield.Read, reads, optInShields, grantrefusal.InsideShield)
}

func checkWriteNotShielded(sb sandbox, writes []string) error {
	return checkNotShielded(sb, shield.Write, writes, nil, grantrefusal.WriteInsideShield)
}

// checkNotShielded rejects a grant that falls inside a fully-shielded location
// (a DenyAll deny-list directory such as ~/.ssh). Such a grant cannot be honored
// - the shield wins - so silently dropping it would leave the user believing a
// path is available when it is not. A READ grant that *contains* a shield is fine
// and common (read: ~ with ~/.ssh shielded inside it); a WRITE grant that contains
// one is refused separately by checkWriteNotAboveShield, since it would make the
// shield's parent writable.
//
// refuse is the sentence the grant's kind is refused in; the two wrappers above are the
// only callers, so a third kind cannot arrive without choosing one.
func checkNotShielded(sb sandbox, kind shield.Kind, grants, optInShields []string, refuse func(grant, shield string) error) error {
	set := shields(sb)
	for _, g := range grants {
		r, v := set.Contains(g, kind, optInShields, nil)
		switch v {
		case shield.InsideCallerShield:
			// Which sentence depends on whose shield it is: the opt-in InsideShield offers
			// exists only for the built-ins, so pointing a caller-denied grant at it would
			// name an escape that is not there.
			return grantrefusal.InsideCallerShield(g, r.Path)
		case shield.InsideShield:
			return refuse(g, r.Path)
		case shield.FoldedShield:
			// One sentence for both kinds, unlike the two above: the exposure is a read of
			// the store under another spelling, which a read grant reaches on its own, so
			// there is no write-specific remedy to word differently.
			return grantrefusal.FoldedShield(g, r.Path)
		}
	}
	return nil
}

// checkWriteNotUnderReadOnlyShield rejects a write grant at or inside a DenyWrite
// shield (~/.local/bin, ~/.cargo/bin, ~/.rustup, ~/.bashrc, ...). Such a grant never
// reached the host, and refusing says so at the one moment the author can act on it.
//
// It failed three different ways before, which is why the refusal is worth more than any
// of them: where the shield path exists, its ro-bind is emitted after the grant's bind
// and wins, so every write fails EROFS; where it does NOT exist, the shield is a tmpfs,
// so writes SUCCEED into a discarded scratch mount and the script exits zero having
// written nothing - the worst of the three, since nothing fails at all; and in the
// degraded Landlock-only tier there are no binds, so the write landed on the real host
// path. That last one is the reason this sits in checkGrants rather than beside the bind
// logic: both tiers share it, so --allow-degraded cannot accept what the full tier only
// pretended to honor.
//
// There is deliberately no opt-in, unlike the DenyAll shields. That escape is
// READ-only by construction - explicitShieldOptIns takes the policy's reads, and a write
// grant to a shielded store is the key-planting threat the deny-list exists to stop. A
// DenyWrite shield is nothing BUT that write surface: its whole content is readable
// already, so an opt-in could only ever grant the plant. Extending the mechanism here
// would not be symmetry with DenyAll, it would be the case DenyAll's own opt-in refuses.
//
// The consequence is real and intended: `rustup update`, `nvm install`, `npm i -g`,
// `gem install --user-install` and `cargo install` cannot be granted, because each
// mutates the host's $PATH from inside a sandbox. The registry and build caches
// (~/.cargo/registry, ~/.m2, ~/.gradle) are not shielded, so an ordinary build is
// unaffected.
//
// The workspace shields are checked in the INSIDE direction only. They derive from the
// write grants themselves, so refusing a grant that CONTAINS one would refuse every
// project write grant - but a self-derived shield sits strictly under its grant, so that
// direction never matches here and needs no exemption. What does match is a second grant
// spelled at or inside one ("write: /proj" plus "write: /proj/.git/hooks"). Unrefused, it
// is also unhonored: prepareWriteDirs would create the directory and denyArgs would
// ro-bind it after the grant's bind, so every write fails EROFS at runtime while the
// manifest reports the grant as honored - the same silent-neutering this refusal exists
// for.
func checkWriteNotUnderReadOnlyShield(sb sandbox, writes []string) error {
	// No isDir gate, unlike shieldRules. There the gate keeps a shield off a grant that
	// is a plain file; here the grant is only ever the thing being TESTED, and gating it
	// would admit "write: <repo>/.git/hooks" while the directory is still absent, let
	// prepareWriteDirs create it, and refuse on the second pass with the artifact already
	// on the host. checkoutRoot walks up regardless of what the grant itself is.
	var workspace []denylist.Rule
	for _, w := range writes {
		workspace = append(workspace, workspaceShields(sb, w)...)
	}
	set := shields(sb)
	for _, g := range writes {
		if r, v := set.Contains(g, shield.Write, nil, workspace); v == shield.UnderWriteShield {
			return grantrefusal.WriteUnderReadOnlyShield(g, r.Path)
		}
	}
	return nil
}

// checkWorkspaceShieldNotRedirected refuses a write grant whose per-workspace shield
// (a git hooks/config path, an editor-task file) is redirected by a symlinked
// directory component so the emitted shield lands somewhere other than the literal
// name. denyArgs binds each shield at its RESOLVED path, but the tooling on the host
// opens the shield's LITERAL name inside the granted directory; when a symlinked
// component makes the two differ, the shield protects the wrong path while the
// symlink - which lives in the writable grant - stays free for the target to delete
// and replace with a real planted hook/task that runs on the host. This covers both
// a component escaping the grant (.vscode -> /outside) and one redirecting within it
// (.vscode -> ./realvscode); either leaves the literal name unshielded. A shield
// whose path is symlink-free resolves to itself and binds correctly. A .git that is
// a regular file (a linked-worktree gitfile) resolves to its literal path too, so it
// is not refused here - it hits bwrap's existing ENOTDIR abort, unchanged.
//
// checkWriteNotAboveShield handles the always-shields (HOME, runtime); this handles
// the grant-relative workspace shields, which it does not cover.
func checkWorkspaceShieldNotRedirected(sb sandbox, writes []string) error {
	for _, w := range writes {
		if w == "/" || !sb.isDir(w) {
			continue
		}
		for _, r := range workspaceShields(sb, w) {
			if real := sb.resolve(r.Path); real != r.Path {
				return fmt.Errorf("write grant %q shields %q, but a symlinked directory component redirects it to %q, so the shield would protect the wrong path while the symlink stays writable; remove the symlink, or move the checkout out from under the grant", w, r.Path, real)
			}
		}
	}
	return nil
}

// checkWriteNotRoot refuses a write grant of the host root. Unlike a read grant,
// "/" is never expanded for writes: making the entire host root writable would
// defeat the sandbox, and it is never a real grant. It lives here rather than in
// compile's write-grant loop because the degraded tier never compiles an argv - it
// hands the grants to landlock.RestrictDegraded, where a "/" write is host-root
// write with nothing above it.
func checkWriteNotRoot(writes []string) error {
	if slices.Contains(writes, "/") {
		return grantrefusal.WriteIsRoot()
	}
	return nil
}

// checkWriteNotAboveShield refuses a write grant that contains a DenyAll home
// shield (a credential directory such as ~/.ssh). Such a grant binds the shield's
// parent read-write, so a run could create the shield on the host where it did not
// exist (leaving an empty, wrong-permission directory that breaks ssh/gpg), or
// delete and replace a symlinked one - because bwrap cannot mount a shield over a
// symlink and so protects only its target, not the name in the granted directory.
// Read grants are not restricted: they cannot write the parent, and shielding a
// broad read grant is the deny-list's normal use.
func checkWriteNotAboveShield(sb sandbox, writes []string) error {
	set := shields(sb)
	for _, w := range writes {
		if w == "/" {
			continue // rejected with a clearer message by checkWriteNotRoot
		}
		if r, v := set.Contains(w, shield.Write, nil, nil); v == shield.AboveShield {
			return grantrefusal.WriteAboveShield(w, r.Path)
		}
	}
	return nil
}

// checkGrantNotProcess refuses a grant that resolves into a host process's
// directory in procfs. /etc/mtab and /dev/fd are how one is reached by accident:
// they are host symlinks through /proc/self, which resolves here to the pid of
// *this* bento.
//
// The sandbox unshares its pid namespace and mounts a procfs of its own, so a
// host pid means one of two things there, both wrong. Usually the pid is absent -
// bwrap cannot create the mount point and aborts the whole run. But where the
// number happens to exist in the sandbox too (pid 1 is the launcher), the bind
// lands on it and the run reads the *host's* process instead: `read: /proc/1`
// served the host's init. Refusing covers both; grants are reported as written,
// since the resolved pid path is not what anyone typed.
//
// Only a resolved path that exists is refused: the grants bind with --ro-bind-try,
// which skips a source that is not there, so those abort nothing. That is what
// /dev/stdout relies on when it is a pipe rather than a terminal - it resolves to
// a /proc/<pid>/fd/pipe:[...] name that does not exist, and the grant is a no-op
// instead of a run-killer.
func checkGrantNotProcess(sb sandbox, p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		real, err := resolveGrant(sb, g)
		if err != nil {
			return err
		}
		if denylist.IsProcessPath(real) && sb.exists(real) {
			return grantrefusal.GrantIsProcess(g, real)
		}
	}
	return nil
}

// checkGrantNotManagedMount refuses a grant that resolves to a pseudo-filesystem
// baseFlags mounts fresh (/proc, /dev, /tmp). Bound whole, the host's version
// overmounts the sandbox's hardened one - the last mount in argv order wins - so a
// read:/proc grant would serve host /proc/<pid>/environ (routinely API tokens and
// DB passwords) of same-uid host processes, read:/dev the full host device set, and
// a /tmp grant other processes' temp files. A specific path inside one still binds
// fine; only the whole root is refused.
func checkGrantNotManagedMount(sb sandbox, p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		real, err := resolveGrant(sb, g)
		if err != nil {
			return err
		}
		for _, m := range denylist.ManagedMounts {
			if real == m {
				return grantrefusal.GrantIsManagedMount(g, real, m)
			}
		}
	}
	return nil
}

// checkGrantNotLooped refuses a grant whose symlinks loop. pathresolve.Existing leaves
// a loop unresolved on purpose - a shield on one still fails closed - but a grant
// is then bound at the looping path itself, and --ro-bind-try tolerates only a
// missing source (ENOENT), not ELOOP, so bwrap aborts the run naming itself
// rather than the grant. A dangling symlink is not a loop and stays supported:
// it resolves to a target that simply does not exist yet.
//
// The check asks the kernel (os.Stat/ELOOP) rather than the sandbox's resolver
// seam, and stays that way deliberately. sb.resolve cannot report a loop - it
// returns the path unchanged, which is also its answer for a path that is no
// symlink at all - and a fake that walked only the granted leaf would miss a loop
// in a parent component and pass where production refuses. A seam whose fake
// disagrees with the kernel is worse than none, so the loop cases are covered
// against real symlink trees instead (TestCheckGrantNotLoopedRealFilesystem).
func checkGrantNotLooped(p *policy.Policy) error {
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return fmt.Errorf("linux: %q: %w", g, err)
		}
		if _, err := os.Stat(abs); errors.Is(err, syscall.ELOOP) {
			return grantrefusal.Looped(g)
		}
	}
	return nil
}

// reachable reports whether a grant could expose path - either because a grant
// contains it, or because it contains a grant.
func reachable(path string, grants []string) bool {
	for _, g := range grants {
		if path == g || policy.CoversResolved(g, path) || policy.CoversResolved(path, g) {
			return true
		}
	}
	return false
}

// resolveGrants makes every granted path absolute and symlink-free.
//
// Resolving is the defense against a symlinked grant: if `write: /tmp/out` points
// at ~/.ssh, we bind the real target, and the deny-list - which runs after and
// also works on real paths - still shields it. Binding the unresolved path would
// have let the symlink redirect the mount.
func resolveGrants(sb sandbox, p *policy.Policy) (reads, writes []string, err error) {
	if reads, err = resolveAll(sb, p.Read); err != nil {
		return nil, nil, err
	}
	if writes, err = resolveAll(sb, p.Write); err != nil {
		return nil, nil, err
	}
	return reads, writes, nil
}

// grantSymlinks recreates, inside the sandbox, every granted path that is a
// symlink on the host, pointing at the same target the host's symlink does.
//
// The grant itself is bound at its resolved target, which is what keeps the
// deny-list honest: shields mount on real paths, and reaching content through a
// symlink still lands on the real path underneath, so a shield there still wins.
// Binding the target at the granted name instead would alias the same content to
// a second name the shields do not cover, which is a hole - hence a symlink, not
// a bind.
//
// Only names that no mount would otherwise fill are recreated. A name already
// inside some mount needs nothing: the mount carries the host's own entry there.
// Recreating it anyway is worse than redundant - bwrap refuses a --symlink onto
// an existing destination, and resolves a later bind's destination *through* the
// link, so `read: /bin` on a usrmerge host (/bin -> usr/bin, and /bin bound by
// systemMounts) would abort the run rather than being bound as before.
func grantSymlinks(sb sandbox, p *policy.Policy, reads, writes, rootDirs []string) ([]string, error) {
	// Every path whose contents the sandbox already has, so a link is only made
	// where nothing else creates the name. The bind mounts carry the host's own
	// entries; --dev and --proc bring entries of their own (/dev/stdout is one of
	// them). Grants are bound at their resolved targets, which is what covers a
	// symlink granted alongside a broader path that already contains it. Note
	// --tmpfs /tmp is deliberately absent: it mounts empty, so a name under it
	// exists only if made here.
	filled := []string{"/dev", "/proc"}
	filled = append(filled, systemMountPaths(sb)...)
	filled = append(filled, writes...)
	filled = append(filled, sb.entrypoint)
	for _, r := range reads {
		// A read grant of "/" is never bound at "/" - it is carried in reads for
		// deny-list reachability and bound as its children, which is what fills the
		// sandbox. Taking it literally would cover every path there is and skip
		// every link, including under the empty /tmp that the expansion omits.
		if r == "/" {
			filled = append(filled, rootDirs...)
			continue
		}
		filled = append(filled, r)
	}

	var links [][2]string
	seen := map[string]bool{}
	for _, g := range append(append([]string{}, p.Read...), p.Write...) {
		abs, err := filepath.Abs(g)
		if err != nil {
			return nil, fmt.Errorf("linux: %q: %w", g, err)
		}
		real, err := resolveGrant(sb, abs)
		if err != nil {
			return nil, err
		}
		if real == abs {
			continue
		}
		hop, err := missingHop(sb, abs, real, filled)
		if err != nil {
			return nil, err
		}
		if hop == "" || seen[hop] {
			continue
		}
		seen[hop] = true
		links = append(links, [2]string{real, hop})
	}
	slices.SortFunc(links, func(a, b [2]string) int { return cmp.Compare(a[1], b[1]) })

	var args []string
	var made []string
	for _, l := range links {
		// A symlink whose name sits under one already made would have to be created
		// through that link, into a target not mounted yet; the parent link already
		// leads to the right place, so the name resolves without this one. Sorting
		// above is what puts a parent link before the names beneath it.
		if coveredBy(l[1], made) {
			continue
		}
		made = append(made, l[1])
		args = append(args, "--symlink", l[0], l[1])
	}
	return args, nil
}

// missingHop returns the name to recreate so that following abs inside the
// sandbox reaches real, or "" when nothing needs recreating.
//
// Usually that is abs itself. But a name a mount already fills is the host's own
// symlink, which points at the next link in the chain rather than at real - and
// that next name can be one no mount fills, breaking the walk in the middle
// (~/link -> /elsewhere/mid -> real, with only ~ and real bound). So each filled
// name is followed the way the kernel will follow it, until one is missing: that
// is the name worth making, and pointing it at real short-circuits the rest.
//
// The chain walk reads the host's links directly (os.Readlink), and only the
// parent resolution goes through sb.resolve, matching how grantSymlinks resolved
// the grant itself. There is no readlink seam: a fake one would have to
// reimplement kernel link-following, which is the same hybrid that resolving
// grants off the seam produced. The multi-hop cases are covered against real
// symlink trees instead (TestGrantSymlinksMultiHopRealFilesystem).
func missingHop(sb sandbox, abs, real string, filled []string) (string, error) {
	cur := abs
	for range pathresolve.MaxDepth {
		if !coveredBy(cur, filled) {
			return cur, nil
		}
		target, err := os.Readlink(cur)
		if err != nil {
			if errors.Is(err, syscall.EINVAL) {
				// Not a symlink: the mount already carries the real thing.
				return "", nil
			}
			// Any other errno (EACCES on a parent, ENOENT from a race) says nothing
			// about whether the name needs recreating, and guessing "no" drops the
			// --symlink and leaves the granted name absent inside the sandbox with
			// nothing reporting why.
			return "", fmt.Errorf("linux: reading the symlink %q on the way to grant %q: %w", cur, abs, err)
		}
		// A relative target resolves from the directory the kernel *reads the link
		// in*, which is not the one the path spells when a parent is itself a
		// symlink - so resolve the parent before joining, rather than letting Join
		// clean ".." lexically and wander off.
		if !filepath.IsAbs(target) {
			target = filepath.Join(sb.resolve(filepath.Dir(cur)), target)
		}
		// Resolve the target's parent so it lands where the kernel would, but keep
		// its own name literal - the next link's location is wanted here, not the
		// thing it points at.
		next := filepath.Join(sb.resolve(filepath.Dir(target)), filepath.Base(target))
		if next == real {
			// The chain reaches the bound target on its own.
			return "", nil
		}
		cur = next
	}
	return "", nil // a symlink loop; resolve leaves these alone too
}

// coveredBy reports whether path is one of roots or sits inside one.
func coveredBy(path string, roots []string) bool {
	for _, r := range roots {
		if path == r || policy.CoversResolved(r, path) {
			return true
		}
	}
	return false
}

func resolveAll(sb sandbox, paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		r, err := resolveGrant(sb, p)
		if err != nil {
			return nil, err
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out, nil
}

// resolveGrant resolves a policy grant through the sandbox's resolver seam, so a
// grant and a shield are compared on the same footing. Both used to reach the host
// filesystem directly and so agreed in production, but only shields went through
// sb.resolve - which left every fake-filesystem test resolving fake shield paths
// against real-host-resolved grants, a hybrid that never runs.
func resolveGrant(sb sandbox, path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("linux: %q: %w", path, err)
		}
		abs = filepath.Clean(wd) + "/" + path
	}
	return sb.resolve(abs), nil
}

// resolve returns an absolute, symlink-resolved path. A path that does not exist
// yet (a write target) is resolved as far as it does exist, so the parts that
// could be a symlink are still followed.
func resolve(path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("linux: %q: %w", path, err)
		}
		abs = filepath.Clean(wd) + "/" + path
	}
	return pathresolve.Existing(abs), nil
}
