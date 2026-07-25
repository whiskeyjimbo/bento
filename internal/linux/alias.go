package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/whiskeyjimbo/bento/enforce"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// fileID identifies a file's content on the host. A hardlink and a bind alias both
// share their (device, inode) with the file they alias, which is the only handle this
// mechanism has: a shield is a bind mount over a PATH, so it hides the name, never the
// content behind it.
type fileID struct {
	dev uint64
	ino uint64
}

// identifiedFile is a walked regular file with its content identity and the number of
// directory entries pointing at it. links is what gates the expensive half of the scan:
// a hardlink alias needs a second entry, so links==1 proves no hardlink to this file
// exists anywhere on the host.
type identifiedFile struct {
	path  string
	id    fileID
	links uint64
}

// mountPoint is one host mount: where it is attached and the identity of the directory
// attached there. A bind shares its source's inode without adding a directory entry to
// it, so no link count ever reflects one and the mount table is the only place it shows.
//
// Only the mountpoint is recorded, never the mount's source. The kernel reports a
// mount's source subtree relative to its own filesystem, not to the host namespace: with
// /home on its own partition a bind of ~/.ssh reports "/u/.ssh", and a btrfs subvolume
// layout reports "/@home/u/.ssh". Comparing either against a host path silently matches
// nothing, and a second filesystem whose internal path happens to equal a credential's
// would match content it does not hold. The mountpoint has no such ambiguity, so the
// scan asks what is actually at it rather than what the kernel says it came from.
type mountPoint struct {
	path string
	id   fileID
}

// credentialAlias is a second readable path, inside a tree the policy grants, that
// reaches a shielded credential's content past the shield on its own path.
type credentialAlias struct {
	Path       string
	Credential string
}

// aliasedCredentials reports the paths inside the trees this run exposes that alias a
// shielded credential. The trees are everything bwrap will bind, not only the paths the
// policy names: an out-of-FHS interpreter has its whole install prefix bound read-only so
// its stdlib comes along, and for a pyenv or nvm interpreter that prefix sits under the
// user's home - a tree the policy never mentions and an alias planted there would be read
// straight past the shield. A shield binds a path, so any other name for the same content
// under a grant stays readable: a hardlink (a second directory entry for the inode) or
// a bind mount (the same inode exposed at a second mountpoint).
//
// The scan is two mechanisms because the two aliases leave different traces, and only
// together do they stay cheap. Hardlinks are found by identity: stat the credential set
// - dozens of files - and if none carries an extra link, no hardlink to any of them
// exists anywhere on the host and the granted-tree walk is provably unnecessary. That
// contrapositive is what keeps an ordinary run off the expensive path; without it a
// broad home grant would stat-walk a large tree on every launch. Binds bump no link
// count, so the gate correctly skips the walk for them, and they are read instead from
// the host's mount table at O(mounts).
//
// Deliberate residuals, documented in the threat model: a reflink shares content
// without sharing an inode, so identity comparison never sees one, and the whole scan
// is a snapshot - a host actor can link after it runs. Both are accepted rather than
// engineered against, because the actor here already holds the user's privileges and
// could read the credential directly; the value delivered is naming where an alias is,
// not blocking someone who needs no alias.
func aliasedCredentials(sb sandbox, trees, optIns []string) []credentialAlias {
	creds, linked := credentialFiles(sb, optIns)
	if len(creds) == 0 {
		return nil
	}

	want := make(map[fileID]string, len(creds))
	shielded := make(map[string]bool, len(creds))
	for _, c := range creds {
		// Two credentials that are already hardlinks of each other share an identity;
		// the shallower path names the pair predictably.
		if prev, dup := want[c.id]; !dup || c.path < prev {
			want[c.id] = c.path
		}
		shielded[c.path] = true
	}

	resolved := make([]string, 0, len(trees))
	for _, t := range trees {
		resolved = append(resolved, sb.resolve(t))
	}
	trees = resolved

	// A grant containing the credential itself walks over the shielded path, whose
	// identity is by definition wanted. The shield covers that path; only a second name
	// is a leak.
	var out []credentialAlias
	collect := func(root string) {
		for _, a := range sb.aliasesUnder(root, want) {
			if !shielded[a.Path] {
				out = append(out, a)
			}
		}
	}
	if linked {
		for _, t := range trees {
			collect(t)
		}
	}

	// Mounts are examined whether or not the gate fired, because a bind adds no directory
	// entry and so never opens it.
	devs := make([]uint64, 0, 2)
	for id := range want {
		if !slices.Contains(devs, id.dev) {
			devs = append(devs, id.dev)
		}
	}
	for _, a := range mountAliases(sb, creds, shielded, trees, devs) {
		out = append(out, a)
	}

	slices.SortFunc(out, func(a, b credentialAlias) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Credential, b.Credential)
	})
	// Overlapping grants (read: ~ alongside read: ~/project) walk the same file twice,
	// and a bind inside a walked tree is found by both mechanisms; report each once.
	return slices.Compact(out)
}

// splitAcknowledgedAliases divides found aliases into the ones that still refuse the run
// and the ones the caller has acknowledged by naming a tree they sit under.
//
// Acknowledgement is by tree because the tools that create these aliases rotate their
// paths: a cp -al snapshot root is dated, so today's alias path is not tomorrow's, and
// acknowledging exact paths would go stale every day while needing one entry per
// credential per snapshot. The trees are resolved before comparing, like every other path
// this package compares - the aliases arrive resolved, so an unresolved acknowledgement
// would match nothing and silently keep refusing.
func splitAcknowledgedAliases(sb sandbox, found []credentialAlias, acceptUnder []string) (refuse, accepted []credentialAlias) {
	if len(found) == 0 {
		return nil, nil
	}
	trees := make([]string, 0, len(acceptUnder))
	for _, t := range acceptUnder {
		trees = append(trees, sb.resolve(t))
	}
	for _, a := range found {
		if slices.ContainsFunc(trees, func(t string) bool { return under(a.Path, t) }) {
			accepted = append(accepted, a)
			continue
		}
		refuse = append(refuse, a)
	}
	return refuse, accepted
}

// reportedAliases converts accepted aliases for the run's result. The scan already sorts
// and dedupes, so this only crosses the type boundary - the adapter's own alias type stays
// out of the core's signatures.
func reportedAliases(accepted []credentialAlias) []enforce.CredentialAlias {
	if len(accepted) == 0 {
		return nil
	}
	out := make([]enforce.CredentialAlias, 0, len(accepted))
	for _, a := range accepted {
		out = append(out, enforce.CredentialAlias{Path: a.Path, Credential: a.Credential})
	}
	return out
}

// aliasRefusal explains which readable paths reach a shielded credential and what to do
// about it. Naming both ends is the point: the alias is host-made, so the user is the one
// who can remove it, and telling them only that "an alias exists" leaves them nothing to
// act on.
//
// It also prints the acknowledgement as a ready-to-paste flag. These alias paths are
// symlink-resolved, and one retyped by hand would not compare equal to what the scan
// produced - so the message hands over the exact string the acknowledgement needs instead
// of describing it.
func aliasRefusal(aliases []credentialAlias) error {
	var b strings.Builder
	b.WriteString("linux: a readable path is a second name for a shielded credential, which would read past the shield:")
	for _, a := range aliases {
		fmt.Fprintf(&b, "\n  %s aliases %s", a.Path, a.Credential)
	}
	b.WriteString("\nremove the alias, or narrow the grant so it does not cover it.")
	b.WriteString("\nif these are known to you - a snapshot or deduplicated backup - acknowledge the tree:")
	for _, r := range acknowledgementRoots(aliases) {
		fmt.Fprintf(&b, "\n  --accept-alias %s", r)
	}
	return errors.New(b.String())
}

// acknowledgementRoots picks the trees to suggest acknowledging. It prefers the single
// tree that contains every alias, because that is what survives the rotation these tools
// do: suggesting each alias's own parent would hand back one flag per credential per
// dated snapshot, all of them stale tomorrow, which is the exact failure a tree-scoped
// acknowledgement exists to avoid.
//
// It falls back to the individual parents when the shared tree would be too much to
// acknowledge in one line - the filesystem root, or any tree that contains a shielded
// credential itself. That second guard is the one that matters: aliases scattered across
// a home share the home as their ancestor, and suggesting it would turn a targeted
// acknowledgement into an off-switch covering the credential stores too.
func acknowledgementRoots(aliases []credentialAlias) []string {
	parents := make([]string, 0, len(aliases))
	for _, a := range aliases {
		if p := filepath.Dir(a.Path); !slices.Contains(parents, p) {
			parents = append(parents, p)
		}
	}

	shared := parents[0]
	for _, p := range parents[1:] {
		shared = commonAncestor(shared, p)
	}
	if shared == "/" || shared == "." {
		return parents
	}
	for _, a := range aliases {
		if under(a.Credential, shared) {
			return parents
		}
	}
	return []string{shared}
}

// commonAncestor returns the deepest directory containing both paths.
func commonAncestor(a, b string) string {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	var shared []string
	for i := 0; i < len(as) && i < len(bs) && as[i] == bs[i]; i++ {
		shared = append(shared, as[i])
	}
	if len(shared) < 2 {
		return "/"
	}
	return strings.Join(shared, "/")
}

// mountAliases reports the credentials a host mount re-exposes at a second path inside a
// granted tree. A bind shares its source's inode without adding a directory entry to it,
// so no link count ever reflects one and the hardlink gate never opens for a bind.
//
// It asks the question by identity rather than by path arithmetic. For each credential it
// walks up the ancestors of the credential's own path, and where an ancestor turns out to
// BE what a mount is attached to, the credential is reachable a second time at that
// mountpoint plus the rest of the path. This needs nothing from the kernel's record of
// where a mount came from - which is unusable, being relative to the source filesystem
// rather than the host namespace (see mountPoint) - and it catches a bind whose mountpoint
// sits ANYWHERE relative to the granted tree: inside it, equal to it, or above it. A
// mountpoint above the grant is the case that matters most and is easiest to miss: a bind
// of the whole home to /srv/backup, granted as "read: /srv/backup/project", exposes every
// credential under a path the grant never mentions.
//
// It also costs no tree walk. For an ordinary, non-bind mount the mountpoint matches the
// credential's own ancestor at that same path, so the alias it computes is the credential
// itself and drops out as the shielded path - which is why the root filesystem's mount
// does not make every launch walk the whole home.
func mountAliases(sb sandbox, creds []identifiedFile, shielded map[string]bool, trees []string, devs []uint64) []credentialAlias {
	byID := map[fileID][]string{}
	for _, m := range sb.mountpoints(devs) {
		byID[m.id] = append(byID[m.id], m.path)
	}
	if len(byID) == 0 {
		return nil
	}

	// Credentials share ancestors (~/.ssh and ~/.aws both sit under home), so each
	// directory is stat'd once however many credentials hang below it.
	ids := map[string]fileID{}
	idOf := func(path string) (fileID, bool) {
		if id, done := ids[path]; done {
			return id, id != fileID{}
		}
		id, ok := sb.statID(path)
		if !ok {
			id = fileID{}
		}
		ids[path] = id
		return id, ok
	}

	var out []credentialAlias
	for _, c := range creds {
		for a := c.path; ; a = filepath.Dir(a) {
			if id, ok := idOf(a); ok {
				for _, mp := range byID[id] {
					rel, err := filepath.Rel(a, c.path)
					if err != nil {
						continue
					}
					alias := filepath.Join(mp, rel)
					// The credential's own path is not an alias of itself: an ordinary
					// mount names the ancestor the credential already sits under, so the
					// path this computes IS the credential. shielded holds every
					// credential path, so it covers that and the cross-credential case.
					if shielded[alias] {
						continue
					}
					if slices.ContainsFunc(trees, func(t string) bool { return under(alias, t) }) {
						out = append(out, credentialAlias{Path: alias, Credential: c.path})
					}
				}
			}
			if parent := filepath.Dir(a); parent != a {
				continue
			}
			break
		}
	}
	return out
}

// credentialFiles returns the identified files behind this host's hidden home
// credential shields, and whether any of them carries an extra hardlink.
//
// The set is built from the deny-list itself, not from the shields a run engaged: a
// credential no grant reached still has its content reachable through an alias that a
// grant DID reach, and coupling the scan to engagement would miss exactly that.
//
// Two scope limits are deliberate. Only DenyAll shields qualify - a read-only shield
// keeps its file readable by design, so a second readable name for it leaks nothing new.
// And among the hidden directories only the key-bearing ones anchor the scan
// (denylist.AliasAnchors); the bulk stores are shielded just as hard but enumerating a
// mail spool or browser profile on every launch would cost more than the scan saves, and
// mail sync tools hardlink duplicate messages routinely enough that anchoring on them
// would trip on mail rather than credentials. Hidden FILE rules all anchor it: a single
// file is cheap to stat and is named because it holds a secret.
//
// The set is NOT restricted to paths under $HOME, and must not be: both sources already
// follow relocation, and a credential store is no less a credential for living
// elsewhere. denylist.AliasAnchors expands an XDG-relative anchor to the relocated base
// as well as the default one, and the hidden file rules follow the documented env vars
// (KUBECONFIG, AWS_SHARED_CREDENTIALS_FILE, the *_HISTFILE family) wherever they point.
// Filtering on $HOME here would shield those at their own path while silently excusing
// them from the alias scan - the exact configurations most likely to have moved a store
// somewhere a grant also reaches. The service directories that filter once guarded
// against (/run) are DIRECTORY rules and are not anchors, so they never enter the set.
//
// A credential whose own path is explicitly opted into the sandbox is dropped - its
// shield never engages, so there is no shield for an alias to defeat.
func credentialFiles(sb sandbox, optIns []string) (files []identifiedFile, linked bool) {
	if sb.home == "" {
		return nil, false
	}
	// The deny-list paths are resolved before comparing, exactly as denyArgs resolves them
	// to bind them: on a host where a store sits behind a symlink an unresolved path
	// matches nothing and the whole scan silently no-ops.
	resolvedOptIns := make([]string, 0, len(optIns))
	for _, o := range optIns {
		resolvedOptIns = append(resolvedOptIns, sb.resolve(o))
	}

	// The anchors are walked directly rather than filtered out of the deny rules. An
	// anchor is not always a rule: a full-node wallet client's keys sit in a named
	// subdirectory of a tree that is shielded whole, so selecting rules by anchorhood
	// would skip the shielded parent as "not an anchor" and never reach the keys inside
	// it. Hidden FILE rules are anchors too - a single file is cheap to stat and is named
	// because it holds a secret.
	roots := make([]string, 0, 128)
	for _, a := range denylist.AliasAnchors(sb.home) {
		roots = append(roots, sb.resolve(a))
	}
	for _, r := range alwaysShields(sb) {
		if r.Deny == denylist.DenyAll && !r.Dir {
			roots = append(roots, sb.resolve(r.Path))
		}
	}

	seen := map[string]bool{}
	for _, path := range roots {
		if seen[path] {
			continue
		}
		if slices.ContainsFunc(resolvedOptIns, func(o string) bool { return under(path, o) }) {
			continue
		}
		seen[path] = true
		// A symlinked credential's target is not chased. A store that deduplicates
		// identical files by hardlinking them (Nix) gives every linked dotfile an extra
		// link by design, and following the link would make that the normal case.
		for _, f := range sb.fileIDs(path) {
			files = append(files, f)
			linked = linked || f.links > 1
		}
	}
	return files, linked
}

// hostFileIDs returns the identity of every regular file at or under path. A file path
// yields itself; a directory shield (~/.ssh, ~/.aws) yields the credential files inside
// it. It walks without following symlinks, so a symlink planted in a credential
// directory cannot redirect the walk or loop it. Best-effort: an unreadable subtree is
// skipped rather than fatal, and the gate it feeds is conservative in the safe
// direction only for what it did see.
func hostFileIDs(path string) []identifiedFile {
	var out []identifiedFile
	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// A credential store kept in git (~/.password-store is one by design) holds its
		// history as content-addressed blobs, and `git clone --local` hardlinks every
		// one of them into the clone. Those extra links are the user's own copy, made
		// deliberately, so anchoring identity on a blob would refuse a run because a
		// clone of the store sits in a granted tree - while the store itself stays
		// shielded either way. The live credential files outside .git still anchor it.
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if f, ok := identify(p, d); ok {
			out = append(out, f)
		}
		return nil
	})
	return out
}

// hostAliasesUnder returns the regular files under root whose content identity is one
// of want's. It does not descend into a filesystem none of the wanted files live on: a
// hardlink cannot cross a device boundary, so another device's subtree - /proc and /sys
// under a "read: /" grant, a mounted backup disk, a FUSE mount - cannot hold one and
// walking it is pure cost.
//
// The root itself is never pruned, however far its own device is from the wanted set. A
// walk of "/" starts on the rootfs while the credentials live on a separate /home, and
// pruning by device at the root would hand fs.SkipDir to WalkDir before it descended
// anywhere - ending the whole walk and reporting no alias for a tree full of them. The
// prune is a statement about a subtree's contents, so it only applies below the root;
// a wanted-device filesystem mounted under a pruned directory is reached through the
// mountpoint scan instead.
func hostAliasesUnder(root string, want map[fileID]string) []credentialAlias {
	devs := map[uint64]bool{}
	for id := range want {
		devs[id.dev] = true
	}
	var out []credentialAlias
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if f, ok := identify(p, d); ok && !devs[f.id.dev] && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, ok := identify(p, d)
		if !ok {
			return nil
		}
		if cred, hit := want[f.id]; hit {
			out = append(out, credentialAlias{Path: p, Credential: cred})
		}
		return nil
	})
	return out
}

func identify(path string, d fs.DirEntry) (identifiedFile, bool) {
	fi, err := d.Info()
	if err != nil {
		return identifiedFile{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return identifiedFile{}, false
	}
	return identifiedFile{path: path, id: fileID{dev: uint64(st.Dev), ino: st.Ino}, links: uint64(st.Nlink)}, true
}

// hostMountpoints reads where the host's filesystems are attached, with the identity of
// what sits at each one, for the devices given. The mount's own source subtree is
// deliberately not read: the kernel records it relative to its filesystem rather than to
// the host namespace, so it cannot be compared against a host path (see mountPoint).
// Statting the mountpoint asks the filesystem directly instead, which is immune to a
// separate /home, a btrfs subvolume layout, and the non-path sources (mnt:[4026532372])
// that nsfs mounts report.
//
// The device filter comes from the mountinfo line itself, before any stat. Only a mount on
// a device a credential lives on can alias one, so everything else is skipped without
// being touched - which matters because os.Lstat on a dead hard-mounted NFS export blocks
// forever, and hanging before launch over a filesystem holding no credential would be a
// worse failure than the one this scan prevents. A device the kernel reports under a
// number that does not match the credential's st_dev (some btrfs anonymous devices) is a
// miss, not a misattribution. Unreadable mountinfo yields nothing: this feeds one of two
// mechanisms, and the hardlink half stands on its own.
func hostMountpoints(devs []uint64) []mountPoint {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []mountPoint
	for _, path := range mountinfoPaths(f, devs) {
		if id, ok := hostStatID(path); ok {
			out = append(out, mountPoint{path: path, id: id})
		}
	}
	return out
}

// mountinfoPaths returns the mountpoints in a mountinfo stream that sit on one of the
// given devices. Splitting the parse from the stat is what makes the device filter
// testable, and the filter is the whole reason nothing outside it is ever touched.
func mountinfoPaths(r io.Reader, devs []uint64) []string {
	wanted := make(map[string]bool, len(devs))
	for _, d := range devs {
		wanted[fmt.Sprintf("%d:%d", unix.Major(d), unix.Minor(d))] = true
	}

	var out []string
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		// id parent major:minor root mountpoint options... - fstype source superopts
		fields := strings.Fields(scan.Text())
		if len(fields) < 5 || !wanted[fields[2]] {
			continue
		}
		out = append(out, unescapeMount(fields[4]))
	}
	return out
}

// hostStatID returns a single path's content identity, without following a final symlink -
// a symlink named as a credential's ancestor must not redirect the comparison.
func hostStatID(path string) (fileID, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, true
}

// unescapeMount decodes the octal escapes the kernel writes for the characters that
// would otherwise break mountinfo's space-separated fields.
func unescapeMount(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
