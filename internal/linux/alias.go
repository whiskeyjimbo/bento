//go:build linux

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
	"github.com/whiskeyjimbo/bento/policy"
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

// aliasScan is what one run's credential scan produced. It carries the shielded
// credential paths alongside the aliases because the two answer different questions and
// only one of them is about this run's grants: found depends on what the policy grants,
// while credentials is every path the scan anchored on, whether or not this run reached
// it. Judging an acknowledgement needs the second - a guard that consults only found
// accepts "--accept-alias $HOME" on any run whose aliases happen to sit elsewhere, and
// accepts anything at all on a run that found nothing.
//
// credentials is the anchor set credentialFiles built, so it inherits both of that
// function's narrowings, and both are in the safe direction. A store the policy opted
// back in is absent because its shield never engages - there is nothing for a wide
// acknowledgement to switch off - and the opt-in is re-judged every run, so the tree
// stops being acceptable the moment the opt-in goes away. A non-anchor bulk store is
// absent because the scan never reports an alias of one either, so no acknowledgement
// can accept something the scan would have refused.
type aliasScan struct {
	found       []credentialAlias
	credentials []string
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
// without sharing an inode, so identity comparison never sees one; the whole scan is a
// snapshot - a host actor can link after it runs; and a directory the walk may traverse
// but not list (mode --x) hides an alias the run could still open by a name it already
// knows. All three are accepted rather than engineered against, because the actor here
// already holds the user's privileges and could read the credential directly; the value
// delivered is naming where an alias is, not blocking someone who needs no alias.
func aliasedCredentials(sb sandbox, trees, literalOptIns []string) (aliasScan, error) {
	creds, linked, err := credentialFiles(sb, literalOptIns)
	if err != nil {
		return aliasScan{}, err
	}
	if len(creds) == 0 {
		return aliasScan{}, nil
	}

	want := make(map[fileID]string, len(creds))
	shielded := make(map[string]bool, len(creds))
	credentials := make([]string, 0, len(creds))
	for _, c := range creds {
		// Two credentials that are already hardlinks of each other share an identity;
		// the shallower path names the pair predictably.
		if prev, dup := want[c.id]; !dup || c.path < prev {
			want[c.id] = c.path
		}
		if !shielded[c.path] {
			shielded[c.path] = true
			credentials = append(credentials, c.path)
		}
	}
	slices.Sort(credentials)

	resolved := make([]string, 0, len(trees))
	for _, t := range trees {
		resolved = append(resolved, sb.resolve(t))
	}
	trees = resolved

	// A grant containing the credential itself walks over the shielded path, whose
	// identity is by definition wanted. The shield covers that path; only a second name
	// is a leak.
	var out []credentialAlias
	if linked {
		for _, t := range trees {
			aliases, err := sb.aliasesUnder(t, want)
			if err != nil {
				return aliasScan{}, err
			}
			for _, a := range aliases {
				if !shielded[a.Path] {
					out = append(out, a)
				}
			}
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
	mounted, err := mountAliases(sb, creds, shielded, trees, devs)
	if err != nil {
		return aliasScan{}, err
	}
	out = append(out, mounted...)

	slices.SortFunc(out, func(a, b credentialAlias) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Credential, b.Credential)
	})
	// Overlapping grants (read: ~ alongside read: ~/project) walk the same file twice,
	// and a bind inside a walked tree is found by both mechanisms; report each once.
	return aliasScan{found: slices.Compact(out), credentials: credentials}, nil
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
func splitAcknowledgedAliases(sb sandbox, scan aliasScan, acceptUnder []string) (refuse, accepted []credentialAlias, err error) {
	trees := make([]string, 0, len(acceptUnder))
	for _, t := range acceptUnder {
		t = sb.resolve(t)
		// An acknowledgement wide enough to contain a shielded credential is not an
		// acknowledgement of known aliases, it is the mechanism turned off: every alias
		// on the host falls inside it, including one planted later somewhere the user
		// never had in mind. Refusing is the honest answer - the caller asked to accept
		// specific aliases and this would accept all of them, so silently narrowing it
		// would be answering a different question than the one they asked.
		//
		// Judged before the empty-scan shortcut below, and against every credential the
		// host shields rather than the ones this run aliased. Both matter: the flag is
		// pasted into a command line that outlives the run that suggested it, so an
		// acknowledgement validated only against today's aliases silently accepts every
		// one planted under it tomorrow - and one validated on a run that found nothing
		// was never judged at all.
		if err := checkAcknowledgementScope(t, scan.credentials); err != nil {
			return nil, nil, err
		}
		trees = append(trees, t)
	}
	for _, a := range scan.found {
		if slices.ContainsFunc(trees, func(t string) bool { return policy.CoversResolved(t, a.Path) }) {
			accepted = append(accepted, a)
			continue
		}
		refuse = append(refuse, a)
	}
	return refuse, accepted, nil
}

// checkAcknowledgementScope rejects an acknowledged tree that would accept more than the
// aliases in front of it. The same predicate decides what aliasRefusal is willing to
// SUGGEST, so the advice and the enforcement cannot drift apart - suggesting a narrow tree
// while accepting an arbitrarily wide one was the gap this closes.
func checkAcknowledgementScope(tree string, credentials []string) error {
	if overbroadAcknowledgement(tree, credentials) {
		return fmt.Errorf("--accept-alias %s would accept every alias of a credential it contains, not the ones you meant; name the tree the aliases actually live in", tree)
	}
	return nil
}

// overbroadAcknowledgement reports whether a tree is too wide to acknowledge: the
// filesystem root, or a tree holding one of the shielded credentials itself. A backup root
// passes - it contains second names for credentials, not the credentials.
//
// credentials is the host's whole shielded set, not the subset this run aliased, so the
// verdict on a given tree is the same on every run.
func overbroadAcknowledgement(tree string, credentials []string) bool {
	if tree == "/" || tree == "." || tree == "" {
		return true
	}
	return slices.ContainsFunc(credentials, func(c string) bool { return policy.CoversResolved(tree, c) })
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
func aliasRefusal(aliases []credentialAlias, credentials []string) error {
	var b strings.Builder
	b.WriteString("a readable path is a second name for a shielded credential, which would read past the shield:")
	for _, a := range aliases {
		fmt.Fprintf(&b, "\n  %s aliases %s", a.Path, a.Credential)
	}
	b.WriteString("\nremove the alias, or narrow the grant so it does not cover it.")
	b.WriteString("\nif these are known to you - a snapshot or deduplicated backup - acknowledge the tree:")
	for _, r := range acknowledgementRoots(aliases, credentials) {
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
func acknowledgementRoots(aliases []credentialAlias, credentials []string) []string {
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
	if overbroadAcknowledgement(shared, credentials) {
		return parents
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
func mountAliases(sb sandbox, creds []identifiedFile, shielded map[string]bool, trees []string, devs []uint64) ([]credentialAlias, error) {
	mounts, err := sb.mountpoints(devs)
	if err != nil {
		return nil, fmt.Errorf("linux: reading the host's mount table to scan for credential aliases: %w", err)
	}
	byID := map[fileID][]string{}
	for _, m := range mounts {
		byID[m.id] = append(byID[m.id], m.path)
	}
	if len(byID) == 0 {
		return nil, nil
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
					if slices.ContainsFunc(trees, func(t string) bool { return policy.CoversResolved(t, alias) }) {
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
	return out, nil
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
// shield never engages, so there is no shield for an alias to defeat. literalOptIns are
// the LITERAL deny-list paths explicitShieldOptIns matched, not the resolved ones it
// also carries: this resolves them itself, alongside the anchors it resolves anyway.
func credentialFiles(sb sandbox, literalOptIns []string) (files []identifiedFile, linked bool, err error) {
	if len(sb.homes) == 0 {
		return nil, false, nil
	}
	// The deny-list paths are resolved before comparing, exactly as denyArgs resolves them
	// to bind them: on a host where a store sits behind a symlink an unresolved path
	// matches nothing and the whole scan silently no-ops.
	resolvedOptIns := make([]string, 0, len(literalOptIns))
	for _, o := range literalOptIns {
		resolvedOptIns = append(resolvedOptIns, sb.resolve(o))
	}

	// The anchors are walked directly rather than filtered out of the deny rules. An
	// anchor is not always a rule: a full-node wallet client's keys sit in a named
	// subdirectory of a tree that is shielded whole, so selecting rules by anchorhood
	// would skip the shielded parent as "not an anchor" and never reach the keys inside
	// it. Hidden FILE rules are anchors too - a single file is cheap to stat and is named
	// because it holds a secret.
	roots := make([]string, 0, 128)
	for _, h := range sb.homes {
		for _, a := range denylist.AliasAnchors(h) {
			roots = append(roots, sb.resolve(a))
		}
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
		if slices.ContainsFunc(resolvedOptIns, func(o string) bool { return policy.CoversResolved(o, path) }) {
			continue
		}
		seen[path] = true
		// A symlinked credential's target is not chased. A store that deduplicates
		// identical files by hardlinking them (Nix) gives every linked dotfile an extra
		// link by design, and following the link would make that the normal case.
		ids, err := sb.fileIDs(path)
		if err != nil {
			return nil, false, err
		}
		for _, f := range ids {
			files = append(files, f)
			linked = linked || f.links > 1
		}
	}
	return files, linked, nil
}

// hostFileIDs returns the identity of every regular file at or under path. A file path
// yields itself; a directory shield (~/.ssh, ~/.aws) yields the credential files inside
// it. It walks without following symlinks, so a symlink planted in a credential
// directory cannot redirect the walk or loop it.
//
// A path with nothing behind it is skipped: the anchor set names every credential store
// bento models and no host has more than a handful of them, so absence is the normal
// answer. That is more than ENOENT - a component that is a regular file (ENOTDIR) or a
// symlink loop (ELOOP) equally means there is no file at the anchor to identify, and
// neither is a file the walk failed to read.
//
// Anything else is fatal, because swallowing it would under-count the links this file's
// caller gates the whole granted-tree walk on, turning "could not look" into a proof that
// no hardlink exists. Unreadability is no proof of safety here, unlike in the granted-tree
// walk: an unreadable DIRECTORY says nothing about the inodes listed in it. A hardlink
// carries the file's own mode, not the mode of the directory it appears in, so a file
// behind an unreadable subtree can still have a perfectly readable second name in a
// granted tree - true of a tree the user chmod'd to 000, and equally of a root-owned 0700
// directory holding a 0644 file.
//
// The cost is that an anchor which has picked up an unreadable subdirectory refuses until
// it is opened back up. `sudo kubectl` with HOME preserved is the usual way one appears
// under ~/.kube, and chowning it back is the remedy - which is why the message names the
// path rather than only the anchor.
func hostFileIDs(path string) ([]identifiedFile, error) {
	var out []identifiedFile
	if err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if nothingBehind(err) {
				return nil
			}
			return fmt.Errorf("reading %s to identify the credentials behind it: %w", p, err)
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
	}); err != nil {
		return nil, fmt.Errorf("linux: %w", err)
	}
	return out, nil
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
func hostAliasesUnder(root string, want map[fileID]string) ([]credentialAlias, error) {
	devs := map[uint64]bool{}
	for id := range want {
		devs[id.dev] = true
	}
	var out []credentialAlias
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A subtree this cannot read is one the RUN cannot read either, so there is
			// nothing behind it to leak past a shield. The scan walks as the invoking uid
			// before launch, and the sandboxed process is that same uid at that same path
			// under the same parent modes - the walk roots ARE the trees bwrap binds. So
			// permission is a proof for a subtree it can neither list nor traverse, not a
			// blind spot, which is what separates this from the mount-table case where a
			// short list silently loses bind detection. Any
			// other error is a genuine could-not-look and is fatal: reporting clean
			// because the walk broke is the failure this refuses.
			//
			// Skipping only on the wanted-device check the prune below uses was tried and
			// does not discriminate - /etc/ssl/private is unreadable and on the same
			// device as a home on an ordinary host, so it would refuse every run whose
			// exposed trees include /etc.
			if nothingBehind(err) || errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return fmt.Errorf("reading %s to scan for credential aliases: %w", p, err)
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
	}); err != nil {
		return nil, fmt.Errorf("linux: %w", err)
	}
	return out, nil
}

// nothingBehind reports whether a walk error means there is no file at the path rather
// than one the walk could not read. Only ENOENT reaches fs.ErrNotExist (syscall.Errno.Is
// maps nothing else to it), so the two other ways a path can name no file are spelled
// out: a component that is a regular file, and a symlink loop.
func nothingBehind(err error) bool {
	return errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ELOOP)
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
// miss, not a misattribution.
//
// A mount table that cannot be read or cannot be parsed to the end is an error, not an
// empty result. A partial list is the dangerous shape precisely because it reads as a
// complete one, and the hardlink half of the scan does not compensate for it: a bind
// adds no directory entry, so it bumps no link count and the hardlink gate never opens
// for one. Losing this mechanism silently loses bind detection outright.
func hostMountpoints(devs []uint64) ([]mountPoint, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	paths, err := mountinfoPaths(f, devs)
	if err != nil {
		return nil, err
	}

	var out []mountPoint
	for _, path := range paths {
		if id, ok := hostStatID(path); ok {
			out = append(out, mountPoint{path: path, id: id})
		}
	}
	return out, nil
}

// mountinfoPaths returns the mountpoints in a mountinfo stream that sit on one of the
// given devices. Splitting the parse from the stat is what makes the device filter
// testable, and the filter is the whole reason nothing outside it is ever touched.
func mountinfoPaths(r io.Reader, devs []uint64) ([]string, error) {
	wanted := make(map[string]bool, len(devs))
	for _, d := range devs {
		wanted[fmt.Sprintf("%d:%d", unix.Major(d), unix.Minor(d))] = true
	}

	var out []string
	scan := bufio.NewScanner(r)
	// A mountinfo line carries a path plus the filesystem's options, and an overlayfs
	// lowerdir= list runs well past the 64 KiB default - on which the scan would stop
	// early and hide every mount after it.
	scan.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scan.Scan() {
		// id parent major:minor root mountpoint options... - fstype source superopts
		fields := strings.Fields(scan.Text())
		if len(fields) < 5 || !wanted[fields[2]] {
			continue
		}
		out = append(out, unescapeMount(fields[4]))
	}
	// A scan that stopped early leaves out mountpoints, and a caller that treats the
	// short list as the whole picture would miss an alias for a shielded path. Report
	// it rather than return the prefix, so the caller decides instead of guessing.
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return out, nil
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
