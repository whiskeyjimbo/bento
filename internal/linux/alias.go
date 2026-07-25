package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

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

// bindMount is one host bind mount: the subtree the kernel exposes and where it is
// exposed. A bind shares its source's inode without adding a directory entry to it, so
// no link count ever reflects one.
type bindMount struct {
	source string
	target string
}

// credentialAlias is a second readable path, inside a tree the policy grants, that
// reaches a shielded credential's content past the shield on its own path.
type credentialAlias struct {
	Path       string
	Credential string
}

// aliasedCredentials reports the paths inside this run's granted trees that alias a
// shielded credential. A shield binds a path, so any other name for the same content
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
func aliasedCredentials(sb sandbox, grants, writes, optIns []string) []credentialAlias {
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

	trees := make([]string, 0, len(grants)+len(writes))
	for _, g := range slices.Concat(grants, writes) {
		trees = append(trees, sb.resolve(g))
	}

	var out []credentialAlias
	if linked {
		for _, t := range trees {
			for _, a := range sb.aliasesUnder(t, want) {
				// A grant containing the credential itself walks over the shielded path,
				// whose identity is by definition wanted. The shield covers that path;
				// only a second name is a leak.
				if !shielded[a.Path] {
					out = append(out, a)
				}
			}
		}
	}
	out = append(out, bindAliases(sb.bindMounts(), creds, shielded, trees)...)

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

// aliasRefusal explains which granted paths reach a shielded credential and what to do
// about it. Naming both ends is the point: the alias is host-made, so the user is the
// one who can remove it, and telling them only that "an alias exists" leaves them
// nothing to act on.
func aliasRefusal(aliases []credentialAlias) error {
	var b strings.Builder
	b.WriteString("linux: a granted path is a second name for a shielded credential, which would read past the shield:")
	for _, a := range aliases {
		fmt.Fprintf(&b, "\n  %s aliases %s", a.Path, a.Credential)
	}
	b.WriteString("\nremove the alias, or narrow the grant so it does not cover it")
	return errors.New(b.String())
}

// credentialFiles returns the identified files behind this host's hidden home
// credential shields, and whether any of them carries an extra hardlink.
//
// The set is built from the deny-list itself, not from the shields a run engaged: a
// credential no grant reached still has its content reachable through an alias that a
// grant DID reach, and coupling the scan to engagement would miss exactly that.
//
// Two scope limits are deliberate. Only DenyAll shields qualify - a read-only shield
// keeps its file readable by design, so a second readable name for it leaks nothing
// new. And only shields under $HOME: the non-home hidden shields are host service
// directories like /run, and enumerating those to collect inodes would descend into
// removable media and FUSE mounts. A credential whose own path is explicitly opted into
// the sandbox is dropped - its shield never engages, so there is no shield for an alias
// to defeat.
func credentialFiles(sb sandbox, optIns []string) (files []identifiedFile, linked bool) {
	if sb.home == "" {
		return nil, false
	}
	// The deny-list paths are resolved before comparing, exactly as denyArgs resolves
	// them to bind them: on a host where $HOME sits behind a symlink (/home -> /var/home)
	// an unresolved prefix matches nothing and the whole scan silently no-ops.
	home := sb.resolve(sb.home)
	resolvedOptIns := make([]string, 0, len(optIns))
	for _, o := range optIns {
		resolvedOptIns = append(resolvedOptIns, sb.resolve(o))
	}

	seen := map[string]bool{}
	for _, r := range alwaysShields(sb) {
		path := sb.resolve(r.Path)
		if r.Deny != denylist.DenyAll || !under(path, home) || seen[path] {
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

// bindAliases reports the credentials a host bind mount re-exposes inside a granted
// tree. A bind of a credential's parent directory exposes every file under it, so the
// alias is the credential's path rewritten onto the mountpoint, not the mountpoint.
func bindAliases(mounts []bindMount, creds []identifiedFile, shielded map[string]bool, trees []string) []credentialAlias {
	var out []credentialAlias
	for _, m := range mounts {
		for _, c := range creds {
			if !under(c.path, m.source) {
				continue
			}
			rel, err := filepath.Rel(m.source, c.path)
			if err != nil {
				continue
			}
			alias := filepath.Join(m.target, rel)
			if shielded[alias] {
				continue
			}
			if slices.ContainsFunc(trees, func(t string) bool { return under(alias, t) }) {
				out = append(out, credentialAlias{Path: alias, Credential: c.path})
			}
		}
	}
	return out
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
// of want's. It never descends into a filesystem none of the wanted files live on: a
// hardlink cannot cross a device boundary, so another device's subtree - a mounted
// backup disk, a FUSE mount under a broad grant - cannot hold one and walking it is
// pure cost.
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
			if f, ok := identify(p, d); ok && !devs[f.id.dev] {
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

// hostBindMounts reads the host's bind mounts from /proc/self/mountinfo. A bind is a
// mount whose root within its source filesystem is not that filesystem's root: the
// kernel records the subtree being exposed, which for a filesystem mounted at / is the
// source path itself. Mounts of a filesystem that is not itself rooted at / (a bind of
// a path on a separate disk) name a subtree relative to that disk, which no host path
// matches, so they are read and simply never match a credential - a miss, not a
// misattribution. Unreadable mountinfo yields nothing: this feeds one of two
// mechanisms, and the hardlink half stands on its own.
func hostBindMounts() []bindMount {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []bindMount
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		// id parent major:minor root mountpoint options... - fstype source superopts
		fields := strings.Fields(scan.Text())
		if len(fields) < 5 || fields[3] == "/" {
			continue
		}
		out = append(out, bindMount{source: unescapeMount(fields[3]), target: unescapeMount(fields[4])})
	}
	return out
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
