//go:build unix

package gate

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// fileID identifies a file's content. A hardlink shares its (device, inode) with the file
// it aliases, which is the only handle this has: a shield hides a PATH, never the content
// behind it.
type fileID struct {
	dev uint64
	ino uint64
}

// credentialAliases reports the paths inside the trees this policy grants that reach a
// shielded credential's content by a second name, which the run refuses over.
//
// It answers the hardlink half of the backend's checkAliasedCredentials and not the bind
// half, which needs the mount table and belongs to the platform rather than to this. That
// is the narrowing that only misses a finding, and it misses the alias no tool in the
// trigger set produces: a cp -al snapshot, an rsync --link-dest backup and a whole-tree
// deduplicator all leave a second DIRECTORY ENTRY, which is what this walks for.
//
// It also narrows on the trees: the run scans everything it binds, which includes an
// out-of-FHS interpreter's whole install prefix, and this scans only the grants the
// manifest names. A subset, so it can miss an alias the run finds and never invent one -
// and the grants are what a reader of this answer can act on anyway.
//
// It costs a walk of the credential anchors on every Check - 2.5ms on a developer home,
// which took `bento validate` from 20ms to 22.5ms - and a walk of the granted trees only
// where that first walk found a credential carrying a second directory entry. That gate is
// the backend's too, and on a host with no such credential no grant is walked at all.
//
// Where it IS open, the granted trees are walked whole, and the cost is set by the number
// of directory entries rather than by bytes. On a host holding one hardlinked key,
// `bento validate` went from 40ms to 1.13s over a 287k-entry module cache and from 60ms to
// 3.6s warm - 15.7s cold - over an 841k-entry home. That is the cost on exactly the hosts
// this exists for - a snapshot tool, a --link-dest backup, a Nix store, all of which leave
// every dotfile a second link by design - so it is per Check, and an embedder calling Check
// in a loop pays it every time.
//
// That is what aliasBudget bounds. The walk stops after that many directory entries and
// the answer is reported as partial - the same flag an unread anchor raises, which the
// caller passes on as a note that the scan did not cover everything, rather than a silence
// that reads as a clean bill. Bounding it
// only misses a finding, which is the direction the package doc sanctions, and it is the
// bound that fits the cost - the caller-held set the ponytail named amortizes a REPEATED
// Check, and `bento validate` invoked once still paid the whole of whichever row above it
// landed on.
//
// Unreadable and unstattable paths are skipped rather than raising. The backend refuses
// over one, because there a could-not-look reported as clean is the failure; here the
// answer is a note beside a verdict that is already narrower than the run's. Skipped, but
// not silently: an anchor that went unread reports the answer partial, since an anchor
// nothing could look at yields no credential and would otherwise render as a host holding
// none.
func credentialAliases(set shield.Set, reads, writes []string) ([]enforce.CredentialAlias, bool) {
	want, shielded, unread := aliasableCredentials(set, reads)
	// Nothing to compare against, so no tree is walked. On an ordinary host this is the
	// answer - a credential with one directory entry cannot be hardlink-aliased - and it
	// is what keeps the walk off the granted trees, which can be a whole checkout. Not a
	// clean bill where an anchor went unread: nothing was found there because nothing was
	// looked at.
	if len(want) == 0 {
		return nil, unread
	}
	var out []enforce.CredentialAlias
	// One budget for the whole answer rather than one per grant: what the caller waits for
	// is the sum, and a manifest granting ten trees would otherwise pay ten times the bound.
	budget := aliasBudget
	partial := unread
	seen := map[string]bool{}
	for _, g := range slices.Concat(reads, writes) {
		root := pathresolve.Existing(filepath.Clean(g))
		if seen[root] {
			continue
		}
		seen[root] = true
		found, stopped := aliasesUnder(root, want, &budget)
		partial = partial || stopped
		for _, a := range found {
			// A grant containing the credential itself walks over the shielded path,
			// whose identity is by definition wanted. The shield covers that path; only a
			// second name is a leak.
			//
			// The comparison is by string, across two walks rooted differently - shielded
			// from the anchor, a.Path from the grant - so it holds on two properties.
			// Both roots are canonicalized before the walk (pathresolve.Existing above and
			// at the anchor roots), and WalkDir descends only into a real directory, so
			// every component below either root is one too and the two walks spell the
			// same file identically. Break either and this suppression misses, reporting a
			// shielded credential as an alias of itself.
			if !shielded[a.Path] {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, func(a, b enforce.CredentialAlias) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Credential, b.Credential)
	})
	// Overlapping grants (read: ~ alongside read: ~/project) walk the same file twice.
	return slices.Compact(out), partial
}

// aliasBudget is how many directory entries the granted trees are walked for before the
// answer is cut short. Cost tracks entries rather than bytes: on this host's warm cache a
// 287k-entry module cache took `bento validate` from 40ms to 1.14s, so an entry is a few
// microseconds warm and around five times that cold. The bound puts a walk that goes the
// whole way at roughly 200ms warm - the cost of an answer a reader is waiting on, rather
// than of a whole-tree scan - and a tree small enough to finish inside it, which is most of
// them, is unaffected.
const aliasBudget = 50_000

// aliasableCredentials identifies the shielded credential files that COULD have a second
// name - the ones carrying more than one directory entry - keyed by content identity, and
// the set of their own paths.
//
// The anchor set is denylist's, not a list restated here, and the shields come from the
// set the caller already built: the two together are what decides which stores count, and
// a store bento starts shielding has to arrive here without anyone remembering to add it.
//
// A store a read grant opts back in is skipped, because its shield never engages - the run
// honors that grant as a deliberate exception, so there is no shield for a second name to
// read past.
// The third return says an anchor went unread - a walk error, or a stat that failed - so
// the empty answer that follows is a could-not-look rather than an absence.
func aliasableCredentials(set shield.Set, reads []string) (map[fileID]string, map[string]bool, bool) {
	// A host with no anchors shields nothing at all, and Check has already said so: it
	// asks ShieldSet for the same anchors at gate.go:141, and an error there sets
	// ShieldsUnknown and returns at :142 - before :146, the one call site this has. So the
	// empty set here is that same answer said again rather than a claim, and the third
	// return is left for the anchors that WERE read and could not be walked. Should a
	// second caller reach this without that guard, the drop becomes a real absence
	// reported as one, and this has to raise unread instead.
	homes, _ := denylist.HomeAnchors()
	roots := make([]string, 0, 128)
	for _, a := range denylist.AliasAnchors(homes...) {
		roots = append(roots, pathresolve.Existing(a))
	}
	// A hidden FILE rule is an anchor too: it is named because it holds a secret, and a
	// single file is cheap to stat.
	for _, r := range set.Rules() {
		if r.Deny == denylist.DenyAll && !r.Dir {
			roots = append(roots, pathresolve.Existing(r.Path))
		}
	}
	// A hidden DIRECTORY anchors only where the anchor list names it - except from these
	// two sources, which the anchor list cannot reach, exactly as the backend takes them.
	// A store whose SUBDIRECTORY is relocated into a dotfile farm (the stow/chezmoi/yadm
	// shape) is the case: resolving the anchor covers a whole store moved out from under
	// its own name, and nothing covers the half of one moved out from inside it.
	for _, r := range slices.Concat(set.CallerDenies(), set.CredentialLinks()) {
		if r.Deny == denylist.DenyAll && r.Dir {
			roots = append(roots, pathresolve.Existing(r.Path))
		}
	}
	optIns := shield.Targets(set.OptIns(reads))

	want := map[fileID]string{}
	shielded := map[string]bool{}
	seen := map[string]bool{}
	var unread bool
	for _, root := range roots {
		// Covering rather than equal, as the backend asks it: an anchor NESTED in an
		// opted-in store is opted in too, and skipping only the exact match would report an
		// alias of a credential the run hands over deliberately - a finding the run does
		// not refuse over, which is the one direction this must not go.
		if seen[root] || slices.ContainsFunc(optIns, func(o string) bool { return policy.CoversResolved(o, root) }) {
			continue
		}
		seen[root] = true
		// Walked without following symlinks, so a symlink planted in a credential
		// directory cannot redirect the walk or loop it. A link out of a store is reached
		// as an anchor of its own instead, and only where the shield set already followed
		// it: CredentialLinks keeps to targets inside a home, so a home-manager link into
		// /nix/store - where a deduplicating store hardlinks identical files by design, and
		// an extra link is the normal case - is not chased here either.
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:errcheck // every error is handled in the callback; see the docstring
			if err != nil {
				// A store this host does not have is not a store it could not look at:
				// most anchors are absent on any given home, and counting those would
				// report every ordinary run partial.
				if !nothingBehind(err) {
					unread = true
				}
				return nil //nolint:nilerr // an anchor bento cannot walk yields no finding, reported partial rather than raised
			}
			// Skipped for the reason the backend skips it: a password store keeps its
			// history as content-addressed blobs, and `git clone --local` hardlinks every
			// one of them into the clone. Those links are the user's own copy, made
			// deliberately, so anchoring on a blob would report a clone in a granted tree
			// as an alias the run does not refuse over. The live credential files outside
			// .git still anchor the store.
			if d.IsDir() && d.Name() == ".git" {
				return fs.SkipDir
			}
			if !d.Type().IsRegular() {
				return nil
			}
			id, links, err := identify(d)
			if err != nil {
				if !nothingBehind(err) {
					unread = true
				}
				return nil
			}
			if links < 2 {
				return nil
			}
			shielded[p] = true
			// Two credentials already hardlinked to each other share an identity; the
			// shallower path names the pair predictably.
			if prev, dup := want[id]; !dup || p < prev {
				want[id] = p
			}
			return nil
		})
	}
	return want, shielded, unread
}

// aliasesUnder returns the files under a granted tree whose content is one of want's.
//
// The device prune is what makes this affordable over a large grant: only a directory on a
// device a wanted credential lives on can hold an alias of one. A directory that cannot be
// identified is descended into rather than pruned - the prune asserts nothing below can
// hold a wanted inode, and a failed stat asserts nothing.
//
// budget is the caller's remaining entry allowance, spent here. The second return says
// this stopped short of the tree's end, reported rather than inferred from an exhausted
// budget: a walk whose last entry spends the last of it read the whole tree, and calling
// that partial would put a note in front of a reader with nothing behind it.
//
// Every entry the walk is handed costs one, a pruned directory included. What is BELOW a
// prune is never enumerated and never charged, which is the point of the device prune: it
// buys back budget as well as time.
func aliasesUnder(root string, want map[fileID]string, budget *int) ([]enforce.CredentialAlias, bool) {
	devs := map[uint64]bool{}
	for id := range want {
		devs[id.dev] = true
	}
	var out []enforce.CredentialAlias
	var stopped bool
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:errcheck // every error is handled in the callback; see credentialAliases
		if err != nil {
			return nil //nolint:nilerr // a subtree this cannot read is one the run cannot read either
		}
		if *budget <= 0 {
			stopped = true
			return fs.SkipAll
		}
		*budget--
		if d.IsDir() {
			if id, _, err := identify(d); err == nil && !devs[id.dev] && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if id, _, err := identify(d); err == nil {
			if cred, hit := want[id]; hit {
				out = append(out, enforce.CredentialAlias{Path: p, Credential: cred})
			}
		}
		return nil
	})
	return out, stopped
}

// identify returns a walk entry's content identity and link count. d.Info is a second
// lstat for an entry read from a directory listing, so it fails on its own account - a
// store rewritten mid-scan (an `ssh-keygen`, an `aws sso login`) is enough. The error is
// returned rather than a bare false because the anchor scan reports a could-not-look and
// has to tell that from an entry that is simply gone.
func identify(d fs.DirEntry) (fileID, uint64, error) {
	fi, err := d.Info()
	if err != nil {
		return fileID{}, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, 0, errNoFileID
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino}, uint64(st.Nlink), nil
}

// errNoFileID is a stat this platform answers without the (device, inode) pair a hardlink
// is identified by. Not "nothing behind it": the file is there and its identity is
// unreadable, which is the could-not-look the anchor scan reports.
var errNoFileID = errors.New("no file identity on this platform")

// nothingBehind reports an error that says the path is not there, as against one that says
// bento could not look. Mirrors internal/linux's predicate of the same name, which the
// backend's credential walk raises on: the gate and the run have to agree on which errors
// are an absence, or one reports a store as clean that the other refuses over.
func nothingBehind(err error) bool {
	return errors.Is(err, fs.ErrNotExist) ||
		errors.Is(err, syscall.ENOTDIR) ||
		errors.Is(err, syscall.ELOOP)
}
