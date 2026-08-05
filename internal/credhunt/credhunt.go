// Package credhunt scans a real home directory for files that LOOK like credentials -
// by mode, by name, and by content shape - and reports the ones no bento shield covers.
//
// IT IS NEVER A GATE. It is a hunting tool a human runs deliberately, reads, and acts
// on. The output is per-host and noisy by construction: it keys on shapes rather than on
// a corpus, so what it finds depends on which tools that particular developer has run.
// Wiring it into `make check` would either flood the gate or force a suppression list,
// and a suppression list here hides exactly the findings the tool exists to surface.
// That framing is the point of the tool, not a caveat on it.
//
// It complements the parity audit rather than duplicating it. That audit diffs against
// firejail and AppArmor, both desktop-application sandboxes, and their shared blind spot
// is the developer token stores (.terraformrc, .m2/settings.xml, .npmrc,
// .composer/auth.json) - measured at 2-of-21 recall against a hand-found set. Shapes are
// the direction that finds those, because a token store looks like a token store whether
// or not any project has listed it.
//
// It also reaches the class the audit records as an accepted residual: an editor leaving
// of an arbitrary dotfile at the home root (.ssh/config.swp, .aws/credentials.bak), which
// holds the same secret under a name no deny-list can enumerate. Those paths are reported
// here in full. Suppressing them because audit.ReviewedGlobs nominally names their shape
// would launder the residual back into invisibility - being enumerable is the whole
// reason to look.
//
// Contents are read to DECIDE, never to REPORT. A finding carries the path, the mode and
// which signals fired; a matched PEM block or bearer token never reaches the output,
// because this output goes into terminals and pasted bug reports.
package credhunt

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// Finding is one credential-shaped file bento does not shield.
type Finding struct {
	// Path is absolute.
	Path string
	// Mode is the file's permission bits, so a reader can weigh a 0600 hit against a
	// world-readable one without re-stat'ing.
	Mode fs.FileMode
	// Signals names the shapes that fired, cheap signals first and the content shapes
	// last, following the order shapesOf tests them in - the sniff runs after the cheap
	// ones, either because one of them narrowed the file or because it sits at the home
	// root. A single signal is a lead; several on one file is close to a certainty.
	Signals []string
}

// Signal names a shape that suggests a file holds a secret. They are reported rather than
// scored: a weight would have to be tuned per host, and the reader is a human who can see
// that ".npmrc, private mode, token-shaped content" is not the same lead as ".vimrc".
const (
	// SignalPrivateMode is the strongest name-independent hint: 0600/0400 is what every
	// tool that writes a secret chooses, and what ssh and gpg refuse to run without.
	SignalPrivateMode = "private-mode"
	// SignalName is the apparmor.d deny vocabulary, which turned out to be name PATTERNS
	// rather than paths - the part of that corpus that transfers to a host bento has
	// never seen.
	SignalName = "name"
	// SignalSuffix catches the config-file naming conventions the pattern vocabulary
	// misses: the developer token stores end in "rc" or "credentials"/"auth" far more
	// often than they contain "key" or "secret".
	SignalSuffix = "suffix"
	// SignalPEM is a private key by its own declaration, wherever it sits and whatever
	// it is called.
	SignalPEM = "pem"
	// SignalToken is a "name = <long opaque string>" assignment, the shape of a stored
	// API token in every ini/toml/netrc-flavored config.
	SignalToken = "token"
	// SignalEditorLeaving is a swap/backup copy of a dotfile. A .swp of ~/.ssh/config or
	// a .bak of ~/.aws/credentials holds the same secret under a name the deny-list
	// cannot enumerate - audit.ReviewedGlobs records exactly this class as an accepted
	// residual. Inside a shielded directory the copy is already covered; at the home root
	// it is not, and making it enumerable is the reason this tool exists.
	SignalEditorLeaving = "editor-leaving"
)

// editorLeavingSuffixes are the endings editors give a swap or backup copy: vim's .swp,
// the generic .bak, emacs' trailing ~ and its numbered ~N~ form.
var editorLeavingSuffixes = []string{".swp", ".swo", ".bak", ".orig", ".save", "~"}

// nameTokens are the apparmor.d private-files deny patterns, reduced to the substrings
// they turn on. They are matched against the file's own name only, not the whole path: a
// path-wide match would fire on every file under ~/.local/share/keyrings, which is
// already shielded whole and would bury the leads that are not.
var nameTokens = []string{"key", "pass", "secret", "cert", "private", "token", "credential", "auth"}

// nameSuffixes are the endings of the developer token stores the upstream corpora miss.
// ".age" is the age(1) encrypted-file extension, which the apparmor vocabulary spells as
// a substring - too short to match as one without catching "package" and "manager".
var nameSuffixes = []string{"rc", "credentials", "token", "auth", ".age", ".pem", ".key", ".p12", ".pfx", ".kdbx"}

// Options are the scan's inputs. Every one is a resolved value rather than an environment
// read, so a test drives the scanner against a planted tree instead of the runner's home.
type Options struct {
	// Home is the directory to walk.
	Home string
	// Rules are the shields to test coverage against - denylist.Home plus
	// denylist.Runtime for a real hunt.
	Rules []denylist.Rule
	// MachineStores are absolute directories to prune as machine-managed content: the
	// language package caches and build caches. Their entries are content-addressed
	// artifacts, not the user's own credential files, so nothing found inside one could
	// become an entry in the home deny-list - and the Go module cache alone writes its
	// files 0600, which measured as 64319 of 74835 hits on one developer home. Left in,
	// the report is unreadable, which for a hunting tool is the same as not working.
	//
	// It is a prune, not a suppression: Hunt reports how many it applied, so the operator
	// sees the tool narrowed and can shorten the list. A silent suppression list here is
	// exactly what would hide the findings this exists to surface.
	MachineStores []string
	// MaxFileSize bounds the content sniff: it is how many bytes of a file's head are
	// read, never a size a file must be under to be looked at. Reading a multi-gigabyte
	// dataset whole to find a PEM header would make the tool unusable on a developer's
	// home, and a secret buried past the first few KB of one is not the class this hunts.
	// A file is never too big to open, though: the token stores put their credential in
	// the first KB and their bulk - a project list, a command history - after it.
	MaxFileSize int64
}

// Hunt walks opts.Home and returns the credential-shaped files no rule in opts.Rules
// covers, sorted by path.
//
// Directories are pruned as soon as a DenyAll rule covers them: everything under a hidden
// store is already unreachable in the sandbox, so descending would report thousands of
// already-covered files and hide the handful that matter. A DenyWrite rule is not
// coverage - see the walk body. Symlinks are never followed -
// a link out of the home would walk the host, and a link within it would report the same
// file twice under two names. That includes the root, whose own type is checked rather
// than assumed: a home that is a link walks nothing, and nothing walked reads as clean.
//
// A file it cannot stat or read is skipped rather than failing the walk. That is the one
// place this tool swallows an error on purpose: it runs over a live home where an
// unreadable socket, a dangling link or a root-owned file is ordinary, and aborting the
// hunt on the first of them would report nothing at all.
func Hunt(opts Options) ([]Finding, int, error) {
	var out []Finding
	pruned := 0
	// Cleaned once, and every comparison below is against this rather than the caller's
	// spelling. The walk asks whether an entry IS the root and whether its parent is, and
	// filepath.Dir hands back a cleaned path: a root spelled with a trailing separator
	// would match neither, switching the home-root sniff off and reporting a clean home.
	home := filepath.Clean(opts.Home)
	// Prepared once for the whole walk: coverage is asked about every entry in the home,
	// and a linear scan of the rule set per entry measured as a third of this function's
	// CPU time. See denylist.Index for why that is a different access pattern rather than
	// a different definition of coverage.
	shields := denylist.NewIndex(opts.Rules)
	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// The root is the exception to the skip-and-continue rule below: a home that
			// cannot be walked yields zero findings, which reads as a clean home. That is
			// the silent wrong answer this tool exists to avoid, so it is the one error
			// worth refusing over.
			if path == home {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// WalkDir Lstats the root, so a home that is itself a symlink - a relocated or
		// bind-mounted home, which HomeAnchors hands over unresolved - is not a directory
		// here. It would fall through to the regular-file drop below and end the walk,
		// reporting a clean home over a scan that never happened. Resolving it here would
		// not fix that so much as break the report the other way: the shields are lexical
		// and anchored on the unresolved path, so a walk over the target matches none of
		// them and every file in the home reads as uncovered. Naming the target is what the
		// operator can act on - a run anchored there has the walk and the shields agreeing.
		if path == home && !d.IsDir() {
			if d.Type()&fs.ModeSymlink == 0 {
				return fmt.Errorf("home %q is not a directory (mode %s)", path, d.Type())
			}
			target, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				return fmt.Errorf("home %q is a symlink that does not resolve: %w", path, resolveErr)
			}
			return fmt.Errorf("home %q resolves to %q: scan that path instead, so the shields anchor where the walk goes", path, target)
		}
		// Only a DenyAll rule counts as covered. DenyWrite leaves the path fully
		// READABLE - it exists to stop a plant, not to hide a secret - so treating it as
		// coverage would prune exactly the trees this hunts: the agent config directories
		// are DenyWrite precisely so the agent can read its own settings, which is why
		// each carries a separate DenyAll rule on the credential file inside it. Those
		// files are what the hunt is looking for.
		if r, covered := shields.Covers(path); covered && r.Deny == denylist.DenyAll {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// A VCS object store inside a credential directory holds the same secrets as
			// loose blobs under names that carry no shape at all, so it contributes only
			// noise. denylist's alias scan makes the same narrowing for the same reason.
			if n := d.Name(); n == ".git" || n == ".hg" || n == ".svn" {
				return fs.SkipDir
			}
			// A source checkout is workspace surface, not home-shield surface: bento
			// governs it through a policy's write grant and denylist.Workspace, so a
			// finding inside one could not become an entry in the home deny-list this
			// hunt feeds. Never the scan root, though: a home that is itself a dotfiles
			// checkout is common, and pruning there scans nothing and reports a clean
			// home - a silent wrong answer, the failure this tool exists to avoid.
			if path != home && isCheckout(path) {
				pruned++
				return fs.SkipDir
			}
			if slices.Contains(opts.MachineStores, path) {
				pruned++
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		// A file that vanished between the walk and the stat cannot be shape-tested; see
		// the function doc for why a live home makes that ordinary rather than fatal.
		if info, statErr := d.Info(); statErr == nil {
			if signals := shapesOf(path, info, opts.MaxFileSize, filepath.Dir(path) == home); len(signals) > 0 {
				out = append(out, Finding{Path: path, Mode: info.Mode().Perm(), Signals: signals})
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, pruned, nil
}

// shapesOf returns the signals a file trips, or nil when it looks like nothing.
//
// The content sniff runs for a file that already tripped a name or mode signal, and for
// any file sitting directly at the home root. Reading every file in a home to look for a
// PEM header would cost a full-tree read for leads the cheap signals have already
// narrowed, and a PEM block in a file with an ordinary name and world-readable mode is a
// certificate, not a hunt result. The home root is the exception because it is the class
// this tool is most for and the one the cheap signals systematically miss: a mode-0644
// ~/.env holding an AWS_SECRET_ACCESS_KEY trips no name token, no suffix, no editor
// leaving and no mode, so nothing but its contents can reach it. The extra reads are the
// few dozen files at the root rather than the thousands under it.
func shapesOf(path string, info fs.FileInfo, maxSize int64, atHomeRoot bool) []string {
	var signals []string
	name := strings.ToLower(info.Name())

	if perm := info.Mode().Perm(); perm != 0 && perm&0o077 == 0 {
		signals = append(signals, SignalPrivateMode)
	}
	if slices.ContainsFunc(nameTokens, func(t string) bool { return strings.Contains(name, t) }) {
		signals = append(signals, SignalName)
	}
	if slices.ContainsFunc(nameSuffixes, func(s string) bool { return strings.HasSuffix(name, s) }) {
		signals = append(signals, SignalSuffix)
	}
	// Only for a dotfile: an editor leaving of an ordinary document is not this class, and
	// counting one would bury the dotfile copies that are.
	if strings.HasPrefix(name, ".") && (slices.ContainsFunc(editorLeavingSuffixes, func(s string) bool { return strings.HasSuffix(name, s) }) || numberedBackup(name)) {
		signals = append(signals, SignalEditorLeaving)
	}
	// Sized on the READ, not on the file: a file's own size says nothing about whether it
	// holds a credential. A real ~/.claude.json carries an oauth token in its first few KB
	// behind ~96 KB of project history, and the shell and editor histories that accumulate
	// an exported token are larger still. The bound belongs on what contentShapes reads.
	if (len(signals) > 0 || atHomeRoot) && info.Size() > 0 {
		signals = append(signals, contentShapes(path, maxSize)...)
	}
	// A private mode on its own is a weak prior, not a shape: measured on a developer
	// home it fires on 64319 files, essentially all of them package-cache artifacts that
	// are 0600 by construction. It stays a reported signal - it is what distinguishes a
	// real store from a sample config once something else has flagged the file - but it
	// cannot carry a finding alone. The content sniff still runs for a mode-only file, so
	// an unnamed 0600 file with a key inside surfaces on its contents.
	if len(signals) == 1 && signals[0] == SignalPrivateMode {
		return nil
	}
	return signals
}

// contentShapes reports the secret shapes a file's first bytes carry. It returns nothing
// for a file it cannot open, which on a live home is ordinary rather than exceptional.
func contentShapes(path string, maxSize int64) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// The head is read whole and split here rather than scanned. A bufio.Scanner gives up on
	// a line longer than its buffer and reports it only through Err(), so a config written
	// as one long line - minified JSON, a generated toml - would look identical to a clean
	// file. maxSize bounds the read either way, so splitting costs the same and has no
	// give-up path to forget to check.
	// A read that failed partway still returns the bytes it got, and those are shape-tested
	// rather than discarded: a file this hunt has already decided to open is a candidate,
	// and dropping a PEM header that was read because the read later hit an I/O error is
	// the same silent give-up the scanner used to produce.
	head, _ := io.ReadAll(&io.LimitedReader{R: f, N: maxSize})

	var signals []string
	for line := range strings.SplitSeq(string(head), "\n") {
		if !slices.Contains(signals, SignalPEM) && strings.HasPrefix(strings.TrimSpace(line), "-----BEGIN ") && strings.Contains(line, "PRIVATE KEY") {
			signals = append(signals, SignalPEM)
		}
		if !slices.Contains(signals, SignalToken) && tokenAssignment(line) {
			signals = append(signals, SignalToken)
		}
		if len(signals) == 2 {
			break
		}
	}
	return signals
}

// tokenAssignment reports whether a line assigns a long opaque value to a secret-named
// key - "password = hunter2" in an ini, "token: ghp_..." in a yaml, "_authToken=..." in
// an .npmrc. The value length floor is what separates a stored token from a setting: a
// short value is a mode or a boolean, and matching those would make every config file a
// finding.
func tokenAssignment(line string) bool {
	i := strings.IndexAny(line, "=:")
	if i < 0 {
		return false
	}
	key := strings.ToLower(strings.Trim(line[:i], " \t\"'"))
	if !slices.ContainsFunc(nameTokens, func(t string) bool { return strings.Contains(key, t) }) {
		return false
	}
	value := strings.Trim(line[i+1:], " \t\"',")
	if len(value) < 20 || strings.ContainsAny(value, " \t") {
		return false
	}
	// A path or a URL assigned to a key-named setting (ssh's IdentityFile, a cert path in
	// a tool config) is a pointer to a secret, not the secret - and the file it points at
	// is hunted on its own shape.
	return !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "~") && !strings.Contains(value, "://")
}

// isCheckout reports whether dir is the root of a version-controlled working tree. Only
// the root is tested, because pruning there prunes the whole tree beneath it.
func isCheckout(dir string) bool {
	for _, marker := range []string{".git", ".hg", ".svn"} {
		if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

// numberedBackup reports whether name ends in emacs' numbered-backup form, "~<n>~".
func numberedBackup(name string) bool {
	rest, ok := strings.CutSuffix(name, "~")
	if !ok {
		return false
	}
	i := strings.LastIndexByte(rest, '~')
	if i < 0 || i == len(rest)-1 {
		return false
	}
	return strings.IndexFunc(rest[i+1:], func(r rune) bool { return r < '0' || r > '9' }) < 0
}
