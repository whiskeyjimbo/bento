// Package gate answers what this host will refuse about a policy, without building a
// sandbox or running anything.
//
// It is the question `bento validate` asks, reachable as a library: an embedder can put
// the same verdict in front of a manifest it is about to run, and get it in the words the
// run would have refused with, rather than meeting them at the run's first step.
//
// The verdict is a property of the HOST, not of the manifest. A policy this host refuses
// may be exactly right where it is meant to run, which is why nothing here returns a
// pass/fail: Check reports what it found and the caller decides what that is worth.
//
// It answers as much of the backend's checkGrants as can be answered without a sandbox,
// and the narrowings are all in the direction of missing a refusal rather than inventing
// one - a gate that refuses what a run accepts is worse than one that passes something
// the run then stops. Grants must already be resolved to host paths: a manifest's own
// relative spelling anchors to the manifest, which is the caller's to resolve before
// asking, since only the caller knows where the manifest came from.
package gate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/internal/grantrefusal"
	"github.com/whiskeyjimbo/bento/internal/pathresolve"
	"github.com/whiskeyjimbo/bento/internal/shield"
	"github.com/whiskeyjimbo/bento/policy"
)

// Runnability is what this host makes of the program a manifest names. Parsing and
// approval do not answer it: a moved entrypoint or a typo'd interpreter passes both and
// fails at the run's first step - the CI case, where the manifest is checked on one
// machine and the failure lands on another.
//
// It is a property of the host, not of the manifest, so it is reported beside the
// approval rather than folded into it: an unrunnable manifest here may be exactly right
// where it is meant to run.
type Runnability struct {
	// Problems are the reasons this host cannot START what the manifest names - a moved
	// entrypoint, an interpreter off PATH. Worded as run words them, since that is the
	// message the reader will meet if they ignore this one.
	Problems []string
	// Refusals are the grants run will not honor: a shielded path, a symlink loop, a write
	// grant that already exists as a file. Separate from Problems because they are a
	// different failure - nothing here is unstartable, and reporting them as "this host
	// cannot start what the manifest names" sends the reader hunting an entrypoint that is
	// fine. Both still refuse a run, so a strict caller fails on either.
	Refusals []string
	// FileishWrites are write grants that name nothing on this host and are spelled like
	// a file. Not a problem, because nothing here can know: run creates the directory and
	// the script may well have meant one. Silence is still wrong - write grants name
	// directories, so a grant meant as a file leaves a host directory called
	// `output.json` and the file the script wanted never appears.
	FileishWrites []string
	// MissingReads are read grants naming nothing on this host. Not a problem: a grant
	// may name a path the script creates, or one that exists only on the target machine.
	// Silence is still wrong - the grant matches nothing, the sandbox denies quietly, and
	// that is the failure run's own epilogue warns is hard to diagnose.
	MissingReads []string
	// CredentialAliases are the paths inside the granted trees that reach a shielded
	// credential's content by a second name - the hardlink a `cp -al` snapshot, an
	// `rsync --link-dest` backup or a whole-tree deduplicator leaves behind. A shield
	// hides a path, not the content behind it, so the run reads one straight past the
	// shield and refuses before the script's first instruction.
	//
	// A refusal there and only a finding here, which is the one place this package reports
	// something the run refuses over without calling it one. The run's refusal is lifted by
	// `--accept-alias`, a flag of the run and deliberately not a field of the policy
	// (enforce.RunOptions.AcceptAliasesUnder), so nothing here can know whether this run
	// will be refused - and refusing on the caller's behalf would refuse what a run
	// accepts, the one direction this package rules out. A strict caller must not fail on
	// it for that reason; a reader is meant to decide between removing the alias,
	// narrowing the grant, and acknowledging the tree.
	//
	// Empty is not a clean bill. Only the hardlink half is answered - a bind alias needs
	// the mount table - and only over the trees the manifest grants rather than everything
	// the run binds. Both narrowings only miss a finding, as does the entry budget
	// CredentialAliasesPartial reports.
	CredentialAliases []enforce.CredentialAlias
	// CredentialAliasesPartial says the scan did not look everywhere it would have to for
	// an empty list to be a clean bill. Three things set it: the entry budget, because the
	// scan is on `bento validate`'s default path and a granted module cache took it from
	// 40ms to 1.14s on a host holding one hardlinked key; a credential anchor this host
	// could not read or stat, which is a could-not-look and not an absence; and a platform
	// with no hardlink identity to read at all, where no tree is walked. What is above
	// still holds - a finding here is a finding - and what is not there was not looked
	// for. Said out loud rather than left to the silence, which otherwise means the trees
	// were read whole and nothing was found.
	CredentialAliasesPartial bool
	// Unresolved marks a question nothing here answered: the caller could not resolve the
	// manifest's paths and signals that by passing a nil policy, so every field above is
	// empty because none was asked. Reported as unknown rather than as a pass - that host
	// refuses the run for the same reason, and an empty findings set here is
	// indistinguishable from a manifest a healthy host has nothing to say about.
	Unresolved bool
	// ShieldsUnknown marks the narrower gap: this host cannot work out where its shields
	// anchor, so CredentialAliases could not be answered and is empty for that reason
	// rather than for want of anything to report, and Refusals holds only the classes the
	// shield set has no part in. Every other field above is a
	// fact about the manifest and the filesystem that the shield set has no part in, and
	// stands. Said separately from Unresolved because a consumer that folds them reports
	// the half this host is sure of as unknown, or the half it is not as clean.
	ShieldsUnknown bool
	// ShieldsUnknownReason is why, in the anchoring failure's own words - the text doctor
	// prints as shield_anchors. Carried beside the bool rather than left to doctor because
	// a reader whose host cannot anchor otherwise learns THAT it could not and has to run
	// a second command to learn WHY, and the two commands then disagree about how much of
	// the same host fact each is allowed to say. Empty exactly when ShieldsUnknown is
	// false.
	ShieldsUnknownReason string
	// ShieldCarveUnknown says the carve half of the grant check was answered over the
	// BUILT-IN shields only. A run also derives shields from the checkout under each write
	// grant that is a directory - its git hook directory, its editor task files - and
	// internal/linux assembles those from host facts a cross-platform package cannot ask
	// for, so ShieldCarveProblems never sees them. Refusals is therefore short of any carve
	// refusal earned by one, and a grant whose only uncarvable mount point is a git hook
	// directory is refused at the run's first step after passing here. Said out loud
	// because an unknown reported as a pass is not the narrowing the package doc permits.
	//
	// Only the carve half: the other two narrowings ShieldedReadProblems' doc enumerates
	// over the derived shields stay accepted, for the reasons stated there.
	//
	// A note rather than a verdict, where ShieldsUnknown is a verdict: that one says this
	// host refuses every run whatever the manifest says, and this one says one class of
	// refusal was answered short on a host that otherwise runs the manifest fine.
	ShieldCarveUnknown bool
}

// Check asks the resolved policy - the one naming host paths - what run would find.
// Passing the manifest's own spelling instead would stat a relative entrypoint against
// whatever directory the caller happened to run from. Resolve into a copy: resolving an
// approved manifest's policy in place makes it read as stale against its own stamp.
func Check(resolved *policy.Policy) Runnability {
	if resolved == nil {
		return Runnability{Unresolved: true}
	}
	var r Runnability
	if _, err := os.Stat(resolved.Entrypoint); err != nil {
		r.Problems = append(r.Problems, fmt.Sprintf("entrypoint %q: %v", resolved.Entrypoint, err))
	}
	// An empty interpreter means the entrypoint runs itself: a compiled binary. LookPath
	// covers both spellings the backend accepts - a bare name searched on PATH, and a
	// path checked where it points.
	if resolved.Interpreter != "" {
		if _, err := exec.LookPath(resolved.Interpreter); err != nil {
			r.Problems = append(r.Problems, fmt.Sprintf("interpreter %q not found: %v", resolved.Interpreter, err))
		}
	}
	r.Problems = append(r.Problems, WorkdirProblems(resolved)...)
	r.FileishWrites = FileishWrites(resolved.Write)
	r.MissingReads = MissingReads(resolved.Read)
	// A host that cannot anchor its shields refuses every run, and it cannot say which
	// shielded grants that run would have refused - so ShieldsUnknown marks the list short
	// of those, and the alias scan, which walks the shielded stores, is not attempted. The
	// looped, file-write, root-write and mount refusals are facts about the manifest and
	// the filesystem that the shield set has no part in, so they are still answered
	// against the zero set, as Refusals does and as validate's summary prints them.
	set, err := shieldSet()
	refused := Refusals(set, err, resolved)
	r.Refusals = refused.Grants
	r.ShieldCarveUnknown = refused.CarveUnknown
	if err != nil {
		r.ShieldsUnknown = true
		r.ShieldsUnknownReason = err.Error()
		return r
	}
	r.CredentialAliases, r.CredentialAliasesPartial = credentialAliases(set, resolved.Read, resolved.Write)
	return r
}

// derivesWorkspaceShields answers whether a run would derive any workspace shields from
// these write grants at all, which is the one condition internal/linux's shieldRules skips
// on: a grant that is not an existing directory is not a checkout and derives nothing, so
// ShieldCarveProblems is the whole answer for such a manifest and marking it unknown would
// be noise. Asked of where the grant lands, as ShieldCarveProblems asks it.
//
// A stat, not a shield derivation: this says only that the derived half is non-empty, and
// which rules it holds stays internal/linux's to know.
//
// Deliberately coarser than the run's own carve set, which keeps only the derived mount
// points a grant actually reaches and the host does not already have (internal/linux's
// shieldNeeded). Asking that here would need the anchors and the checkout walk this package
// cannot reach, so the unknown is raised wherever the half is non-empty - which on a real
// host is most manifests holding a directory write grant. Coarse the safe way: the flag
// says a question was not asked, and asking it of fewer grants than the run does would put
// the silence back.
func derivesWorkspaceShields(writes []string) bool {
	for _, w := range writes {
		lands, _ := pathresolve.Existing(w)
		if fi, err := os.Stat(lands); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// WorkdirState is what this host makes of a manifest's workdir. It is a state rather
// than a sentence because three answerers need the same verdict in three wordings - the
// gate's report, approve's refusal to stamp, and the profiler's proposal - and the two
// commits that built this predicate each wrote it for one of them and left the others
// answering a different question about the same host.
type WorkdirState int

const (
	// WorkdirStartable is an unset workdir, one that exists as a directory, and an absent
	// one a write grant at or beneath it materializes before the sandbox exists.
	WorkdirStartable WorkdirState = iota
	// WorkdirRelative is a workdir this package's precondition rules out: it would be
	// stat'd against the embedder's own working directory here, and the backend refuses
	// it outright (internal/linux, "workdir %q is not absolute").
	WorkdirRelative
	// WorkdirUndetermined is a workdir whose existence could not be established - an
	// unreadable ancestor, a symlink loop. Distinct from absence because the remedies a
	// reader reaches for on hearing "does not exist" (create it, grant it) are not the
	// problem, and because a path neither side of a containment test could resolve makes
	// that test a comparison of two unwalked strings.
	WorkdirUndetermined
	// WorkdirNotDirectory is a workdir that exists as something else. bwrap's chdir into
	// one fails with ENOTDIR (measured), and nothing the sandbox binds turns a host file
	// into a directory there - a write grant naming it is refused as a file before the
	// sandbox exists, and a shield over a file is an empty read-only bind, still a file.
	WorkdirNotDirectory
	// WorkdirUnreachable is a workdir that is absent with no write grant at or beneath
	// it. A grant merely COVERING it is not enough: a read grant binds the host tree as
	// it is, so the absent child stays absent inside the sandbox.
	WorkdirUnreachable
)

// WorkdirCheck answers what this host makes of the resolved policy's workdir, for the
// reasons WorkdirState gives. Stat rather than Lstat, so a symlink to a directory stays
// the directory it names.
//
// Absence alone is not the answer: a write grant at or beneath the workdir is created
// before the sandbox exists and bound inside it, so `workdir: ./out` beside
// `write: [./out]` starts fine on a host where ./out has never existed - the shape a
// re-profile of a manifest that already sets that workdir writes back. Refusing that
// would refuse a run that works, the one direction this package rules out.
//
// The write grants are the whole of what materializes an absent path, which is why they
// are the whole of what is consulted. A built-in shield at an absent directory is mounted
// only where a write grant reaches it too - the backend's shieldNeeded takes `exists ||
// writable`, and for an absent path that is `writable` alone - so `workdir: ~/.aws`
// beside `read: [~]` gets no tmpfs and does not start. Measured against the backend's
// shield emission, not reasoned from the mount shapes, and held by internal/linux's
// TestAbsentDenyAllIsShieldedOnlyWhereAWriteGrantReachesIt - which lives there because
// the claim is only constructible at denyArgs, which is unexported. The grant-derived
// half of the shield set, which the gate does not carry at all (see ShieldedReadProblems'
// last paragraph), changes nothing here for a different reason: its directory-shaped
// rules - .git/hooks, .vscode, .idea, .husky, a resolved core.hooksPath
// (internal/denylist.Workspace, internal/linux/autoexec.go) - leave a directory a
// directory at that path under either shield shape, and its file-shaped ones
// (.git/config, .cargo/config.toml) name paths that are host FILES, which this already
// answers as WorkdirNotDirectory. A derived rule that shielded a host DIRECTORY as a file
// would end that, and nothing executable pins it: see bv2-kxv8p.
func WorkdirCheck(resolved *policy.Policy) WorkdirState {
	if resolved == nil || resolved.Workdir == "" {
		return WorkdirStartable
	}
	if !filepath.IsAbs(resolved.Workdir) {
		return WorkdirRelative
	}
	if fi, err := os.Stat(resolved.Workdir); err == nil {
		if fi.IsDir() {
			return WorkdirStartable
		}
		return WorkdirNotDirectory
	}
	// Not "the stat failed, so it is absent": EACCES on an ancestor fails the stat over a
	// directory that is there. pathresolve is the one thing here that tells those apart,
	// and its Unreadable arm also says the path below was never placed - so the grant
	// comparison must not run on it, or a lexical match between two unwalked strings
	// passes for the containment CoversResolved asserts.
	lands, outcome := pathresolve.Existing(resolved.Workdir)
	if outcome != pathresolve.OK {
		return WorkdirUndetermined
	}
	for _, g := range resolved.Write {
		if grant, _ := pathresolve.Existing(g); policy.CoversResolved(lands, grant) {
			return WorkdirStartable
		}
	}
	return WorkdirUnreachable
}

// WorkdirProblems reports a manifest workdir this host cannot start the run in, in the
// words a reader of the gate meets. The backend chdirs into it after the sandbox is
// already built (internal/linux --chdir), so without this the manifest validates clean
// and dies at a step that has already paid for the mount namespace - the exact class
// Runnability exists to report first.
//
// Exported for the same reason Refusals is: approve has to refuse what the run refuses,
// and a workdir predicate reachable only through Check is one the stamp gate never asks.
// It is not folded INTO Refusals because that set is grants - clampProposal asks it per
// grant to decide what to withhold, and a workdir fact there would withhold a grant over
// something that is not about any grant.
//
// It says nothing about a workdir that EXISTS as a directory on the host but has nothing
// granted beneath it, which the enforced run also refuses. Answering that needs the
// sandbox's whole bind set - the runtime scratch, the system trees, the shield mounts -
// and a gate that enumerates them refuses a run the moment one moves. `bento profile`
// names that case instead, where the proposal is being written.
//
// One path escapes that and is left alone: a PROFILING run covers HOME with an empty
// tmpfs, so a manifest whose workdir is a home that is not on the host starts under
// `bento profile` and is reported here. An absent home is rare, the report is only ever
// read beside a run that did start, and buying the exception means telling this function
// which mode it is predicting.
func WorkdirProblems(resolved *policy.Policy) []string {
	switch WorkdirCheck(resolved) {
	case WorkdirStartable:
		return nil
	case WorkdirRelative:
		return []string{fmt.Sprintf("workdir %q is not absolute, so nothing here can say where the run would start; resolve the policy first (manifest.Resolve) or write the path out in full", resolved.Workdir)}
	case WorkdirUndetermined:
		return []string{fmt.Sprintf("workdir %q could not be read on this host, so bento cannot say whether the run can start there - a directory above it is unreadable, and whether the workdir itself exists stayed unknown", resolved.Workdir)}
	case WorkdirNotDirectory:
		return []string{fmt.Sprintf("workdir %q exists on this host but is not a directory, so the run cannot start there", resolved.Workdir)}
	case WorkdirUnreachable:
		return []string{fmt.Sprintf("workdir %q does not exist on this host and no write grant is at or beneath it, so the run cannot start there", resolved.Workdir)}
	}
	return nil
}

// Refusals is every grant this host will not honor for a reason the manifest holds, in
// the words run refuses them with: the whole of the backend's checkGrants that the gate
// can answer from here. It is NOT the run's whole refusal set - preflightGrants runs
// checkGrants and then the credential-alias scan, which is a finding rather than a refusal
// here, for the reason ShieldedReadProblems' last paragraph gives. One
// function because every reader of it - a validate verdict, a refusal to stamp an
// approval, an embedder's preflight - has to agree on the set, and a check added to only
// one of them is how a manifest gets stamped for a permission that does not exist.
//
// A host that cannot work out where the shields anchor answers against a zero shield set
// rather than raising: a run there is refused for that same reason, so failing here would
// only rename it. What comes back is not empty, though - four of the six classes are facts
// about the manifest and the filesystem that the set has no part in, and only the two
// shielded ones go quiet. So the list is quietly SHORT of the shield refusals rather than
// absent. It says so itself now, in RefusalSet's two qualifications, rather than leaving
// each caller to ask ShieldSet a second time and word the shortfall for itself - which is
// how the carve shortfall reached validate and no other reader of the same set.
//
// The set is the caller's, with the error ShieldSet raised beside it, for the reason
// ShieldedReadProblems gives: a CLI asking five times over one manifest walks the
// credential stores once, and the anchoring failure is the caller's to render in its own
// words.
func Refusals(set shield.Set, anchorErr error, resolved *policy.Policy) RefusalSet {
	shieldedReads := ShieldedReadProblems(set, resolved.Read)
	shieldedWrites := ShieldedWriteProblems(set, resolved.Write)
	problems := append(shieldedReads, shieldedWrites...)
	problems = append(problems, LoopedGrantProblems(resolved.Read, resolved.Write)...)
	problems = append(problems, FileWriteGrantProblems(resolved.Write)...)
	problems = append(problems, RootWriteProblems(resolved.Write)...)
	problems = append(problems, MountGrantProblems(resolved.Read, resolved.Write)...)
	problems = append(problems, ShieldCarveProblems(set, resolved.Read, resolved.Write)...)
	out := RefusalSet{Grants: problems, AnchorErr: anchorErr}
	// Only where the shields anchored: an unanchored host answered the carve half against
	// a zero set, which is the larger unknown AnchorErr already carries, and raising both
	// tells the reader the same thing twice in the smaller of the two wordings.
	if anchorErr == nil {
		out.CarveUnknown = derivesWorkspaceShields(resolved.Write)
	}
	return out
}

// RefusalSet is what this host will not honor about a policy's grants, together with what
// the answer is SHORT of - the two qualifications Check computes and a []string could not
// carry. Every reader of the refusal set gets both from one call: a caller that asks only
// Grants gets exactly the old answer, and one that gates on it - a stamp, a proposal - can
// say which half of the question went unanswered instead of reading an empty list as a
// clean bill.
type RefusalSet struct {
	// Grants is the refusals themselves, in the words run refuses them with.
	Grants []string
	// AnchorErr is the ShieldSet error the caller passed in, non-nil where this host could
	// not work out where its shields anchor. Grants is then short of the two shielded
	// classes, and the reason is here rather than only in the caller's own second ask, so
	// every reader of the set can say WHY it is short and not merely that it is.
	AnchorErr error
	// CarveUnknown says the carve half of the check was answered over the BUILT-IN shields
	// only, for the reason Runnability.ShieldCarveUnknown gives at length. It is asked of
	// the write grants rather than of the set, so a caller that assembled the derived
	// rules into its own set gets it raised anyway and should ignore it.
	CarveUnknown bool
}

// LoopedGrantProblems reports the grants whose symlinks loop, read and write alike, since
// the backend refuses either kind on the same fact and in the same sentence.
//
// ELOOP is the one stat error that decides anything here. It is the answer the backend
// itself acts on (internal/linux checkGrantNotLooped matches ELOOP and nothing else), so
// parity holds on every other error too: a grant bento cannot stat because a directory
// above it is unreadable says nothing about what run will find, since the sandbox sees
// that tree as a different user.
//
// Asked of the kernel and not of pathresolve's Loop arm, for the reason checkGrantNotLooped
// spells out: Loop is that resolver's budget running out, which neither implies nor is
// implied by the link count the kernel refuses on.
//
// Asked of the grant AS SPELLED, where the three functions below ask where the grant lands:
// the backend stats filepath.Abs(g), and a chain longer than the kernel's link budget onto
// a directory that exists resolves perfectly well (filepath.EvalSymlinks has its own, far
// larger budget) while the kernel refuses to walk it. Resolving first would stat the target
// and pass a grant the run refuses. TestLoopedGrantProblemsRefusesOnlyLoops carries that
// row against internal/linux's TestCheckGrantNotLoopedRealFilesystem.
func LoopedGrantProblems(read, write []string) []string {
	var problems []string
	seen := map[string]bool{}
	// One host fact, said once: the same path may be granted for reading and for writing,
	// and the backend refuses on the first of them it reaches.
	for _, g := range slices.Concat(read, write) {
		if seen[g] {
			continue
		}
		seen[g] = true
		// Abs fails only where the process has no working directory to anchor a relative
		// spelling to, and the backend refuses the whole policy there. Skipped rather than
		// raised: nothing about the grant was shown to be wrong, and missing a refusal is
		// the direction this package narrows in.
		abs, err := filepath.Abs(g)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); errors.Is(err, syscall.ELOOP) {
			problems = append(problems, grantrefusal.Looped(g).Error())
		}
	}
	return problems
}

// FileWriteGrantProblems reports the write grants that already exist as something other
// than a directory, in the words the backend refuses them with - the case validate exists
// to catch before run's first step.
//
// Asked of where the grant LANDS, as RootWriteProblems asks it and as prepareWriteDirs
// stats it: run resolves the grant physically, so a ".." popping over a symlink lands
// somewhere a lexical filepath.Clean does not - and Cleaning here refuses a grant the run
// honors, the one direction this package rules out. It also disposes of the trailing slash
// `dir/file.txt/`, which stats as ENOTDIR unspelled-away and would otherwise be neither a
// problem nor a note, while run refuses it as the file it is - except where the resolver's
// depth budget hands the path back verbatim, and the ENOTDIR is refused in the unstattable
// sentence instead. Both refuse, so the wording is the whole of the difference.
//
// A stat that fails for anything but absence or a loop is a refusal too, in the same
// sentence prepareWriteDirs' default arm refuses it with. It is asked here and not narrowed
// away as an unstattable READ is (MissingReads): a read grant is one the sandbox binds as
// another user's view of the tree, while a write grant is statted by the invoking user
// before any sandbox exists, so what fails here is exactly what fails there. Absence is
// not a problem - the backend creates the directory - and a loop is LoopedGrantProblems'
// sentence, which the backend also words for itself.
func FileWriteGrantProblems(write []string) []string {
	var problems []string
	for _, g := range write {
		lands, _ := pathresolve.Existing(g)
		fi, err := os.Stat(lands)
		switch {
		case err == nil && !fi.IsDir():
			problems = append(problems, grantrefusal.WriteIsFile(g).Error())
		case err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ELOOP):
			problems = append(problems, grantrefusal.WriteUnstattable(g, err).Error())
		}
	}
	return problems
}

// RootWriteProblems reports a write grant of the host root. The shield mirrors skip "/"
// the way the backend's shield checks do - because checkWriteNotRoot has already refused
// it in a sentence naming the whole filesystem rather than whichever dotfile sorts first
// - so without this the gate passes the one grant that defeats the sandbox outright.
//
// Asked of where the grant LANDS, as the backend asks it: checkWriteNotRoot runs on grants
// resolveGrants has already made symlink-free, so a write naming a link into "/" is refused
// there, and testing the spelling alone here would let that one through. Resolved without
// a filepath.Clean first: Clean pops ".." lexically, over a symlink, and the run pops it
// physically - a gate that Cleans refuses a grant the run lands somewhere else entirely
// and honors.
func RootWriteProblems(write []string) []string {
	if slices.ContainsFunc(write, isRootWrite) {
		return []string{grantrefusal.WriteIsRoot().Error()}
	}
	return nil
}

// isRootWrite reports whether a write grant lands on the host root. One function because
// the shield mirrors skip exactly what RootWriteProblems refuses: a grant the two answer
// differently about is refused in nobody's words, or in the wrong ones.
func isRootWrite(g string) bool {
	lands, _ := pathresolve.Existing(g)
	return g == "/" || lands == "/"
}

// MountGrantProblems reports the grants that land on a host process's /proc/<pid>
// directory or on a pseudo-filesystem the sandbox mounts fresh, mirroring
// checkGrantNotProcess and checkGrantNotManagedMount. Neither is an exotic grant -
// `read: /tmp` is a line an author writes without thinking - and both refuse a run at its
// first step, so a gate that passes over them green-lights a manifest that cannot run.
//
// Both the managed-mount set and the per-process predicate are shared (denylist) rather
// than mirrored: the backend and the gate are compiled for different platforms, so either
// restated here would drift the moment the other moved.
//
// Existence is asked of the process case for the reason the backend asks it: a grant on a
// pid that is not running says nothing about the sandbox's procfs, and refusing it here
// would be a refusal the run does not make.
func MountGrantProblems(read, write []string) []string {
	var problems []string
	seen := map[string]bool{}
	for _, g := range slices.Concat(read, write) {
		if seen[g] {
			continue
		}
		seen[g] = true
		lands, _ := pathresolve.Existing(g)
		if i := slices.Index(denylist.ManagedMounts, lands); i >= 0 {
			problems = append(problems, grantrefusal.GrantIsManagedMount(g, lands, denylist.ManagedMounts[i]).Error())
			continue
		}
		if denylist.IsProcessPath(lands) {
			if _, err := os.Stat(lands); err == nil {
				problems = append(problems, grantrefusal.GrantIsProcess(g, lands).Error())
			}
		}
	}
	return problems
}

// shieldSet is the seam Check reads the shield set through, so a test can reach the
// unanchored-host branch: making HomeAnchors fail for real needs a uid with no passwd home.
var shieldSet = ShieldSet

// ShieldSet is the run's shield set as far as the CLI can build it: the same anchors, the
// same rules, the same symlink expansion and the same drops, from internal/shield - the
// package the backend answers with too, so the gate cannot predict a refusal the run does
// not raise or miss one it does. It stops one rule short of a run's own set, the
// caller-supplied denies an embedder passes in, which no manifest can be checked against
// from here; that narrowing only ever misses a refusal.
//
// Walked fresh on every call, and it is not cheap: 4.7ms on a developer home against
// 36us to hand back a memoized one. It was memoized for the process, keyed on the
// environment, which is wrong for a library - the set is walked off DISK, and a
// credential store a sibling ssh-keygen creates, a checkout cloned under a write grant or
// a relocation symlink repointed all move it with the environment untouched. A long-lived
// embedder asking twice would have got the first answer forever, in both directions: a
// refusal for a shield that has since gone, which the package doc above puts as the worse
// of the two, and a pass for a grant that now reaches a credential store.
//
// A caller asking repeatedly holds the set instead, which also fixes the lifetime the
// memo could not: Check walks once for the whole verdict, and the CLI - where five asks
// over one manifest is what the memo was for - caches it for the one command.
func ShieldSet() (shield.Set, error) {
	anchors, err := denylist.HomeAnchors()
	if err != nil {
		return shield.Set{}, err
	}
	return shield.Assemble(shield.Host(), anchors, denylist.RuntimeDir(), nil), nil
}

// ShieldedReadProblems and ShieldedWriteProblems report the grants the run's shield checks
// refuse, in the words they refuse them with. They are the counterpart to the shield
// opt-ins (shield.Set.OptIns): those name the read grants a run honors as a warned
// exception, these name the grants a run will not honor at all - which a caller otherwise
// passes over in silence, leaving the refusal to land at the run's first step on a
// manifest the CI gate green-lit.
//
// The set is the caller's, from ShieldSet - which is where the one error either of these
// could raise stays, asked once by a caller that already needs it for the rest of its
// answer. A zero set refuses nothing, which is what a host with no anchors deserves: a run
// there is refused for that same reason.
//
// Between them they ask shield.Set.Contains, the same question the run asks, so the three
// refusals arrive in the order and the wording a run would have printed - a grant that
// trips more than one (a write naming a shield exactly is both inside it and above it) is
// reported the way the run reports it:
//
//   - a grant at or inside a DenyAll shield. A read naming one exactly is the deliberate
//     opt-in shield.Set.OptIns reports instead; a write of the same path is not, which
//     is the asymmetry this exists to say out loud, and why the two kinds are refused in
//     different sentences with only one offering the opt-in as a remedy.
//   - a write at or inside a DenyWrite shield, which has no opt-in at all.
//   - a write containing a DenyAll shield.
//
// The grants are the policy's resolved ones, and they are symlink-resolved before the
// comparison because the run compares grants its own resolution has already made
// symlink-free. The refusal still quotes the grant as the
// manifest spells it and the shield as the deny-list does, which is what each reader is
// looking at.
//
// The rest of checkGrants is answered elsewhere in the gate: the root write by
// RootWriteProblems, the process and managed-mount grants by MountGrantProblems, the
// looped grant by LoopedGrantProblems.
//
// Six narrowings remain against a run, all in the direction that only misses a refusal.
// The set omits the caller-supplied denies an embedder passes in, which no manifest can be
// checked against from here.
//
// Three come of the gate passing no workspace shields - the ones derived per write grant
// from the checkout under it, which is state the gate would have to walk the grant to
// reconstruct, and which internal/linux computes off host facts a cross-platform package
// cannot reach. Two are refusals over those shields: the redirected-workspace-shield one
// (checkWorkspaceShieldNotRedirected), which is about a symlink on this host rather than
// anything the manifest says; and the UnderWriteShield a SECOND grant earns by naming one
// of them, which the manifest does say - `write: /proj` alongside `write: /proj/.git/hooks`
// is refused by the run and reported Honored here. The third is the workspace half of
// ShieldNotCarvable: the refusal itself is answered over the built-in shields by
// ShieldCarveProblems, which catches the case it exists for - a write grant on a system
// tree such as /etc - and misses only a grant whose sole uncarvable mount point is one of
// those derived shields.
//
// The fifth is AboveWriteShield, which the degraded tier alone refuses: the gate does not
// know which tier will run, and raising it would refuse write: ~/.pyenv for every full-tier
// run. Counted here for the same reason the credential alias below is - a run does refuse
// it - and argued at the arm that declines it, in writeShieldProblem.
//
// And the credential-alias refusal is not in this set at all - the one narrowing that is
// not a missing case but a missing check. preflightGrants runs checkGrants and then scans
// for a second readable name (a hardlink, a bind) reaching a shielded credential's inode
// from inside a tree the run exposes, and refuses on one. So an empty refusal set does not
// mean the run honors every grant. It stays out because that refusal is conditional on
// `--accept-alias`, a flag of the run and deliberately not a field of the policy
// (enforce.RunOptions.AcceptAliasesUnder), so a gate raising it would refuse what a run
// accepts - the one direction the package doc above rules out. Check answers what it can
// of it as a finding instead: Runnability.CredentialAliases.
func ShieldedReadProblems(set shield.Set, reads []string) []string {
	optIns := shield.Targets(set.OptIns(reads))
	var problems []string
	for _, g := range reads {
		landed, _ := pathresolve.Existing(g)
		r, v := set.Contains(landed, shield.Read, optIns, nil)
		// Enumerated rather than defaulted to one sentence: the InsideShield wording
		// offers the read opt-in, which exists for bento's own shields and not for an
		// embedder's deny. The arms mirror the backend's checkNotShielded so the two
		// cannot word the same verdict differently.
		switch v {
		case shield.InsideShield:
			problems = append(problems, grantrefusal.InsideShield(g, r.Path).Error())
		case shield.InsideCallerShield:
			problems = append(problems, grantrefusal.InsideCallerShield(g, r.Path).Error())
		case shield.FoldedShield:
			problems = append(problems, grantrefusal.FoldedShield(g, r.Path).Error())
		case shield.Honored:
		case shield.UnderWriteShield, shield.AboveShield, shield.AboveWriteShield:
			// Write-only verdicts: Contains cannot reach any of them under shield.Read. It is
			// one early return in Contains that makes that true, and nothing here would stop
			// compiling if it moved, so the property is pinned where it lives -
			// internal/shield's TestAReadGrantEarnsNoWriteOnlyVerdict.
		}
	}
	return problems
}

func ShieldedWriteProblems(set shield.Set, writes []string) []string {
	var problems []string
	for _, g := range writes {
		// Skipped for the reason the backend skips it: a write of "/" is refused by
		// checkWriteNotRoot first, in a sentence that names the whole filesystem rather
		// than whichever dotfile happens to sort first. Asked of where the grant LANDS,
		// as RootWriteProblems asks it - the backend's own skip reads a grant resolveGrants
		// has already made symlink-free, and the gate's has not been.
		if isRootWrite(g) {
			continue
		}
		if p, ok := writeShieldProblem(set, g); ok {
			problems = append(problems, p)
		}
	}
	return problems
}

// ShieldCarveProblems reports the write grants whose tree the run cannot carve its own
// shield mount points into, in the words the backend's checkShieldsCarvable refuses them
// with. A grant on a directory this uid cannot create entries in (a system tree such as
// /etc or /opt, drwxr-xr-x root root) makes bwrap die during setup, and the launcher then
// reports nothing but an unattested silent stage - so the manifest's own `write:` line has
// to be named here, before the launch, where the author can act on it.
//
// Built-in shields only, which is the narrowing: the workspace shields a run derives per
// write grant from the checkout under it are assembled from host facts internal/linux
// reads and this package cannot, so a grant whose only uncarvable mount point is a git
// hook directory passes here and is refused by the run. That is the direction the package
// doc permits - missing a refusal, never inventing one - and it leaves the case the
// refusal exists for, a write grant on a system tree, answered. Check marks that half
// Runnability.ShieldCarveUnknown, since a short list nothing says is short reads as a
// clean one, which is not a narrowing but a silence.
//
// Answered for the DEFAULT tier, which is why the degraded tier not running
// checkShieldsCarvable at all is no reason to demote this to a finding the way the
// AboveWriteShield arm of writeShieldProblem is demoted: that verdict is the rare opt-in
// tier's alone, this one is the tier every run lands on unless the caller opts out. What
// opts out is a posture of the RUN (--allow-degraded, enforce.RunOptions.AllowDegraded) and
// no part of the manifest, so nothing the gate is given says it will be taken - and the
// callers that act on this refusal carry no such posture of their own. The clamp
// withholds a proposal on this refusal through Refusals rather than knowing about it
// (cmd/bento's TestClampProposalWithholdsAGrantWhoseShieldsCannotBeCarved), and approve
// declines to stamp on it, so a grant dropped from the set here is one both hand to a run
// that dies at its first step.
//
// Only the mount points are asked, not the intermediate directories bwrap would create to
// hold one: both walks end at the same deepest EXISTING ancestor, which is the directory
// that has to accept the mkdir, so asking the parents again would only repeat this answer.
func ShieldCarveProblems(set shield.Set, reads, writes []string) []string {
	resolved := make([]string, 0, len(writes))
	for _, w := range writes {
		lands, _ := pathresolve.Existing(w)
		resolved = append(resolved, lands)
	}
	optIns := shield.Targets(set.OptIns(reads))

	var problems []string
	for _, a := range set.Mount(set.Rules()) {
		mount := a.Resolved
		// The mount points bwrap CREATES: a shield the host already has needs no mkdir.
		// A nonexistent one is shielded only where a write grant could otherwise create
		// it, which is also what makes its parent a read-write bind - so reachability
		// from the writes is the whole of shieldNeeded that survives here, the
		// grant-reachability half being implied by it.
		if _, err := os.Stat(mount); err == nil || !reachableFrom(mount, resolved) {
			continue
		}
		// An exact opt-in read grant wins over a DenyAll shield, so no mount point is
		// carved for it - the same skip the backend's shieldNeeded takes first.
		if a.Rule.Deny == denylist.DenyAll && slices.Contains(optIns, mount) {
			continue
		}
		// bwrap makes the whole missing chain, so the directory that has to accept the
		// mkdir is the deepest ancestor already there. The walk terminates at "/".
		parent := filepath.Dir(mount)
		for !exists(parent) {
			parent = filepath.Dir(parent)
		}
		if writableDir(parent) {
			continue
		}
		for i, w := range resolved {
			if policy.CoversResolved(w, mount) {
				problems = append(problems, grantrefusal.ShieldNotCarvable(writes[i], mount, parent).Error())
				break
			}
		}
	}
	return problems
}

// reachableFrom mirrors the backend's reachable: a shield is touched by a grant when
// either contains the other, since a grant inside a shield exposes part of it and a grant
// above one exposes the whole.
func reachableFrom(path string, grants []string) bool {
	for _, g := range grants {
		if path == g || policy.CoversResolved(g, path) || policy.CoversResolved(path, g) {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MissingReads returns the already-resolved read grants naming nothing on this
// host, in the order they were declared. Only a path that is absent is worth reporting:
// a grant bento cannot stat for any other reason - a directory above it the invoker
// cannot traverse - says nothing about whether the sandbox will reach it, since the
// sandbox binds it as a different user's view of the tree.
//
// Read grants only. A write grant that names nothing is created by the backend, so its
// absence before the run is not a miss.
func MissingReads(read []string) []string {
	var missing []string
	for _, g := range read {
		if _, err := os.Stat(g); errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, g)
		}
	}
	return missing
}

// FileishWrites returns the already-resolved write grants naming nothing on this
// host whose last element is spelled like a file. Write grants name directories, so the
// backend creates one - and a grant meant as a file leaves `out.json/` on the host while
// the file the script wanted lands inside it, where no later grant names it.
//
// A guess about a naming convention, so every caller reports it as a note and none as a
// verdict: a strict caller must not fail on it. A versioned directory (`python3.11`, `conf.d`)
// reads as file-ish here and is knowingly accepted noise - the alternative is a list of
// extensions that is wrong the first time someone writes to a directory nobody thought
// of. A name with no extension at all (`Makefile`) is missed for the same reason.
//
// Write grants only. A read grant naming nothing is MissingReads' answer, and it is
// a different one: nothing is created for it.
func FileishWrites(write []string) []string {
	var fileish []string
	for _, g := range write {
		lands, _ := pathresolve.Existing(g)
		if _, err := os.Stat(lands); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// A name that is all extension is a dotfile - `.env`, `.cache` - which is an
		// ordinary directory name and not a signal of anything. A trailing slash is
		// stripped by Base, so a grant that spells the directory out stays flagged: the
		// backend treats the two spellings identically, and so does the mistake.
		base := filepath.Base(g)
		if ext := filepath.Ext(base); ext != "" && ext != base {
			fileish = append(fileish, g)
		}
	}
	return fileish
}

// writeShieldProblem reports the refusal a write grant trips, or ok false where it trips
// none. The workspace shields are not passed: they are derived per write grant from the
// checkout under it, which is state the gate would have to walk the grant to reconstruct.
// Two refusals stay unmirrored for it, not one - the redirected-workspace-shield refusal,
// which never goes through Contains at all, and the UnderWriteShield a second grant
// spelled at or inside one of those shields earns from the workspace loop inside it. Both
// only miss a refusal; the second is the one a manifest alone can trigger, so it is the
// one a reader of a clean verdict here has to know is unanswered.
func writeShieldProblem(set shield.Set, g string) (string, bool) {
	landed, _ := pathresolve.Existing(g)
	r, v := set.Contains(landed, shield.Write, nil, nil)
	switch v {
	case shield.InsideShield:
		return grantrefusal.WriteInsideShield(g, r.Path).Error(), true
	case shield.InsideCallerShield:
		// The caller's sentence for both kinds, as the backend's checkNotShielded words it:
		// the write sentence calls the path always-shielded and explains the missing opt-in
		// as the credential plant, and an embedder's deny is neither - its reason is a trust
		// domain the manifest must not talk its way out of.
		return grantrefusal.InsideCallerShield(g, r.Path).Error(), true
	case shield.UnderWriteShield:
		return grantrefusal.WriteUnderReadOnlyShield(g, r.Path).Error(), true
	case shield.AboveShield:
		return grantrefusal.WriteAboveShield(g, r.Path).Error(), true
	case shield.FoldedShield:
		return grantrefusal.FoldedShield(g, r.Path).Error(), true
	case shield.Honored:
		return "", false
	case shield.AboveWriteShield:
		// The one verdict a run raises that the gate deliberately does not: only the
		// degraded tier refuses it, because only that tier has no bind to enforce the
		// shield with, and the gate does not know which tier will run. Reporting it would
		// refuse write: ~/.pyenv for every full-tier run, which is the direction the
		// package doc rules out.
		return "", false
	}
	// Unreachable: the switch above names every verdict, and the exhaustive linter fails
	// the build for one that arrives without an arm here - which is what pins the
	// enumeration, since nothing would stop compiling.
	//
	// Silent rather than a guessed refusal, matching ShieldedReadProblems and the backend's
	// checkNotShielded. A new verdict is not a refusal the run necessarily raises: the
	// backend answers a write in four checks, only the first of which this mirrors, and one
	// added to internal/shield without a matching check is honored by the run. Refusing it
	// here would refuse what the run accepts, the one direction the package doc rules out,
	// and it would do so in a sentence about a shield the grant may be nowhere near.
	return "", false
}
