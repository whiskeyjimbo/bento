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
	// Unresolved marks a host that could not answer at all: the caller could not resolve
	// the manifest's paths and signals that by passing a nil policy, or this host cannot
	// work out where its shields anchor. Reported as unknown rather than as a pass -
	// either host refuses the run for that same reason, and an empty refusal set here is
	// indistinguishable from a manifest a healthy host has nothing to refuse about.
	Unresolved bool
}

// Check asks the resolved policy - the one naming host paths - what run would find.
// Passing the manifest's own spelling instead would stat a relative entrypoint against
// whatever directory the caller happened to run from. Resolve into a copy: resolving an
// approved manifest's policy in place makes it read as stale against its own stamp.
func Check(resolved *policy.Policy) Runnability {
	if resolved == nil {
		return Runnability{Unresolved: true}
	}
	// A host that cannot anchor its shields refuses every run, and it cannot say which
	// grants that run would have refused - so the answer is unknown rather than the empty
	// refusal set a host with nothing to refuse yields, which is what the same manifest
	// looks like on a healthy host.
	set, err := ShieldSet()
	if err != nil {
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
	r.Refusals = refusals(set, resolved)
	r.FileishWrites = FileishWrites(resolved.Write)
	r.MissingReads = MissingReads(resolved.Read)
	return r
}

// Refusals is every grant this host will not honor for a reason the manifest holds, in
// the words run refuses them with: the whole of the backend's checkGrants that the gate
// can answer from here. It is NOT the run's whole refusal set - preflightGrants runs
// checkGrants and then the credential-alias scan, and that scan is unmirrored, for the
// reason ShieldedReadProblems' last paragraph gives. One
// function because every reader of it - a validate verdict, a refusal to stamp an
// approval, an embedder's preflight - has to agree on the set, and a check added to only
// one of them is how a manifest gets stamped for a permission that does not exist.
//
// A host that cannot work out where the shields anchor yields no problems rather than an
// error: a run there is refused for that same reason, so failing here would only rename
// it. Callers that need to distinguish the two ask ShieldSet, which reports the error.
func Refusals(resolved *policy.Policy) []string {
	set, _ := ShieldSet()
	return refusals(set, resolved)
}

// refusals is the set against a shield set the caller already has, so Check pays for one
// walk of the credential stores rather than two.
func refusals(set shield.Set, resolved *policy.Policy) []string {
	shieldedReads := ShieldedReadProblems(set, resolved.Read)
	shieldedWrites := ShieldedWriteProblems(set, resolved.Write)
	problems := append(shieldedReads, shieldedWrites...)
	problems = append(problems, LoopedGrantProblems(resolved.Read, resolved.Write)...)
	problems = append(problems, FileWriteGrantProblems(resolved.Write)...)
	problems = append(problems, RootWriteProblems(resolved.Write)...)
	return append(problems, MountGrantProblems(resolved.Read, resolved.Write)...)
}

// LoopedGrantProblems reports the grants whose symlinks loop, read and write alike, since
// the backend refuses either kind on the same fact and in the same sentence.
//
// ELOOP is the one stat error that decides anything here. It is the answer the backend
// itself acts on (internal/linux checkGrantNotLooped matches ELOOP and nothing else), so
// parity holds on every other error too: a grant bento cannot stat because a directory
// above it is unreadable says nothing about what run will find, since the sandbox sees
// that tree as a different user.
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
		if _, err := os.Stat(filepath.Clean(g)); errors.Is(err, syscall.ELOOP) {
			problems = append(problems, grantrefusal.Looped(g).Error())
		}
	}
	return problems
}

// FileWriteGrantProblems reports the write grants that already exist as something other
// than a directory, in the words the backend refuses them with - the case validate exists
// to catch before run's first step.
//
// Cleaned before it is statted, because `dir/file.txt/` stats as ENOTDIR and would
// otherwise be neither a problem nor a note - while run resolves the trailing slash away
// and refuses it as the file it is.
func FileWriteGrantProblems(write []string) []string {
	var problems []string
	for _, g := range write {
		if fi, err := os.Stat(filepath.Clean(g)); err == nil && !fi.IsDir() {
			problems = append(problems, grantrefusal.WriteIsFile(g).Error())
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
// there, and testing the spelling alone here would let that one through.
func RootWriteProblems(write []string) []string {
	for _, g := range write {
		if g == "/" || pathresolve.Existing(filepath.Clean(g)) == "/" {
			return []string{grantrefusal.WriteIsRoot().Error()}
		}
	}
	return nil
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
		lands := pathresolve.Existing(filepath.Clean(g))
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
// Three narrowings remain against a run, all in the direction that only misses a refusal.
// The set omits the caller-supplied denies an embedder passes in, which no manifest can be
// checked against from here. The redirected-workspace-shield refusal is not raised at
// all: those shields are derived per write grant from the checkout under it, which is
// state the gate would have to walk the grant to reconstruct, and the refusal is about a
// symlink on this host rather than anything the manifest says.
//
// And the whole credential-alias refusal is unmirrored - the one narrowing that is not a
// missing case but a missing check. preflightGrants runs checkGrants and then scans for a
// second readable name (a hardlink, a bind) reaching a shielded credential's inode from
// inside a tree the run exposes, and refuses on one. Nothing here answers it, so an empty
// refusal set does not mean the run honors every grant. It stays out rather than being
// approximated because the refusal is conditional on `--accept-alias`, a flag of the run
// and deliberately not a field of the policy (enforce.RunOptions.AcceptAliasesUnder), so a
// gate that raised it would refuse what a run accepts - the one direction the package doc
// above rules out.
func ShieldedReadProblems(set shield.Set, reads []string) []string {
	optIns := shield.Targets(set.OptIns(reads))
	var problems []string
	for _, g := range reads {
		r, v := set.Contains(pathresolve.Existing(g), shield.Read, optIns, nil)
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
		case shield.UnderWriteShield, shield.AboveShield:
			// Write-only verdicts: Contains cannot reach either under shield.Read.
		}
	}
	return problems
}

func ShieldedWriteProblems(set shield.Set, writes []string) []string {
	var problems []string
	for _, g := range writes {
		// Skipped for the reason the backend skips it: a write of "/" is refused by
		// checkWriteNotRoot first, in a sentence that names the whole filesystem rather
		// than whichever dotfile happens to sort first.
		if g == "/" {
			continue
		}
		if p, ok := writeShieldProblem(set, g); ok {
			problems = append(problems, p)
		}
	}
	return problems
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
		if _, err := os.Stat(filepath.Clean(g)); !errors.Is(err, fs.ErrNotExist) {
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
// checkout under it, which is state the gate would have to walk the grant to reconstruct,
// so that one refusal stays unmirrored - in the direction that only misses one.
func writeShieldProblem(set shield.Set, g string) (string, bool) {
	r, v := set.Contains(pathresolve.Existing(g), shield.Write, nil, nil)
	switch v {
	case shield.InsideShield, shield.InsideCallerShield:
		return grantrefusal.WriteInsideShield(g, r.Path).Error(), true
	case shield.UnderWriteShield:
		return grantrefusal.WriteUnderReadOnlyShield(g, r.Path).Error(), true
	case shield.AboveShield:
		return grantrefusal.WriteAboveShield(g, r.Path).Error(), true
	case shield.FoldedShield:
		return grantrefusal.FoldedShield(g, r.Path).Error(), true
	case shield.Honored:
		return "", false
	}
	// Only Honored means no problem. A verdict added to shield and not named above is a
	// refusal the run raises, and reporting none green-lights a manifest that dies at its
	// first step - so it is reported in the nearest sentence instead, which can be wrong
	// about the remedy where silence would be wrong about the outcome.
	return grantrefusal.WriteInsideShield(g, r.Path).Error(), true
}
