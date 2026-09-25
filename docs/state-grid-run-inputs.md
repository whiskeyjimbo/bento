# State grid: run-input self-protection

Area: the files a sandboxed run's launcher reads or trusts vs the run's own write grants.
`gate/manifest.go` (`ManifestProblems`), `cmd/bento/run.go` (load, approval, gate, the
`ReadOnlyPaths` bind), `cmd/bento/validate.go` (`loadDocument`), `trust/trust.go`
(`Inspect`), `cmd/bento/profile.go` (`snapshotOut`/`unchanged`, `mergeExisting`),
`cmd/bento/approve.go` (`writeManifestAtomically`, `selfWriteGrants`), `cmd/bento/hook.go`,
`cmd/bento/journal.go` + the journal shield in `internal/denylist/denylist.go`,
`internal/linux/shields.go` (`findWorkspaceEntries`).

## Phase 0 - fit

Good fit. Mirror pair: the gate (`gate.ManifestProblems`, called by run, validate, approve
and the hook) against the enforcer (one read-only bind on `mt.RealPath`,
`enforce.Options.ReadOnlyPaths`), which by its own comment holds only its own name and
delegates every other shape to the gate. Repeat-fix history confirmed afterwards (five fix
commits since 265a790). One-sided invariant:

- A run may refuse an input its grants could not actually replace; it must never launch
  with, or later trust, an input its own write grants can replace, redirect, or create.

## Phase 1 - dimensions (from the code)

- INPUT: manifest file (M); the manifest's named-path chain (symlinks and dirs between the
  name given and the file); `profile --out` (O); the approval journal (J); agent project
  config and other read-back (A).
- REACH: no grant; grant rooted at the leaf's dir; grant starting above the dir; symlinked
  component in a writable dir; hardlink (existing, or created after launch); name relative
  or with `..`; created or swapped during the run.

Grids split per input; inputs do not interact. 30 cells. Grid was written (cells, no
verdicts) before the bug history or tracker was read.

## Grid M - manifest (run, validate, approve, hook share `gate.ManifestProblems`)

| # | Reach | Verdict |
|---|-------|---------|
| M1 | no write grant reaches the manifest, single link | HANDLED - `gate/manifest.go:52` returns no problem; nothing in the sandbox can write it. READING |
| M2 | write grant rooted at the manifest's own dir | HANDLED - `gate/manifest.go:56-60` allows it: the dir is the grant's mount point, cannot be renamed; bind at `cmd/bento/run.go:183` covers the leaf. READING |
| M3 | write grant starting above the manifest's dir | HANDLED - refused `gate/manifest.go:57-59`. EXECUTION (existing `TestManifestProblemsNamesEveryWayAroundTheBind`) |
| M4 | manifest leaf is a symlink in a writable dir | HANDLED - `gate/manifest.go:41-51`. EXECUTION (same test) |
| M5 | a directory component is a symlink in a writable dir | HANDLED - same loop, `at` resolved via the parent (`gate/manifest.go:46-48`). EXECUTION (same test) |
| M6 | symlink component in a NON-writable dir, target under a grant | HANDLED - link not writable so not flagged, and the real file is then judged by M2/M3 at `gate/manifest.go:52-60`. READING |
| M7 | manifest under a grant, nlink > 1 | HANDLED - `gate/manifest.go:61-65`. EXECUTION (same test) |
| **M8** | manifest OUTSIDE every grant, second hard link INSIDE a write grant | **WRONG (forbidden direction)** - `gate/manifest.go:52-54` returns before the link-count check at :61 whenever the real path is not under a write grant. The other name sits under the grant's RW mount, the RO bind is per-mount, so the run can rewrite and re-stamp its manifest in place. `enforce/run.go` ReadOnlyPaths comment ("Outside every write grant nothing can write it anyway") makes the same wrong assumption. VERIFIED BY SPIKE (gate returns no problem) + VERIFIED BY READING (per-mount RO semantics; no sandbox run executed) |
| M9 | hard link created by the run after launch | IMPOSSIBLE - the manifest is visible in-sandbox only through its RO bind (a separate mount), and `linkat` across mounts fails EXDEV; where it is visible through the grant's own mount that is M2/M3/M7. Enforced by the kernel, not by bento code. VERIFIED BY READING |
| M10 | name given relative | HANDLED - `filepath.Abs` at `gate/manifest.go:26`. READING |
| **M11** | name contains `..` after a symlink component | **WRONG (forbidden direction)** - `run.go:88` opens `args[0]` with kernel (physical) `..` resolution, but `gate/manifest.go:26` `filepath.Abs` cleans `..` lexically, so the gate judges a different file (and a different symlink chain) than the one loaded and bound. With a decoy at the lexical path, a manifest below a write grant's root is admitted. Contrived (the operator must type such a name, or a wrapper must build one). Fix shape: judge `mt.RealPath` plus the chain of the name as the kernel walks it, not a re-cleaned string. VERIFIED BY SPIKE |
| M12 | write grant spelled through a symlink | HANDLED - `resolvedGrant` `gate/manifest.go:81-86` resolves it as the sandbox binds it. READING |
| M13 | write grant absent at launch | HANDLED - compared as spelled (`gate/manifest.go:85`); an absent grant cannot be an ancestor of an existing manifest's real path unless it is lexically one, which is then caught. READING |
| M14 | nlink unreadable on this host | HANDLED - refused, `gate/manifest.go:61-62` (allowed direction). READING |
| M15 | degraded tier with manifest under a write grant | HANDLED - refused per `enforce/run.go` ReadOnlyPaths contract. UNVERIFIED (read the doc comment only, not the refusal site) |
| M16 | file swapped between load (`run.go:88`) and gate (`run.go:113`) | UNHANDLED by design of the grid - an interleaving, not a state; route to concurrency-audit. The bind uses the fd-derived `mt.RealPath`, the gate re-resolves the name; same root cause as M11. UNVERIFIED |
| M17 | hook path | HANDLED - `cmd/bento/hook.go:86,93,102` Abs then load then gate, then emits `bento run <abs>`; inherits M8 and M11 (M11 only if `--manifest` carries `..`). READING |

## Grid O - `bento profile --out`

| # | Reach | Verdict |
|---|-------|---------|
| O1 | program rewrites --out bytes | HANDLED - `profile.go:161,297`, `unchanged` byte compare `profile.go:1919`. READING |
| O2 | program creates --out where none was | HANDLED - `absent` compare, same site. READING |
| O3 | program plants a link at --out (incl. dangling) | HANDLED - `Readlink` compare `profile.go:1920-1924`. READING |
| O4 | program swaps a parent dir of --out for a symlink to its own dir with identical bytes | HANDLED DOWNSTREAM - `unchanged` checks only the leaf link, so the merge proceeds and `writeManifestAtomically` (`approve.go:514`) writes into the program's dir; but the draft carries no stamp, and approve/run by the named path refuse the writable symlink (M5). By its real path it is M2 or M3. Allowed-direction gap only, worth a leaf-to-root check if tightening. VERIFIED BY READING |
| O5 | missing parent of --out created as a symlink by the program (first run) | HANDLED DOWNSTREAM - `trust.InspectNew` resolves the chain (`trust.go:244`), write lands at the resolved location; same downstream refusal as O4. READING |
| O6 | program replaces --out with a hard link to its own identical copy | HANDLED - the atomic rename (`approve.go:544`) replaces the name with a fresh inode; the program's copy keeps the old bytes. READING |
| O7 | the draft lands where a later run's grants can replace it | HANDLED - no stamp is written by profile, and approve refuses via `approve.go:86` (M-grid gate). Inherits M8/M11. READING |

## Grid J - approval journal

| # | Reach | Verdict |
|---|-------|---------|
| J1 | home write grant covering `~/.local/state/bento` | HANDLED - DenyWrite shield `internal/denylist/denylist.go:1028-1045`. READING |
| J2 | `$XDG_STATE_HOME` relocated | HANDLED - `homeLocations` adds the XDG location (`denylist.go:1978,1999`), matching `journalDir` (`journal.go:87`), both dropping a relative base. READING. Cross-file claim; parity test not checked |
| J3 | journal dir shared-writable | HANDLED - `requirePrivateJournal` degrades to "untrusted", never trusted (`journal.go:320-331`). READING |

## Grid A - agent project config and other read-back

| # | Reach | Verdict |
|---|-------|---------|
| A1 | agent config entry is a symlink under a write grant | HANDLED - refused `internal/linux/shields.go:317-324`. READING |
| A2 | agent config is a real entry under a write grant | HANDLED - DenyWrite shield `shields.go:327`. READING |
| A3 | entrypoint script under a write grant | HANDLED as disclosure only - `selfWriteGrants` (`approve.go:394`) reports it; the launcher does not trust script content for policy, so outside this invariant. READING |

## Counts

30 cells: HANDLED 25 (incl. 2 downstream, 1 disclosure-only), WRONG 2 (M8, M11, both
forbidden direction), IMPOSSIBLE 1 (M9), UNHANDLED 1 (M16, routed to concurrency-audit),
UNVERIFIED-stamped HANDLED 1 (M15).

## Phase 2 re-open pass

- `26ae603` (refuse a manifest its write grants can replace) fixed M3/M7 but gated the
  hardlink check behind "real path is under a write grant", leaving M8.
- `1cb6954` (symlinked dirs in a manifest's name) fixed M5 on the lexically cleaned name,
  leaving M11.
- `5148209`/`5a76121` (--out) fixed O1-O3 at the leaf; O4/O5 fall to the downstream gate.

## Rejected

- O4/O5 as a forbidden-direction bug: nothing trusts the redirected draft; approve and run
  refuse it. Allowed-direction only.
- A3: script content is not a launcher input for policy.
- Cross-manifest restamping (run A with a write grant over manifest B): outside "own write
  grants"; the unkeyed stamp is a known design and `stampNote` flags an unrecorded stamp.

## Spikes

`gate/spike_runinputs_test.go` (deleted): M8 and M11 both failed the safe-behaviour
assertion, confirming the finding. Recommended for graduation into
`gate/manifest_test.go` as the regression tests for the two fixes.

## Regression tests to graduate

Package `gate_test`, `//go:build unix`. Both fail today; graduate into `gate/manifest_test.go`.

```go
// M8 (bv2-q1rmx)
func TestSpikeHardlinkOutsideGrant(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	safe := filepath.Join(root, "safe"); w := filepath.Join(root, "w")
	os.Mkdir(safe, 0o755); os.Mkdir(w, 0o755)
	m := filepath.Join(safe, "m.yaml")
	os.WriteFile(m, []byte("entrypoint: x\n"), 0o644)
	if err := os.Link(m, filepath.Join(w, "copy.yaml")); err != nil { t.Fatal(err) }
	if p := gate.ManifestProblems(m, &policy.Policy{Write: []string{w}}); len(p) == 0 {
		t.Errorf("no problem reported for a manifest writable through a hard link in %s", w)
	}
}

// M11 (bv2-xlbhd)
func TestSpikeDotDotAfterSymlink(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	w := filepath.Join(root, "w"); deep := filepath.Join(w, "sub", "deeper")
	os.MkdirAll(deep, 0o755)
	os.WriteFile(filepath.Join(w, "sub", "m.yaml"), []byte("entrypoint: x\n"), 0o644)
	x := filepath.Join(root, "x"); os.Mkdir(x, 0o755)
	os.WriteFile(filepath.Join(x, "m.yaml"), []byte("decoy\n"), 0o644)
	os.Symlink(deep, filepath.Join(x, "lnk"))
	if p := gate.ManifestProblems(x+"/lnk/../m.yaml", &policy.Policy{Write: []string{w}}); len(p) == 0 {
		t.Errorf("gate judged the lexical decoy, not the opened file under the write grant")
	}
}
```
