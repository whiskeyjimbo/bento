# What a denial looks like from inside the sandbox

Bento enforces the filesystem boundary with mounts, not with a permission check
it can annotate. A denied path is therefore not reported to the program as
denied. It is reported as something ordinary: absent, empty, or read-only.

That inversion is the point of this page. For a human at a terminal it is a
confusing error message. For a program that reacts to errors instead of
reporting them - an autonomous agent most of all - it is a trap, because every
shape below is a plausible fact about a healthy host, and acting on it produces
work that looks correct and is wrong.

## The four shapes

Measured on Linux under the full (bubblewrap) tier, with `read: ~` granted so
the shields are the only thing standing between the program and the file.

| What the program touches | What it sees |
|---|---|
| A hidden directory (`~/.ssh`, `~/.gnupg`, `~/.aws`) | `stat` succeeds. The directory is **empty** - it is a tmpfs mounted over the real one. |
| A hidden file (`~/.netrc`, `~/.claude/.credentials.json`) | `open` succeeds and reads **zero bytes** - it is a bind of an empty file. |
| A child of a hidden directory, or any ungranted path | `ENOENT`, identical to truly absent. |
| A read-only shield (`.git/hooks`, `.gitconfig`) | Reads work and return the real contents. Writes fail with `EROFS`, and creating a new file there also fails with `EROFS`. |

`EACCES` is not on the list. Deny-by-default means an ungranted path is not in
the sandbox's mount namespace at all, so the kernel has nothing to refuse access
*to*; and a shield replaces a path rather than restricting it. Under the
degraded (Landlock-only) tier there is no mount namespace, so the shields are
not applied at all - they surface in `Exposed` instead - and an ungranted path
answers `EACCES` rather than `ENOENT`. An embedder cannot key behavior off the
errno either.

## Why the empty ones are worse than the missing ones

`ENOENT` at least produces a failure. The zero-byte read does not.

An agent that opens a credentials file and gets zero bytes does not conclude the
file is unreadable. It concludes the tool is unconfigured, and does the helpful
thing: re-runs an auth flow, or writes a fresh credential over what it believes
is an empty file. The empty directory reads the same way - an empty `~/.ssh` is
a machine that has never had a key generated on it.

The `ENOENT` case fails more honestly but lands in the same place. The agent
accepts the premise that the file is genuinely absent and codes around it:
vendors a config it could not read, stubs a dependency, adds a fallback branch.

In every case the transcript contains no permission problem, because from inside
the sandbox there was not one. A wrong diff arrives with nothing naming the
cause.

## What an embedder owes its users

**Read the `Report`, not the exit code.** The program's exit code says whether
the program thought it succeeded. It says nothing about what the sandbox took
away from it, and a run that hit every shield can exit 0.

`enforce.Result` carries what the run actually did:

- `Shields []ShieldApplied` - every shield the run engaged, each with a `Path`
  and a `Kind` of `"hidden"`, `"read-only"`, or `"discarded"` (an empty scratch
  directory for a shielded path the host does not have - writable, but nothing
  written there survives the run). This is the recovery: after a run
  that produced a suspicious result, the embedder can name the shielded paths
  rather than leaving the user to guess why their agent vendored a config.
- `ShieldedGrants` - shields a grant deliberately lifted, each by the home-expanded absolute path,
  what it `Holds` (`"credentials"`, `"history"`, ...), and an `OnHost` for the
  case where the granted name is a symlink and the exposure landed elsewhere.
- `Exposed []ShieldApplied` - under the degraded tier, shields that would have
  been applied and were not.
- `Report` - which enforcement layers were live, and at what tier.

The CLI does this already: `bento run` prints a shield count on stderr after a
run that engaged any shield, and the denial legend under full enforcement - which
maps the errnos above to the manifest fields that produced them, and names the
empty-directory and zero-byte shapes separately, since those raise no errno to
map. The legend covers both the clean exit, where nothing else speaks, and the
failure no narrower hint claimed, where the reader is holding one of those errno
strings. Under `--json` it emits the full `shields` array instead. An
embedder that swallows those has taken away the only surface that connects a
wrong answer to its cause.

**Say it in the prompt, for an agent target.** An agent cannot infer this
boundary from the inside - that is what makes it a sandbox. If the target is a
model, the system prompt should state that it is running under a filesystem
policy and that an absent, empty, or read-only file may be a policy artifact
rather than a fact about the host, and that the correct response is to report it,
not to route around it.
