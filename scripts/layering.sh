#!/bin/sh
# Checks the two architectural boundaries this codebase claims, mechanically, because an
# invariant asserted only in prose is one nobody notices breaking. docs/architecture.md
# says kernel enforcement is confined to the platform backend, and ADR-0012 says one
# package answers shield containment; neither survives a refactor on its own.
#
# 1. KERNEL ENFORCEMENT IS CONFINED. The packages that speak to the kernel's isolation
#    primitives - seccomp filters, Landlock rulesets, the in-sandbox launcher, the ptrace
#    observer - are importable only by the platform backend and by each other. This is
#    the import-level claim, which is the true one: raw syscalls for terminal control and
#    stat are used elsewhere and legitimately (see the note in docs/architecture.md).
#
# 2. ONE PACKAGE ASSEMBLES THE SHIELD RULE SET. internal/shield owns turning the deny-list
#    into the shields a run applies, so the enforcer, the validate gate and the profiler
#    clamp cannot answer "is this grant shielded" three different ways again - which is
#    exactly what they did before ADR-0012. Reading the deny-list as DATA is a different
#    thing and stays open: the credential hunt and the upstream parity audit both do it,
#    and neither decides what a run shields.
#
# Both checks carry an explicit exception list rather than a pattern loose enough to admit
# them. An exception is printed on every run: one that stops being needed should be
# noticed, and one that is about to be copied should be read first.
#
# The second check is textual, so it assumes the deny-list is reached by its own package
# name: an aliased or dot import would slip past it. That is the trust boundary, and it is
# a shallow one on purpose - the alternative is a type-checked analyzer for a rule that
# takes one line of grep to state.
#
# Exit codes: 0 clean, 1 a boundary was crossed, 2 the check could not run.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo" || exit 2

status=0

# The kernel isolation primitives, and who may reach them. internal/linux is the platform
# backend the enforce.Enforcer seam leads to; internal/launcher is the process that runs
# inside the sandbox and applies the filters; the landlock probe is that package's own
# capability test; backend dispatches the launcher's re-exec, which is how the in-sandbox
# process is entered at all.
kernel_pkgs='internal/seccomp
internal/landlock
internal/launcher
internal/observe'

kernel_importers='github.com/whiskeyjimbo/bento/internal/linux
github.com/whiskeyjimbo/bento/internal/launcher
github.com/whiskeyjimbo/bento/internal/landlock/internal/probe
github.com/whiskeyjimbo/bento/backend'

# Every platform the tree claims to compile for, matching crossbuild's list. go list only
# reports the files whose build constraints match, so the host pass alone cannot see an
# import inside a _other.go or a GOARCH-tagged file - and this repo splits exactly that
# way (backend/backend_other.go, cmd/bento/tty_other.go). A boundary that holds only on
# the build you happen to run is the silent pass this check exists to prevent.
#
# Test imports count too. A test that reaches a filter package from outside the backend is
# a dependency the next non-test caller will copy, and it compiles in CI either way.
imports=""
for platform in linux/amd64 linux/arm64 darwin/arm64; do
	goos=${platform%/*}
	goarch=${platform#*/}
	pass=$(GOWORK=off GOOS="$goos" GOARCH="$goarch" go list -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./...) || {
		echo "layering: go list failed for $platform" >&2
		exit 2
	}
	imports="$imports
$pass"
done

pattern=$(echo "$kernel_pkgs" | tr '\n' '|' | sed 's/|$//')
offenders=$(echo "$imports" | awk -v pat="($pattern)\$" '{
	for (i = 2; i <= NF; i++) {
		if ($i ~ pat) print $1 " imports " $i
	}
}' | sort -u | while read -r line; do
	pkg=${line%% *}
	if ! echo "$kernel_importers" | grep -qxF "$pkg"; then
		echo "$line"
	fi
done)

if [ -n "$offenders" ]; then
	echo "layering: kernel enforcement is meant to stay inside the platform backend, but:" >&2
	echo "$offenders" | sed 's/^/  /' >&2
	echo "  If this is deliberate, add the package to kernel_importers in $0 and say why." >&2
	status=1
fi

# Every way a rule reaches a run's shield set: the built-in constructors, and a Rule
# written out by hand - which is how the whole grant-derived family is built, and was
# invisible here while only the constructors were matched. Assembling any of them is
# internal/shield's job; the exceptions below say what else does and why.
assemblers='denylist\.Home\(|denylist\.Relocated\(|denylist\.Runtime\(|denylist\.Workspace\(|denylist\.Rule\{'

shield_assemblers='internal/shield
internal/linux
internal/denylist/audit
internal/credhunt
cmd/credhunt
cmd/bento'

# cmd/bento is the exception that should not outlive the epic: foreignHomeShields still
# builds its own rules for a home OTHER than the profiler's, to report grants reaching it.
# That is a different question from what a run shields - the run shields only the home it
# executes as - so it is not a fourth answer to this one, but it is the last place outside
# internal/shield that builds rules at all. Tracked as bv2-pj8x.8.
#
# internal/linux is not reading rules as data: workspaceShields and gitDirShields really do
# assemble part of a run's shield set, from what the grants reached, using host facts
# (sb.isDir, sb.listDir, checkoutRoot) that internal/shield has no way to ask for. So the
# boundary holds for the built-in shields and is stated rather than enforced for the
# grant-derived half. Listed so a NEW package building rules still fails here.

# gate hands a Rule to shield.Assemble as INPUT, which is the opposite of assembling a set.
# Exempted per file rather than per directory, unlike the entries above: the justification is
# about the test, so a production rule in the same package must still fail here.
fixture_files='gate/problems_test.go'

found=$(grep -rEln --include='*.go' "$assemblers" . | while read -r f; do
	f=${f#./}
	if echo "$fixture_files" | grep -qxF "$f"; then
		continue
	fi
	# A constructor named in prose is not an assembly site. Line comments and the body of a
	# block comment are dropped; a block comment written without leading stars still reads
	# as a call here, which is the direction that fails loudly rather than quietly.
	if grep -E "$assemblers" "$f" | grep -qvE '^[[:space:]]*(//|/\*|\*)'; then
		dirname "$f"
	fi
done | sort -u)

extra=$(echo "$found" | while read -r dir; do
	[ -n "$dir" ] || continue
	if ! echo "$shield_assemblers" | grep -qxF "$dir"; then
		echo "$dir"
	fi
done)

if [ -n "$extra" ]; then
	echo "layering: only internal/shield assembles the shields a run applies, but rules are built in:" >&2
	echo "$extra" | sed 's/^/  /' >&2
	echo "  Route it through internal/shield, or add it to shield_assemblers in $0 with the reason it builds its own." >&2
	status=1
fi

echo "layering: kernel enforcement confined to $(echo "$kernel_importers" | wc -l | tr -d ' ') packages; shield assembly in internal/shield, with rules also built in:"
echo "$shield_assemblers" | grep -vx 'internal/shield' | sed 's/^/  /'

exit $status
