#!/bin/sh
# Verifies bento builds byte-identically from two different source directories.
#
# Building twice in one directory would only catch a clock or ordering variable; it
# cannot catch the failure this guards, which is the toolchain embedding the builder's
# absolute paths into the binary (that is what -trimpath removes). So the second build
# runs from a copy at a different path, and the two hashes must match.
#
# The copy comes from `git archive HEAD`, so both builds compile the same committed
# tree and uncommitted edits cannot make this pass or fail spuriously. That archive has
# no .git, so the version stamp cannot be derived inside it - the values are computed
# once here and passed to both builds, which is also what a release rebuild would do.
#
# Scope of the claim: identical Go toolchain, same machine. A different toolchain
# version can still produce a different binary; pinning the toolchain is the remaining
# half of a full reproducibility story and is not asserted here.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo" || exit 2

if ! git -C "$repo" rev-parse HEAD >/dev/null 2>&1; then
	echo "repro: not a git repository, cannot archive a clean tree" >&2
	exit 2
fi

# Without this the hashes below come back empty on a host lacking the tool, compare
# equal, and the check reports success having measured nothing - the one failure a
# verification gate must never have.
if ! command -v sha256sum >/dev/null 2>&1; then
	echo "repro: sha256sum not found, cannot compare builds" >&2
	exit 2
fi

# Taken from the environment so `make repro` verifies the flags `make build` actually
# uses; a local default keeps the script runnable on its own. Hardcoding a second copy
# would let the two drift and leave this gate certifying a build nobody ships.
build_flags=${GO_BUILD_FLAGS:--trimpath -buildvcs=false}

version=${VERSION:-0.1.0-dev}
commit=$(git -C "$repo" rev-parse --short HEAD)
epoch=$(git -C "$repo" log -1 --format=%ct)
date=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
	date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
ldflags="-X main.version=$version -X main.commit=$commit -X main.date=$date"

work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/a" "$work/b"
git -C "$repo" archive --format=tar HEAD | (cd "$work/a" && tar x) || exit 2
git -C "$repo" archive --format=tar HEAD | (cd "$work/b" && tar x) || exit 2

for d in a b; do
	# The two trees sit at different paths, which is the point: an untrimmed build
	# bakes $work/<d> into the binary and the hashes then differ.
	# build_flags is deliberately unquoted: it carries several words.
	# shellcheck disable=SC2086
	(cd "$work/$d" && GOWORK=off CGO_ENABLED=0 go build $build_flags \
		-ldflags "$ldflags" -o "$work/bento-$d" ./cmd/bento) || {
		echo "repro: build failed in $d" >&2
		exit 2
	}
done

ha=$(sha256sum "$work/bento-a" | cut -d' ' -f1)
hb=$(sha256sum "$work/bento-b" | cut -d' ' -f1)

if [ "$ha" != "$hb" ]; then
	echo "repro: FAIL - the binary is not reproducible across source paths" >&2
	echo "  $ha  (built in $work/a)" >&2
	echo "  $hb  (built in $work/b)" >&2
	exit 1
fi

echo "repro: OK - byte-identical from two source paths"
echo "  sha256 $ha"
echo "  commit $commit  stamp $date"
