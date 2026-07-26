#!/bin/sh
# Cross-references bento's credential/exec deny-list against firejail's upstream
# disable-common.inc and reports any secret- or exec-scope shield firejail has that
# bento does not cover (see cmd/denylist-audit and internal/denylist/audit). Run it, and
# every in-scope upstream entry bento lacks is printed for a human to classify into
# internal/denylist/denylist.go (DenyAll credential vs DenyWrite exec) or dismiss.
#
# A green run means PARITY WITH FIREJAIL, not a complete deny-list: firejail is the only
# corpus, so a store it does not list cannot surface here. Paths in bento's model but
# outside firejail's still have to be found by review - see the audit package doc.
#
# GPL note: firejail's data is GPLv2. It is fetched over the network and read as a
# diff reference only - never vendored into the binary; bento ships its own entries.
#
# The underlying command's exit codes drive a CI gate: 1 means a real gap (fail the
# build - fix the list or file a bead), 2 means the upstream fetch failed (offline or
# GitHub down), which is an infrastructure condition, not a deny-list regression, so
# this wrapper reports it and passes rather than turning network flakiness into red.
set -u

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo" || exit 2

# Build then run, rather than `go run`, so the audit's own exit code reaches the case
# below unmuddied by `go run`'s "exit status N" wrapper line. A build failure is a real
# problem (the audit does not compile), distinct from the run's gap/network codes, so it
# fails hard.
bin=$(mktemp) || exit 2
trap 'rm -f "$bin"' EXIT
if ! GOWORK=off go build -o "$bin" ./cmd/denylist-audit; then
	echo "denylist-audit: build failed." >&2
	exit 1
fi

"$bin"
status=$?

case "$status" in
0)
	exit 0
	;;
1)
	echo "denylist-audit: in-scope firejail shields are missing from bento's list above." >&2
	echo "denylist-audit: classify each into internal/denylist/denylist.go, or file a bead." >&2
	exit 1
	;;
2)
	echo "denylist-audit: could not fetch firejail upstream (offline?); skipping the check." >&2
	exit 0
	;;
*)
	echo "denylist-audit: unexpected failure (exit $status)." >&2
	exit "$status"
	;;
esac
