#!/bin/sh
# Cross-references bento's credential/exec deny-list against two upstream corpora -
# firejail's disable-common.inc/disable-programs.inc and AppArmor's private-files
# abstractions - and reports any secret- or exec-scope shield they have that
# bento does not cover (see cmd/denylist-audit and internal/denylist/audit). Run it, and
# every in-scope upstream entry bento lacks is printed for a human to classify into
# internal/denylist/denylist.go (DenyAll credential vs DenyWrite exec) or dismiss.
#
# A green run means PARITY WITH THESE CORPORA, not a complete deny-list: a store neither
# lists cannot surface here. Both are desktop-application sandboxes, so the developer
# token stores (.terraformrc, .m2/settings.xml, .npmrc) are outside BOTH of them and
# still have to be found by review - see the audit package doc.
#
# GPL note: firejail's and AppArmor's data are both GPLv2. They are fetched over the
# network and read as a diff reference only - never vendored into the binary; bento
# ships its own entries.
#
# The underlying command's exit codes drive a CI gate: 1 means a real gap (fail the
# build - fix the list or file a bead), 3 means the upstream fetch failed (offline or
# GitHub down), which is an infrastructure condition, not a deny-list regression, so
# this wrapper reports it and passes rather than turning network flakiness into red, and
# 4 means a corpus is not there to be had - the URL redirects, so the profile moved - or it
# arrived and is not the profile it should be; either is a real red, and 5
# means the audit could not clear the relocation variables that make its own list CI's
# rather than this host's - red too, and separate from 4 so a reader is not sent after an
# upstream corpus that is fine.
#
# Only the fetch failure passes, and it has a status of its own so that nothing else can
# reach that arm. In particular Go's runtime exits 2 on panic: were the pass-over status
# still 2, a crash inside the audit would print the skip banner and report success.
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
	echo "denylist-audit: in-scope upstream shields are missing from bento's list above." >&2
	echo "denylist-audit: classify each into internal/denylist/denylist.go, or file a bead." >&2
	exit 1
	;;
3)
	echo "denylist-audit: could not fetch an upstream corpus (offline?); skipping the check." >&2
	exit 0
	;;
4)
	echo "denylist-audit: an upstream corpus moved or is not the profile it should be (see above); the audit proved nothing." >&2
	exit 1
	;;
5)
	echo "denylist-audit: could not clear a relocation variable (see above), so the audit's own list would have been this host's, not CI's." >&2
	exit 1
	;;
*)
	echo "denylist-audit: unexpected failure (exit $status)." >&2
	exit "$status"
	;;
esac
