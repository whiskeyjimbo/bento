#!/bin/sh
# Proves bento's public API is self-sufficient. This example is a separate module
# (see go.mod's replace), so Go's internal-package rule makes any import of
# github.com/whiskeyjimbo/bento/internal/... a hard compile error here - the
# build below cannot pass while reaching into internal/. The grep is a clearer
# early failure for the same violation.
set -eu
cd "$(dirname "$0")"

if grep -rn 'github.com/whiskeyjimbo/bento/internal/' . --include='*.go'; then
	echo "FAIL: example imports an internal package; the public surface is insufficient" >&2
	exit 1
fi

bin="$(mktemp -d)/embed"
trap 'rm -rf "$(dirname "$bin")"' EXIT
GOWORK=off go build -o "$bin" .
GOWORK=off go vet ./...
# Runs TestMain, exercising the DispatchReexec-from-TestMain pattern this example
# exists to demonstrate.
GOWORK=off go test ./...
echo "OK: example builds and tests against bento's public API only"

# The default posture, checked before the sandbox ones because it needs no sandbox:
# the refusal lands before a backend is built. Every command below opts out of it, so
# without this nothing would notice the check disappearing.
if out="$("$bin" demo/reach.yaml 2>&1)"; then
	echo "$out" >&2
	echo "FAIL: an unapproved manifest ran instead of being refused" >&2
	exit 1
fi
case "$out" in
*'is not approved'*) ;;
*)
	echo "$out" >&2
	echo "FAIL: an unapproved manifest was refused for the wrong reason" >&2
	exit 1
	;;
esac
echo "OK: an unapproved manifest is refused by default"

# The tests above never invoke the binary the README documents, so a broken demo
# manifest passed them all. Run the README's two non-interactive modes and assert
# their documented output. Both are offline-safe: with no route out, the target
# reports "blocked" either way, and mode 2's honesty line comes from the gate
# being consulted at connect time, not from the connection succeeding.
#
# setsid is what makes them non-interactive. The gate opens /dev/tty itself, and a
# command substitution redirects stdout, not the controlling terminal - so run from
# a developer's shell these would sit at the README's mode-3 prompt with the
# question drawn on a terminal this script is not reading. A new session has no
# controlling terminal to find.
if ! command -v bwrap >/dev/null 2>&1 || ! command -v setsid >/dev/null 2>&1; then
	echo "SKIP: demo run needs bwrap (bubblewrap) and setsid; the API checks above still ran" >&2
	exit 0
fi
# bwrap on the PATH does not mean the kernel grants the sandbox: a host can refuse
# the user namespace, or grant it and refuse the procfs mount inside it (docker's
# default masking of /proc). Either way the run is refused before the target speaks,
# which is a host gap rather than the regression this guards.
if ! bwrap --unshare-user --ro-bind / / --proc /proc true 2>/dev/null; then
	echo "SKIP: demo run needs a host bubblewrap can build its sandbox on; the API checks above still ran" >&2
	exit 0
fi

out="$(setsid --wait "$bin" --allow-unapproved demo/reach.yaml 2>&1)" || {
	echo "$out" >&2
	echo "FAIL: README mode 1 (./bentoembed --allow-unapproved demo/reach.yaml) did not succeed" >&2
	exit 1
}
case "$out" in
*blocked*) ;;
*)
	echo "$out" >&2
	echo "FAIL: README mode 1 admitted undeclared egress instead of blocking it" >&2
	exit 1
	;;
esac

out="$(BENTO_GATE_ALLOW=example.com setsid --wait "$bin" --allow-unapproved demo/reach.yaml 2>&1)" || {
	echo "$out" >&2
	echo "FAIL: README mode 2 (BENTO_GATE_ALLOW=example.com) did not succeed" >&2
	exit 1
}
case "$out" in
*'gate admitted undeclared egress to "example.com" port 443'*) ;;
*)
	echo "$out" >&2
	echo "FAIL: README mode 2 did not surface the gate-admitted egress" >&2
	exit 1
	;;
esac
echo "OK: the README's documented demo commands run"
