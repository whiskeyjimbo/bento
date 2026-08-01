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

# The tests above never invoke the binary the README documents, so a broken demo
# manifest passed them all. Run the README's two non-interactive modes and assert
# their documented output. Both are offline-safe: with no route out, the target
# reports "blocked" either way, and mode 2's honesty line comes from the gate
# being consulted at connect time, not from the connection succeeding.
if ! command -v bwrap >/dev/null 2>&1; then
	echo "SKIP: demo run needs bwrap (bubblewrap); the API checks above still ran" >&2
	exit 0
fi

out="$("$bin" demo/reach.yaml 2>&1)" || {
	echo "$out" >&2
	echo "FAIL: README mode 1 (./embed demo/reach.yaml) did not succeed" >&2
	exit 1
}
case "$out" in
*blocked) ;;
*)
	echo "$out" >&2
	echo "FAIL: README mode 1 admitted undeclared egress instead of blocking it" >&2
	exit 1
	;;
esac

out="$(BENTO_GATE_ALLOW=example.com "$bin" demo/reach.yaml 2>&1)" || {
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
