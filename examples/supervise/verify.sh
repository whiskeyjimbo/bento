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

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
GOWORK=off go build -o "$work/supervise" .
GOWORK=off go vet ./...
# Runs TestMain, exercising the DispatchReexec-from-TestMain pattern this example
# exists to demonstrate.
GOWORK=off go test ./...
echo "OK: example builds and tests against bento's public API only"

# The tests above never invoke the binary the README documents. The whole
# walkthrough is interactive, so what a script can assert is the honest refusal:
# with no human on stdin the run must stop rather than draw prompts it answers
# itself. Gating on stdin (not on /dev/tty) is what makes this deterministic here
# and on a developer's terminal alike. XDG_CONFIG_HOME is redirected so a failure
# cannot write the developer's real permission store.
out="$(XDG_CONFIG_HOME="$work/config" "$work/supervise" run demo/agent.sh </dev/null 2>&1)" && {
	echo "$out" >&2
	echo "FAIL: run with no terminal on stdin succeeded instead of refusing" >&2
	exit 1
}
case "$out" in
*"needs a terminal"*) ;;
*)
	echo "$out" >&2
	echo "FAIL: run with no terminal on stdin did not say it needs one" >&2
	exit 1
	;;
esac
if [ -e "$work/config/bento-supervise/permissions.json" ]; then
	echo "FAIL: a refused run wrote decisions to the permission store" >&2
	exit 1
fi
echo "OK: the README's run command refuses a non-terminal stdin"
