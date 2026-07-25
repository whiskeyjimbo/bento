#!/bin/sh
# Proves bento's public API is self-sufficient. This example is a separate module
# (see go.mod's replace), so Go's internal-package rule makes any import of
# github.com/whiskeyjimbo/bento/internal/... a hard compile error here - the
# build below cannot pass while reaching into internal/. The grep is a clearer
# early failure for the same violation.
set -eu
cd "$(dirname "$0")"

if grep -rn 'bento-v2/internal/' . --include='*.go'; then
	echo "FAIL: example imports an internal package; the public surface is insufficient" >&2
	exit 1
fi

GOWORK=off go build -o /dev/null .
GOWORK=off go vet ./...
# Runs TestMain, exercising the DispatchReexec-from-TestMain pattern this example
# exists to demonstrate.
GOWORK=off go test ./...
echo "OK: example builds and tests against bento's public API only"
