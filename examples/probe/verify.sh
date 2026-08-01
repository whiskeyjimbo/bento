#!/bin/sh
# Runs the root README's quick start - profile, validate, approve, run - against
# probe.py and asserts each step's exit code. Nothing else executes that sequence,
# which is how a step-2 that always exited 125 survived every other gate.
#
# The work happens in a copy under a temp dir: step 1 writes probe.py.manifest.yaml
# and step 4 writes probe-cwd.txt next to the entrypoint, so running in the example
# itself would leave generated files (and the binary) in the tree.
#
# Network outcomes are deliberately unasserted. The probe's net.* results flip with
# whether the host has a route out, and the README's sequence is about the four
# steps agreeing with each other, not about reaching example.com.
set -eu
cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"

if ! command -v bwrap >/dev/null 2>&1 || ! command -v setsid >/dev/null 2>&1; then
	echo "SKIP: the quick start needs bwrap (bubblewrap) and setsid" >&2
	exit 0
fi
# bwrap on the PATH does not mean the kernel grants the sandbox: a host can refuse
# the user namespace, or grant it and refuse the procfs mount inside it (docker's
# default masking of /proc). Either way every step is refused before the probe speaks,
# which is a host gap rather than the regression this guards.
if ! bwrap --unshare-user --ro-bind / / --proc /proc true 2>/dev/null; then
	echo "SKIP: the quick start needs a host bubblewrap can build its sandbox on" >&2
	exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="$work/bento"
box="$work/probe"
mkdir "$box"
cp -R probe.py data secret "$box/"

GOWORK=off go build -o "$bin" "$root/cmd/bento"

# setsid keeps every step off the developer's terminal: approve opens /dev/tty
# itself, so a redirected stdin alone would still draw its prompt there, and a new
# session has no controlling terminal to find. approve refuses a stdin it cannot ask
# on, so step 3 passes --yes - the README's own CI spelling.
step() {
	name="$1"
	shift
	if ! out="$(cd "$box" && setsid --wait "$bin" "$@" </dev/null 2>&1)"; then
		echo "$out" >&2
		echo "FAIL: quick start step $name (bento $*) exited nonzero" >&2
		exit 1
	fi
	printf '%s\n' "$out"
}

out="$(step 1-profile profile ./probe.py)"
if [ ! -f "$box/probe.py.manifest.yaml" ]; then
	echo "$out" >&2
	echo "FAIL: step 1 did not write the manifest the next three steps read" >&2
	exit 1
fi

out="$(step 2-validate validate ./probe.py.manifest.yaml)"
case "$out" in
*'not approved'*) ;;
*)
	echo "$out" >&2
	echo "FAIL: step 2 did not report the freshly profiled manifest as unapproved" >&2
	exit 1
	;;
esac

out="$(step 3-approve approve --yes ./probe.py.manifest.yaml)"
case "$out" in
*'approved ./probe.py.manifest.yaml'*) ;;
*)
	echo "$out" >&2
	echo "FAIL: step 3 did not stamp an approval" >&2
	exit 1
	;;
esac

# run refuses an unapproved manifest, so reaching PROBE-COMPLETE here also proves
# step 3's stamp is the one step 4 accepts.
out="$(step 4-run run ./probe.py.manifest.yaml)"
case "$out" in
*PROBE-COMPLETE*) ;;
*)
	echo "$out" >&2
	echo "FAIL: step 4 did not run probe.py to completion under the profiled manifest" >&2
	exit 1
	;;
esac

echo "OK: the README quick start's four steps run in order"
