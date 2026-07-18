#!/bin/sh
# Runs the degraded-tier end-to-end test in a clamped container.
#
# The degraded (no-bwrap, Landlock-only) tier only engages where an unprivileged
# user namespace cannot be created - the Ubuntu AppArmor clampdown. A normal dev box
# has userns working, so TestDegradedEndToEndOnClampedHost skips there. A default
# Docker container blocks nested user namespaces, which is exactly the condition the
# tier is built for, so this runs the test inside one: bwrap is installed and present
# but cannot create a namespace, so the probe reports the filesystem layer Degraded
# and enforce.Run selects the no-bwrap path, which the test then asserts confines.
#
# The host kernel (shared with the container) must have Landlock (>= 5.13). The host
# Go module cache is mounted read-only so no download is needed; buildvcs is off
# because the source is a read-only mount.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
gomod=$(go env GOMODCACHE)

exec docker run --rm \
	-v "$repo":/src:ro \
	-v "$gomod":/gomod:ro \
	-e GOWORK=off \
	-e GOMODCACHE=/gomod \
	-e GOCACHE=/tmp/gocache \
	-e "GOFLAGS=-mod=readonly -buildvcs=false" \
	-e HOME=/tmp \
	-w /src \
	golang:1.26.5 \
	sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y bubblewrap >/dev/null 2>&1; \
		go test ./internal/linux/ -run TestDegradedEndToEndOnClampedHost -count=1 -v'
