#!/bin/sh
# A stand-in for an untrusted agent. It reads two files from ../vault, writes a log
# in its own directory, and reaches two hosts. Under supervise you approve each in
# the trial pass; the enforced pass allows exactly those and denies the rest, and
# prompts you live for the host you did not declare.
#
# Scratch goes to /tmp (a private tmpfs the sandbox always provides, so it never
# shows up as something to approve) and output is captured, not sent to /dev/null,
# so nothing writes outside what the demo is about.
report() { printf '  -> %s\n' "$1"; }

echo "[agent] read  vault/data.csv"
if x=$(cat ../vault/data.csv 2>&1); then report ok; else report "DENIED (kernel)"; fi

echo "[agent] read  vault/secret.txt"
if x=$(cat ../vault/secret.txt 2>&1); then report ok; else report "DENIED (kernel)"; fi

echo "[agent] write out.log"
if echo ran >out.log 2>>out.log; then report ok; else report "DENIED (kernel)"; fi

echo "[agent] reach example.com"
if code=$(curl -sq --proxytunnel -o /tmp/agent-body -w '%{http_code}' --max-time 8 https://example.com/ 2>/tmp/agent-err); then
	report "HTTP $code"
else
	report blocked
fi

echo "[agent] reach ads.tracker.example"
if code=$(curl -sq --proxytunnel -o /tmp/agent-body -w '%{http_code}' --max-time 8 https://ads.tracker.example/ 2>/tmp/agent-err); then
	report "HTTP $code"
else
	report blocked
fi
