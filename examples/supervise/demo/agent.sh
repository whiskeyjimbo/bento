#!/bin/sh
# A stand-in for an untrusted agent. It reads two files from ../vault, writes a log
# in its own directory, and reaches two hosts outright plus a third it only learns
# about at runtime. Under supervise you approve the first two in the trial pass; the
# enforced pass allows exactly those, denies the rest, and prompts you live for the
# third.
#
# That third host is what makes the live gate reachable in the demo at all. The trial
# runs default-deny, so its example.com fetch fails and the follow-up below is never
# attempted - which means the host never enters the trial's recorded set and is never
# put to you as a decision to remember. The enforced run allows example.com, the fetch
# succeeds, and the follow-up hits the gate as a genuinely undeclared destination. A
# real agent discovers hosts from what it fetches in exactly this way.
#
# Scratch goes to /tmp (a private tmpfs the sandbox always provides, so it never
# shows up as something to approve) and output is captured, not sent to /dev/null,
# so nothing writes outside what the demo is about.
report() { printf '  -> %s\n' "$1"; }

# Exits non-zero when the CONNECT is refused, which is how both a recorded-and-refused
# trial fetch and a gate denial arrive here.
fetch() {
	curl -sq --proxytunnel -o /tmp/agent-body -w '%{http_code}' --max-time 8 "$1" 2>/tmp/agent-err
}

echo "[agent] read  vault/data.csv"
if x=$(cat ../vault/data.csv 2>&1); then report ok; else report "DENIED (kernel)"; fi

echo "[agent] read  vault/secret.txt"
if x=$(cat ../vault/secret.txt 2>&1); then report ok; else report "DENIED (kernel)"; fi

echo "[agent] write out.log"
if echo ran >out.log 2>>out.log; then report ok; else report "DENIED (kernel)"; fi

echo "[agent] reach example.com"
if code=$(fetch https://example.com/); then
	report "HTTP $code"
	# Only on success, so the trial never sees this host. Stand-in for the asset URL
	# an agent would have parsed out of the response it just got.
	echo "[agent] reach images.cdn.example (learned from the response)"
	if code=$(fetch https://images.cdn.example/logo.png); then
		report "HTTP $code"
	else
		report blocked
	fi
else
	report blocked
fi

echo "[agent] reach ads.tracker.example"
if code=$(fetch https://ads.tracker.example/); then
	report "HTTP $code"
else
	report blocked
fi
