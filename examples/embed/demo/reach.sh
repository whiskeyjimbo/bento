#!/bin/sh
# The target the sandbox runs. It tries to reach a host the manifest does NOT
# declare, so egress is refused unless the network gate admits it. curl is
# funneled through bento's proxy (HTTP(S)_PROXY is set inside the sandbox) with
# --proxytunnel so even an http:// URL goes out as a CONNECT.
echo -n "reaching example.com ... "
if curl -sS --proxytunnel -o /dev/null -w 'HTTP %{http_code}' --max-time 8 https://example.com/ 2>/dev/null; then
	echo " (reached)"
else
	echo "blocked"
fi
