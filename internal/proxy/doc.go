// Package proxy implements the outbound traffic interception proxies.
//
// Bento unshares the network namespace inside the Bubblewrap sandbox,
// routing permitted outgoing script connections through local loopback
// endpoints backed by a SOCKS5 and HTTP CONNECT proxy pair. This allows
// host-level domain name and port rules to be dynamically verified and
// prompted (via grants callbacks) before dialing remote servers.
package proxy
