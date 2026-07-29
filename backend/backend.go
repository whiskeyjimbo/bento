package backend

// ProfileOptions tunes a Profile run.
type ProfileOptions struct {
	// AllowNetwork forwards the target's egress during profiling instead of
	// recording it and refusing to forward. Off by default, so profiling untrusted
	// code cannot exfiltrate.
	AllowNetwork bool

	// DenyPaths are absolute host paths shielded from the target during the
	// profiling run, on top of bento's built-in deny-list. Profile honors whatever
	// Read the caller's policy sets, so a supervising embedder uses this to keep its
	// own control state (e.g. a permission store) shielded regardless of how broad
	// that policy's reads are. Each path is shielded as an
	// empty directory (or an empty read-only file if it exists as a non-directory);
	// a relative path, or one resolving to "/", is refused. The shield hides the
	// path's contents, not its existence, and the attempted access is still observed
	// - so the caller must still refuse a grant that later covers these paths.
	DenyPaths []string

	// AcceptAliasesUnder acknowledges the credential aliases inside the named host
	// trees, which would otherwise refuse the profiling run. Profiling scans for them
	// exactly as an enforced run does - the profiled target is untrusted by
	// construction - so the same acknowledgement has to be available here, or a host
	// with a deduplicated backup could never be profiled at all. See
	// RunOptions.AcceptAliasesUnder for what an acknowledgement means.
	AcceptAliasesUnder []string
}
