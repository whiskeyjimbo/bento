package backend

// ProfileOptions tunes a Profile run.
type ProfileOptions struct {
	// AllowNetwork forwards the target's egress during profiling instead of
	// recording it and refusing to forward. Off by default, so profiling untrusted
	// code cannot exfiltrate.
	AllowNetwork bool

	// DenyPaths are absolute host paths shielded from the target during the
	// profiling run, on top of bento's built-in deny-list. Profiling is default-deny,
	// so a caller's control state (e.g. a permission store) is already unmounted unless
	// granted; a supervising embedder uses this to keep that state shielded even behind
	// a grant that would otherwise cover it. Each path is shielded as an
	// empty directory (or an empty read-only file if it exists as a regular file);
	// a relative path, or one resolving to "/", is refused. The shield hides the
	// path's contents, not its existence, and the attempted access is still observed
	// - so the caller must still refuse a grant that later covers these paths.
	DenyPaths []string
}
