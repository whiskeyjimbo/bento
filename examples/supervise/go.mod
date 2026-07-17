// Its own module, on purpose. Go's internal-package rule blocks import paths
// across module-external code, so from here any import of
// github.com/whiskeyjimbo/bento-v2/internal/... is a hard compile error. If this
// module builds, bento's public packages are self-sufficient for an embedder.
// The replace points at the in-tree checkout; keep this module out of any go.work
// so the isolation holds.
module bentosupervise

go 1.26.5

require github.com/whiskeyjimbo/bento-v2 v0.0.0

require (
	github.com/elastic/go-seccomp-bpf v1.6.0 // indirect
	github.com/landlock-lsm/go-landlock v0.9.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.78 // indirect
)

replace github.com/whiskeyjimbo/bento-v2 => ../..
