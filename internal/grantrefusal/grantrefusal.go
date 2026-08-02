// Package grantrefusal holds the words bento refuses a grant in.
//
// A refusal is raised at whichever point in the run first sees the host fact behind it -
// a write grant that is a file is caught by the argv compiler on one path and by the
// directory preparation on another, a loop by the grant check on one and by the same
// preparation on another - and `bento validate` predicts all of them before anything
// runs. That is five call sites for two sentences. Shared here so a reader who meets one
// of them in a CI gate and again at run time reads the same sentence, and so a reworded
// refusal cannot answer half of them.
//
// The wording only. Each caller keeps its own stat: they work on paths resolved to
// different degrees and answer differently - the run refuses, the gate reports - and a
// classifier common to all of them would have to be parameterized into saying nothing.
package grantrefusal

import "fmt"

// WriteIsFile refuses a write grant that names an existing file. Write grants name
// directories - the sandbox binds one - so a grant naming a file inside it cannot be
// honored as written, and creating a directory over it would destroy nothing but confuse
// everything.
func WriteIsFile(grant string) error {
	return fmt.Errorf("write grant %q is a file; grant its parent directory instead", grant)
}

// Looped refuses a grant whose symlinks loop. Read and write alike: bwrap's --ro-bind-try
// tolerates only a missing source, not ELOOP, so a looping grant of either kind aborts
// the run naming bwrap rather than the grant.
func Looped(grant string) error {
	return fmt.Errorf("grant %q loops through itself on the host, so it names nothing that can be bound; fix the link or remove the grant", grant)
}
