//go:build !linux

package trust

import (
	"fmt"
	"os"
)

// ACLNamedWrite cannot answer off Linux, and says so rather than reporting no named writer.
// The Linux half reads system.posix_acl_access, which no other platform carries: on darwin
// the attribute is simply absent - ENOATTR, itself a different errno from the ENODATA that
// means the same thing on Linux - and the ACL lives behind acl_get_file instead. Reading
// that absence as "no ACL" would wave through the one grant this check exists to catch, on
// every path that reaches it. An error is the direction to be wrong in: every caller reads
// one as untrusted. Reading the real list is what a platform backend owes.
func ACLNamedWrite(path string) (bool, error) {
	return false, fmt.Errorf("who else can write %s cannot be checked on this platform: its access-control list is not readable through the POSIX attribute", path)
}

// manifestLocation reports the location as unknown off Linux: reading back where an open
// descriptor came from is what /proc is used for here, and the name the manifest was
// opened by is not a substitute - it is the name that a swapped directory would have
// redirected. Unknown rather than an error so the facts fstat does carry are still
// reported; LocationFlaws is what says the rest is missing.
func manifestLocation(f *os.File) (string, error) {
	return "", ErrLocationUnknown
}

// pathDirs reports unknown off Linux rather than falling back to a lexical walk. The walk
// it stands in for needs O_PATH descriptors and reads each directory's ACL through /proc,
// and the lexical resolution that would remain is what produced a wrong verdict before it
// was removed: reporting a location as sound when nobody checked it is worse than saying so.
func pathDirs(path string) (dirs, links []fileFacts, leaf string, err error) {
	return nil, nil, "", ErrLocationUnknown
}
