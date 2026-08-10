//go:build !linux

package trust

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// attrMissing is ENOATTR off Linux, which is a distinct errno from the ENODATA the Linux
// build answers with - see the Linux half. Getting it wrong is not a fail-open: the ACL
// check would error, and the callers read an error as untrusted.
func attrMissing(err error) bool { return errors.Is(err, unix.ENOATTR) }

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
