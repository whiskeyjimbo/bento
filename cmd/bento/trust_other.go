//go:build !linux

package main

import (
	"os"
)

// manifestLocation reports the location as unknown off Linux: reading back where an open
// descriptor came from is what /proc is used for here, and the name the manifest was
// opened by is not a substitute - it is the name that a swapped directory would have
// redirected. Unknown rather than an error so the facts fstat does carry are still
// reported; locationFlaws is what says the rest is missing.
func manifestLocation(f *os.File) (string, error) {
	return "", errLocationUnknown
}

// pathDirs reports unknown off Linux rather than falling back to a lexical walk. The walk
// it stands in for needs O_PATH descriptors and reads each directory's ACL through /proc,
// and the lexical resolution that would remain is what produced a wrong verdict before it
// was removed: reporting a location as sound when nobody checked it is worse than saying so.
func pathDirs(path string) (dirs, links []fileFacts, leaf string, err error) {
	return nil, nil, "", errLocationUnknown
}
