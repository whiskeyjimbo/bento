package runner

import (
	"fmt"
	"os"
)

// warn emits a degradation notice. bento's policy: required tools
// missing → hard error; optional capabilities missing → warn +
// continue with reduced enforcement.
//
// If a Logger is configured, the warning goes there with a "[warn]"
// prefix. Either way the warning ALSO goes to stderr so callers that
// forgot to pass WithLogger still see security-relevant degradation.
// See doc.go in the root package for the full policy.
func (c *Config) warn(format string, args ...any) {
	msg := "bento [warn] " + fmt.Sprintf(format, args...)
	if c.Logger != nil {
		c.Logger.Printf("[warn] "+format, args...)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
}
