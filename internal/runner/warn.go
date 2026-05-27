//go:build linux || darwin

package runner

import (
	"fmt"
	"os"
)

// warn emits a degradation notice. Goes to the Logger if set, else stderr.
func (c *Config) warn(format string, args ...any) {
	msg := "bento [warn] " + fmt.Sprintf(format, args...)
	if c.Logger != nil {
		c.Logger.Printf("[warn] "+format, args...)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
}
