package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/internal/launcher"
)

// newForwardCmd is the in-sandbox half of egress enforcement, not a user
// command. bento re-execs itself as `bento __forward <socket> -- <cmd>...`
// inside the sandbox, where the launcher package sets up the egress bridge and
// runs the real target. This wrapper only unpacks argv; the logic lives in
// internal/launcher so it is testable and so the future seccomp stage joins it
// there rather than as a competing entrypoint.
func newForwardCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "__forward <socket> -- <command>...",
		Hidden:             true,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			socket := args[0]
			target := args[1:]
			if len(target) > 0 && target[0] == "--" {
				target = target[1:]
			}
			if len(target) == 0 {
				return fmt.Errorf("__forward: no command to run")
			}
			code, err := launcher.Run(socket, target)
			if err != nil {
				return err
			}
			return &exitError{code: code}
		},
	}
}
