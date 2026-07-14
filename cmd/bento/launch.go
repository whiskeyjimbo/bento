package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento-v2/internal/launcher"
)

// newLaunchCmd is the in-sandbox stage, not a user command. bento re-execs
// itself as `bento __launch --exec MODE [--socket S] -- <cmd>...` inside the
// sandbox, where the launcher package sets up the egress bridge and/or the
// exec-block filter and then runs the target. This wrapper only unpacks argv;
// the logic lives in internal/launcher.
func newLaunchCmd() *cobra.Command {
	var (
		socket   string
		execMode string
		writable []string
	)
	cmd := &cobra.Command{
		Use:    "__launch -- <command>...",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := launcher.Run(launcher.Config{
				Socket:   socket,
				Block:    execMode != "all",
				Writable: writable,
				Target:   args,
			})
			if err != nil {
				return err
			}
			return &exitError{code: code}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "egress proxy unix socket to bridge to")
	cmd.Flags().StringVar(&execMode, "exec", "none", "exec policy: none, none-strict, or all")
	cmd.Flags().StringArrayVar(&writable, "rw", nil, "a write-granted path the Landlock backstop permits (repeatable)")
	return cmd
}

// newBridgeCmd is the `bento __bridge <socket>` child the launcher starts to
// forward the sandbox's loopback proxy port to the host-side proxy socket. It is
// its own process so it survives the launcher's execveat into the target.
func newBridgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "__bridge <socket>",
		Hidden:             true,
		Args:               cobra.ExactArgs(1),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := launcher.BridgeMain(args[0]); err != nil {
				return fmt.Errorf("bridge: %w", err)
			}
			return nil
		},
	}
}
