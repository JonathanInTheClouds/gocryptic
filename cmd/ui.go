package cmd

import (
	"github.com/gocryptic/gocryptic/internal/tui"
	"github.com/spf13/cobra"
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the interactive terminal UI",
	Long: `Launch GoCryptic's interactive terminal UI.

Navigate with arrow keys or tab, select options with enter, and go back
with esc.  All commands are available: encrypt, decrypt, hash, keygen,
encode/decode, sign, and verify.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		return tui.Run()
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
}
