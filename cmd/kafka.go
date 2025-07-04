package cmd

import (
	"github.com/spf13/cobra"
)

var kafkaCmd = &cobra.Command{
	Use: "kafka",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.AddCommand(kafkaCmd)

}
