package ipvlan

import (
	"fmt"

	"github.com/spf13/cobra"
)

var isHttps bool

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add a virtual IP",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("add called")
		if err := AloneAdd(appIpPort, destIpPort); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

func init() {
	ipvlanCmd.AddCommand(addCmd)
	addCmd.Flags().BoolVarP(&isHttps, "isHttps", "i", false, "is https")
}
