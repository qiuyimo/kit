package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var name string

// nifCmd represents the nif command
var nifCmd = &cobra.Command{
	Use:   "nif",
	Short: "判断网卡是否存在，看看不存在返回什么",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nif called")

		_, err := netlink.LinkByName(name)
		if err != nil {
			cmd.PrintErrln("LinkByName error", err) // Link not found
		} else {
			cmd.PrintErrln("LinkByName success")
		}
	},
}

func init() {
	rootCmd.AddCommand(nifCmd)

	nifCmd.Flags().StringVarP(&name, "name", "n", "ens160", "网卡名称")
}
