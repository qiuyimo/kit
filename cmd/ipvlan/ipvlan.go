package ipvlan

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/qiuyimo/kit/cmd"
)

var (
	appIpPort  string
	destIpPort string
)

// ipvlanCmd represents the ipvlan command
var ipvlanCmd = &cobra.Command{
	Use:   "ipvlan",
	Short: "ipvlan handle",
	Long:  `基于 ipvlan 实现虚拟IP`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ipvlan called")
	},
}

func init() {
	cmd.RootCmd().AddCommand(ipvlanCmd)

	ipvlanCmd.PersistentFlags().StringVarP(&appIpPort, "appIP", "a", "192.168.7.211:8080", "应用的 IP:port")
	ipvlanCmd.PersistentFlags().StringVarP(&destIpPort, "destIP", "d", "192.168.7.29:80", "源站的 IP:port")
}
