package cmd

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

// routeCmd represents the route command
var routeCmd = &cobra.Command{
	Use:   "route",
	Short: "route",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("route called")
		// 假设我们有一个目标路由和源地址
		dst, _ := netlink.ParseIPNet("192.168.8.0/24")
		gw := net.ParseIP("192.168.3.13")
		// 创建新的路由，不指定LinkIndex
		newRoute := netlink.Route{
			Dst: dst,
			Gw:  gw,
		}

		// 添加路由
		if err := netlink.RouteAdd(&newRoute); err != nil {
			fmt.Printf("Failed to add route: %v\n", err)
			return
		}

		fmt.Println("Route added successfully")

		time.Sleep(10 * time.Second)

		delErr := netlink.RouteDel(&netlink.Route{
			Dst: dst,
			Gw:  gw,
		})
		if delErr != nil {
			fmt.Printf("Failed to del route: %v\n", delErr)
		} else {
			fmt.Println("Route del successfully")
		}
	},
}

func init() {
	rootCmd.AddCommand(routeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// routeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// routeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
