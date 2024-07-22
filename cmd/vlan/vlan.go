package vlan

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/qiuyimo/kit/cmd"
)

// vlanCmd represents the vlan command
var vlanCmd = &cobra.Command{
	Use:   "vlan",
	Short: "vlan for work",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("vlan called")
		createVlan()
	},
}

func init() {
	cmd.RootCmd().AddCommand(vlanCmd)
}

func createVlan() {
	// 物理接口名称
	parentInterface := "ens224"
	// VLAN ID
	vlanID := 100
	// VLAN 接口名称
	vlanInterface := fmt.Sprintf("%s.%d", parentInterface, vlanID)

	// 获取物理接口
	link, err := netlink.LinkByName(parentInterface)
	if err != nil {
		log.Fatalf("Failed to get link by name %s: %v", parentInterface, err)
	}

	// 创建 VLAN 接口
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        vlanInterface,
			ParentIndex: link.Attrs().Index,
		},
		VlanId: vlanID,
	}

	// 添加 VLAN 接口
	if err := netlink.LinkAdd(vlan); err != nil {
		log.Fatalf("Failed to add VLAN interface: %v", err)
	}

	// 启用 VLAN 接口
	if err := netlink.LinkSetUp(vlan); err != nil {
		log.Fatalf("Failed to set VLAN interface up: %v", err)
	}

	fmt.Printf("VLAN interface %s created and set up successfully\n", vlanInterface)
}
