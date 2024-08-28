package cmd

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var (
	ip   string
	port string
)

// demoCmd represents the demo command
var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "demo",
	Run: func(c *cobra.Command, args []string) {
		fmt.Println("demo called")

		// 定义要执行的命令
		cmd := exec.Command("ip", "-6", "route")

		// 创建一个缓冲区，用来存储命令输出的数据
		var out bytes.Buffer
		cmd.Stdout = &out

		// 执行命令
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Error executing command: %v\n", err)
			return
		}

		// 读取输出数据
		output := out.String()

		// 输出结果
		fmt.Println("Command Output:")
		fmt.Println(output)

		res := strings.Split(output, "\n")
		for i, v := range res {
			fmt.Println(i, v)
		}
	},
}

func init() {
	rootCmd.AddCommand(demoCmd)

	demoCmd.Flags().StringVarP(&port, "port", "p", "80", "ip")
	demoCmd.Flags().StringVarP(&ip, "ip", "i", "", "port")
}

func CheckPortIsUsed(ip string, port string) bool {
	address := fmt.Sprintf("%s:%s", ip, port)
	conn, err := net.Listen("tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			return true // 端口被占用
		}
		return false
	}
	// 端口未被占用，需要关闭监听
	conn.Close()
	return false
}
