package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/net"
	"github.com/spf13/cobra"
)

var (
	TcpIP   string
	TcpPort int
)

// tcpCmd represents the tcp command
var tcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "判断 tcp 中 IP port 是否被占用",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tcp called")

		fmt.Println(checkPort(TcpIP, TcpPort))
	},
}

func init() {
	rootCmd.AddCommand(tcpCmd)

	tcpCmd.Flags().StringVarP(&TcpIP, "ip", "i", "127.0.0.1", "ip")
	tcpCmd.Flags().IntVarP(&TcpPort, "port", "p", 80, "port")
}

// parseHexToIP 解析16进制的IP地址到人类可读的格式
func parseHexToIP(hexIP string, ipv6 bool) string {
	if ipv6 {
		// 解析IPv6地址
		ip := make([]string, 8)
		for i := 0; i < 8; i++ {
			ip[i] = hexIP[i*4 : (i+1)*4]
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7])
	} else {
		// 解析IPv4地址
		ip := make([]int, 4)
		for i := 0; i < 4; i++ {
			part, _ := strconv.ParseInt(hexIP[i*2:(i+1)*2], 16, 64)
			ip[3-i] = int(part)
		}
		return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

// checkPortInProc 检查端口是否在/proc/net/tcp 或 /proc/net/tcp6 中
func checkPortInProc(file, ip string, port int, ipv6 bool) bool {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Failed to open %s: %v\n", file, err)
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) < 2 {
			continue
		}

		// 提取本地地址
		localAddress := parts[1]
		hexIPPort := strings.Split(localAddress, ":")
		if len(hexIPPort) != 2 {
			continue
		}

		parsedIP := parseHexToIP(hexIPPort[0], ipv6)
		parsedPort, _ := strconv.ParseInt(hexIPPort[1], 16, 64)

		if parsedIP == ip && int(parsedPort) == port {
			return true
		}
	}

	return false
}

func handle() {
	occupied := checkPortInProc("/proc/net/tcp", TcpIP, TcpPort, false) || checkPortInProc("/proc/net/tcp6", TcpIP, TcpPort, true)

	if occupied {
		fmt.Printf("IP:Port %s:%d is occupied.\n", TcpIP, TcpPort)
	} else {
		fmt.Printf("IP:Port %s:%d is available.\n", TcpIP, TcpPort)
	}
}

func checkPort(ip string, port int) bool {
	connections, err := net.Connections("tcp")
	if err != nil {
		fmt.Printf("Error getting connections: %v\n", err)
		return false
	}

	for _, conn := range connections {
		if conn.Laddr.IP == ip && conn.Laddr.Port == uint32(port) {
			return true
		}
	}

	return false
}
