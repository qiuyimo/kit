package cmd

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

var port string

// httpServerCmd represents the httpServer command
var httpServerCmd = &cobra.Command{
	Use:   "httpServer",
	Short: "http server，收到请求后打印请求的 src ip port 和 dest ip port",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("httpServer called")
		r := gin.Default()
		r.NoRoute(func(c *gin.Context) {
			srcIpPort := c.Request.RemoteAddr
			dstIpPort := c.Request.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
			log.Println("src_ip_port", srcIpPort)
			log.Println("dest_ip_port", dstIpPort)
			c.String(http.StatusOK, "response form httpServer\nsrcIpPort: %v, dstIpPort: %v\n", srcIpPort, dstIpPort)
		})
		panic(r.Run(":" + port))
	},
}

func init() {
	rootCmd.AddCommand(httpServerCmd)

	httpServerCmd.Flags().StringVarP(&port, "port", "p", "80", "http 服务监听的端口")
}
