package cmd

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

// ipv6Cmd represents the ipv6 command
var ipv6Cmd = &cobra.Command{
	Use:   "ipv6",
	Short: "ipv6",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ipv6 called")

		r := gin.Default()

		r.GET("/", func(c *gin.Context) {
			println("host: ", c.Request.Host) // host:  [fd00:dead:aaaa::14]:8080
			c.String(http.StatusOK, "Hello, IPv6 world!")
		})

		// IPv6 地址和端口
		ipv6Address := "[fd00:dead:aaaa::14]:8080"

		// 启动服务器监听 IPv6 地址
		server := &http.Server{
			Addr:    ipv6Address,
			Handler: r,
		}

		log.Printf("Starting server on %s\n", ipv6Address)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start server: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(ipv6Cmd)
}
