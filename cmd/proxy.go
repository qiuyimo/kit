package cmd

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

var dst string
var listenPort string

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "使用 gin 创建一个反向代理",
	Long:  `使用 gin 创建一个反向代理`,
	Run: func(cmd *cobra.Command, args []string) {
		r := gin.Default()
		r.NoRoute(func(c *gin.Context) {
			println("src_ip_port", c.Request.RemoteAddr)
			println("dest_ip_port", c.Request.Context().Value(http.LocalAddrContextKey).(net.Addr).String())

			targetURL, err := url.Parse(dst)
			if err != nil {
				log.Fatalf("Failed to parse dst URL: %v", err)
			}

			proxy := httputil.NewSingleHostReverseProxy(targetURL)

			c.Request.URL.Host = targetURL.Host
			c.Request.URL.Scheme = targetURL.Scheme
			c.Request.Header.Set("X-Forwarded-Host", c.Request.Host)
			c.Request.Host = targetURL.Host

			proxy.ServeHTTP(c.Writer, c.Request)
		})
		panic(r.Run(":" + listenPort))
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().StringVarP(&dst, "dst", "d", "http://192.168.3.29", "反向代理的目标")
	proxyCmd.Flags().StringVarP(&listenPort, "port", "p", "80", "反向代理服务监听的端口号")
}
