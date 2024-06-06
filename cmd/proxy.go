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
		r.GET("/proxy", func(c *gin.Context) {
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// 本地标志：它只适用于该指定命令
	proxyCmd.Flags().StringVarP(&dst, "dst", "d", "192.168.3.29", "反向代理的目标")
	// 标记为必选，如果没有提供，则会报错
	// _ = proxyCmd.MarkFlagRequired("dst")

	proxyCmd.Flags().StringVarP(&listenPort, "port", "p", "80", "反向代理服务监听的端口号")
}
