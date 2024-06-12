package httpserver

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"

	"github.com/qiuyimo/kit/cmd"
)

var (
	ip   string
	port string
)

// httpServerCmd represents the httpServer command
var httpServerCmd = &cobra.Command{
	Use:   "httpServer",
	Short: `http server`,
	Long: `http server

NoRoute: 收到请求后打印请求的 src ip port 和 dest ip port
mock 墨攻的接口，获取用户信息: /auth/plat/userinfo
mock 墨攻的接口，订单回调: /mogong/feedback
`,
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
		// mock 墨攻的用户同步接口
		r.POST("/auth/plat/userinfo", func(c *gin.Context) {
			c.String(200, "50c655eddd6bba91bb2e237c0322367ab06a42f7a84e4c7aff53a5ed0229ed85350435a638c6c8d4871f8376ea64a99d034967b179c2fa3fac3b44ba7159cc597b977c66b221465b8dc0034345ae50fe4c34f391ffe73096e3d4ac6a8b4a274dcd08551a4a8fb80bf49e81f6befc0f9758c4903311de6187903685bce5999c3f6d848eb9c28c3c826a734a21a307f9a088ae1198011a689c48d1e650c89c2418ec44b8881b50c5b02b2a8eb0e46f070d0516edb68eab8a18dfa4e503dcc1b429a7cc14685dbc09827a09948db85fcbed964e10ab3a11e7a5b06677e01cd9449bb981fa3212d4b0217f2c45e099f7cef4ef893817d65d1834533a35ab341e6f8afd3181a46a2cbfb5608cf3f7a4b71fc86ef4321d78099000951a0573f07023c8848b8aaa65c4a0069b49e2298f66ce77cea01bca370cbd7bbbc5c6580a112485ec63673cf945b96f9468f6295c696d4b7c0d04cb196499658505a2dc04866fd7d5d1fb76bdcdb048c34bde0c69374d6b9c734873406ba91f25f0c6ac8920d2b9666ebfbee1c9f46ec1af2b9da25a4a3b20392a16b4623a9a9b7a1ca97ea4cb7f")
		})
		// mock 墨攻的回调
		r.POST("/mogong/feedback", func(c *gin.Context) {
			c.JSON(200, map[string]interface{}{"msg": "操作成功", "code": 200})
		})
		panic(r.Run(fmt.Sprintf("%s:%s", ip, port)))
	},
}

func init() {
	cmd.RootCmd().AddCommand(httpServerCmd)

	httpServerCmd.Flags().StringVarP(&port, "port", "p", "80", "http 服务监听的端口")
	httpServerCmd.Flags().StringVarP(&ip, "ip", "i", "", "http 服务监听的ip (默认全部IP)")
}
