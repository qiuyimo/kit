package cmd

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

var servers map[string]*http.Server

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "listen",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("listen called")

		demo()

	},
}

func init() {
	rootCmd.AddCommand(listenCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

type ServerManager struct {
	servers    map[string]*http.Server
	tlsServers map[string]*http.Server
	h          *gin.Engine
	mu         sync.Mutex
}

func (s *ServerManager) DelHttpListen(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	server, ok := s.servers[addr]
	if !ok {
		return fmt.Errorf("server %s not found", addr)
	}

	// 创建一个带有超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 优雅地关闭服务器
	if err := server.Shutdown(ctx); err != nil {
		return err
	}

	// 从映射中删除服务器
	delete(s.servers, addr)

	return nil
}

func demo() {
	// 示例用法
	r := gin.Default()
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	sm := &ServerManager{
		servers: make(map[string]*http.Server),
	}

	sm.servers[":8080"] = server

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("listen: %s\n", err)
		}
	}()

	// 模拟关闭服务器
	if err := sm.DelHttpListen(":8080"); err != nil {
		fmt.Printf("Failed to stop server: %s\n", err)
	} else {
		fmt.Println("Server stopped successfully")
	}
}
