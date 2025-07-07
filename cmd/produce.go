/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"github.com/spf13/cobra"
	"github.com/xdg-go/scram"
)

// 新增结构体
type KafkaConfig struct {
	Brokers        []string
	Topic          string
	CertPath       string
	KeyPath        string
	CaPath         string
	Mechanism      string
	User           string
	Pwd            string
	Connections    int
	Message        string
	MessageSize    int
	SleepTime      time.Duration
	Verbose        bool
	GroupID        string
	OffsetsInitial string
}

// 用于 flag 绑定的全局变量
var kafkaConfig KafkaConfig

// produceCmd represents the produce command
var produceCmd = &cobra.Command{
	Use:   "produce",
	Short: "kafka produce",
	Example: `dev env:
	go run . kafka produce --ca /Users/rain/yingke/certs/certs_35/ca.crt \
	--cert /Users/rain/yingke/certs/certs_35/client.crt \
	--key /Users/rain/yingke/certs/certs_35/client.key \
	--user xxxxx \
	--pwd xxxxx \
	--topic rain_test_1 \
	--mechanism SCRAM-SHA-256 \
	--brokers 127.0.0.1:9092 \
	--connections 10 \
	--message Hello \
	--message-size 1024 \
	--sleep-time 1s \
	--verbose=false
	
	product dev:
	kit kafka produce --ca /home/user/certs/ca.crt \
	--cert /home/user/certs/client.crt \
	--key /home/user/certs/client.key \
	--user xxxxx \
	--pwd xxxxxxxxx \
	--mechanism PLAIN \
	--brokers 127.0.0.1:9092 \
	--topic rain_test_1 \
	--connections 10 \
	--message Hello \
	--message-size 2048 \
	--sleep-time 500ms \
	--verbose=true`,

	Run: func(cmd *cobra.Command, args []string) {
		kafkaProducer(kafkaConfig)
	},
}

func init() {
	kafkaCmd.AddCommand(produceCmd)

	produceCmd.Flags().StringSliceVar(&kafkaConfig.Brokers, "brokers", []string{"10.213.144.10:9092"}, "Kafka broker addresses")
	produceCmd.Flags().StringVar(&kafkaConfig.Topic, "topic", "test-topic", "Kafka topic")
	produceCmd.Flags().StringVar(&kafkaConfig.CertPath, "cert", "", "TLS cert path")
	produceCmd.Flags().StringVar(&kafkaConfig.KeyPath, "key", "", "TLS key path")
	produceCmd.Flags().StringVar(&kafkaConfig.CaPath, "ca", "", "CA cert path")
	produceCmd.Flags().StringVar(&kafkaConfig.Mechanism, "mechanism", "PLAIN", "SASL mechanism (PLAIN,SCRAM-SHA-256 or SCRAM-SHA-512)")
	produceCmd.Flags().StringVar(&kafkaConfig.User, "user", "", "SASL user")
	produceCmd.Flags().StringVar(&kafkaConfig.Pwd, "pwd", "", "SASL password")
	produceCmd.Flags().IntVar(&kafkaConfig.Connections, "connections", 1, "Number of producer connections")
	produceCmd.Flags().StringVar(&kafkaConfig.Message, "message", "Hello, Kafka!", "Message content to send")
	produceCmd.Flags().IntVar(&kafkaConfig.MessageSize, "message-size", 1024, "Message size in bytes")
	produceCmd.Flags().DurationVar(&kafkaConfig.SleepTime, "sleep-time", 1*time.Second, "Sleep time between messages")
	produceCmd.Flags().BoolVar(&kafkaConfig.Verbose, "verbose", true, "Enable verbose output for successful messages")
}

// 自定义 SCRAM 客户端
type XDGSCRAMClient struct {
	HashGeneratorFcn scram.HashGeneratorFcn
	client           *scram.Client
	conv             *scram.ClientConversation
}

func (x *XDGSCRAMClient) Begin(user, password, authzID string) error {
	var err error
	x.client, err = x.HashGeneratorFcn.NewClient(user, password, authzID)
	if err != nil {
		return fmt.Errorf("failed to create SCRAM client: %v", err)
	}
	x.conv = x.client.NewConversation()
	return nil
}

func (x *XDGSCRAMClient) Step(challenge string) (string, error) {
	return x.conv.Step(challenge)
}

func (x *XDGSCRAMClient) Done() bool {
	return x.conv.Done()
}

// 生成 SCRAM 客户端的工厂方法
func scramClientGeneratorFunc(mechanism sarama.SASLMechanism) sarama.SCRAMClient {
	var client XDGSCRAMClient
	switch mechanism {
	case sarama.SASLTypeSCRAMSHA256:
		client.HashGeneratorFcn = scram.SHA256
	case sarama.SASLTypeSCRAMSHA512:
		client.HashGeneratorFcn = scram.SHA512
	default:
		client.HashGeneratorFcn = scram.SHA256
	}
	return &client
}

func getTlsCfg(certPath, keyPath, caPath string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal("msg", "failed to load TLS certificate", "error", err)
	}
	caCertBytes, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatal("msg", "failed to load caCertBytes", "error", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCertBytes) {
		log.Fatal("failed to append ca cert")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      certPool,
	}
}

// 生成指定大小的消息
func generateMessage(baseMessage string, size int) string {
	if size <= len(baseMessage) {
		return baseMessage[:size]
	}

	// 如果指定大小大于基础消息，则重复填充
	result := baseMessage
	for len(result) < size {
		remaining := size - len(result)
		if remaining >= len(baseMessage) {
			result += baseMessage
		} else {
			result += baseMessage[:remaining]
		}
	}
	return result
}

func kafkaProducer(cfg KafkaConfig) {
	// 记录开始时间
	startTime := time.Now()

	// 创建上下文用于优雅停止
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 用于统计消息数量的原子计数器
	var totalMessages int64
	var wg sync.WaitGroup

	for i := 0; i < cfg.Connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			config := sarama.NewConfig()
			config.Producer.RequiredAcks = sarama.WaitForAll
			config.Producer.Retry.Max = 5
			config.Producer.Return.Successes = true

			config.Net.SASL.Enable = true
			config.Net.SASL.User = cfg.User
			config.Net.SASL.Password = cfg.Pwd
			switch cfg.Mechanism {
			case "PLAIN":
				config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
			case "SCRAM-SHA-256":
				config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
			case "SCRAM-SHA-512":
				config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
			default:
				panic("unsupported SASL mechanism")
			}
			config.Net.TLS.Enable = true
			config.Net.TLS.Config = getTlsCfg(cfg.CertPath, cfg.KeyPath, cfg.CaPath)
			config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
				return scramClientGeneratorFunc(config.Net.SASL.Mechanism)
			}

			producer, err := sarama.NewSyncProducer(cfg.Brokers, config)
			if err != nil {
				log.Fatalf("Producer %d: Failed to start Sarama producer: %v", id, err)
			}
			defer producer.Close()

			for {
				select {
				case <-ctx.Done():
					fmt.Printf("Producer %d: 正在停止...\n", id)
					return
				default:
					msg := &sarama.ProducerMessage{
						Topic: cfg.Topic,
						Key:   sarama.StringEncoder(fmt.Sprintf("key-%d", id)),
						Value: sarama.StringEncoder(generateMessage(cfg.Message, cfg.MessageSize)),
					}
					partition, offset, err := producer.SendMessage(msg)
					if err != nil {
						log.Printf("ERROR: Producer %d: Failed to send message: %v", id, err)
					} else {
						// 原子递增消息计数
						atomic.AddInt64(&totalMessages, 1)
						if cfg.Verbose {
							fmt.Printf("[%s] SUCCESS: Producer %d: Message is stored in topic(%s)/partition(%d)/offset(%d)\n",
								time.Now().Format("2006-01-02 15:04:05.000"), id, cfg.Topic, partition, offset)
						}
					}

					// 使用带超时的 sleep，以便能够响应停止信号
					select {
					case <-time.After(cfg.SleepTime):
						continue
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动信号处理协程
	<-sigChan
	fmt.Println("\n接收到停止信号，正在优雅停止...")
	cancel()

	// 等待所有生产者协程完成，带5秒超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("所有生产者已优雅停止")
	case <-time.After(5 * time.Second):
		fmt.Println("警告: 5秒超时，强制停止程序")
	}

	// 计算运行时间
	runtime := time.Since(startTime)

	// 输出最终统计结果
	finalCount := atomic.LoadInt64(&totalMessages)
	fmt.Printf("\n=== 程序已停止 ===\n")
	fmt.Printf("运行时间: %v\n", runtime)
	fmt.Printf("连接数: %d\n", cfg.Connections)
	fmt.Printf("每个消息大小: %d 字节\n", cfg.MessageSize)
	fmt.Printf("每个连接的消息发送间隔: %v\n", cfg.SleepTime)
	fmt.Printf("总共发送消息数量: %d\n", finalCount)
	fmt.Printf("平均每个连接发送: %.2f 条消息\n", float64(finalCount)/float64(cfg.Connections))
	fmt.Printf("总发送数据量: %.2f MB\n", float64(finalCount*int64(cfg.MessageSize))/1024/1024)
	fmt.Printf("平均每秒发送: %.2f 条消息\n", float64(finalCount)/runtime.Seconds())
}
