/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
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
)

// consumeCmd represents the consume command
var consumeCmd = &cobra.Command{
	Use:   "consume",
	Short: "kafka consume",
	Example: `kit kafka consume --ca /home/user/certs/ca.crt \
		--cert /home/user/certs/client.crt \
		--key /home/user/certs/client.key \
		--user xxxx \
		--pwd xxxxxxxxxxx \
		--mechanism PLAIN \
		--brokers 127.0.0.1:9092 \
		--topic rain_test_gateway \
		--connections 10 \
		--sleep-time 0 \
		--verbose=false \
		--group-id group_name \
		--offsets-initial oldest`,

	Run: func(cmd *cobra.Command, args []string) {
		kafkaConsumer(kafkaConfig)
	},
}

func init() {
	kafkaCmd.AddCommand(consumeCmd)

	consumeCmd.Flags().StringSliceVar(&kafkaConfig.Brokers, "brokers", []string{"127.0.0.1:9092"}, "Kafka broker addresses")
	consumeCmd.Flags().StringVar(&kafkaConfig.Topic, "topic", "test-topic", "Kafka topic")
	consumeCmd.Flags().StringVar(&kafkaConfig.CertPath, "cert", "", "TLS cert path")
	consumeCmd.Flags().StringVar(&kafkaConfig.KeyPath, "key", "", "TLS key path")
	consumeCmd.Flags().StringVar(&kafkaConfig.CaPath, "ca", "", "CA cert path")
	consumeCmd.Flags().StringVar(&kafkaConfig.Mechanism, "mechanism", "PLAIN", "SASL mechanism (PLAIN,SCRAM-SHA-256 or SCRAM-SHA-512)")
	consumeCmd.Flags().StringVar(&kafkaConfig.User, "user", "", "SASL user")
	consumeCmd.Flags().StringVar(&kafkaConfig.Pwd, "pwd", "", "SASL password")
	consumeCmd.Flags().IntVar(&kafkaConfig.Connections, "connections", 1, "Number of producer connections")
	consumeCmd.Flags().DurationVar(&kafkaConfig.SleepTime, "sleep-time", 1*time.Second, "Sleep time between messages")
	consumeCmd.Flags().BoolVar(&kafkaConfig.Verbose, "verbose", true, "Enable verbose output for successful messages")
	consumeCmd.Flags().StringVar(&kafkaConfig.GroupID, "group-id", "", "Consumer group ID")
	consumeCmd.Flags().StringVar(&kafkaConfig.OffsetsInitial, "offsets-initial", "newest", "Offsets initial position (oldest/newest), If the consumer group has been used, it is invalid")
}

type consumerGroupHandler struct {
	totalMessages *int64
	verbose       bool
	sleepTime     time.Duration
}

func (h consumerGroupHandler) Setup(sess sarama.ConsumerGroupSession) error {
	fmt.Println("Setup called, assigned partitions:", sess.Claims())
	return nil
}

func (h consumerGroupHandler) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (h consumerGroupHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		atomic.AddInt64(h.totalMessages, 1)
		if h.verbose {
			fmt.Printf("[%s] ConsumerGroup: Received message from topic(%s)/partition(%d)/offset(%d): %s\n",
				time.Now().Format("2006-01-02 15:04:05.000"), msg.Topic, msg.Partition, msg.Offset, string(msg.Value))
		}
		sess.MarkMessage(msg, "")
		if h.sleepTime > 0 {
			time.Sleep(h.sleepTime)
		}
	}
	return nil
}

func getClient(cfg KafkaConfig) *sarama.Config {
	config := sarama.NewConfig()
	config.Version = sarama.V2_1_0_0 // 可根据实际Kafka版本调整
	config.Consumer.Return.Errors = true
	config.Consumer.Offsets.AutoCommit.Enable = true
	config.Consumer.Offsets.AutoCommit.Interval = 1 * time.Second
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

	/*
		cfg.OffsetsInitial（即 config.Consumer.Offsets.Initial）只在 group 第一次消费某个分区时生效。
		只要 group id 在 Kafka 里有 offset 记录（即之前消费过），下次启动会从上次提交的 offset 继续消费，而不是从头（oldest）或最新（newest）。
		OffsetsInitial 只有在该 group id 从未消费过该 topic/partition时，才决定起始 offset。
	*/
	// 根据参数设置 offsets initial
	if cfg.OffsetsInitial == "oldest" {
		config.Consumer.Offsets.Initial = sarama.OffsetOldest
	} else {
		config.Consumer.Offsets.Initial = sarama.OffsetNewest
	}

	return config
}

func kafkaConsumer(cfg KafkaConfig) {
	startTime := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var totalMessages int64
	var wg sync.WaitGroup

	config := getClient(cfg)
	client, err := sarama.NewClient(cfg.Brokers, config)
	if err != nil {
		log.Fatalf("Failed to create Kafka client: %v", err)
	}
	defer client.Close()

	partitions, err := client.Partitions(cfg.Topic)
	if err != nil {
		log.Fatalf("Failed to get partitions: %v", err)
	}
	fmt.Printf("topic %s 分区数: %d\n", cfg.Topic, len(partitions))

	for i := 0; i < cfg.Connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			groupID := cfg.GroupID
			if groupID == "" {
				groupID = "kit-consumer-group"
			}
			consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, groupID, config)
			if err != nil {
				log.Fatalf("ConsumerGroup %d: Failed to start: %v", id, err)
			}
			defer consumerGroup.Close()

			for {
				if ctx.Err() != nil {
					// fmt.Printf("ConsumerGroup %d: Context error: %v", id, ctx.Err())
					return
				}
				err := consumerGroup.Consume(ctx, []string{cfg.Topic}, consumerGroupHandler{totalMessages: &totalMessages, verbose: cfg.Verbose, sleepTime: cfg.SleepTime})
				if err != nil {
					log.Printf("ConsumerGroup %d: Error from Consume: %v", id, err)
				}
			}
		}(i)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
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

	runtime := time.Since(startTime)
	finalCount := atomic.LoadInt64(&totalMessages)

	fmt.Printf("\n=== 程序已停止 ===\n")
	fmt.Printf("运行时间: %v\n", runtime)
	fmt.Printf("brokers: %v\n", cfg.Brokers)
	fmt.Printf("topic: %v\n", cfg.Topic)
	fmt.Printf("分区数: %d\n", len(partitions))
	fmt.Printf("消费组: %v\n", cfg.GroupID)
	fmt.Printf("连接数: %d\n", cfg.Connections)
	fmt.Printf("每个连接的消息消费间隔: %v\n", cfg.SleepTime)
	fmt.Printf("总共消费消息数量: %d\n", finalCount)
	fmt.Printf("平均每个连接消费: %.2f 条消息\n", float64(finalCount)/float64(cfg.Connections))
	fmt.Printf("平均每秒消费: %.2f 条消息\n", float64(finalCount)/runtime.Seconds())
}
