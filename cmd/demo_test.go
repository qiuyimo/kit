package cmd

import (
	"fmt"
	"testing"
	"time"
)

func Test_checkAddress(t *testing.T) {
	addr := "127.0.0.1:3306"

	err := d(addr)
	fmt.Printf("err: %v\n", err)
}

func d(addr string) error {
	for i := 0; i < 5; i++ {
		time.Sleep(1 * time.Second)
		if err := checkAddress(addr); err == nil {
			return nil
		}
	}

	return fmt.Errorf("fail")
}
