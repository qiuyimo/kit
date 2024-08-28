package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "decode",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("decode called")

		dd()
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decodeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func dd() {
	// fd, err := os.Open("/Users/rain/code/kit/a.txt")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer fd.Close()
	// data, _ := ioutil.ReadAll(fd)
	// data := `\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\x0agoogle.com\x00\x50GET / HTTP/1.0\r\n\r\n`
	data := `\x00\x00\b\a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PRI * H`
	fmt.Printf("original bytes from file: %v\n", data)
	fmt.Printf("original strings from file: %v\n", string(data))

	var (
		decodeStr []rune
		tmp       string
	)
	for _, char := range data {
		if char == '\\' {
			if len(tmp) != 0 {
				if tmp[0] == '\\' {
					decodeStr = append(decodeStr, decode(tmp)...)
				} else {
					for _, t := range tmp {
						decodeStr = append(decodeStr, t)
					}
				}
				tmp = "\\"
			}
			tmp = "\\"
		} else {
			tmp += string(char)
		}
	}

	decodeStr = append(decodeStr, decode(tmp)...)
	fmt.Printf("decoded bytes: %v\n", decodeStr)
	fmt.Printf("decoded strings: %s\n", string(decodeStr))
}

func decode(chars string) []rune {
	var result []rune
	switch chars[1] {
	case 'x':
		if len(chars) <= 4 {
			s, err := strconv.ParseUint(chars[2:], 16, 32)
			if err == nil {
				result = append(result, rune(s))
			}
		} else {
			s, err := strconv.ParseUint(chars[2:4], 16, 32)
			if err == nil {
				result = append(result, rune(s))
			}
			for _, x := range chars[4:] {
				result = append(result, x)
			}
		}
	case 'n':
		result = append(result, '\n')
	case 'r':
		result = append(result, '\r')
	case 't':
		result = append(result, '\t')
	}

	if chars[1] != 'x' && len(chars) > 2 {
		for _, x := range chars[3:] {
			result = append(result, x)
		}
	}

	return result
}
