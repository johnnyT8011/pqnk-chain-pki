// list-sign 列出 hpqc 目前註冊的所有簽章方案，連同各自的公鑰、私鑰、
// 簽章大小。
//
// 用途：pk_auth 目前用的是 ML-DSA-65；這支工具用來確認還有哪些方案
// 可選，以及各自的簽章大小 —— 這個數字直接影響 server 送出 KeyUpdate
// frame 的大小，以及（若簽章上鏈時）gas 成本。
//
// 用法：
//
//	go run ./tools/list-sign
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

func main() {
	schemes := signschemes.All()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "NAME\tPUBLIC KEY\tPRIVATE KEY\tSIGNATURE")

	for _, s := range schemes {
		printRow(w, s)
	}
}

func printRow(w *tabwriter.Writer, s sign.Scheme) {
	fmt.Fprintf(w, "%s\t%d\t%d\t%d\n",
		s.Name(),
		s.PublicKeySize(),
		s.PrivateKeySize(),
		s.SignatureSize(),
	)
}
