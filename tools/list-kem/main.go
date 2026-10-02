// list-kem 列出 hpqc 目前註冊的所有 KEM 方案，連同各自的公鑰、密文、
// 共享金鑰大小。
//
// 用途：換 KEM 演算法比較效能/成本之前，先看清楚各方案的資料大小差異
// ——這些數字直接對應到 pqNK 訊息長度、以及 commitment 的 gas 成本。
//
// 用法：
//
//	go run ./tools/list-kem
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/katzenpost/circl/kem/mlkem/mlkem1024"
	"github.com/katzenpost/circl/kem/mlkem/mlkem512"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/circlkem"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
)

func main() {
	schemes := kemschemes.All()
	schemes = append(schemes, mlkem768.Scheme())
	schemes = append(schemes, circlkem.FromCircl(mlkem512.Scheme()))
	schemes = append(schemes, circlkem.FromCircl(mlkem1024.Scheme()))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "NAME\tPUBLIC KEY\tCIPHERTEXT\tSHARED KEY\tSEED")

	for _, s := range schemes {
		printRow(w, s)
	}
}

func printRow(w *tabwriter.Writer, s kem.Scheme) {
	fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\n",
		s.Name(),
		s.PublicKeySize(),
		s.CiphertextSize(),
		s.SharedKeySize(),
		s.SeedSize(),
	)
}
