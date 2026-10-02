// client 是 pqNK demo 的 initiator 端。
//
// 穩態下完全不查詢 commitment：直接以本地快取的公鑰握手。只有在握手
// 失敗時才進入復原路徑 —— 這正是本設計相對 TLS 的核心差異：TLS 每次
// 連線都要驗證憑證鏈，此處的驗證只在金鑰輪替後發生一次。
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	hpqckem "github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/mldsa"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"

	"github.com/johnnyT8011/pqnk-chain-pki/internal/commitment"
	"github.com/johnnyT8011/pqnk-chain-pki/internal/frame"
	"github.com/johnnyT8011/pqnk-chain-pki/internal/keys"
)

var (
	flagServer  = flag.String("server", "10.99.0.2:9443", "server 的網路位址")
	flagAddr    = flag.String("addr", "server-1", "server 的識別碼（帶外取得）")
	flagDataDir = flag.String("data", "./client-data", "快取與信任錨的存放目錄")
	flagStore   = flag.String("store", "./data/commitments.json", "commitment 儲存位置")
	flagRuns    = flag.Int("n", 1, "重複執行握手的次數；大於 1 時進入量測模式，"+
		"僅測穩態路徑（已快取的公鑰），不含 commitment 查詢或復原流程")
	flagOut = flag.String("out", "results.csv", "量測結果輸出的 CSV 路徑（僅 -n 大於 1 時使用）")
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

	if err := run(); err != nil {
		log.Fatalf("錯誤: %v", err)
	}
}

func run() error {
	protocol := &nyquist.Protocol{
		Pattern: pattern.PqNK,
		KEM:     kemschemes.ByName("Kyber768-X25519"),
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}
	signScheme := mldsa.Scheme65()

	if err := os.MkdirAll(*flagDataDir, 0o700); err != nil {
		return err
	}
	cachePath := filepath.Join(*flagDataDir, "server-pub.pem")
	authPubPath := filepath.Join(*flagDataDir, "auth-pub.pem")

	// pk_auth 是信任錨，必須帶外取得。絕不可從 server 接收 —— 否則
	// 對手只要同時替換 pk_auth 與簽章即可通過驗證。
	pkAuth, err := keys.LoadAuthPublic(authPubPath, signScheme)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("找不到 %s —— pk_auth 需帶外取得（從 server 的 data/auth-pub.pem 複製過來）", authPubPath)
	}
	if err != nil {
		return err
	}

	c := &client{
		protocol:   protocol,
		signScheme: signScheme,
		pkAuth:     pkAuth,
		store:      commitment.NewFileStore(*flagStore),
		cachePath:  cachePath,
	}

	// server 公鑰與 pk_auth 同為帶外分發的初始狀態。缺少時拒絕啟動，
	// 而非改走自動取得的路徑 —— 首次連線應完全不依賴鏈上查詢，這是
	// 「穩態不查鏈」的一部分。自動取得只用於輪替後的復原（見 recover）。
	cached, err := keys.LoadStaticPublic(cachePath, protocol.KEM)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("找不到 %s —— server 公鑰需帶外取得（從 server 的 data/static-pub.pem 複製過來）", cachePath)
	}
	if err != nil {
		return fmt.Errorf("讀取快取: %w", err)
	}

	// 量測模式：重複執行穩態握手 N 次，記錄各次耗時。
	// 只測穩態路徑，不含 commitment 查詢或復原流程 —— 那些走的是
	// 完全不同的路徑，跟本次要量的「單次握手成本」混在一起沒有意義。
	if *flagRuns > 1 {
		return c.benchmark(cached)
	}

	// 穩態路徑：直接以快取的公鑰握手，完全不碰 commitment
	if _, err := c.attempt(cached); err == nil {
		return nil
	} else {
		log.Printf("以快取的公鑰握手失敗: %v", err)
	}

	c.cached = cached
	return c.recover()
}

// benchmark 重複執行穩態握手 flagRuns 次，把每次的耗時（與失敗訊息，若有）
// 寫進一份 CSV，供之後用 Python/R 等工具算中位數、95th percentile 或繪圖。
//
// 每一列格式為 run,elapsed_ns,error —— error 欄位平常是空字串，只有該次
// 握手失敗時才填。之所以記錄失敗而非直接中止整批量測，是因為單次網路
// 抖動或封包遺失造成的握手失敗，本身也是量測的一部分，不該讓它中斷整
// 個實驗；但失敗的那筆耗時不該被當成正常樣本計入統計，這件事交給後續
// 的分析腳本依 error 欄位是否為空來過濾，不在這裡先做主觀判斷。
func (c *client) benchmark(remoteStatic hpqckem.PublicKey) error {
	f, err := os.Create(*flagOut)
	if err != nil {
		return fmt.Errorf("建立輸出檔 %s: %w", *flagOut, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"run", "elapsed_ns", "error"}); err != nil {
		return fmt.Errorf("寫入 CSV 標頭: %w", err)
	}

	c.quiet = true // 抑制單次握手的 log，否則 -n 1000 會洗版
	var failures int

	for i := 0; i < *flagRuns; i++ {
		elapsed, err := c.attempt(remoteStatic)

		errStr := ""
		if err != nil {
			errStr = err.Error()
			failures++
		}

		if werr := w.Write([]string{
			strconv.Itoa(i),
			strconv.FormatInt(elapsed.Nanoseconds(), 10),
			errStr,
		}); werr != nil {
			return fmt.Errorf("寫入第 %d 筆結果: %w", i, werr)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("寫入 CSV: %w", err)
	}

	log.Printf("完成 %d 次握手，%d 次失敗，結果寫入 %s", *flagRuns, failures, *flagOut)
	return nil
}

type client struct {
	protocol   *nyquist.Protocol
	signScheme sign.Scheme
	pkAuth     sign.PublicKey
	store      commitment.Reader
	cachePath  string
	cached     hpqckem.PublicKey // 握手失敗時的本地公鑰，recover 用來判斷是否已輪替
	quiet      bool              // true 時抑制單次握手的 log，量測模式用
}

// logf 在非量測模式下印出訊息；量測模式下（quiet=true）靜默略過，
// 避免 -n 1000 這種重複執行時洗版終端機。
func (c *client) logf(format string, args ...interface{}) {
	if !c.quiet {
		log.Printf(format, args...)
	}
}

// recover 是握手失敗後的復原路徑。
func (c *client) recover() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	onchain, err := c.store.GetPkHash(ctx, *flagAddr)
	if errors.Is(err, commitment.ErrNotFound) {
		return fmt.Errorf("commitment 中查無 %s", *flagAddr)
	}
	if err != nil {
		return fmt.Errorf("查詢 commitment: %w", err)
	}

	// 若本地快取的摘要與已發布的一致，代表金鑰是對的，握手失敗另有原因
	// （中間人、server 故障、網路問題）。此時不應重試取得新公鑰 ——
	// 那只會讓對手有機會反覆消耗資源。
	if keys.PkHash(c.cached) == onchain {
		return errors.New("本地公鑰與 commitment 一致，握手失敗另有原因（可能為中間人攻擊），中止")
	}
	log.Print("本地公鑰與 commitment 不符，server 已輪替")

	update, err := c.fetchKey()
	if err != nil {
		return err
	}

	// 驗證一：公鑰必須與 commitment 記錄的摘要相符。
	// server 送來的內容本身不需被信任，這個比對才是判準。
	pkNew, err := kempem.FromPublicPEMBytes(update.PublicKeyPEM, c.protocol.KEM)
	if err != nil {
		return fmt.Errorf("解析 server 送來的公鑰: %w", err)
	}
	if got := keys.PkHash(pkNew); got != onchain {
		return fmt.Errorf("server 送來的公鑰摘要 %x 與 commitment 的 %x 不符，中止", got, onchain)
	}

	// 驗證二：commitment 必須經 sk_auth 授權。這一層擋的是「對手偽造
	// 交易寫入鏈上」—— 在古典簽章鏈上，寫入權限本身不可信，授權完全
	// 由此簽章提供。
	//
	// 注意訊息以「本地帶外取得的」*flagAddr 組成，而非 server 送來的
	// 任何資料，否則位址綁定形同虛設。
	if !keys.VerifyCommitment(c.signScheme, c.pkAuth, *flagAddr, onchain, update.Signature) {
		return errors.New("pk_auth 簽章驗證失敗，commitment 未經授權，中止")
	}
	log.Print("公鑰摘要與 pk_auth 簽章皆驗證通過")

	if _, err := c.attempt(pkNew); err != nil {
		// 驗證通過但握手仍失敗：不更新快取，保留上次能用的狀態
		return fmt.Errorf("以新公鑰握手仍失敗，不更新快取: %w", err)
	}

	// 握手成功才寫入快取 —— 驗證通過只證明「這把是被授權的」，
	// 不證明「這把現在真的能用」（例如 server 已發布但尚未切換）。
	if err := keys.SaveStaticPublic(c.cachePath, pkNew); err != nil {
		return fmt.Errorf("更新快取: %w", err)
	}
	log.Print("快取已更新")
	return nil
}

// fetchKey 向 server 索取當前的公鑰與簽章。
func (c *client) fetchKey() (*keys.KeyUpdate, error) {
	conn, err := net.DialTimeout("tcp", *flagServer, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("連線至 %s: %w", *flagServer, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}

	if err := frame.Write(conn, frame.TypeKeyQuery, nil); err != nil {
		return nil, fmt.Errorf("送出 KeyQuery: %w", err)
	}

	msgType, payload, err := frame.Read(conn)
	if err != nil {
		return nil, fmt.Errorf("讀取 KeyUpdate: %w", err)
	}
	if msgType != frame.TypeKeyUpdate {
		return nil, fmt.Errorf("預期 KeyUpdate，收到 0x%02x", msgType)
	}

	update, err := keys.UnmarshalKeyUpdate(payload)
	if err != nil {
		return nil, err
	}
	log.Printf("收到公鑰 %d bytes、簽章 %d bytes", len(update.PublicKeyPEM), len(update.Signature))
	return update, nil
}

// attempt 以指定的公鑰執行一次完整的握手與訊息交換，回傳握手耗時
// （見 handshake 內的計時範圍說明）。
func (c *client) attempt(remoteStatic hpqckem.PublicKey) (time.Duration, error) {
	conn, err := net.DialTimeout("tcp", *flagServer, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("連線至 %s: %w", *flagServer, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}

	return c.handshake(conn, remoteStatic)
}

func (c *client) handshake(conn net.Conn, remoteStatic hpqckem.PublicKey) (time.Duration, error) {
	hs, err := nyquist.NewHandshake(&nyquist.HandshakeConfig{
		Protocol: c.protocol,
		KEM: &nyquist.KEMConfig{
			RemoteStatic: remoteStatic,
			GenKey:       seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	})
	if err != nil {
		return 0, fmt.Errorf("NewHandshake: %w", err)
	}
	defer hs.Reset()

	// 計時範圍對照 Paquin/Stebila/Tamvada (2020) 對「handshake completion
	// time」的定義：從發起方送出第一則訊息，到能夠開始送應用層資料為止
	// （即這裡的 ErrDone）。不含 TCP 三次握手，也不含 transport 階段。
	start := time.Now()

	msg1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("WriteMessage(msg1): %w", err)
	}
	if err := frame.Write(conn, frame.TypeHandshake, msg1); err != nil {
		return 0, fmt.Errorf("送出 msg1: %w", err)
	}

	msgType, msg2, err := frame.Read(conn)
	if err != nil {
		return 0, fmt.Errorf("讀取 msg2: %w", err)
	}
	if msgType != frame.TypeHandshake {
		return 0, fmt.Errorf("預期 Handshake，收到 0x%02x", msgType)
	}

	// msg2 是 pqNK 的最後一則訊息，故此處預期 ErrDone
	if _, err := hs.ReadMessage(nil, msg2); err != nil && err != nyquist.ErrDone {
		return 0, fmt.Errorf("ReadMessage(msg2): %w", err)
	}

	elapsed := time.Since(start)

	status := hs.GetStatus()
	c.logf("握手完成，耗時 %v，HandshakeHash=%x", elapsed, status.HandshakeHash[:8])

	// client 這側 CipherStates[0] 是「送」、[1] 是「收」
	tx, rx := status.CipherStates[0], status.CipherStates[1]
	defer func() {
		tx.Reset()
		rx.Reset()
	}()

	ct, err := tx.EncryptWithAd(nil, nil, []byte("hello from client"))
	if err != nil {
		return elapsed, fmt.Errorf("加密: %w", err)
	}
	if err := frame.Write(conn, frame.TypeData, ct); err != nil {
		return elapsed, fmt.Errorf("送出訊息: %w", err)
	}

	_, replyCt, err := frame.Read(conn)
	if err != nil {
		// 若 client 用了過期的公鑰，KEM 的 implicit rejection 會讓握手
		// 看似成功，錯誤直到此處（server 解不開、直接斷線）才浮現。
		return elapsed, fmt.Errorf("讀取回覆（可能持有過期的公鑰）: %w", err)
	}
	reply, err := rx.DecryptWithAd(nil, nil, replyCt)
	if err != nil {
		return elapsed, fmt.Errorf("解密回覆: %w", err)
	}
	c.logf("收到 server 回覆: %q", reply)
	return elapsed, nil
}
