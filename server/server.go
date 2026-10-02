// server 是 pqNK demo 的 responder 端。
//
// 兩種啟動模式：
//
//	./server            一般啟動：載入既有金鑰，自我檢查後開始服務
//	./server -rotate    輪替：產生新金鑰、簽署、發布 commitment、存檔
//
// 預設為一般啟動。輪替是罕見且有成本的操作（接鏈後會發出交易），
// 不應因為誤重啟而觸發。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	flagRotate  = flag.Bool("rotate", false, "產生新的靜態金鑰並發布 commitment")
	flagListen  = flag.String("listen", "10.99.0.2:9443", "監聽位址")
	flagDataDir = flag.String("data", "./data", "金鑰與簽章的存放目錄")
	flagAddr    = flag.String("addr", "server-1", "本 server 的識別碼（接鏈後為鏈上位址）")
	flagStore   = flag.String("store", "./data/commitments.json", "commitment 儲存位置")
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

	staticPath := filepath.Join(*flagDataDir, "static.pem")
	staticPubPath := filepath.Join(*flagDataDir, "static-pub.pem")
	sigPath := filepath.Join(*flagDataDir, "commitment.sig")
	authPubPath := filepath.Join(*flagDataDir, "auth-pub.pem")
	authPrivPath := filepath.Join(*flagDataDir, "auth-priv.pem")

	store := commitment.NewFileStore(*flagStore)

	// auth 金鑰對只在第一次使用時產生。它是 client 的信任錨，一旦分發
	// 出去就不應更換 —— 更換需要帶外機制（見設計文件第 8 節）。
	if _, err := os.Stat(authPrivPath); errors.Is(err, os.ErrNotExist) {
		log.Printf("產生 pk_auth / sk_auth（%s）", signScheme.Name())
		if err := keys.SaveAuthPair(signScheme, authPubPath, authPrivPath); err != nil {
			return err
		}
		log.Printf("pk_auth 已寫入 %s —— 這是 client 的信任錨，需帶外分發", authPubPath)
	}

	if *flagRotate {
		return rotate(protocol.KEM, signScheme, store, staticPath, staticPubPath, sigPath, authPrivPath)
	}
	return serve(protocol, store, staticPath, sigPath)
}

// rotate 產生新的靜態金鑰並發布 commitment。
//
// 順序是「先發布、後存檔」：若反過來，一旦發布失敗，本地已換成新金鑰
// 而 commitment 仍指向舊的，所有 client 都會連線失敗且無復原路徑。
// 先發布的話，失敗時本地仍是舊狀態，重試即可。
func rotate(
	kemScheme hpqckem.Scheme,
	signScheme sign.Scheme,
	store commitment.Store,
	staticPath, staticPubPath, sigPath, authPrivPath string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	skAuth, err := keys.LoadAuthPrivate(authPrivPath, signScheme)
	if err != nil {
		return fmt.Errorf("載入 sk_auth: %w", err)
	}

	log.Printf("產生新的靜態 KEM 金鑰（%s）", kemScheme.Name())
	skStatic, err := keys.GenerateStatic(kemScheme)
	if err != nil {
		return err
	}

	pkHash := keys.PkHash(skStatic.Public())
	log.Printf("新公鑰摘要: %x", pkHash)

	sig := keys.SignCommitment(signScheme, skAuth, *flagAddr, pkHash)
	log.Printf("簽章長度: %d bytes", len(sig))

	if err := store.Publish(ctx, *flagAddr, pkHash); err != nil {
		return fmt.Errorf("發布 commitment: %w", err)
	}

	// 回讀確認：發布可能因交易被丟棄、rollback 等原因而未生效。
	// 未確認就存檔的話，本地與 commitment 會不同步。
	got, err := store.GetPkHash(ctx, *flagAddr)
	if err != nil {
		return fmt.Errorf("回讀 commitment: %w", err)
	}
	if got != pkHash {
		return fmt.Errorf("回讀不符：commitment %x，預期 %x", got, pkHash)
	}
	log.Print("commitment 發布並確認完成")

	// 確認無誤才覆蓋本地狀態
	if err := keys.SaveStatic(staticPath, skStatic); err != nil {
		return err
	}
	// 公鑰另存一份，供帶外分發給 client 作為初次連線的依據。
	// 這份檔案是公開資訊，外流無妨；重點是分發管道要能確保它不被替換。
	if err := keys.SaveStaticPublic(staticPubPath, skStatic.Public()); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return err
	}

	log.Printf("輪替完成。公鑰已寫入 %s，初次部署時需與 pk_auth 一併帶外分發給 client", staticPubPath)
	log.Print("以 ./server 啟動服務")
	return nil
}

// serverState 是服務期間需要的狀態。
//
// 注意 sk_auth 不在其中：服務期間所需的簽章是輪替時產生並存檔的，
// 因此 sk_auth 可以離線保存，只在執行 -rotate 時載入。
type serverState struct {
	protocol *nyquist.Protocol
	skStatic hpqckem.PrivateKey
	pkPEM    []byte // 公鑰的 PEM 編碼，回應 KeyQuery 用
	sig      []byte // pk_auth 對 (addr ‖ hash) 的簽章
}

func serve(
	protocol *nyquist.Protocol,
	store commitment.Reader,
	staticPath, sigPath string,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	skStatic, err := keys.LoadStatic(staticPath, protocol.KEM)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("找不到 %s —— 請先執行 ./server -rotate 產生金鑰", staticPath)
	}
	if err != nil {
		return err
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("讀取簽章 %s: %w", sigPath, err)
	}

	pkStatic := skStatic.Public()
	pkHash := keys.PkHash(pkStatic)

	// 啟動自我檢查：本地金鑰必須與已發布的 commitment 一致。
	// 不一致時拒絕啟動，而非警告後繼續 —— 此狀態下所有 client 都會
	// 驗證失敗，提供服務沒有意義，只會產生難以診斷的錯誤。
	onchain, err := store.GetPkHash(ctx, *flagAddr)
	switch {
	case errors.Is(err, commitment.ErrNotFound):
		return fmt.Errorf("commitment 中查無 %s —— client 無從驗證，請先執行 ./server -rotate", *flagAddr)
	case err != nil:
		return fmt.Errorf("查詢 commitment: %w", err)
	case onchain != pkHash:
		return fmt.Errorf("本地金鑰與 commitment 不同步：本地 %x，已發布 %x —— 請執行 ./server -rotate", pkHash, onchain)
	}
	log.Printf("自我檢查通過，公鑰摘要 %x", pkHash)

	st := &serverState{
		protocol: protocol,
		skStatic: skStatic,
		pkPEM:    kempem.ToPublicPEMBytes(pkStatic),
		sig:      sig,
	}

	listener, err := net.Listen("tcp", *flagListen)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("監聽 %s", *flagListen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go st.handle(conn)
	}
}

func (st *serverState) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Printf("[%s] 設定 deadline: %v", remote, err)
		return
	}

	msgType, payload, err := frame.Read(conn)
	if err != nil {
		log.Printf("[%s] 讀取首個 frame: %v", remote, err)
		return
	}

	switch msgType {
	case frame.TypeKeyQuery:
		// 回應公鑰與簽章。內容皆為公開資訊，不需加密也不需驗證對方身分
		// —— client 會以 commitment 的摘要與帶外的 pk_auth 自行驗證。
		log.Printf("[%s] 收到 KeyQuery，回應公鑰與簽章", remote)
		update := keys.MarshalKeyUpdate(st.pkPEM, st.sig)
		if err := frame.Write(conn, frame.TypeKeyUpdate, update); err != nil {
			log.Printf("[%s] 回應 KeyUpdate: %v", remote, err)
		}

	case frame.TypeHandshake:
		if err := st.handshake(conn, payload, remote); err != nil {
			log.Printf("[%s] 握手失敗: %v", remote, err)
		}

	default:
		log.Printf("[%s] 未知的 frame 型別 0x%02x", remote, msgType)
	}
}

func (st *serverState) handshake(conn net.Conn, msg1 []byte, remote net.Addr) error {
	hs, err := nyquist.NewHandshake(&nyquist.HandshakeConfig{
		Protocol: st.protocol,
		KEM: &nyquist.KEMConfig{
			LocalStatic: st.skStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: false,
	})
	if err != nil {
		return fmt.Errorf("NewHandshake: %w", err)
	}
	defer hs.Reset()

	if _, err := hs.ReadMessage(nil, msg1); err != nil {
		return fmt.Errorf("ReadMessage(msg1): %w", err)
	}

	// msg2 是 pqNK 的最後一則訊息，故此處預期 ErrDone
	msg2, err := hs.WriteMessage(nil, nil)
	if err != nil && err != nyquist.ErrDone {
		return fmt.Errorf("WriteMessage(msg2): %w", err)
	}
	if err := frame.Write(conn, frame.TypeHandshake, msg2); err != nil {
		return fmt.Errorf("送出 msg2: %w", err)
	}

	status := hs.GetStatus()
	log.Printf("[%s] 握手完成，HandshakeHash=%x", remote, status.HandshakeHash[:8])

	// pqNK 的 N 代表 client 無靜態金鑰，故 server 不應取得對方身分
	if status.KEM.RemoteStatic != nil {
		return errors.New("異常：server 取得了 client 的靜態公鑰")
	}

	// CipherStates[0] 是「送」、[1] 是「收」，且相對於自身角色。
	// server 與 client 的對應恰好相反。
	rx, tx := status.CipherStates[0], status.CipherStates[1]
	defer func() {
		rx.Reset()
		tx.Reset()
	}()

	// transport 階段：收一則、回一則
	_, ct, err := frame.Read(conn)
	if err != nil {
		return fmt.Errorf("讀取應用層訊息: %w", err)
	}
	pt, err := rx.DecryptWithAd(nil, nil, ct)
	if err != nil {
		// 握手看似成功但解密失敗，通常代表 client 用了過期的靜態公鑰
		// —— KEM 的 implicit rejection 會讓錯誤延後至此才浮現。
		return fmt.Errorf("解密失敗（client 可能持有過期的公鑰）: %w", err)
	}
	log.Printf("[%s] 收到: %q", remote, pt)

	reply, err := tx.EncryptWithAd(nil, nil, []byte("hello from server"))
	if err != nil {
		return fmt.Errorf("加密回覆: %w", err)
	}
	return frame.Write(conn, frame.TypeData, reply)
}
