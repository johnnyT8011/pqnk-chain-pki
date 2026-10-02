// Package keys 處理靜態 KEM 金鑰的存取，以及 commitment 的簽署與驗證。
//
// 金鑰的序列化與檔案格式一律交給 hpqc 的 pem 套件處理，不自行實作 ——
// 該格式的 PEM 標頭帶有 scheme 名稱（例如 "ML-DSA-65 PUBLIC KEY"），
// 讀取時會檢查是否與指定的 scheme 相符，因此不會發生「用錯誤的 scheme
// 解讀而靜默得到垃圾」的情況。
//
// 本套件只自行實作兩樣東西，因為它們屬於本協定的定義而非密碼學原語:
// commitment 的簽名範圍，以及 KeyUpdate 的線上格式。
package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/hash"
	hpqckem "github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/seec"
)

// HashSize 是 commitment 摘要的長度。
const HashSize = hash.HashSize

// PkHash 計算公鑰的摘要，作為上鏈的 commitment 內容。
//
// 此函式的確定性是整個設計的前提: 同一把公鑰每次都必須得到完全相同的
// 摘要，否則鏈上的值永遠對不上。
func PkHash(pk hpqckem.PublicKey) [HashSize]byte {
	return hash.Sum256From(pk)
}

// PkHashBytes 對已 marshal 的公鑰位元組計算摘要。
func PkHashBytes(pkBytes []byte) [HashSize]byte {
	return hash.Sum256(pkBytes)
}

// --- 靜態 KEM 金鑰 ---

// GenerateStatic 產生一組新的靜態 KEM 金鑰對。
func GenerateStatic(scheme hpqckem.Scheme) (hpqckem.PrivateKey, error) {
	genRand, err := seec.GenKeyPRPAES(nil, 256)
	if err != nil {
		return nil, fmt.Errorf("seec.GenKeyPRPAES: %w", err)
	}
	_, sk := kem.GenerateKeypair(scheme, genRand)
	return sk, nil
}

// LoadStatic 載入靜態 KEM 私鑰。
func LoadStatic(path string, scheme hpqckem.Scheme) (hpqckem.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return kempem.FromPrivatePEMBytes(b, scheme)
}

// SaveStatic 寫入靜態 KEM 私鑰。
//
// 使用 hpqc 的 PEM 編碼，但檔案寫入自行處理: hpqc 的 PrivateKeyToFile
// 直接覆寫目標檔案，若寫入過程中斷會留下損毀的檔案。輪替時這個檔案會
// 被覆寫，故採「寫暫存檔再 rename」—— rename 在同一檔案系統內是原子
// 操作，不會出現半舊半新的中間狀態。
func SaveStatic(path string, sk hpqckem.PrivateKey) error {
	return writeAtomic(path, kempem.ToPrivatePEMBytes(sk), 0o600)
}

// LoadStaticPublic 載入 client 快取的 server 公鑰。
func LoadStaticPublic(path string, scheme hpqckem.Scheme) (hpqckem.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return kempem.FromPublicPEMBytes(b, scheme)
}

// SaveStaticPublic 寫入 client 的公鑰快取。
func SaveStaticPublic(path string, pk hpqckem.PublicKey) error {
	return writeAtomic(path, kempem.ToPublicPEMBytes(pk), 0o644)
}

// --- commitment 授權金鑰 ---

// LoadAuthPublic 載入驗證 commitment 用的 pk_auth。
//
// 這是 client 的信任錨，必須經由帶外管道取得（隨軟體發布、手動設定等），
// 絕不可從 server 接收 —— 否則對手只要同時替換 pk_auth 與簽章即可通過
// 驗證，整層授權形同虛設。
func LoadAuthPublic(path string, scheme sign.Scheme) (sign.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return signpem.FromPublicPEMBytes(b, scheme)
}

// LoadAuthPrivate 載入簽署 commitment 用的 sk_auth。
//
// 僅在輪替時需要，平時應離線保存。
func LoadAuthPrivate(path string, scheme sign.Scheme) (sign.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return signpem.FromPrivatePEMBytes(b, scheme)
}

// SaveAuthPair 產生並儲存一組 pk_auth / sk_auth。僅在初始化時使用。
func SaveAuthPair(scheme sign.Scheme, pubPath, privPath string) error {
	pk, sk, err := scheme.GenerateKey()
	if err != nil {
		return fmt.Errorf("產生 auth 金鑰: %w", err)
	}
	if err := writeAtomic(pubPath, signpem.ToPublicPEMBytes(pk), 0o644); err != nil {
		return err
	}
	return writeAtomic(privPath, signpem.ToPrivatePEMBytes(sk), 0o600)
}

// --- commitment 的簽署與驗證 ---

// commitmentMessage 組出被 pk_auth 簽署的訊息。
//
// 涵蓋 server 位址是為了將 commitment 綁定至特定的鏈上身分: 若不綁定，
// 對手可將某個 server 的真實簽章，搬到他所控制的位址底下重新發布。
//
// client 驗證時必須以「自己帶外取得的」位址組這個訊息，而非 server
// 送來的任何資料，否則綁定形同虛設。
func commitmentMessage(serverAddr string, pkHash [HashSize]byte) []byte {
	msg := make([]byte, 0, len(serverAddr)+HashSize)
	msg = append(msg, []byte(serverAddr)...)
	msg = append(msg, pkHash[:]...)
	return msg
}

// SignCommitment 以 sk_auth 簽署 (serverAddr ‖ pkHash)。
func SignCommitment(scheme sign.Scheme, sk sign.PrivateKey, serverAddr string, pkHash [HashSize]byte) []byte {
	return scheme.Sign(sk, commitmentMessage(serverAddr, pkHash), nil)
}

// VerifyCommitment 以 pk_auth 驗證簽章。
func VerifyCommitment(scheme sign.Scheme, pk sign.PublicKey, serverAddr string, pkHash [HashSize]byte, sig []byte) bool {
	return scheme.Verify(pk, commitmentMessage(serverAddr, pkHash), sig, nil)
}

// --- KeyUpdate 線上格式 ---

// KeyUpdate 是 TypeKeyUpdate frame 的內容: 完整公鑰加上 pk_auth 簽章。
//
// 此訊息不需加密也不需來源驗證 —— 公鑰與簽章本為公開資訊，且 client
// 會以鏈上的摘要與帶外的 pk_auth 驗證內容，送出者身分無關緊要。
type KeyUpdate struct {
	PublicKeyPEM []byte
	Signature    []byte
}

var ErrMalformedKeyUpdate = errors.New("keys: KeyUpdate 格式錯誤")

// MarshalKeyUpdate 序列化為 [4 bytes 公鑰長度][公鑰 PEM][簽章]。
func MarshalKeyUpdate(pkPEM, sig []byte) []byte {
	out := make([]byte, 4+len(pkPEM)+len(sig))
	out[0] = byte(len(pkPEM) >> 24)
	out[1] = byte(len(pkPEM) >> 16)
	out[2] = byte(len(pkPEM) >> 8)
	out[3] = byte(len(pkPEM))
	copy(out[4:], pkPEM)
	copy(out[4+len(pkPEM):], sig)
	return out
}

// UnmarshalKeyUpdate 解析 MarshalKeyUpdate 的輸出。
func UnmarshalKeyUpdate(b []byte) (*KeyUpdate, error) {
	if len(b) < 4 {
		return nil, ErrMalformedKeyUpdate
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 || 4+n > len(b) {
		return nil, ErrMalformedKeyUpdate
	}
	return &KeyUpdate{
		PublicKeyPEM: b[4 : 4+n],
		Signature:    b[4+n:],
	}, nil
}

// --- 檔案寫入 ---

// writeAtomic 寫暫存檔後 rename。rename 在同一檔案系統內是原子操作，
// 因此不會出現寫到一半中斷所留下的損毀檔案。
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // 成功時 rename 已移走，此處為 no-op

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
