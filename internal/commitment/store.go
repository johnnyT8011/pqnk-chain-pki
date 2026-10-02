// Package commitment 抽象化 commitment 的存取。
//
// 目前提供以檔案模擬的實作，供邏輯驗證使用；之後接上區塊鏈時，
// 只需新增一個實作同樣介面的型別，client 與 server 的程式碼不需改動。
// 這也是設計上「鏈不可知」(chain-agnostic) 的具體體現。
package commitment

import (
	"context"
	"errors"
)

// ErrNotFound 表示該 server 尚未發布過任何 commitment。
//
// 必須與「hash 為全零」明確區分：若查無紀錄時回傳零值，
// client 將無法分辨「未發布」與「發布的 hash 恰好為零」。
var ErrNotFound = errors.New("commitment: 查無紀錄")

// Reader 供 client 查詢 commitment。
type Reader interface {
	// GetPkHash 回傳指定 server 當前的公鑰摘要。
	// 查無紀錄時回傳 ErrNotFound。
	GetPkHash(ctx context.Context, serverAddr string) ([32]byte, error)
}

// Publisher 供 server 發布 commitment。
type Publisher interface {
	// Publish 寫入或更新指定 server 的公鑰摘要。
	Publish(ctx context.Context, serverAddr string, pkHash [32]byte) error
}

// Store 同時具備讀寫能力。
type Store interface {
	Reader
	Publisher
}
