// Package frame 提供帶型別標記的長度前綴訊息框架。
//
// TCP 是位元組串流，不保證「送一次 = 收一次」，因此需要自行標示訊息邊界。
// 格式為：
//
//	[ 4 bytes 長度 (big-endian, 不含自身與型別) ][ 1 byte 型別 ][ N bytes 內容 ]
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// 訊息型別。
const (
	TypeHandshake byte = 0x01 // pqNK 握手訊息
	TypeKeyUpdate byte = 0x02 // server → client：當前公鑰與 pk_auth 簽章
	TypeKeyQuery  byte = 0x03 // client → server：索取當前公鑰
	TypeData      byte = 0x04 // transport 階段的應用層資料
)

// MaxFrameSize 限制單一 frame 的大小，避免惡意的長度前綴導致巨量記憶體配置。
// pqNK 的 msg1 約 2.3 KB，公鑰加 ML-DSA-65 簽章約 4.5 KB，64 KB 綽綽有餘。
const MaxFrameSize = 64 * 1024

var ErrFrameTooLarge = errors.New("frame: 長度超過上限")

// Write 送出一個 frame。
func Write(w io.Writer, msgType byte, data []byte) error {
	if len(data) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(data))
	}

	buf := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(data)+1))
	buf[4] = msgType
	copy(buf[5:], data)

	// 一次寫出，避免長度前綴與內容之間被其他 goroutine 插入
	_, err := w.Write(buf)
	return err
}

// Read 讀取一個 frame，回傳型別與內容。
func Read(r io.Reader) (msgType byte, data []byte, err error) {
	var lenBuf [4]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}

	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 1 {
		return 0, nil, errors.New("frame: 長度不足以容納型別位元組")
	}
	if n > MaxFrameSize {
		return 0, nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}

	body := make([]byte, n)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}

	return body[0], body[1:], nil
}
