package commitment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore 以本機 JSON 檔模擬鏈上的 commitment 儲存。
//
// 這只是開發階段的替身，用來在不依賴任何鏈基礎設施的情況下驗證
// client 與 server 的邏輯。它「不」提供鏈所提供的任何安全性質 ——
// 沒有不可竄改性、沒有全域一致性、沒有可稽核性。
type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) load() (map[string]string, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}

	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", s.path, err)
	}
	return m, nil
}

func (s *FileStore) GetPkHash(_ context.Context, serverAddr string) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return [32]byte{}, err
	}

	hexStr, ok := m[serverAddr]
	if !ok {
		return [32]byte{}, ErrNotFound
	}

	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return [32]byte{}, fmt.Errorf("解析 %s 的 hash: %w", serverAddr, err)
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("%s 的 hash 長度為 %d，應為 32", serverAddr, len(raw))
	}

	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func (s *FileStore) Publish(_ context.Context, serverAddr string, pkHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.load()
	if err != nil {
		return err
	}
	m[serverAddr] = hex.EncodeToString(pkHash[:])

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}
