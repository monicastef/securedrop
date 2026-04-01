package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type PeerConn struct {
	Name       string
	Conn       interface{ Close() error }
	RW         interface {
		ReadString(byte) (string, error)
		WriteString(string) (int, error)
		Flush() error
	}
	Key        []byte
	RemotePub  []byte
	RemoteAddr string
}

type App struct {
	Self    *Identity
	Conns   map[string]*PeerConn
	Mu      sync.Mutex
	Pending []PendingRequest
}

type PendingRequest struct {
	Peer     *PeerConn
	Filename string
}

func NewApp(self *Identity) *App {
	return &App{
		Self:  self,
		Conns: make(map[string]*PeerConn),
	}
}

func (a *App) AddPending(pc *PeerConn, filename string) {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	a.Pending = append(a.Pending, PendingRequest{Peer: pc, Filename: filename})
}

func (a *App) PopPending() (PendingRequest, bool) {
	a.Mu.Lock()
	defer a.Mu.Unlock()

	if len(a.Pending) == 0 {
		return PendingRequest{}, false
	}

	req := a.Pending[0]
	a.Pending = a.Pending[1:]
	return req, true
}

func (a *App) AddConn(pc *PeerConn) {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	if _, exists := a.Conns[pc.Name]; exists {
		_ = pc.Conn.Close()
		return
	}
	a.Conns[pc.Name] = pc
}

func (a *App) GetConn(name string) (*PeerConn, bool) {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	pc, ok := a.Conns[name]
	return pc, ok
}

func (a *App) ListPeers() []string {
	a.Mu.Lock()
	defer a.Mu.Unlock()
	out := make([]string, 0, len(a.Conns))
	for name := range a.Conns {
		out = append(out, name)
	}
	return out
}

func (a *App) HasPeer(addr string) bool {
	a.Mu.Lock()
	defer a.Mu.Unlock()

	for _, p := range a.Conns {
		if p.RemoteAddr == addr {
			return true
		}
	}
	return false
}

func sendEncrypted(pc *PeerConn, payload string) error {
	nonce, ciphertext, err := Encrypt(pc.Key, []byte(payload))
	if err != nil {
		return err
	}
	line := fmt.Sprintf(
		"DATA|%s|%s\n",
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ciphertext),
	)
	if _, err := pc.RW.WriteString(line); err != nil {
		return err
	}
	return pc.RW.Flush()
}

func listSharedFiles() []string {
	_ = os.MkdirAll("shared_files", 0755)
	entries, err := os.ReadDir("shared_files")
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".meta") { // CHANGED: hide metadata files
			out = append(out, e.Name())
		}
	}
	return out
}

// CHANGED FOR TASK 9: per-user local encryption key instead of global constant
func localStorageKey(name string) []byte {
	return sha256Bytes([]byte(name + "-local-storage"))
}

func saveDownloadWithKey(filename string, data []byte, key []byte) error {
	_ = os.MkdirAll("downloads", 0755)
	path := filepath.Join("downloads", filepath.Base(filename))

	nonce, ciphertext, err := Encrypt(key, data)
	if err != nil {
		return err
	}

	payload := base64.StdEncoding.EncodeToString(nonce) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext)

	return os.WriteFile(path, []byte(payload), 0600)
}

func loadDownloadWithKey(filename string, key []byte) ([]byte, error) {
	path := filepath.Join("downloads", filepath.Base(filename))
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(strings.TrimSpace(string(content)), "|")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid stored file")
	}

	nonce, err1 := base64.StdEncoding.DecodeString(parts[0])
	ciphertext, err2 := base64.StdEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("invalid stored file encoding")
	}

	return Decrypt(key, nonce, ciphertext)
}

func metadataPath(filename string) string {
	return filepath.Join("downloads", filepath.Base(filename)+".meta")
}

func sharedMetadataPath(filename string) string {
	return filepath.Join("shared_files", filepath.Base(filename)+".meta")
}

func saveMetadataToPath(path, originName string, originPub, hash, sig []byte) error {
	content := strings.Join([]string{
		originName,
		base64.StdEncoding.EncodeToString(originPub),
		base64.StdEncoding.EncodeToString(hash),
		base64.StdEncoding.EncodeToString(sig),
	}, "|")
	return os.WriteFile(path, []byte(content), 0600)
}

func saveMetadata(filename, originName string, originPub, hash, sig []byte) error {
	return saveMetadataToPath(metadataPath(filename), originName, originPub, hash, sig)
}

func loadMetadata(path string) (originName string, originPub, hash, sig []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, nil, nil, err
	}
	parts := strings.Split(strings.TrimSpace(string(data)), "|")
	if len(parts) != 4 {
		return "", nil, nil, nil, fmt.Errorf("invalid metadata format")
	}

	originName = parts[0]
	originPub, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, nil, err
	}
	hash, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, nil, nil, err
	}
	sig, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", nil, nil, nil, err
	}
	return originName, originPub, hash, sig, nil
}

func processPayload(a *App, pc *PeerConn, payload string) {
	parts := strings.Split(payload, "|")
	switch parts[0] {
	case "PING":
		fmt.Printf("[%s] PING received\n", pc.Name)

	case "LIST_REQ":
		files := strings.Join(listSharedFiles(), ",")
		_ = sendEncrypted(pc, "LIST_RES|"+files)

	case "LIST_RES":
		if len(parts) < 2 || parts[1] == "" {
			fmt.Printf("[%s] shared files: (none)\n", pc.Name)
			return
		}
		fmt.Printf("[%s] shared files: %s\n", pc.Name, parts[1])

	case "GET_REQ":
		if len(parts) < 2 {
			_ = sendEncrypted(pc, "ERROR|missing filename")
			return
		}

		filename := filepath.Base(parts[1])
		a.AddPending(pc, filename)
		return

	case "GET_RES":
		if len(parts) < 7 {
			fmt.Printf("[%s] malformed GET_RES\n", pc.Name)
			return
		}

		filename := filepath.Base(parts[1])
		fileData, err1 := base64.StdEncoding.DecodeString(parts[2])
		hash, err2 := base64.StdEncoding.DecodeString(parts[3])
		sig, err3 := base64.StdEncoding.DecodeString(parts[4])
		originPub, err4 := base64.StdEncoding.DecodeString(parts[5])
		originName := parts[6]
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			fmt.Printf("[%s] failed to decode GET_RES\n", pc.Name)
			return
		}

		actualHash := sha256Bytes(fileData)
		if !equalBytes(actualHash, hash) {
			fmt.Printf("[%s] integrity check failed for %s\n", pc.Name, filename)
			return
		}

		if !verifyHash(originPub, hash, sig) {
			fmt.Printf("[%s] signature verification FAILED for %s\n", pc.Name, filename)
			return
		}

		// CHANGED FOR TASK 5:
		// If we already have metadata for this filename, require the same origin identity.
		metaPath := metadataPath(filename)
		if _, err := os.Stat(metaPath); err == nil {
			oldName, oldPub, _, _, err := loadMetadata(metaPath)
			if err == nil {
				if oldName != originName || !equalBytes(oldPub, originPub) {
					fmt.Printf("[%s] origin mismatch for %s\n", pc.Name, filename)
					return
				}
			}
		}

		// CHANGED FOR TASK 9: use per-user storage key
		if err := saveDownloadWithKey(filename, fileData, localStorageKey(a.Self.Name)); err != nil {
			fmt.Printf("[%s] save failed: %v\n", pc.Name, err)
			return
		}

		if err := saveMetadata(filename, originName, originPub, hash, sig); err != nil {
			fmt.Printf("[%s] metadata save failed: %v\n", pc.Name, err)
			return
		}

		fmt.Printf("[%s] downloaded and verified %s (original owner: %s)\n", pc.Name, filename, originName)

	case "KEY_UPDATE":
		// CHANGED FOR TASK 6:
		// Format: KEY_UPDATE|new_pub|signature_by_old_key_over_new_pub
		if len(parts) < 3 {
			fmt.Printf("[%s] malformed KEY_UPDATE\n", pc.Name)
			return
		}

		newPub, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			fmt.Printf("[%s] invalid KEY_UPDATE pubkey\n", pc.Name)
			return
		}

		sig, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			fmt.Printf("[%s] invalid KEY_UPDATE signature\n", pc.Name)
			return
		}

		if !verifyHash(pc.RemotePub, newPub, sig) {
			fmt.Printf("[%s] KEY_UPDATE verification FAILED\n", pc.Name)
			return
		}

		pc.RemotePub = newPub
		fmt.Printf("[%s] securely updated public key\n", pc.Name)

	case "ERROR":
		if len(parts) >= 2 {
			fmt.Printf("[%s] ERROR: %s\n", pc.Name, parts[1])
		}
	}
}