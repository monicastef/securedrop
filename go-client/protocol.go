package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	// "bufio"
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
	Self  *Identity
	Conns map[string]*PeerConn
	Mu    sync.Mutex
}

func NewApp(self *Identity) *App {
	return &App{
		Self:  self,
		Conns: make(map[string]*PeerConn),
	}
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
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func saveDownload(filename string, data []byte) error {
	_ = os.MkdirAll("downloads", 0755)
	path := filepath.Join("downloads", filepath.Base(filename))
	return os.WriteFile(path, data, 0644)
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
	
		// ask user
		fmt.Printf("[%s] wants file '%s' → auto-accepting\n", pc.Name, filename)
	
		path := filepath.Join("shared_files", filename)
		data, err := os.ReadFile(path)
		if err != nil {
			_ = sendEncrypted(pc, "ERROR|file not found")
			return
		}
	
		hash := sha256Bytes(data)
		sig := signHash(a.Self.Priv, hash)
	
		msg := "GET_RES|" +
			filename + "|" +
			base64.StdEncoding.EncodeToString(data) + "|" +
			base64.StdEncoding.EncodeToString(hash) + "|" +
			base64.StdEncoding.EncodeToString(sig)
	
		_ = sendEncrypted(pc, msg)
		fmt.Println("DEBUG: sending GET_REQ to", parts[1])

	case "GET_RES":
		if len(parts) != 5 {
			fmt.Printf("[%s] malformed GET_RES\n", pc.Name)
			return
		}
		filename := parts[1]
		fileData, err1 := base64.StdEncoding.DecodeString(parts[2])
		hash, err2 := base64.StdEncoding.DecodeString(parts[3])
		sig, err3 := base64.StdEncoding.DecodeString(parts[4])
		if err1 != nil || err2 != nil || err3 != nil {
			fmt.Printf("[%s] failed to decode GET_RES\n", pc.Name)
			return
		}

		actualHash := sha256Bytes(fileData)
		if !equalBytes(actualHash, hash) {
			fmt.Printf("[%s] hash mismatch for %s\n", pc.Name, filename)
			return
		}
		if !verifyHash(pc.RemotePub, hash, sig) {
			fmt.Printf("[%s] signature verification failed for %s\n", pc.Name, filename)
			return
		}
		if err := saveDownload(filename, fileData); err != nil {
			fmt.Printf("[%s] save failed: %v\n", pc.Name, err)
			return
		}
		fmt.Printf("[%s] downloaded and verified %s\n", pc.Name, filename)

	case "ERROR":
		if len(parts) >= 2 {
			fmt.Printf("[%s] ERROR: %s\n", pc.Name, parts[1])
		}
	}
}