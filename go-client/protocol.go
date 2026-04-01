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
	// RemotePub ed25519.PublicKey
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
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func saveDownload(filename string, data []byte) error {
	 _ = os.MkdirAll("downloads", 0755)
	path := filepath.Join("downloads", filepath.Base(filename))
	// return os.WriteFile(path, data, 0644)
	key := sha256Bytes([]byte("local-secret-key")) // simple local key

	nonce, ciphertext, err := Encrypt(key, data)
	if err != nil {
		return err
	}

	payload := base64.StdEncoding.EncodeToString(nonce) + "|" +
		base64.StdEncoding.EncodeToString(ciphertext)

	return os.WriteFile(path, []byte(payload), 0600)
	
}

func metadataPath(filename string) string {
	return filepath.Join("downloads", filepath.Base(filename)+".meta")
}

func sharedMetadataPath(filename string) string {
	return filepath.Join("shared_files", filepath.Base(filename)+".meta")
}

func saveMetadata(filename, originName string, originPub, hash, sig []byte) error {
	content := strings.Join([]string{
		originName,
		base64.StdEncoding.EncodeToString(originPub),
		base64.StdEncoding.EncodeToString(hash),
		base64.StdEncoding.EncodeToString(sig),
	}, "|")
	return os.WriteFile(metadataPath(filename), []byte(content), 0600)
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
	
		fmt.Printf("[%s] wants file '%s'. Accept? (y/n): ", pc.Name, filename)
	
		var resp string
		fmt.Scanln(&resp)
	
		if strings.ToLower(strings.TrimSpace(resp)) != "y" {
			_ = sendEncrypted(pc, "ERROR|request denied")
			return
		}
	
		var data []byte
		var hash []byte
		var sig []byte
		var originPub []byte
		var originName string
	
		sharedPath := filepath.Join("shared_files", filename)
		downloadPath := filepath.Join("downloads", filename)
	
		if _, err := os.Stat(sharedPath); err == nil {
			// File is locally owned or explicitly shared
			data, err = os.ReadFile(sharedPath)
			if err != nil {
				_ = sendEncrypted(pc, "ERROR|file not found")
				return
			}
	
			metaPath := sharedMetadataPath(filename)
			if _, err := os.Stat(metaPath); err == nil {
				originName, originPub, hash, sig, err = loadMetadata(metaPath)
				if err != nil {
					_ = sendEncrypted(pc, "ERROR|invalid metadata")
					return
				}
			} else {
				// This peer is the original owner
				hash = sha256Bytes(data)
				sig = signHash(a.Self.Priv, hash)
				originPub = a.Self.Pub
				originName = a.Self.Name
			}
		} else if _, err := os.Stat(downloadPath); err == nil {
			// File was downloaded earlier; serve with original metadata
			encPayload, err := os.ReadFile(downloadPath)
			if err != nil {
				_ = sendEncrypted(pc, "ERROR|file not found")
				return
			}
	
			encParts := strings.Split(string(encPayload), "|")
			if len(encParts) != 2 {
				_ = sendEncrypted(pc, "ERROR|invalid stored file")
				return
			}
	
			localKey := sha256Bytes([]byte("local-secret-key"))
			nonce, err1 := base64.StdEncoding.DecodeString(encParts[0])
			ciphertext, err2 := base64.StdEncoding.DecodeString(encParts[1])
			if err1 != nil || err2 != nil {
				_ = sendEncrypted(pc, "ERROR|invalid stored file")
				return
			}
	
			data, err = Decrypt(localKey, nonce, ciphertext)
			if err != nil {
				_ = sendEncrypted(pc, "ERROR|failed to decrypt stored file")
				return
			}
	
			originName, originPub, hash, sig, err = loadMetadata(metadataPath(filename))
			if err != nil {
				_ = sendEncrypted(pc, "ERROR|missing original metadata")
				return
			}
		} else {
			_ = sendEncrypted(pc, "ERROR|file not found")
			return
		}
	
		msg := "GET_RES|" +
			filename + "|" +
			base64.StdEncoding.EncodeToString(data) + "|" +
			base64.StdEncoding.EncodeToString(hash) + "|" +
			base64.StdEncoding.EncodeToString(sig) + "|" +
			base64.StdEncoding.EncodeToString(originPub) + "|" +
			originName
	
		_ = sendEncrypted(pc, msg)

	case "GET_RES":
		if len(parts) < 7 {
			fmt.Printf("[%s] malformed GET_RES\n", pc.Name)
			return
		}
		// filename := parts[1]
		filename := filepath.Base(parts[1])
		fileData, err1 := base64.StdEncoding.DecodeString(parts[2])
		hash, err2 := base64.StdEncoding.DecodeString(parts[3])
		sig, err3 := base64.StdEncoding.DecodeString(parts[4])
		originPub, err4 := base64.StdEncoding.DecodeString(parts[5])
		originName := parts[6]
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil{
			fmt.Printf("[%s] failed to decode GET_RES\n", pc.Name)
			return
		}

		actualHash := sha256Bytes(fileData)
		if !equalBytes(actualHash, hash) {
			// fmt.Printf("[%s] hash mismatch for %s\n", pc.Name, filename)
			fmt.Printf("[%s] integrity check failed for %s\n", pc.Name, filename)
			return
		}
		if !verifyHash(originPub, hash, sig) {
			// fmt.Printf("[%s] signature verification failed for %s\n", pc.Name, filename)
			fmt.Printf("[%s] signature verification FAILED for %s\n", pc.Name, filename)
			return
		}
		if err := saveDownload(filename, fileData); err != nil {
			fmt.Printf("[%s] save failed: %v\n", pc.Name, err)
			return
		}
		
		if err := saveMetadata(filename, originName, originPub, hash, sig); err != nil {
			fmt.Printf("[%s] metadata save failed: %v\n", pc.Name, err)
			return
		}

		fmt.Printf("[%s] downloaded and verified %s (original owner: %s)\n", pc.Name, filename, originName)

	case "ERROR":
		if len(parts) >= 2 {
			fmt.Printf("[%s] ERROR: %s\n", pc.Name, parts[1])
		}
	}
}