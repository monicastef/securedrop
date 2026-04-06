package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var printMu sync.Mutex

func safePrintf(format string, a ...any) {
	printMu.Lock()
	fmt.Printf(format, a...)
	printMu.Unlock()
}

func safePrintln(a ...any) {
	printMu.Lock()
	fmt.Println(a...)
	printMu.Unlock()
}

func stdinLoop(lines chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines <- scanner.Text()
	}
	close(lines)
}

func sha256Bytes(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func signHash(priv ed25519.PrivateKey, hash []byte) []byte {
	return ed25519.Sign(priv, hash)
}

func verifyHash(pub []byte, hash []byte, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), hash, sig)
}

func equalBytes(a, b []byte) bool {
	return string(a) == string(b)
}

func handleConn(app *App, conn net.Conn) {
	pc, err := performHandshake(conn, app.Self, app)
	if err != nil {
		safePrintln("handshake failed:", err)
		_ = conn.Close()
		return
	}

	app.AddConn(pc)
	safePrintf("connected to %s (%s)\n", pc.Name, pc.RemoteAddr)

	for {
		line, err := pc.RW.ReadString('\n')
		if err != nil {
			safePrintf("[%s] disconnected\n", pc.Name)
			_ = conn.Close()
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.Split(line, "|")

		if len(parts) != 3 || parts[0] != "DATA" {
			continue
		}

		nonce, err1 := base64.StdEncoding.DecodeString(parts[1])
		ciphertext, err2 := base64.StdEncoding.DecodeString(parts[2])
		if err1 != nil || err2 != nil {
			continue
		}

		plaintext, err := Decrypt(pc.Key, nonce, ciphertext)
		if err != nil {
			safePrintf("[%s] decrypt failed\n", pc.Name)
			continue
		}

		processPayload(app, pc, string(plaintext))
	}
}

func connectWithRetry(app *App, addr string) {
	for i := 0; i < 15; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			handleConn(app, conn)
			return
		}
		time.Sleep(1 * time.Second)
	}
	safePrintln("could not connect to", addr)
}

func main() {
	name := flag.String("name", "go", "peer name")
	port := flag.String("port", "9001", "listen port")
	peers := flag.String("peers", "", "comma-separated peers")
	flag.Parse()

	_ = os.MkdirAll("shared_files", 0755)
	_ = os.MkdirAll("downloads", 0755)
	_ = os.WriteFile(filepath.Join("shared_files", "go-note.txt"), []byte("hello from go"), 0644)

	self, err := LoadOrCreateIdentity(*name)
	if err != nil {
		panic(err)
	}

	app := NewApp(self)

	startMDNS(app, *port)

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		panic(err)
	}

	safePrintf("%s listening on %s\n", *name, *port)

	go func() {
		for {
			conn, err := ln.Accept()
			if err == nil {
				go handleConn(app, conn)
			}
		}
	}()

	if strings.TrimSpace(*peers) != "" {
		for _, addr := range strings.Split(*peers, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				go connectWithRetry(app, addr)
			}
		}
	}

	commandLines := make(chan string, 32)
	go stdinLoop(commandLines)
	safePrintln("commands: peers | list <peer> | get <peer> <file> | ping <peer> | rotate")

	for {

		// handle file requests first
		if req, ok := app.PopPending(); ok {
	
			safePrintln()
			safePrintf("[%s] wants file '%s'. Accept? (y/n): ", req.Peer.Name, req.Filename)
	
			// block only while waiting for the approval response
			line, ok := <-commandLines
			if !ok {
				break
			}

			resp := strings.ToLower(strings.TrimSpace(line))
	
			if resp != "y" {
				_ = sendEncrypted(req.Peer, "ERROR|request denied")
				continue
			}
	
			var data []byte
			var hash []byte
			var sig []byte
			var originPub []byte
			var originName string
	
			sharedPath := filepath.Join("shared_files", req.Filename)
			downloadPath := filepath.Join("downloads", req.Filename)
	
			if _, err := os.Stat(sharedPath); err == nil {
				data, err = os.ReadFile(sharedPath)
				if err != nil {
					_ = sendEncrypted(req.Peer, "ERROR|file not found")
					continue
				}
	
				metaPath := sharedMetadataPath(req.Filename)
				if _, err := os.Stat(metaPath); err == nil {
					originName, originPub, hash, sig, err = loadMetadata(metaPath)
					if err != nil {
						_ = sendEncrypted(req.Peer, "ERROR|invalid metadata")
						continue
					}
				} else {
					hash = sha256Bytes(data)
					sig = signHash(app.Self.Priv, hash)
					originPub = app.Self.Pub
					originName = app.Self.Name
				}
	
			} else if _, err := os.Stat(downloadPath); err == nil {
	
				data, err = loadDownloadWithKey(req.Filename, localStorageKey(app.Self.Name))
				if err != nil {
					_ = sendEncrypted(req.Peer, "ERROR|failed to decrypt stored file")
					continue
				}
	
				originName, originPub, hash, sig, err = loadMetadata(metadataPath(req.Filename))
				if err != nil {
					_ = sendEncrypted(req.Peer, "ERROR|missing original metadata")
					continue
				}
	
			} else {
				_ = sendEncrypted(req.Peer, "ERROR|file not found")
				continue
			}
	
			msg := "GET_RES|" +
				req.Filename + "|" +
				base64.StdEncoding.EncodeToString(data) + "|" +
				base64.StdEncoding.EncodeToString(hash) + "|" +
				base64.StdEncoding.EncodeToString(sig) + "|" +
				base64.StdEncoding.EncodeToString(originPub) + "|" +
				originName
	
			_ = sendEncrypted(req.Peer, msg)
			continue
		}
	
		// handle command input
		select {
		case line, ok := <-commandLines:
			if !ok {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, " ")
		
			switch parts[0] {
	
			case "peers":
				safePrintln("connected peers:", strings.Join(app.ListPeers(), ", "))
	
			case "ping":
				if len(parts) != 2 {
					safePrintln("usage: ping <peer>")
					continue
				}
				if pc, ok := app.GetConn(parts[1]); ok {
					_ = sendEncrypted(pc, "PING")
				} else {
					safePrintln("unknown peer")
				}
	
			case "list":
				if len(parts) != 2 {
					safePrintln("usage: list <peer>")
					continue
				}
				if pc, ok := app.GetConn(parts[1]); ok {
					_ = sendEncrypted(pc, "LIST_REQ")
				} else {
					safePrintln("unknown peer")
				}
	
			case "get":
				if len(parts) != 3 {
					safePrintln("usage: get <peer> <filename>")
					continue
				}
				if pc, ok := app.GetConn(parts[1]); ok {
					_ = sendEncrypted(pc, "GET_REQ|"+parts[2])
				} else {
					safePrintln("unknown peer")
				}
	
			case "rotate":
				oldPriv := app.Self.Priv
	
				newIdentity, err := LoadOrCreateIdentity(*name + "_rotated_temp")
				if err != nil {
					safePrintln("key rotation failed:", err)
					continue
				}
	
				newPub := newIdentity.Pub
				updateSig := signHash(oldPriv, newPub)
	
				app.Self = newIdentity
				safePrintln("key rotated successfully")
	
				payload := "KEY_UPDATE|" +
					base64.StdEncoding.EncodeToString(newPub) + "|" +
					base64.StdEncoding.EncodeToString(updateSig)
	
				for _, peerName := range app.ListPeers() {
					pc, ok := app.GetConn(peerName)
					if ok {
						_ = sendEncrypted(pc, payload)
					}
				}
			}
		default:
			// small sleep tp prevent CPU spinning and allow request handling to stay responsive
			time.Sleep(50 * time.Millisecond)
		}
	}
}
