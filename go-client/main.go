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
	"time"
)

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
	pc, err := performHandshake(conn, app.Self)
	if err != nil {
		fmt.Println("handshake failed:", err)
		_ = conn.Close()
		return
	}
	app.AddConn(pc)
	fmt.Printf("connected to %s (%s)\n", pc.Name, pc.RemoteAddr)

	for {
		line, err := pc.RW.ReadString('\n')
		if err != nil {
			fmt.Printf("[%s] disconnected\n", pc.Name)
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
			fmt.Printf("[%s] decrypt failed\n", pc.Name)
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
	fmt.Println("could not connect to", addr)
}

func main() {
	name := flag.String("name", "go", "peer name")
	port := flag.String("port", "9001", "listen port")
	peers := flag.String("peers", "", "comma-separated host:port peers")
	flag.Parse()

	_ = os.MkdirAll("shared_files", 0755)
	_ = os.MkdirAll("downloads", 0755)
	_ = os.WriteFile(filepath.Join("shared_files", "go-note.txt"), []byte("hello from go"), 0644)

	self, err := NewIdentity(*name)
	if err != nil {
		panic(err)
	}
	app := NewApp(self)

	startMDNS(app, *port)

	ln, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s listening on %s\n", *name, *port)

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

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("commands: peers | list <peer> | get <peer> <file> | ping <peer>")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Split(line, " ")
		switch parts[0] {
		case "peers":
			fmt.Println("connected peers:", strings.Join(app.ListPeers(), ", "))

		case "ping":
			if len(parts) != 2 {
				fmt.Println("usage: ping <peer>")
				continue
			}
			if pc, ok := app.GetConn(parts[1]); ok {
				_ = sendEncrypted(pc, "PING")
			} else {
				fmt.Println("unknown peer")
			}

		case "list":
			if len(parts) != 2 {
				fmt.Println("usage: list <peer>")
				continue
			}
			if pc, ok := app.GetConn(parts[1]); ok {
				_ = sendEncrypted(pc, "LIST_REQ")
			} else {
				fmt.Println("unknown peer")
			}

		case "get":
			if len(parts) != 3 {
				fmt.Println("usage: get <peer> <filename>")
				continue
			}
			if pc, ok := app.GetConn(parts[1]); ok {
				_ = sendEncrypted(pc, "GET_REQ|"+parts[2])
			} else {
				fmt.Println("unknown peer")
			}
		}
	}
}
