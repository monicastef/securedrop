package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
)

type Message struct {
	IdentityPub  string
	EphemeralPub string
	Signature    string
}

func main() {
	go startServer()

	// Wait a bit so server starts
	select {}

}

func startServer() {
	ln, _ := net.Listen("tcp", ":8000")
	fmt.Println("Go peer listening on 8000")

	for {
		conn, _ := ln.Accept()
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	var msg Message
	decoder.Decode(&msg)

	fmt.Println("Received handshake from peer")

	// Decode base64
	peerEph, _ := base64.StdEncoding.DecodeString(msg.EphemeralPub)

	// Generate own keys
	idPub, idPriv, ephPriv, ephPub := GenerateKeys()

	// Sign our ephemeral key
	sig := SignEphemeral(idPriv, ephPub[:])

	// Compute shared key
	shared := ComputeSharedSecret(ephPriv, peerEph)
	key := DeriveKey(shared)

	fmt.Println("Shared key established:", key[:8])

	// Send response
	response := Message{
		IdentityPub:  base64.StdEncoding.EncodeToString(idPub),
		EphemeralPub: base64.StdEncoding.EncodeToString(ephPub[:]),
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}

	json.NewEncoder(conn).Encode(response)
}