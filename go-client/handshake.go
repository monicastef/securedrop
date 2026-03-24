package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type Identity struct {
	Name string
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

func NewIdentity(name string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Name: name, Pub: pub, Priv: priv}, nil
}

func generateEphemeral() ([32]byte, [32]byte, error) {
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

func deriveSessionKey(priv [32]byte, peerPubRaw []byte) ([]byte, error) {
	if len(peerPubRaw) != 32 {
		return nil, errors.New("peer ephemeral public key must be 32 bytes")
	}
	var peerPub [32]byte
	copy(peerPub[:], peerPubRaw)

	var shared [32]byte
	curve25519.ScalarMult(&shared, &priv, &peerPub)

	sum := sha256.Sum256(shared[:])
	return sum[:], nil
}

func performHandshake(conn net.Conn, self *Identity) (*PeerConn, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	ephPriv, ephPub, err := generateEphemeral()
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(self.Priv, ephPub[:])

	hello := fmt.Sprintf(
		"HELLO|%s|%s|%s|%s\n",
		self.Name,
		base64.StdEncoding.EncodeToString(self.Pub),
		base64.StdEncoding.EncodeToString(ephPub[:]),
		base64.StdEncoding.EncodeToString(sig),
	)
	if _, err := rw.WriteString(hello); err != nil {
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		return nil, err
	}

	line, err := rw.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)

	parts := strings.Split(line, "|")
	if len(parts) != 5 || parts[0] != "HELLO" {
		return nil, fmt.Errorf("invalid HELLO line: %s", line)
	}

	remoteName := parts[1]
	remotePub, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	remoteEph, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	remoteSig, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	if len(remotePub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("remote identity key wrong size: %d", len(remotePub))
	}
	if !ed25519.Verify(ed25519.PublicKey(remotePub), remoteEph, remoteSig) {
		return nil, errors.New("signature verification failed")
	}

	key, err := deriveSessionKey(ephPriv, remoteEph)
	if err != nil {
		return nil, err
	}

	return &PeerConn{
		Name:       remoteName,
		Conn:       conn,
		RW:         rw,
		Key:        key,
		RemotePub:  ed25519.PublicKey(remotePub),
		RemoteAddr: conn.RemoteAddr().String(),
	}, nil
}