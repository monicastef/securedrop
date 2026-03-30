package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

func LoadOrCreateIdentity(name string) (*Identity, error) {
	_ = os.MkdirAll("keys", 0700)
	path := filepath.Join("keys", name+"_ed25519.key")

	if data, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, err
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return &Identity{Name: name, Pub: pub, Priv: priv}, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, err
	}

	return &Identity{Name: name, Pub: pub, Priv: priv}, nil
}