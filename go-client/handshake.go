package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeys() ([]byte, ed25519.PrivateKey, [32]byte, [32]byte) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	var ephPriv, ephPub [32]byte
	rand.Read(ephPriv[:])
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	return pub, priv, ephPriv, ephPub
}

func SignEphemeral(priv ed25519.PrivateKey, eph []byte) []byte {
	return ed25519.Sign(priv, eph)
}

func ComputeSharedSecret(priv [32]byte, peerPub []byte) [32]byte {
	var shared, peer [32]byte
	copy(peer[:], peerPub)
	curve25519.ScalarMult(&shared, &priv, &peer)
	return shared
}

func DeriveKey(shared [32]byte) []byte {
	hash := sha256.Sum256(shared[:])
	return hash[:]
}