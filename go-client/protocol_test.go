package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func withTempWorkingDir(t *testing.T) string {
	t.Helper()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir to temp dir: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	})

	return tempDir
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := sha256Bytes([]byte("unit-test-key"))
	plaintext := []byte("secure payload")

	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	got, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSaveAndLoadDownloadWithKey(t *testing.T) {
	withTempWorkingDir(t)

	key := localStorageKey("go-tester")
	filename := "note.txt"
	data := []byte("hello from a stored download")

	if err := saveDownloadWithKey(filename, data, key); err != nil {
		t.Fatalf("saveDownloadWithKey returned error: %v", err)
	}

	got, err := loadDownloadWithKey(filename, key)
	if err != nil {
		t.Fatalf("loadDownloadWithKey returned error: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Fatalf("loaded download mismatch: got %q want %q", got, data)
	}
}

func TestSaveAndLoadMetadataRoundTrip(t *testing.T) {
	withTempWorkingDir(t)

	if err := os.MkdirAll("downloads", 0o755); err != nil {
		t.Fatalf("mkdir downloads: %v", err)
	}

	originPub := []byte("origin-public-key")
	hash := []byte("hash-bytes")
	sig := []byte("signature-bytes")

	if err := saveMetadata("note.txt", "go", originPub, hash, sig); err != nil {
		t.Fatalf("saveMetadata returned error: %v", err)
	}

	originName, gotPub, gotHash, gotSig, err := loadMetadata(metadataPath("note.txt"))
	if err != nil {
		t.Fatalf("loadMetadata returned error: %v", err)
	}

	if originName != "go" {
		t.Fatalf("origin name mismatch: got %q want %q", originName, "go")
	}
	if !bytes.Equal(gotPub, originPub) {
		t.Fatalf("origin pub mismatch: got %q want %q", gotPub, originPub)
	}
	if !bytes.Equal(gotHash, hash) {
		t.Fatalf("hash mismatch: got %q want %q", gotHash, hash)
	}
	if !bytes.Equal(gotSig, sig) {
		t.Fatalf("sig mismatch: got %q want %q", gotSig, sig)
	}
}

func TestListSharedFilesSkipsMetadata(t *testing.T) {
	withTempWorkingDir(t)

	if err := os.MkdirAll("shared_files", 0o755); err != nil {
		t.Fatalf("mkdir shared_files: %v", err)
	}

	if err := os.WriteFile(filepath.Join("shared_files", "visible.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write visible file: %v", err)
	}
	if err := os.WriteFile(filepath.Join("shared_files", "visible.txt.meta"), []byte("meta"), 0o644); err != nil {
		t.Fatalf("write metadata file: %v", err)
	}

	files := listSharedFiles()
	if len(files) != 1 || files[0] != "visible.txt" {
		t.Fatalf("unexpected shared files: %v", files)
	}
}

func TestProcessPayloadQueuesRequest(t *testing.T) {
	app := NewApp(&Identity{Name: "go"})
	pc := &PeerConn{Name: "python"}

	processPayload(app, pc, "GET_REQ|../notes.txt")

	req, ok := app.PopPending()
	if !ok {
		t.Fatal("expected queued request")
	}
	if req.Peer != pc {
		t.Fatal("queued request stored wrong peer")
	}
	if req.Filename != "notes.txt" {
		t.Fatalf("queued filename mismatch: got %q want %q", req.Filename, "notes.txt")
	}
}

func TestProcessPayloadKeyUpdateChangesTrustedKey(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}

	pc := &PeerConn{
		Name:      "python",
		RemotePub: oldPub,
	}

	sig := ed25519.Sign(oldPriv, newPub)
	payload := "KEY_UPDATE|" + encodeB64(newPub) + "|" + encodeB64(sig)

	processPayload(NewApp(&Identity{Name: "go"}), pc, payload)

	if !bytes.Equal(pc.RemotePub, newPub) {
		t.Fatal("remote public key was not updated")
	}
}

func encodeB64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
