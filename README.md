# SecureDrop

CISC 468 Project: Secure Peer-to-Peer File Sharing Application

## Team Members

* Monica Stef (Go Client)
* Ben Leray (Python Client)
* Anjali Patel (Java Client)

---

## Overview

SecureDrop is a cross-language peer-to-peer file sharing system that enables secure discovery, authentication, and file transfer between clients implemented in **Go, Python, and Java**.

The system guarantees:

* Mutual authentication (Ed25519)
* Confidentiality (AES-GCM encryption)
* Integrity (SHA-256 hashing)
* Authenticity (digital signatures)
* Perfect forward secrecy (session keys)
* Secure local storage (encrypted downloads)
* Key migration (identity rotation)
* Verified file propagation (trust preserved across peers)

---

## Features Implemented

### Task 3 - User Consent for File Transfers

* When a peer requests a file, the receiver must approve:

```
[peer] wants file 'example.txt'. Accept? (y/n):
```

* Transfer only proceeds on `y`

---

### Task 5 - Verified File Re-Sharing

* Files include:

  * Original owner’s public key
  * Original signature
  * File hash
* A peer can re-share a file **without being the original sender**
* Receiver verifies:

  * Hash matches
  * Signature matches original owner

---

### Task 6 - Key Rotation

* Users can rotate identity keys using:

```
rotate
```

* Peers receive:

```
KEY_UPDATE|<new_public_key>
```

* Connections automatically update trust

---

### Task 9 - Secure Local Storage

* Downloaded files are encrypted using AES-GCM
* Stored as:

```
base64(nonce|ciphertext)
```

* Metadata stored separately:

```
filename.meta
```

* Prevents offline attackers from reading files

---

## Project Structure

```
securedrop/
│
├── go-client/
│   ├── main.go
│   ├── protocol.go
│   ├── handshake.go
│   ├── crypto.go
│   └── ...
│
├── python-client/
│   ├── main.py
│   ├── protocol.py
│   ├── handshake.py
│   ├── crypto.py
│   └── ...
│
├── java-client/
│   ├── Main.java
│   ├── Protocol.java
│   ├── Handshake.java
│   └── ...
│
├── shared_files/
├── downloads/
└── docs/
```

---

## Requirements

### General

* macOS / Linux recommended
* All clients run on localhost or LAN

---

### Go Client

* Go 1.20+

Install dependencies:

```bash
go mod tidy
```

---

### Python Client

* Python 3.9+

Create virtual environment:

```bash
cd python-client
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

---

### Java Client

* Java 11+

Compile:

```bash
cd java-client
javac -cp ".:lib/*" *.java
```

Run:

```bash
java -cp ".:lib/*" Main --name java --port 9003
```

---

## Testing

### Automated Unit Tests

Run the Go unit tests:

```bash
cd go-client
go test ./...
```

Run the Python unit tests from the repo root:

```bash
python-client/.venv/bin/python -m unittest tests/test_python_protocol.py -v
```

Run the Java unit tests:

```bash
cd java-client
javac -cp ".:lib/*" *.java
java -cp ".:lib/*" ClientTests
```

Current automated coverage includes:

* Go crypto round-trip
* Go encrypted download storage round-trip
* Go metadata round-trip
* Go pending request and key-update handling
* Python metadata round-trip
* Python encrypted download storage round-trip
* Python shared-file filtering
* Python invalid stored-file handling
* Java crypto round-trip
* Java metadata round-trip
* Java shared-file filtering
* Java handshake sign/verify

Manual test scenarios are documented in `tests/TESTS.md`.

---

## How to Run

### Step 1 — Start Go Client

```bash
cd go-client
go run .
```

---

### Step 2 — Start Python Client

```bash
cd python-client
source .venv/bin/activate
python3 main.py --name python --port 9002
```

---

### Step 3 — Start Java Client

```bash
cd java-client
java -cp ".:lib/*" Main --name java --port 9003
```

---

## Available Commands

```
peers: list connected peers
list <peer>: list files from peer
get <peer> <file>: request file
ping <peer>: test connection
rotate: rotate identity keys
```

---

## Example Workflow

### 1. Request a File

Python:

```bash
get go go-note.txt
```

Go:

```
[python] wants file 'go-note.txt'. Accept? (y/n): y
```

Python:

```
[go] downloaded and verified go-note.txt (original: go)
```

---

### 2. Verify Encryption

```bash
cat downloads/go-note.txt
```

Output:

```
ajsdhaskjdhakjsdh...   (encrypted)
```

---

### 3. Re-share File (Task 5)

If Python downloaded from Go:

Java:

```bash
get python go-note.txt
```

✔ Java verifies original Go signature
✔ Python acts as relay

---

### 4. Rotate Keys

```bash
rotate
```

Peers:

```
[peer] updated public key
```

---

## Security Design

### Encryption

* AES-GCM for:

  * Network messages
  * Stored files

### Authentication

* Ed25519 key pairs
* Verified during handshake

### Integrity

* SHA-256 hash of file

### Authenticity

* Signature = Sign(hash, private key)

### Secure Storage

* Files encrypted with local key
* Metadata stored separately

---

## Metadata Format

Each downloaded file has:

```
filename.meta
```

Contents:

```
origin_name | origin_pub | hash | signature
```

---

## Troubleshooting

---

### "hashlib is not defined"

Fix:

```python
import hashlib
```

---

### No y/n prompt appears

Cause:

* Blocking input or incorrect threading

Fix:

* Use input thread + queue (Python)
* Ensure Go uses single stdin reader

---

### Could not connect

* Ensure ports are correct
* Restart all clients
* Ignore mdns IPv6 warnings

---

### Java compile error

```bash
variable already defined
```

Fix:

* Rename duplicate variable (e.g., `payload2`)

---

## Known Limitations

* mDNS may fail on IPv6 (non-critical)
* No persistent peer directory
* Local encryption key is static (for demo purposes)

---

## Testing Checklist

* [ ] Python <-> Go file transfer works
* [ ] Java <-> Go works
* [ ] Java <-> Python works
* [ ] Consent prompt appears
* [ ] Files are encrypted locally
* [ ] Metadata saved correctly
* [ ] Signature verification passes
* [ ] Key rotation updates peers
* [ ] Re-sharing preserves original signature

---

## Conclusion

SecureDrop demonstrates a complete secure file-sharing protocol with:

* Cross-language interoperability
* Strong cryptographic guarantees
* Real-world security features
* Robust peer-to-peer architecture

---

## Authors

Monica Stef
Ben Leray
Anjali Patel

---
