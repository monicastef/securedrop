# Test Cases

## Automated Unit Tests

### Go Unit Tests

Run from the repo root:

```bash
cd go-client
go test ./...
```

Coverage included:

* AES-GCM encrypt/decrypt round-trip
* Encrypted download save/load round-trip
* Metadata save/load round-trip
* Shared file listing excludes `.meta` files
* `GET_REQ` queues a sanitized pending filename
* Verified `KEY_UPDATE` replaces the trusted public key

### Python Unit Tests

Run from the repo root:

```bash
python-client/.venv/bin/python -m unittest tests/test_python_protocol.py -v
```

Coverage included:

* Metadata save/load round-trip
* Shared file listing excludes `.meta` files
* Encrypted download save/load round-trip
* Invalid encrypted-download format raises an error
* Local storage keys are deterministic per identity and differ across identities

### Java Unit Tests

Run from the repo root:

```bash
cd java-client
javac -cp ".:lib/*" *.java
java -cp ".:lib/*" ClientTests
```

Coverage included:

* AES-GCM encrypt/decrypt round-trip
* Metadata save/load round-trip
* Shared file listing excludes `.meta` files
* Ed25519 sign/verify round-trip for handshake helpers

## Manual End-to-End Tests

### 1. Peer Discovery
Start Go, Python, and Java clients.

Expected: peers connect or become reachable through configured peer addresses.

### 2. File Listing
Command: `list <peer>`

Expected: the requesting client prints the peer’s shared files.

### 3. File Transfer Approval
Command: `get <peer> <file>`

Expected: the sender sees `Accept? (y/n):` immediately and transfer proceeds only after `y`.

### 4. Verified File Transfer
Command: `get <peer> <file>`

Expected: the receiver prints that the file was downloaded and verified.

### 5. Integrity Verification
Tamper with file contents before re-sharing.

Expected: the receiver reports an integrity-check failure.

### 6. Signature Verification
Tamper with signature or origin public key in metadata.

Expected: the receiver reports signature verification failure.

### 7. Key Rotation
Run: `rotate`

Expected: connected peers accept a valid signed key update and continue trusting the rotated identity.

### 8. Disconnection Handling
Stop one peer while connected.

Expected: remaining peers print a disconnect message.

### 9. Verified File Re-Sharing
Download a file from one peer, then re-share it from another.

Expected: the next receiver still verifies the original owner metadata successfully.
