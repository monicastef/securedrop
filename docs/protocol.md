# SecureDrop Protocol (Localhost Prototype)

This prototype uses a line-based protocol over TCP.

## Handshake line
HELLO|<name>|<identity_pub_b64>|<ephemeral_pub_b64>|<signature_b64>

- identity_pub: raw Ed25519 public key (32 bytes), base64
- ephemeral_pub: raw X25519 public key (32 bytes), base64
- signature: Ed25519 signature over the raw ephemeral public key, base64

Both sides:
1. generate identity keypair
2. generate ephemeral X25519 keypair
3. send HELLO
4. read HELLO
5. verify signature on ephemeral public key
6. derive shared secret with X25519
7. derive session key = SHA256(shared_secret)

## Encrypted message line
DATA|<nonce_b64>|<ciphertext_b64>

- nonce: 12 bytes
- ciphertext: AES-256-GCM encrypted application payload

## Application payloads (inside encrypted DATA)
PING
LIST_REQ
LIST_RES|file1,file2,file3
GET_REQ|filename
GET_RES|filename|<file_b64>|<hash_b64>|<sig_b64>
ERROR|message