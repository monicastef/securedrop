import socket, json, base64
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import hashes

# Generate keys
id_priv = ed25519.Ed25519PrivateKey.generate()
id_pub = id_priv.public_key()

eph_priv = x25519.X25519PrivateKey.generate()
eph_pub = eph_priv.public_key()

# Sign ephemeral
sig = id_priv.sign(eph_pub.public_bytes_raw())

# Connect to Go peer
s = socket.socket()
s.connect(("localhost", 8000))

msg = {
    "IdentityPub": base64.b64encode(id_pub.public_bytes_raw()).decode(),
    "EphemeralPub": base64.b64encode(eph_pub.public_bytes_raw()).decode(),
    "Signature": base64.b64encode(sig).decode()
}

s.send(json.dumps(msg).encode())

# Receive response
resp = json.loads(s.recv(4096).decode())

peer_eph = base64.b64decode(resp["EphemeralPub"])

peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_eph)

shared = eph_priv.exchange(peer_pub)

# Derive key
digest = hashes.Hash(hashes.SHA256())
digest.update(shared)
key = digest.finalize()

print("Python shared key:", key[:8])