import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

class Identity:
    def __init__(self, name: str):
        self.name = name
        self.priv = ed25519.Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()

    def pub_raw(self) -> bytes:
        return self.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

def new_ephemeral():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, raw

def perform_handshake(sock_file, self_id: Identity):
    eph_priv, eph_pub_raw = new_ephemeral()
    sig = self_id.priv.sign(eph_pub_raw)

    hello = "HELLO|{}|{}|{}|{}\n".format(
        self_id.name,
        base64.b64encode(self_id.pub_raw()).decode(),
        base64.b64encode(eph_pub_raw).decode(),
        base64.b64encode(sig).decode(),
    )
    sock_file.write(hello.encode())
    sock_file.flush()

    line = sock_file.readline().decode().strip()
    parts = line.split("|")
    if len(parts) != 5 or parts[0] != "HELLO":
        raise ValueError(f"invalid HELLO line: {line}")

    remote_name = parts[1]
    remote_pub_raw = base64.b64decode(parts[2])
    remote_eph_raw = base64.b64decode(parts[3])
    remote_sig = base64.b64decode(parts[4])

    remote_pub = ed25519.Ed25519PublicKey.from_public_bytes(remote_pub_raw)
    remote_pub.verify(remote_sig, remote_eph_raw)

    remote_eph = x25519.X25519PublicKey.from_public_bytes(remote_eph_raw)
    shared_secret = eph_priv.exchange(remote_eph)
    session_key = hashlib.sha256(shared_secret).digest()

    return remote_name, remote_pub_raw, session_key