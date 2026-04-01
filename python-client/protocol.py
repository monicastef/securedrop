import base64
import hashlib
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization

SHARED_DIR = Path("shared_files")
DOWNLOAD_DIR = Path("downloads")
META_DIR = Path("downloads")

def metadata_path(filename: str) -> Path:
    return META_DIR / f"{Path(filename).name}.meta"

def shared_metadata_path(filename: str) -> Path:
    return SHARED_DIR / f"{Path(filename).name}.meta"

def save_metadata(filename: str, origin_name: str, origin_pub: bytes, file_hash: bytes, sig: bytes):
    content = "|".join([
        origin_name,
        base64.b64encode(origin_pub).decode(),
        base64.b64encode(file_hash).decode(),
        base64.b64encode(sig).decode(),
    ])
    metadata_path(filename).write_text(content)

def save_metadata_to_path(path: Path, origin_name: str, origin_pub: bytes, file_hash: bytes, sig: bytes):
    content = "|".join([
        origin_name,
        base64.b64encode(origin_pub).decode(),
        base64.b64encode(file_hash).decode(),
        base64.b64encode(sig).decode(),
    ])
    path.write_text(content)

def load_metadata(filename: str):
    parts = metadata_path(filename).read_text().strip().split("|")
    if len(parts) != 4:
        raise ValueError("invalid metadata")
    return (
        parts[0],
        base64.b64decode(parts[1]),
        base64.b64decode(parts[2]),
        base64.b64decode(parts[3]),
    )

def load_metadata_from_path(path: Path):
    parts = path.read_text().strip().split("|")
    if len(parts) != 4:
        raise ValueError("invalid metadata")
    return (
        parts[0],
        base64.b64decode(parts[1]),
        base64.b64decode(parts[2]),
        base64.b64decode(parts[3]),
    )

def ensure_dirs(default_name: str, default_content: str):
    SHARED_DIR.mkdir(exist_ok=True)
    DOWNLOAD_DIR.mkdir(exist_ok=True)
    sample = SHARED_DIR / default_name
    if not sample.exists():
        sample.write_text(default_content)

def list_shared_files():
    return [p.name for p in SHARED_DIR.iterdir() if p.is_file() and not p.name.endswith(".meta")]

def file_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# CHANGED FOR TASK 9
def local_storage_key(identity_name: str) -> bytes:
    return file_hash(f"{identity_name}-local-storage".encode())

def save_download(filename: str, data: bytes, key: bytes):
    safe = os.path.basename(filename)
    path = DOWNLOAD_DIR / safe

    from crypto import encrypt
    nonce, ciphertext = encrypt(key, data)
    payload = base64.b64encode(nonce).decode() + "|" + base64.b64encode(ciphertext).decode()
    path.write_text(payload)

def load_download(filename: str, key: bytes) -> bytes:
    safe = os.path.basename(filename)
    path = DOWNLOAD_DIR / safe

    content = path.read_text().strip().split("|")
    if len(content) != 2:
        raise ValueError("invalid stored file")

    nonce = base64.b64decode(content[0])
    ciphertext = base64.b64decode(content[1])

    from crypto import decrypt
    return decrypt(key, nonce, ciphertext)

def build_get_res(identity, filename: str, data: bytes, origin_pub: bytes = None, origin_name: str = None, existing_hash: bytes = None, existing_sig: bytes = None) -> str:
    if existing_hash is not None and existing_sig is not None and origin_pub is not None and origin_name is not None:
        h = existing_hash
        sig = existing_sig
    else:
        h = file_hash(data)
        sig = identity.priv.sign(h)
        origin_pub = identity.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        origin_name = identity.name

    return "GET_RES|{}|{}|{}|{}|{}|{}".format(
        filename,
        base64.b64encode(data).decode(),
        base64.b64encode(h).decode(),
        base64.b64encode(sig).decode(),
        base64.b64encode(origin_pub).decode(),
        origin_name
    )