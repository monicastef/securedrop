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

def save_metadata(filename: str, origin_name: str, origin_pub: bytes, file_hash: bytes, sig: bytes):
    content = "|".join([
        origin_name,
        base64.b64encode(origin_pub).decode(),
        base64.b64encode(file_hash).decode(),
        base64.b64encode(sig).decode(),
    ])
    metadata_path(filename).write_text(content)

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

def ensure_dirs(default_name: str, default_content: str):
    SHARED_DIR.mkdir(exist_ok=True)
    DOWNLOAD_DIR.mkdir(exist_ok=True)
    sample = SHARED_DIR / default_name
    if not sample.exists():
        sample.write_text(default_content)

def list_shared_files():
    return [p.name for p in SHARED_DIR.iterdir() if p.is_file()]

def file_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def save_download(filename: str, data: bytes):
    safe = os.path.basename(filename)
    (DOWNLOAD_DIR / safe).write_bytes(data)

def build_get_res(identity, filename: str, data: bytes) -> str:
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