import base64
import hashlib
import os
from pathlib import Path

SHARED_DIR = Path("shared_files")
DOWNLOAD_DIR = Path("downloads")

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

def build_get_res(identity_priv, filename: str, data: bytes) -> str:
    h = file_hash(data)
    sig = identity_priv.sign(h)
    return "GET_RES|{}|{}|{}|{}".format(
        filename,
        base64.b64encode(data).decode(),
        base64.b64encode(h).decode(),
        base64.b64encode(sig).decode(),
    )