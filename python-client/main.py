import argparse
import base64
import os
import socket
import threading
import time
import queue

request_queue = queue.Queue()
command_queue = queue.Queue()

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

from handshake import Identity, perform_handshake
from crypto import encrypt, decrypt
from cryptography.hazmat.primitives import serialization
from protocol import (
    ensure_dirs,
    list_shared_files,
    load_download,
    save_download,
    save_metadata,
    load_metadata,
    load_metadata_from_path,
    file_hash,
    build_get_res,
    SHARED_DIR,
    DOWNLOAD_DIR,
    metadata_path,
    shared_metadata_path,
    local_storage_key,
)
from mdns import start_mdns


class PeerConn:
    def __init__(self, name, sock, sock_file, key, remote_pub):
        self.name = name
        self.sock = sock
        self.sock_file = sock_file
        self.key = key
        self.remote_pub = remote_pub


class App:
    def __init__(self, identity):
        self.identity = identity
        self.conns = {}
        self.lock = threading.Lock()

    def add_conn(self, pc):
        with self.lock:
            if pc.name in self.conns:
                safe_print(f"already connected to {pc.name}, ignoring duplicate")
                pc.sock.close()
                return False
            self.conns[pc.name] = pc
            return True

    def get_conn(self, name):
        with self.lock:
            return self.conns.get(name)

    def peer_names(self):
        with self.lock:
            return list(self.conns.keys())

    def connect_to_peer(self, addr):
        try:
            host, port = addr.split(":")
            port = int(port)

            sock = socket.socket()
            sock.connect((host, port))

            # run connection in its own thread
            threading.Thread(
                target=connection_loop,
                args=(self, sock),
                daemon=True
            ).start()

        except Exception as e:
            safe_print(f"failed to connect to {addr}: {e}")


def send_encrypted(pc: PeerConn, payload: str):
    nonce, ciphertext = encrypt(pc.key, payload.encode())
    line = "DATA|{}|{}\n".format(
        base64.b64encode(nonce).decode(),
        base64.b64encode(ciphertext).decode(),
    )
    pc.sock_file.write(line.encode())
    pc.sock_file.flush()


# only place that reads stdin
def input_thread():
    while True:
        try:
            line = input()
            command_queue.put(line)
        except:
            break


def process_payload(app: App, pc: PeerConn, payload: str):
    parts = payload.split("|")
    cmd = parts[0]

    if cmd == "PING":
        safe_print(f"[{pc.name}] PING received")

    elif cmd == "LIST_REQ":
        files = ",".join(list_shared_files())
        send_encrypted(pc, "LIST_RES|" + files)

    elif cmd == "LIST_RES":
        files = parts[1] if len(parts) > 1 else ""
        safe_print(f"[{pc.name}] shared files: {files if files else '(none)'}")

    elif cmd == "GET_REQ":
        if len(parts) < 2:
            send_encrypted(pc, "ERROR|missing filename")
            return

        filename = os.path.basename(parts[1])
        safe_print(f"[{pc.name}] wants file '{filename}'")
        request_queue.put((pc, filename))

    elif cmd == "GET_RES":
        if len(parts) != 7:
            safe_print(f"[{pc.name}] malformed GET_RES")
            return

        filename = os.path.basename(parts[1])
        data = base64.b64decode(parts[2])
        expected_hash = base64.b64decode(parts[3])
        sig = base64.b64decode(parts[4])
        origin_pub = base64.b64decode(parts[5])
        origin_name = parts[6]

        actual_hash = file_hash(data)
        if actual_hash != expected_hash:
            safe_print(f"[{pc.name}] integrity check failed for {filename}")
            return

        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(origin_pub)
            pub.verify(sig, expected_hash)
        except Exception:
            safe_print(f"[{pc.name}] signature verification FAILED for {filename}")
            return

        # task 5
        meta_file = metadata_path(filename)
        if meta_file.exists():
            try:
                old_name, old_pub, _, _ = load_metadata(filename)
                if old_name != origin_name or old_pub != origin_pub:
                    safe_print(f"[{pc.name}] origin mismatch for {filename}")
                    return
            except:
                pass

        # task 9
        save_download(filename, data, local_storage_key(app.identity.name))
        save_metadata(filename, origin_name, origin_pub, expected_hash, sig)

        safe_print(f"[{pc.name}] downloaded and verified {filename}")

    elif cmd == "KEY_UPDATE":
        if len(parts) < 3:
            safe_print(f"[{pc.name}] malformed KEY_UPDATE")
            return

        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            new_pub = base64.b64decode(parts[1])
            sig = base64.b64decode(parts[2])

            old_pub = ed25519.Ed25519PublicKey.from_public_bytes(pc.remote_pub)
            old_pub.verify(sig, new_pub)
        except:
            safe_print(f"[{pc.name}] KEY_UPDATE verification FAILED")
            return

        pc.remote_pub = new_pub
        safe_print(f"[{pc.name}] securely updated public key")

    elif cmd == "ERROR":
        msg = parts[1] if len(parts) > 1 else "unknown"
        safe_print(f"[{pc.name}] ERROR: {msg}")


def connection_loop(app: App, sock: socket.socket):
    sock_file = sock.makefile("rwb")
    try:
        remote_name, remote_pub, key = perform_handshake(sock_file, app.identity)
        pc = PeerConn(remote_name, sock, sock_file, key, remote_pub)

        if app.add_conn(pc):
            safe_print(f"connected to {remote_name}")

        while True:
            line = sock_file.readline()
            if not line:
                safe_print(f"[{pc.name}] disconnected")
                return

            parts = line.decode().strip().split("|")
            if len(parts) != 3 or parts[0] != "DATA":
                continue

            nonce = base64.b64decode(parts[1])
            ciphertext = base64.b64decode(parts[2])
            plaintext = decrypt(pc.key, nonce, ciphertext).decode()

            process_payload(app, pc, plaintext)

    except Exception as e:
        safe_print("connection error:", e)
    finally:
        sock.close()


def listen(app: App, port: int):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()

    safe_print(f"{app.identity.name} listening on {port}")

    while True:
        conn, _ = server.accept()
        threading.Thread(target=connection_loop, args=(app, conn), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="python")
    parser.add_argument("--port", type=int, default=9002)
    parser.add_argument("--peers", default="")
    args = parser.parse_args()

    ensure_dirs("python-note.txt", "hello from python")
    app = App(Identity(args.name))

    threading.Thread(target=listen, args=(app, args.port), daemon=True).start()
    threading.Thread(target=input_thread, daemon=True).start()
    start_mdns(app, args.port)

    safe_print("commands: peers | list <peer> | get <peer> <file> | ping <peer> | rotate")

    while True:

        # handle file requests
        try:
            pc, filename = request_queue.get(timeout=0.1)

            safe_print(f"[{pc.name}] wants file '{filename}'. Accept? (y/n): ", end="", flush=True)

            # safely wait for input 
            while True:
                try:
                    resp = command_queue.get(timeout=0.1).strip().lower()
                    break
                except queue.Empty:
                    continue

            if resp != "y":
                send_encrypted(pc, "ERROR|request denied")
                continue

            shared_path = SHARED_DIR / filename
            download_path = DOWNLOAD_DIR / filename

            if shared_path.exists():
                data = shared_path.read_bytes()
                msg = build_get_res(app.identity, filename, data)
                send_encrypted(pc, msg)

            elif download_path.exists():
                data = load_download(filename, local_storage_key(app.identity.name))
                origin_name, origin_pub, h, sig = load_metadata(filename)

                msg = build_get_res(
                    app.identity,
                    filename,
                    data,
                    origin_pub=origin_pub,
                    origin_name=origin_name,
                    existing_hash=h,
                    existing_sig=sig,
                )
                send_encrypted(pc, msg)

            else:
                send_encrypted(pc, "ERROR|file not found")

        except queue.Empty:
            pass

        # handle commands
        try:
            line = command_queue.get_nowait().strip()
            parts = line.split(" ")

            if parts[0] == "peers":
                safe_print("connected peers:", ", ".join(app.peer_names()))

            elif parts[0] == "get" and len(parts) == 3:
                pc = app.get_conn(parts[1])
                if pc:
                    send_encrypted(pc, "GET_REQ|" + parts[2])
                else:
                    safe_print("unknown peer")

        except queue.Empty:
            pass


if __name__ == "__main__":
    main()