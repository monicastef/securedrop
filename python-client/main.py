import argparse
import base64
import os
import socket
import threading
import time
import queue

request_queue = queue.Queue()

from handshake import Identity, perform_handshake
from crypto import encrypt, decrypt
from protocol import ensure_dirs, list_shared_files, save_metadata, save_download, file_hash, build_get_res, SHARED_DIR
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
        import socket
        try:
            host, port = addr.split(":")
            port = int(port)

            sock = socket.socket()
            sock.connect((host, port))
            connection_loop(self, sock)
        except:
            pass

def send_encrypted(pc: PeerConn, payload: str):
    nonce, ciphertext = encrypt(pc.key, payload.encode())
    line = "DATA|{}|{}\n".format(
        base64.b64encode(nonce).decode(),
        base64.b64encode(ciphertext).decode(),
    )
    pc.sock_file.write(line.encode())
    pc.sock_file.flush()

def process_payload(app: App, pc: PeerConn, payload: str):
    parts = payload.split("|")
    cmd = parts[0]

    if cmd == "PING":
        print(f"[{pc.name}] PING received")

    elif cmd == "LIST_REQ":
        files = ",".join(list_shared_files())
        send_encrypted(pc, "LIST_RES|" + files)

    elif cmd == "LIST_RES":
        files = parts[1] if len(parts) > 1 else ""
        print(f"[{pc.name}] shared files: {files if files else '(none)'}")

    elif cmd == "GET_REQ":
        if len(parts) < 2:
            send_encrypted(pc, "ERROR|missing filename")
            return

        filename = os.path.basename(parts[1])
        print(f"[{pc.name}] wants file '{filename}'")

        # send to main thread for user input
        request_queue.put((pc, filename))
        print("DEBUG: queued request for", filename)

    elif cmd == "GET_RES":        
        if len(parts) != 7:
            print(f"[{pc.name}] malformed GET_RES")
            return

        filename = parts[1]
        data = base64.b64decode(parts[2])
        expected_hash = base64.b64decode(parts[3])
        sig = base64.b64decode(parts[4])
        origin_pub = base64.b64decode(parts[5])
        origin_name = parts[6]

        actual_hash = file_hash(data)
        if actual_hash != expected_hash:
            print(f"[{pc.name}] hash mismatch for {filename}")
            return

        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(origin_pub)
            pub.verify(sig, expected_hash)
        except Exception:
            print(f"[{pc.name}] signature verification FAILED for {filename} (original: {origin_name})")
            return

        save_download(filename, data)
        save_metadata(filename, origin_name, origin_pub, expected_hash, sig)

        print(f"[{pc.name}] downloaded and verified {filename} (original: {origin_name})")

    elif cmd == "ERROR":
        msg = parts[1] if len(parts) > 1 else "unknown"
        print(f"[{pc.name}] ERROR: {msg}")

def connection_loop(app: App, sock: socket.socket):
    sock_file = sock.makefile("rwb")
    try:
        remote_name, remote_pub, key = perform_handshake(sock_file, app.identity)
        pc = PeerConn(remote_name, sock, sock_file, key, remote_pub)
        if app.add_conn(pc):
            print(f"connected to {remote_name}")
        else:
            return

        while True:
            line = sock_file.readline()
            if not line:
                print(f"[{pc.name}] disconnected")
                return
            line = line.decode().strip()
            parts = line.split("|")
            if len(parts) != 3 or parts[0] != "DATA":
                continue
            nonce = base64.b64decode(parts[1])
            ciphertext = base64.b64decode(parts[2])
            plaintext = decrypt(pc.key, nonce, ciphertext).decode()
            process_payload(app, pc, plaintext)

    except Exception as e:
        print("connection error:", e)
    finally:
        sock.close()

def listen(app: App, port: int):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # server.bind(("127.0.0.1", port))
    server.bind(("0.0.0.0", port))
    server.listen()
    print(f"{app.identity.name} listening on {port}")

    while True:
        conn, _ = server.accept()
        threading.Thread(target=connection_loop, args=(app, conn), daemon=True).start()

def connect_with_retry(app: App, addr: str):
    host, port = addr.split(":")
    port = int(port)
    for _ in range(15):
        try:
            sock = socket.socket()
            sock.connect((host, port))
            connection_loop(app, sock)
            return
        except Exception:
            time.sleep(1)
    print("could not connect to", addr)

""" def input_loop(app):
    while True:
        line = input().strip()
        parts = line.split(" ")

        if parts[0] == "peers":
            print("connected peers:", ", ".join(app.peer_names()))

        elif parts[0] == "ping" and len(parts) == 2:
            pc = app.get_conn(parts[1])
            if pc:
                send_encrypted(pc, "PING")
            else:
                print("unknown peer")

        elif parts[0] == "list" and len(parts) == 2:
            pc = app.get_conn(parts[1])
            if pc:
                send_encrypted(pc, "LIST_REQ")
            else:
                print("unknown peer")

        elif parts[0] == "get" and len(parts) == 3:
            pc = app.get_conn(parts[1])
            if pc:
                print(f"DEBUG: sending GET_REQ to {parts[1]}")
                send_encrypted(pc, "GET_REQ|" + parts[2])
            else:
                print("unknown peer") """

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="python")
    parser.add_argument("--port", type=int, default=9002)
    parser.add_argument("--peers", default="")
    args = parser.parse_args()

    ensure_dirs("python-note.txt", "hello from python")
    app = App(Identity(args.name))

    threading.Thread(target=listen, args=(app, args.port), daemon=True).start()
    # threading.Thread(target=input_loop, args=(app,), daemon=True).start()
    zeroconf = start_mdns(app, args.port)

    if args.peers.strip():
        for addr in [x.strip() for x in args.peers.split(",") if x.strip()]:
            threading.Thread(target=connect_with_retry, args=(app, addr), daemon=True).start()

    print("commands: peers | list <peer> | get <peer> <file> | ping <peer>")
    print("DEBUG: main request loop running")
    """ while True:
        pc, filename = request_queue.get()

        resp = input(f"[{pc.name}] wants file '{filename}'. Accept? (y/n): ").strip().lower()

        if resp != "y":
            send_encrypted(pc, "ERROR|request denied")
            continue

        path = SHARED_DIR / filename
        if not path.exists():
            send_encrypted(pc, "ERROR|file not found")
            continue

        data = path.read_bytes()
        send_encrypted(pc, build_get_res(app.identity, filename, data))   """

    """ while True:
        pc, filename = request_queue.get()

        resp = input(f"[{pc.name}] wants file '{filename}'. Accept? (y/n): ").strip().lower()

        if resp != "y":
            send_encrypted(pc, "ERROR|request denied")
            continue

        path = SHARED_DIR / filename
        if not path.exists():
            send_encrypted(pc, "ERROR|file not found")
            continue

        data = path.read_bytes()
        send_encrypted(pc, build_get_res(app.identity, filename, data)) """
    while True:
        pc, filename = request_queue.get()

        resp = input(f"[{pc.name}] wants file '{filename}'. Accept? (y/n): ").strip().lower()

        if resp != "y":
            send_encrypted(pc, "ERROR|request denied")
            continue

        path = SHARED_DIR / filename
        if not path.exists():
            send_encrypted(pc, "ERROR|file not found")
            continue

        data = path.read_bytes()
        send_encrypted(pc, build_get_res(app.identity, filename, data))

if __name__ == "__main__":
    main()