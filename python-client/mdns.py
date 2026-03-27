from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
import socket
import threading

SERVICE_TYPE = "_securedrop._tcp.local."

class PeerListener:
    def __init__(self, app, self_port):
        self.app = app
        self.self_port = self_port

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if not info:
            return

        addr = socket.inet_ntoa(info.addresses[0])
        port = info.port

        # avoid connecting to self
        if port == self.self_port:
            return

        peer_addr = f"{addr}:{port}"
        print(f"[mDNS] discovered peer at {peer_addr}")

        threading.Thread(
            target=self.app.connect_to_peer,
            args=(peer_addr,),
            daemon=True
        ).start()

    def update_service(self, zeroconf, type, name):
        # required by zeroconf, can be empty
        pass

    def remove_service(self, zeroconf, type, name):
        # optional, safe to ignore
        pass


def start_mdns(app, port):
    zeroconf = Zeroconf()

    # register self
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    service_name = f"{hostname}-{port}.{SERVICE_TYPE}" 

    info = ServiceInfo(
        SERVICE_TYPE,
        service_name,
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties={},
    )

    zeroconf.register_service(info)

    # discover others
    listener = PeerListener(app, port)
    ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    print(f"[mDNS] advertising on {ip}:{port}")

    return zeroconf