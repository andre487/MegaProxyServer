"""Exercise rendered GOST services: python tests/integration/transports.py --gost /path/to/gost."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer, ThreadingUDPServer
from threading import Thread

from jinja2 import Environment, StrictUndefined
from ruamel.yaml import YAML
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived, DataReceived, DatagramReceived
from aioquic.quic.configuration import QuicConfiguration

from megaproxy_server.inventory import ROOT, ansible_inventory
from megaproxy_server.models import Inventory

USERNAME, PASSWORD = "tester", "test-password-123456789"
_ports: set[int] = set()


def port() -> int:
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            selected = sock.getsockname()[1]
        if selected not in _ports and not 40000 <= selected <= 40100:
            _ports.add(selected)
            return selected


def receive(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError("SOCKS connection closed")
        result += part
    return result


def authenticate(proxy_port, password=PASSWORD, username=USERNAME):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    sock.sendall(b"\x05\x01\x02" if username else b"\x05\x01\x00")
    assert receive(sock, 2) == (b"\x05\x02" if username else b"\x05\x00")
    if username:
        u, p = username.encode(), password.encode()
        sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        response = receive(sock, 2)
        if password != PASSWORD:
            assert response[1] != 0
            sock.close()
            return None
        assert response == b"\x01\x00"
    return sock


def request(sock, command, target_port):
    sock.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
    header = receive(sock, 4)
    if header[1] != 0:
        return header[1], None
    assert header[3] in {1, 4}
    address = socket.inet_ntop(socket.AF_INET if header[3] == 1 else socket.AF_INET6, receive(sock, 4 if header[3] == 1 else 16))
    return 0, (address, struct.unpack("!H", receive(sock, 2))[0])


def exchange(proxy_port, tcp_port, udp_port, *, username=USERNAME):
    with authenticate(proxy_port, username=username) as sock:
        assert request(sock, 1, tcp_port)[0] == 0
        sock.sendall(b"TCP transport check")
        assert receive(sock, 19) == b"TCP transport check"
    with authenticate(proxy_port, username=username) as control:
        status, relay = request(control, 3, 0)
        assert status == 0 and relay[1] != 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            data = b"\0\0\0\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port) + b"UDP transport check"
            udp.sendto(data, relay)
            received, _ = udp.recvfrom(4096)
            assert received[10:] == b"UDP transport check"
    return relay[1]


class TcpEcho(BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


class UdpEcho(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class MasqueClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic, enable_webtransport=True)
        self.headers = asyncio.get_running_loop().create_future()
        self.data = asyncio.Queue()

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived) and not self.headers.done():
                self.headers.set_result(dict(item.headers))
            elif isinstance(item, (DataReceived, DatagramReceived)):
                self.data.put_nowait(item.data)


async def masque_check(proxy_port, target_port, ca, *, udp=False, password=PASSWORD):
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name="localhost", max_datagram_frame_size=65536, idle_timeout=5)
    config.load_verify_locations(cafile=str(ca))
    async with connect("127.0.0.1", proxy_port, configuration=config, create_protocol=MasqueClient) as client:
        stream = client._quic.get_next_available_stream_id()
        headers = [(b":method", b"CONNECT")]
        if udp:
            headers += [(b":scheme", b"https"), (b":authority", f"localhost:{proxy_port}".encode()),
                (b":path", f"/.well-known/masque/udp/127.0.0.1/{target_port}/".encode()),
                (b":protocol", b"connect-udp"), (b"capsule-protocol", b"?1")]
        else:
            headers += [(b":authority", f"127.0.0.1:{target_port}".encode())]
        headers += [(b"proxy-authorization", b"Basic " + base64.b64encode(f"{USERNAME}:{password}".encode()))]
        client.http.send_headers(stream, headers)
        client.transmit()
        response = await asyncio.wait_for(client.headers, 5)
        if password != PASSWORD:
            assert response[b":status"] == b"407"
            return
        assert response[b":status"] == b"200"
        message = b"MASQUE transport check"
        if udp:
            assert response[b"capsule-protocol"] == b"?1"
            client.http.send_datagram(stream, b"\0" + message)
        else:
            client.http.send_data(stream, message, end_stream=False)
        client.transmit()
        received = await asyncio.wait_for(client.data.get(), 5)
        assert received == (b"\0" + message if udp else message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gost", required=True)
    args = parser.parse_args()
    yaml = YAML(typ="safe")
    env = Environment(undefined=StrictUndefined)
    env.filters["to_json"] = json.dumps
    template = env.from_string((ROOT / "roles/https_proxy/templates/gost.yml.j2").read_text())
    processes, logs = [], []
    tcp, udp = ThreadingTCPServer(("127.0.0.1", 0), TcpEcho), ThreadingUDPServer(("127.0.0.1", 0), UdpEcho)
    for server in (tcp, udp):
        Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="megaproxy-transports-") as directory:
            root = Path(directory)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                            "-keyout", str(root / "privkey.pem"), "-out", str(root / "fullchain.pem")],
                           check=True, capture_output=True)
            entry_port, socks_port, backend = port(), port(), port()
            admin = {"user": "deploy", "private_key_file": "/unused", "public_key": "ssh-ed25519 TEST"}
            inv = Inventory.model_validate({"users": {"https": [{"name": USERNAME, "password": PASSWORD}]},
                "settings": {"https_chain_backend_port": backend},
                "hosts": {"entry": {"address": "127.0.0.1", "admin": admin, "services": {"https": {
                    "endpoint": "localhost", "port": entry_port, "certificate": "domain", "acme_email": "test@example.com", "http3": True,
                    "socks5": {"enabled": True, "port": socks_port, "udp_port_min": 40000, "udp_port_max": 40100}}}}}})
            variables = ansible_inventory(inv)["all"]["hosts"]
            def start(name, config, ready_port):
                path = root / f"{name}.yml"
                with path.open("w") as stream:
                    yaml.dump(config, stream)
                log = (root / f"{name}.log").open("w+")
                logs.append(log)
                process = subprocess.Popen([args.gost, "-C", str(path)], stdout=log, stderr=log)
                processes.append(process)
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        with socket.create_connection(("127.0.0.1", ready_port), timeout=.1):
                            return process
                    except OSError:
                        time.sleep(.05)
                raise AssertionError(f"{name} did not start")
            context = dict(variables["entry"], megaproxy_container_certificate_directory=str(root))
            start("entry", yaml.load(template.render(**context)), socks_port)
            authenticate(socks_port, password="wrong-password")
            with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
                sock.sendall(b"\x05\x01\x00")
                assert receive(sock, 2) == b"\x05\xff"
            relay = exchange(socks_port, tcp.server_address[1], udp.server_address[1])
            assert 40000 <= relay <= 40100
            for is_udp, target in ((False, tcp.server_address[1]), (True, udp.server_address[1])):
                asyncio.run(masque_check(entry_port, target, root / "fullchain.pem", udp=is_udp))
                asyncio.run(masque_check(entry_port, target, root / "fullchain.pem", udp=is_udp, password="wrong-password"))
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=other-root", "-keyout", str(root / "other-key.pem"),
                            "-out", str(root / "other-ca.pem")], check=True, capture_output=True)
            try:
                asyncio.run(masque_check(entry_port, tcp.server_address[1], root / "other-ca.pem"))
            except (ConnectionError, ssl.SSLError):
                pass
            else:
                raise AssertionError("MASQUE accepted an untrusted certificate")
            print("GOST transports passed: authenticated SOCKS5 TCP/UDP, bounded UDP ports, MASQUE CONNECT-TCP/CONNECT-UDP, trusted TLS and rejection of bad credentials.")
    except Exception:
        for log in logs:
            log.seek(0)
            print(Path(log.name).name, log.read()[-5000:])
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for log in logs:
            log.close()
        for server in (tcp, udp):
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
