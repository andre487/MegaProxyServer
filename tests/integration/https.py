"""Check HTTPS masking, knock, server chains and nested TLS Jump on loopback."""
import argparse
import base64
import json
import socket
import ssl
import subprocess
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from socketserver import ThreadingTCPServer
from threading import Thread

from jinja2 import Environment, StrictUndefined
from ruamel.yaml import YAML

from megaproxy_server.inventory import ROOT, ansible_inventory
from megaproxy_server.models import Inventory
from transports import PASSWORD, USERNAME, TcpEcho, port, receive


class NestedTLS:
    """A TLS stream inside an existing TLS CONNECT tunnel, using stdlib MemoryBIO."""
    def __init__(self, outer, context):
        self.outer = outer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname="localhost")
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.pump()

    def flush(self):
        if self.outgoing.pending:
            self.outer.sendall(self.outgoing.read())

    def pump(self):
        self.flush()
        data = self.outer.recv(16384)
        if not data:
            raise EOFError("Nested TLS tunnel closed")
        self.incoming.write(data)

    def sendall(self, data):
        while data:
            written = self.tls.write(data)
            data = data[written:]
            self.flush()

    def recv(self, size):
        while True:
            try:
                return self.tls.read(size)
            except ssl.SSLWantReadError:
                self.pump()


def connect(sock, host, target_port, *, password=PASSWORD):
    auth = base64.b64encode(f"{USERNAME}:{password}".encode()).decode() if password is not None else None
    headers = f"CONNECT {host}:{target_port} HTTP/1.1\r\nHost: {host}:{target_port}\r\n"
    if auth:
        headers += f"Proxy-Authorization: Basic {auth}\r\n"
    sock.sendall((headers + "\r\n").encode())
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        response += receive(sock, 1)
        assert len(response) < 16384
    return int(response.split(b" ", 2)[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gost", required=True)
    args = parser.parse_args()
    echo = ThreadingTCPServer(("127.0.0.1", 0), TcpEcho)
    Thread(target=echo.serve_forever, daemon=True).start()
    processes, logs = [], []
    yaml = YAML(typ="safe")
    try:
        with tempfile.TemporaryDirectory(prefix="megaproxy-https-") as directory:
            root = Path(directory)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,DNS:chain.localhost",
                "-keyout", str(root / "privkey.pem"), "-out", str(root / "fullchain.pem")], check=True, capture_output=True)
            entry_port, exit_port, chain_port = port(), port(), port()
            admin = {"user": "deploy", "private_key_file": "/unused", "public_key": "ssh-ed25519 TEST"}
            inv = Inventory.model_validate({"users": {"https": [{"name": USERNAME, "password": PASSWORD}]},
                "settings": {"https_chains_enabled": True, "https_chain_domain": "localhost",
                    "https_chain_pairs": [{"entry": "entry", "exit": "exit", "title": "CHAIN", "country_code": "US",
                        "hostname": "chain.localhost", "probe_resistance": {"enabled": True, "knock": ["chain.localhost"]}}]},
                "hosts": {
                    "entry": {"address": "127.0.0.1", "admin": admin, "services": {"https": {
                        "title": "ENTRY", "endpoint": "localhost", "port": entry_port, "certificate": "domain",
                        "acme_email": "test@example.com", "chain_entry": True,
                        "probe_resistance": {"enabled": True, "knock": ["localhost"]}}}},
                    "exit": {"address": "127.0.0.1", "admin": admin, "services": {"https": {
                        "title": "EXIT", "endpoint": "localhost", "port": exit_port, "certificate": "domain",
                        "acme_email": "test@example.com", "chain_exit": True, "chain_password": "machine-password-123"}}}}})
            env = Environment(undefined=StrictUndefined)
            env.filters["to_json"] = json.dumps
            template = env.from_string((ROOT / "roles/https_proxy/templates/gost.yml.j2").read_text())
            variables = ansible_inventory(inv)["all"]["hosts"]
            configs = {}
            for name, public in (("entry", entry_port), ("exit", exit_port)):
                config = yaml.load(template.render(**dict(variables[name], megaproxy_container_certificate_directory=str(root))))
                # Distinct loopback ports replace separate host network namespaces and HAProxy.
                for service in config["services"]:
                    if service["name"] == "direct":
                        service["addr"] = f"127.0.0.1:{public}"
                    elif service["name"] == "via-exit":
                        service["addr"] = f"127.0.0.1:{chain_port}"
                    elif service["name"] == "decoy":
                        decoy_port = port()
                        service["addr"] = f"127.0.0.1:{decoy_port}"
                        service["handler"]["metadata"]["dir"] = str(root)
                        for candidate in config["services"]:
                            metadata = candidate["handler"].get("metadata", {})
                            if "probeResist" in metadata:
                                metadata["probeResist"] = f"host:127.0.0.1:{decoy_port}"
                for chain in config.get("chains") or []:
                    chain["hops"][0]["nodes"][0]["dialer"]["tls"]["caFile"] = str(root / "fullchain.pem")
                configs[name] = config
            (root / "index.html").write_text("A local decoy page\n")

            def start(name, config, ready):
                path = root / f"{name}.yml"
                with path.open("w") as stream:
                    yaml.dump(config, stream)
                log = (root / f"{name}.log").open("w+")
                logs.append(log)
                process = subprocess.Popen([args.gost, "-C", str(path)], stdout=log, stderr=log)
                processes.append(process)
                for _ in range(100):
                    assert process.poll() is None, f"{name} stopped"
                    try:
                        with socket.create_connection(("127.0.0.1", ready), timeout=.1):
                            return process
                    except OSError:
                        time.sleep(.05)
                raise AssertionError(f"{name} did not start")

            exit_process = start("exit", configs["exit"], exit_port)
            entry_process = start("entry", configs["entry"], chain_port)
            context = ssl.create_default_context(cafile=str(root / "fullchain.pem"))

            def check(proxy_port, *, hostname="localhost", target="127.0.0.1", password=PASSWORD, accepted=True):
                with context.wrap_socket(socket.create_connection(("127.0.0.1", proxy_port), timeout=5), server_hostname=hostname) as sock:
                    status = connect(sock, target, echo.server_address[1], password=password)
                    if accepted is True:
                        assert status == 200, status
                        sock.sendall(b"HTTPS transport check")
                        assert receive(sock, 21) == b"HTTPS transport check"
                    elif accepted is False:
                        assert status != 200
                    return status

            assert check(entry_port, target="localhost", password=None, accepted=False) == 407
            assert check(chain_port, hostname="chain.localhost", target="chain.localhost", password=None, accepted=False) == 407
            assert check(entry_port, password=None, accepted=None) != 407
            check(entry_port)
            check(chain_port, hostname="chain.localhost")
            with context.wrap_socket(socket.create_connection(("127.0.0.1", entry_port), timeout=5), server_hostname="localhost") as outer:
                assert connect(outer, "localhost", exit_port) == 200
                inner = NestedTLS(outer, context)
                assert connect(inner, "127.0.0.1", echo.server_address[1]) == 200
                inner.sendall(b"HTTPS Jump check")
                assert receive(inner, 16) == b"HTTPS Jump check"
            for mutation in ("password", "certificate"):
                entry_process.terminate()
                entry_process.wait(timeout=5)
                bad = deepcopy(configs["entry"])
                node = bad["chains"][0]["hops"][0]["nodes"][0]
                if mutation == "password":
                    node["connector"]["auth"]["password"] = "incorrect-machine-password"
                else:
                    node["dialer"]["tls"]["serverName"] = "wrong.example"
                entry_process = start(f"entry-bad-{mutation}", bad, chain_port)
                check(chain_port, hostname="chain.localhost", accepted=False)
                check(entry_port)  # Direct route still works, without bypassing a broken chain.
            entry_process.terminate()
            entry_process.wait(timeout=5)
            start("entry-restored", configs["entry"], chain_port)
            exit_process.terminate()
            exit_process.wait(timeout=5)
            check(chain_port, hostname="chain.localhost", accepted=False)
            check(entry_port)
            print("HTTPS passed: masking, knock and override, trusted server chain, nested TLS Jump, rejected machine auth/TLS and unavailable exit without bypass.")
    except Exception:
        for log in logs:
            log.seek(0)
            print(Path(log.name).name, log.read()[-4000:])
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        for log in logs:
            log.close()
        echo.shutdown()
        echo.server_close()


if __name__ == "__main__":
    main()
