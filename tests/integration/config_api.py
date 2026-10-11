"""Run against a local nginx binary: python tests/integration/config_api.py --nginx /path/to/nginx."""
from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from megaproxy_server.config_api import serve
from megaproxy_server.config_bundle import public_url, write_bundle
from megaproxy_server.inventory import ROOT
from megaproxy_server.models import Inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="megaproxy-api-tls-") as directory:
        root = Path(directory)
        (root / "logs").mkdir()
        certificates = root / "certificates"
        certificates.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(certificates / "privkey.pem"), "-out", str(certificates / "fullchain.pem")],
                       check=True, capture_output=True)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public_port = reservation.getsockname()[1]
        inventory = Inventory.model_validate({"users": {"https": [{"name": "tester", "password": "test-password-123456789"}]}, "hosts": {
            "de_proxy": {"address": "192.0.2.1", "admin": {"user": "deploy", "private_key_file": "/keys/admin", "public_key": "ssh-ed25519 TEST"},
                         "services": {"https": {"title": "HTTPS", "endpoint": "proxy.example", "certificate": "domain", "acme_email": "test@example.com"}}},
            "config": {"address": "127.0.0.1", "admin": {"user": "deploy", "private_key_file": "/keys/admin", "public_key": "ssh-ed25519 TEST"},
                       "services": {"config_api": {"endpoint": "localhost", "port": public_port, "acme_email": "test@example.com"}}},
        }})
        bundle = root / "bundle.json"
        write_bundle(inventory, bundle)
        api = inventory.hosts["config"].services.config_api
        server = serve(bundle, 0, api.path, public_url(api))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        api.backend_port = server.server_port
        env = Environment(loader=FileSystemLoader(str(ROOT / "roles/config_api/templates")), undefined=StrictUndefined)
        nginx = env.get_template("nginx.conf.j2").render(
            ansible_facts={"all_ipv6_addresses": ["::1"]},
            megaproxy_services={"config_api": api.model_dump()},
            megaproxy_config_api_certificate_directory=str(certificates))
        nginx = nginx.replace(f"listen {public_port} ssl", f"listen 127.0.0.1:{public_port} ssl")
        nginx = nginx.replace(f"listen [::]:{public_port} ssl", f"listen [::1]:{public_port} ssl")
        # Test path/auth behavior without the production throttle masking a routing failure.
        nginx = nginx.replace("rate=30r/m;", "rate=60000r/m;").replace("burst=20 nodelay", "burst=100 nodelay")
        configuration = root / "nginx.conf"
        configuration.write_text(f"pid {root}/nginx.pid;\nerror_log {root}/errors.log;\nevents {{ worker_connections 128; }}\nhttp {{\n{nginx}\n}}\n")
        command = [args.nginx, "-p", str(root) + "/", "-c", str(configuration)]
        subprocess.run(command + ["-t"], check=True, capture_output=True)
        process = subprocess.Popen(command + ["-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(certificates / "fullchain.pem"))))
        origin = f"https://127.0.0.1:{public_port}"
        authorization = "Basic " + base64.b64encode(b"tester:test-password-123456789").decode()

        def request(path, headers=None, method="GET"):
            try:
                response = opener.open(Request(origin + path, headers=headers or {}, method=method), timeout=10)
            except HTTPError as error:
                response = error
            with response:
                return response.status, response.headers, response.read()
        try:
            for attempt in range(100):
                try:
                    status, headers, body = request("/robots.txt")
                    break
                except URLError:
                    if process.poll() is not None:
                        raise RuntimeError("nginx failed to start") from None
                    time.sleep(0.05)
            else:
                raise RuntimeError("nginx did not start")
            assert status == 200 and body == b"User-agent: *\nDisallow: /\n"
            for path in ("/", "/favicon.ico", "/robots.txt?x=1", "/x/../robots.txt", "//robots.txt"):
                status, headers, body = request(path)
                assert status == 403, (path, status)
                assert "noindex" in headers["X-Robots-Tag"]
            status, headers, body = request(api.path, {"Authorization": authorization, "X-MegaProxy-Client": "browser_firefox"})
            assert status == 200
            assert headers["Cache-Control"] == "private, no-store"
            assert "noindex" in headers["X-Robots-Tag"]
            assert "WWW-Authenticate" not in headers
            assert json.loads(body)["version"] == 8
            etag = headers["ETag"]
            status, headers, body = request(api.path, {"Authorization": authorization, "X-MegaProxy-Client": "browser_firefox", "If-None-Match": etag})
            assert status == 304
            for path, auth, method in ((api.path, "Basic bad", "GET"), ("//api/config", authorization, "GET"),
                                       (api.path + "?x=1", authorization, "GET"), (api.path, authorization, "POST")):
                status, headers, body = request(path, {"Authorization": auth}, method)
                assert status == 403, (path, status)
                assert "noindex" in headers["X-Robots-Tag"]
                assert "WWW-Authenticate" not in headers
            context = ssl.create_default_context(cafile=str(certificates / "fullchain.pem"))
            for raw in (
                f"GET {api.path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nAuthorization: Basic bad\r\nConnection: close\r\n\r\n",
                "GET / HTTP/1.1\r\nBroken header\r\n\r\n",
            ):
                with socket.create_connection(("127.0.0.1", public_port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname="localhost") as secured:
                        secured.sendall(raw.encode())
                        response = secured.recv(4096)
                        assert response.split(b"\r\n", 1)[0].split()[1] == b"403", response
                        assert b"www-authenticate" not in response.lower()
            limited = nginx.replace("rate=60000r/m;", "rate=30r/m;").replace("burst=100 nodelay", "burst=20 nodelay")
            configuration.write_text(f"pid {root}/nginx.pid;\nerror_log {root}/errors.log;\nevents {{ worker_connections 128; }}\nhttp {{\n{limited}\n}}\n")
            subprocess.run(command + ["-s", "reload"], check=True, capture_output=True)
            time.sleep(0.2)
            limited_responses = [request(api.path) for _ in range(40)]
            assert all(status == 403 for status, _, _ in limited_responses)
            assert any(body != b"Forbidden\n" for _, _, body in limited_responses)
            assert all("WWW-Authenticate" not in headers for _, headers, _ in limited_responses)
            print("HTTPS/nginx integration passed: TLS, v8, ETag, exact paths, duplicate/malformed headers, rate limiting and fail-closed responses.")
        finally:
            process.terminate()
            process.wait(timeout=5)
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
