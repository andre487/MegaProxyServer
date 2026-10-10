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
                         "services": {"https": {"endpoint": "proxy.example", "certificate": "domain", "acme_email": "test@example.com"}}},
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
            print("HTTPS/nginx integration passed: trusted TLS, v8, authenticated ETag, robots.txt, exact paths, 403 and noindex.")
        finally:
            process.terminate()
            process.wait(timeout=5)
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
