"""Standalone, loopback-only config API. nginx provides the mandatory public TLS."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if __package__:
    from .config_format import configuration, https_jump_profile, profile
else:
    from config_format import configuration, https_jump_profile, profile

ROBOTS = b"User-agent: *\nDisallow: /\n"
MAX_RESPONSE = 1024 * 1024


class AccessDenied(ValueError):
    pass


def user_id(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8")).hexdigest()


def derive_key(value: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(value, salt=salt, n=2**17, r=8, p=1, dklen=32, maxmem=256 * 1024 * 1024)


def credential_bytes(username: str, password: str) -> bytes:
    if not username or len(username) > 1024 or len(password) > 1024 or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
        raise AccessDenied("Invalid credentials")
    return json.dumps([username, password], ensure_ascii=False).encode("utf-8")


def unlock(bundle: dict[str, Any], username: str, password: str) -> dict[str, Any]:
    credentials = credential_bytes(username, password)
    identity = user_id(username)
    entry = bundle["users"].get(identity)
    # Unknown users still pay the same authentication KDF cost.
    salt = bytes.fromhex(entry["auth_salt"]) if entry else bytes(16)
    verifier = derive_key(credentials, salt)
    expected = bytes.fromhex(entry["verifier"]) if entry else bytes(32)
    if not hmac.compare_digest(verifier, expected) or entry is None:
        raise AccessDenied("Invalid credentials")
    key = derive_key(password.encode("utf-8"), bytes.fromhex(entry["encryption_salt"]))
    try:
        plaintext = AESGCM(key).decrypt(
            bytes.fromhex(entry["nonce"]), bytes.fromhex(entry["ciphertext"]),
            ("megaproxy-config-api/v1/" + identity).encode("ascii"),
        )
    except InvalidTag:
        raise AccessDenied("Invalid encrypted data") from None
    return json.loads(plaintext)


def render_config(bundle: dict[str, Any], username: str, password: str, client: str = "", *, url: str | None = None, interval: int = 60) -> dict[str, Any]:
    payload = unlock(bundle, username, password)
    profiles = []
    chain_profiles = []
    direct_https = {}
    for route in bundle["https_routes"]:
        proxy = {"type": "HTTPS", "host": route["host"], "port": route["port"],
                 "username": username, "password": password,
                 "allowInvalidProxyCertificate": route["allow_invalid_certificate"]}
        item = profile(route["title"], proxy, len(profiles), route["country_code"],
                       identity=json.dumps(["https", route["host_name"], route["route_name"], username]))
        options = deepcopy(payload["https_options"][json.dumps([route["host_name"], route["route_name"]])])
        item.update({k: v for k, v in options.items() if k != "proxy"})
        proxy.update(options.get("proxy", {}))
        (profiles if route["route_name"] == "direct" else chain_profiles).append(item)
        if route["route_name"] == "direct":
            direct_https[route["host_name"]] = item
        if route.get("http3_port") and route.get("masque_profiles"):
            masque = deepcopy(item)
            generated = profile(f"{item['name']} MASQUE",
                dict(proxy, type="MASQUE", port=route["http3_port"]), len(profiles), route["country_code"],
                identity=json.dumps(["masque", route["host_name"], route["route_name"], username]))
            masque.update({k: generated[k] for k in ("id", "name", "color", "proxy")})
            masque["proxy"].pop("preferHttp3", None)
            masque.pop("browser", None)  # MASQUE does not use HTTPS knock hosts.
            profiles.append(masque)
    for host in bundle.get("socks5_hosts", []):
        profiles.append(profile(f"{host['name']} SOCKS5 / {username}",
            {"type": "SOCKS5", "host": host["host"], "port": host["port"], "username": username, "password": password},
            len(profiles), identity=json.dumps(["socks5", host["name"], username])))

    endpoints = {}
    for host in bundle["ssh_hosts"]:
        for account in payload["ssh_accounts"]:
            proxy = {"type": "SSH", "host": host["address"], "port": host["port"],
                     "username": account["username"], "trustedHostKey": "", "acceptAnyHostKey": False,
                     "privateKey" if account["type"] == "key" else "password": account["secret"]}
            item = profile(host["title"], proxy, len(profiles),
                           identity=json.dumps(["ssh", host["name"], account["username"]]))
            options = deepcopy(payload["ssh_options"][host["name"]])
            item.update({k: v for k, v in options.items() if k != "proxy"})
            proxy.update(options.get("proxy", {}))
            if host.get("generate_profile", False):
                profiles.append(item)
            endpoints[(host["name"], account["username"])] = (host, account, proxy)
    profiles.extend(chain_profiles)
    for pair in bundle.get("https_jump_pairs", []):
        profiles.append(https_jump_profile(
            direct_https[pair["entry"]], direct_https[pair["exit"]], pair["title"],
            pair["country_code"], len(profiles),
            identity=json.dumps(["https_jump", pair["entry"], pair["exit"], username]),
        ))

    for pair in payload.get("ssh_jump_pairs", []):
        for account in payload["ssh_accounts"]:
            destination_endpoint = endpoints.get((pair["exit"], account["username"]))
            jump_endpoint = endpoints.get((pair["entry"], account["username"]))
            if destination_endpoint is None or jump_endpoint is None:
                continue  # Only accounts explicitly linked to this HTTPS user are available.
            destination, dst_account, dst_proxy = destination_endpoint
            jump, jump_account, jump_proxy = jump_endpoint
            proxy = dict(dst_proxy, type="SSH_JUMP")
            proxy["jump"] = {k: v for k, v in jump_proxy.items() if k != "type"}
            proxy["jump"]["sameAuthentication"] = True
            item = profile(
                pair["title"], proxy, len(profiles),
                pair["country_code"] if re.fullmatch(r"[A-Z]{2}", pair["country_code"]) else "",
                identity=json.dumps(["ssh_jump", jump["name"], jump_account["username"], destination["name"], dst_account["username"]]),
            )
            item.update({k: v for k, v in deepcopy(payload["ssh_options"][destination["name"]]).items() if k != "proxy"})
            profiles.append(item)

    for index, item in enumerate(profiles):
        item["color"] = index

    result = configuration(profiles)
    for key in ("routing", "tls", "ssh", "failover", "diagnosticLogLimitMb"):
        result.pop(key, None)
    defaults = profile("", {}, 0)
    for item in profiles:
        for key in ("tls", "dns"):
            if item.get(key) == defaults[key]:
                item.pop(key)
    result["version"] = 8
    overrides = payload["client_config"]
    result.update({k: v for k, v in overrides.items() if k in {"tls", "passwordsIncluded", "privateKeysIncluded"}})
    result["profiles"] = profiles + overrides.get("profiles", [])
    if client in {"browser_chromium", "browser_firefox"}:
        supported = []
        for item in result["profiles"]:
            proxy = item["proxy"]
            if proxy["type"] not in {"HTTPS", "SOCKS5"}:
                continue
            if proxy["type"] == "SOCKS5" and (
                any(len(proxy.get(k, "").encode("utf-8")) > 255 for k in ("username", "password"))
                or (client == "browser_chromium" and any(proxy.get(k) for k in ("username", "password")))
            ):
                continue
            projected = {k: v for k, v in item.items() if k not in {"tls", "dns", "routing"}}
            projected["proxy"] = {k: v for k, v in proxy.items() if k in {"type", "host", "port", "username", "password"}}
            supported.append(projected)
        result["profiles"] = supported
        for key in ("tls", "ssh", "failover", "alwaysOnProfileId", "diagnosticLogLimitMb"):
            result.pop(key, None)
        result["privateKeysIncluded"] = False
    elif client in {"android", "android_megaproxy"}:
        result.pop("browser", None)
        result["profiles"] = [item for item in result["profiles"] if ":" not in item["proxy"]["host"] and ":" not in item["proxy"].get("jump", {}).get("host", "")]
        for item in result["profiles"]:
            item.pop("browser", None)
    ids = {item["id"] for item in result["profiles"]}
    if not ids or len(ids) != len(result["profiles"]) or len(ids) > 1000:
        raise AccessDenied("No usable configuration")
    subscription_options = overrides.get("subscription") or {}
    if url:
        result["subscription"] = {
            "url": url, "fallbackUrls": [endpoint for endpoint in bundle["urls"] if endpoint != url],
            "username": username, "password": password, "intervalMinutes": interval, "enabled": True,
        }
        result["subscription"].update(subscription_options)
    for item in result["profiles"]:
        proxy = item["proxy"]
        for node in (proxy, proxy.get("jump", {})):
            if not result.get("passwordsIncluded", True):
                node.pop("password", None)
            if not result.get("privateKeysIncluded", True):
                node.pop("privateKey", None)
    if not result.get("passwordsIncluded", True) and result.get("subscription"):
        result["subscription"].pop("password", None)
    result.pop("routing", None)
    for item in result["profiles"]:
        for key in tuple(item):
            if key not in {"id", "name", "color", "countryCode", "proxy", "tls", "browser"}:
                item.pop(key)
        if "browser" in item:
            item["browser"] = {k: v for k, v in item["browser"].items()
                               if k in {"knockHost", "authMode", "masqueTemplate"}}
            if not item["browser"]:
                item.pop("browser")
    return result


class ConfigHandler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Paths, credentials and response bodies never enter the journal.

    def respond(self, status: int, body: bytes = b"Forbidden\n", content_type: str = "text/plain; charset=utf-8", etag: str | None = None) -> None:
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Vary", "Authorization, X-MegaProxy-Client, X-MegaProxy-Version")
        self.send_header("Connection", "close")
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.respond(403)

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return lambda: self.respond(403)
        raise AttributeError(name)

    def do_GET(self) -> None:
        target = self.requestline.split()[1]  # Preserve raw target: HTTPServer normalizes leading //.
        if target == "/robots.txt":
            self.respond(200, ROBOTS)
            return
        if target != self.server.config_path or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            self.respond(403)
            return
        try:
            authorizations = self.headers.get_all("Authorization", [])
            if len(authorizations) != 1:
                raise AccessDenied("Invalid credentials")
            scheme, encoded = authorizations[0].split(" ", 1)
            if scheme.lower() != "basic" or len(encoded) > 12000:
                raise AccessDenied("Invalid credentials")
            username, password = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
            bundle = json.loads(self.server.bundle_path.read_bytes())
            if bundle.get("version") != 1:
                raise ValueError("Unsupported bundle")
            client = self.headers.get("X-MegaProxy-Client", "")
            version = self.headers.get("X-MegaProxy-Version", "")
            result = render_config(bundle, username, password, client, url=self.server.public_url, interval=self.server.interval)
            body = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_RESPONSE:
                raise ValueError("Response exceeds client limit")
            context = json.dumps([self.server.public_url, username, client, version]).encode()
            etag_key = bytes.fromhex(bundle["users"][user_id(username)]["verifier"])
            etag = '"' + hmac.new(etag_key, context + body, "sha256").hexdigest() + '"'
            validators = [tag.strip().removeprefix("W/") for tag in ",".join(self.headers.get_all("If-None-Match", [])).split(",")]
            if etag in validators or "*" in validators:
                self.respond(304, b"", etag=etag)
            else:
                self.respond(200, body, "application/json; charset=utf-8", etag)
        except (AccessDenied, UnicodeError, binascii.Error, ValueError):
            self.respond(403)
        except (OSError, KeyError, TypeError):
            logging.error("Configuration unavailable")
            self.respond(403)


class ConfigServer(HTTPServer):
    request_queue_size = 32

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


def serve(bundle: Path, port: int, path: str, url: str, interval: int = 60) -> HTTPServer:
    # ponytail: one request at a time bounds scrypt memory; use a bounded worker pool if throughput matters.
    server = ConfigServer(("127.0.0.1", port), ConfigHandler)
    server.bundle_path, server.config_path = bundle, path
    server.public_url, server.interval = url, interval
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--path", default="/api/config")
    parser.add_argument("--url", required=True)
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    with serve(args.bundle, args.port, args.path, args.url, args.interval) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
