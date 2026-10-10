"""Prepare credential-free routing metadata and password-encrypted user payloads."""
from __future__ import annotations

import json
import os
import re
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator

from .config_api import AccessDenied, MAX_RESPONSE, credential_bytes, derive_key, render_config, unlock, user_id
from .export import _secret
from .inventory import ROOT, https_routes
from .models import ConfigApiService, Inventory


def public_url(service: ConfigApiService) -> str:
    host = f"[{service.endpoint}]" if ":" in service.endpoint else service.endpoint.lower()
    port = "" if service.port == 443 else f":{service.port}"
    return f"https://{host}{port}{service.path}"


def validate_config(document: dict[str, Any]) -> None:
    schema = json.loads((ROOT / "schemas/megaproxy-v8.schema.json").read_text())
    # Validation errors must never print a document containing credentials.
    errors = Draft202012Validator(schema).iter_errors(document)
    error = next(errors, None)
    if error is not None:
        raise ValueError("Invalid client configuration at " + "/".join(map(str, error.absolute_path)))
    ids = [profile["id"] for profile in document["profiles"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Client profile IDs must be unique")
    references = [document.get("activeProfileId"), document.get("alwaysOnProfileId")]
    references += document.get("failover", {}).get("profileIds", [])
    references += [item["profileId"] for item in document.get("browser", {}).get("routing", {}).get("assignments", [])]
    if any(ref is not None and ref not in ids for ref in references):
        raise ValueError("Client configuration contains an unknown profile reference")
    if len(json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_RESPONSE:
        raise ValueError("Client configuration exceeds the 1 MiB download limit")


def validate_profile_options(options: dict[str, Any]) -> None:
    for key in ("proxy", "browser"):
        if key in options and not isinstance(options[key], dict):
            raise ValueError(f"client_profile.{key} must be an object")
    if {"id", "name", "color", "countryCode"} & options.keys() or {"type", "host", "port", "username", "password", "privateKey", "jump"} & options.get("proxy", {}).keys():
        raise ValueError("client_profile cannot override generated identity, endpoints or credentials")


def build_bundle(inventory: Inventory, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle: dict[str, Any] = {"version": 1, "https_routes": [], "socks5_hosts": [], "ssh_hosts": [], "users": {}, "urls": []}
    https_options, ssh_options = {}, {}
    for name, host in inventory.hosts.items():
        api = host.services.config_api
        if api and api.enabled:
            url = public_url(api)
            if len(url) > 2048:
                raise ValueError("Config API URL exceeds subscription limit")
            bundle["urls"].append(url)
        https = host.services.https
        if https and https.enabled:
            validate_profile_options(https.client_profile)
            for route in https_routes(inventory, name):
                resistance = route["probe_resistance"]
                options = deepcopy(https.client_profile)
                if options.get("proxy", {}).get("preferHttp3") and route["http3_port"] != https.port:
                    raise ValueError("preferHttp3 requires HTTP/3 on the same direct endpoint")
                if resistance["enabled"] and resistance["knock"]:
                    options.setdefault("browser", {}).setdefault("knockHost", resistance["knock"][0])
                https_options[json.dumps([name, route["name"]])] = options
                bundle["https_routes"].append({
                    "host_name": name, "route_name": route["name"],
                    "host": route["hostname"], "port": https.port,
                    "title": route["title"] if route["name"] != "direct" or https.title else name,
                    "country_code": route["country_code"] if re.fullmatch(r"[A-Z]{2}", route["country_code"]) else "",
                    "allow_invalid_certificate": https.certificate == "self-signed",
                    "http3_port": route["http3_port"],
                    "masque_profiles": https.masque_profiles,
                })
            if https.socks5.enabled:
                bundle["socks5_hosts"].append({"name": name, "host": https.endpoint, "port": https.socks5.port})
        ssh = host.services.ssh
        if ssh and ssh.enabled:
            validate_profile_options(ssh.client_profile)
            bundle["ssh_hosts"].append({"name": name, "address": host.address, "port": ssh.port})
            ssh_options[name] = ssh.client_profile
    accounts = {user.name: user for user in inventory.users.ssh}
    for user in inventory.users.https:
        overrides = dict(inventory.settings.client_config, **user.client_config)
        if {"schema", "version"} & overrides.keys():
            raise ValueError("client_config cannot override schema or version")
        subscription = overrides.get("subscription", {})
        if subscription is not None and (not isinstance(subscription, dict) or subscription.keys() - {"intervalMinutes", "enabled"}):
            raise ValueError("client_config.subscription may only set intervalMinutes and enabled; URLs and credentials are managed")
        extras = overrides.get("profiles", [])
        if not isinstance(extras, list) or not all(isinstance(item, dict) and isinstance(item.get("proxy"), dict) for item in extras):
            raise ValueError("client_config.profiles must contain profile objects with proxy settings")
        for item in extras:
            proxy = item["proxy"]
            if proxy.get("type") in {"SSH", "SSH_JUMP"}:
                names = {proxy.get("username")}
                if proxy["type"] == "SSH_JUMP":
                    jump = proxy.get("jump", {})
                    if not isinstance(jump, dict):
                        raise ValueError("SSH jump settings must be an object")
                    if not jump.get("sameAuthentication", True) or "username" in jump:
                        names.add(jump.get("username"))
                if not names.issubset(user.ssh_users):
                    raise ValueError("Additional SSH profiles must use explicitly linked SSH accounts")
        payload = {"ssh_accounts": [], "client_config": overrides, "https_options": https_options, "ssh_options": ssh_options}
        if bundle["ssh_hosts"]:
            for name in user.ssh_users:
                account = accounts[name]
                payload["ssh_accounts"].append({"username": name, "type": account.authentication.type, "secret": _secret(account.authentication, name)})
        identity = user_id(user.name)
        entry = None
        if previous and previous.get("version") == 1 and identity in previous.get("users", {}):
            try:
                if unlock(previous, user.name, user.password) == payload:
                    entry = previous["users"][identity]
            except (AccessDenied, KeyError, ValueError):
                pass
        if entry is None:
            auth_salt, encryption_salt, nonce = os.urandom(16), os.urandom(16), os.urandom(12)
            verifier = derive_key(credential_bytes(user.name, user.password), auth_salt)
            key = derive_key(user.password.encode("utf-8"), encryption_salt)
            ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode(), ("megaproxy-config-api/v1/" + identity).encode())
            entry = {"auth_salt": auth_salt.hex(), "verifier": verifier.hex(), "encryption_salt": encryption_salt.hex(), "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
        bundle["users"][identity] = entry
    for user in inventory.users.https:
        try:
            document = render_config(bundle, user.name, user.password, url=bundle["urls"][0] if bundle["urls"] else None)
        except (TypeError, KeyError, AttributeError):
            raise ValueError("Invalid client_config structure") from None
        validate_config(document)
        for client in ("browser_chromium", "browser_firefox", "android"):
            try:
                projected = render_config(bundle, user.name, user.password, client, url=bundle["urls"][0] if bundle["urls"] else None)
            except AccessDenied:
                continue  # This user may have no profiles supported by that client.
            validate_config(projected)
    return bundle


def write_bundle(inventory: Inventory, path: Path) -> None:
    previous = json.loads(path.read_bytes()) if path.is_file() else None
    content = json.dumps(build_bundle(inventory, previous), ensure_ascii=False, indent=2) + "\n"
    if path.is_file() and path.read_text() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".config-bundle-")
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
