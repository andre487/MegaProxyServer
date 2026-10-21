from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config_format import configuration, https_jump_profile
from .config_format import profile as _profile
from .inventory import (
    atomic_write,
    https_jump_routes,
    https_profile_routes,
    https_routes,
    ssh_jump_routes,
)
from .models import Host, Inventory, SshUser


def _secret(auth: Any, key: str) -> str:
    if auth.type == "password":
        return auth.password or ""
    path = Path(auth.generated_private_key).expanduser() if auth.generated_private_key else None
    if not path or not path.is_file():
        raise ValueError(f"Private key for {key} is unavailable: {path}")
    return path.read_text(encoding="utf-8")


def _ssh_proxy(host_name: str, host: Host, user: SshUser, kind: str = "SSH") -> dict[str, Any]:
    auth = user.authentication
    result: dict[str, Any] = {"type": kind, "host": host.address, "port": host.services.ssh.port, "username": user.name, "allowInvalidProxyCertificate": False, "sshProfile": "DEFAULT", "trustedHostKey": "", "acceptAnyHostKey": False}
    result["password" if auth.type == "password" else "privateKey"] = _secret(auth, f"{host_name}/{user.name}")
    return result


def jump_candidates(inventory: Inventory) -> list[dict[str, Any]]:
    """List only configured SSH host pairs for each SSH account."""
    return [
        {"name": f"{pair['title']} / {user.name}",
         "destination": pair["exit"], "destinationUser": user.name,
         "jump": pair["entry"], "jumpUser": user.name, "country_code": pair["country_code"]}
        for pair in ssh_jump_routes(inventory)
        for user in inventory.users.ssh
    ]


def _jump_profiles(inventory: Inventory, start_color: int) -> list[dict[str, Any]]:
    profiles = []
    for pair in jump_candidates(inventory):
        dst_name, jump_name = pair["destination"], pair["jump"]
        dst_user = next(u for u in inventory.hosts[dst_name].services.ssh.users if u.name == pair["destinationUser"])
        jump_user = next(u for u in inventory.hosts[jump_name].services.ssh.users if u.name == pair["jumpUser"])
        proxy = _ssh_proxy(dst_name, inventory.hosts[dst_name], dst_user, "SSH_JUMP")
        jump = _ssh_proxy(jump_name, inventory.hosts[jump_name], jump_user)
        proxy["jump"] = {k: v for k, v in jump.items() if k != "type"}
        proxy["jump"]["sameAuthentication"] = True
        profiles.append(_profile(pair["name"], proxy, start_color + len(profiles),
            pair["country_code"] if re.fullmatch(r"[A-Z]{2}", pair["country_code"]) else "",
            identity=json.dumps(["ssh_jump", jump_name, jump_user.name, dst_name, dst_user.name])))
    return profiles


def export_profiles(inventory: Inventory, output: Path, include_all_jumps: bool = True) -> None:
    profiles: list[dict[str, Any]] = []
    direct_https = {}
    chain_profiles = {}
    ssh_profiles = []
    for host_name, host in inventory.hosts.items():
        https = host.services.https
        if https and https.enabled:
            for route in https_routes(inventory, host_name):
                for user in https.users:
                    title = route["title"]
                    name = f"{title} / {user.name}"
                    proxy = {"type": "HTTPS", "host": route["hostname"], "port": https.port, "username": user.name, "password": user.password, "allowInvalidProxyCertificate": https.certificate == "self-signed", "sshProfile": "DEFAULT", "trustedHostKey": "", "acceptAnyHostKey": False}
                    item = _profile(name, proxy, len(profiles), route["country_code"],
                        identity=json.dumps(["https", host_name, route["name"], user.name]))
                    resistance = route["probe_resistance"]
                    if resistance["enabled"] and resistance["knock"]:
                        item["browser"] = {"knockHost": resistance["knock"][0]}
                    if route["name"] == "direct":
                        profiles.append(item)
                    else:
                        chain_profiles.setdefault((host_name, route["name"]), []).append(item)
                    if route["name"] == "direct":
                        direct_https[(host_name, user.name)] = item
                    if route["http3_port"] and https.masque_profiles:
                        masque = dict(proxy, type="MASQUE", port=route["http3_port"])
                        masque.pop("preferHttp3", None)
                        profiles.append(_profile(f"{title} MASQUE / {user.name}", masque, len(profiles), route["country_code"],
                            identity=json.dumps(["masque", host_name, route["name"], user.name])))
            if https.socks5.enabled:
                for user in https.users:
                    profiles.append(_profile(f"{host_name} SOCKS5 / {user.name}", {
                        "type": "SOCKS5", "host": https.endpoint, "port": https.socks5.port,
                        "username": user.name, "password": user.password}, len(profiles)))
        if host.services.ssh and host.services.ssh.enabled and host.services.ssh.generate_profile:
            for user in host.services.ssh.users:
                name = f"{host.services.ssh.title} / {user.name}"
                ssh_profiles.append(_profile(name, _ssh_proxy(host_name, host, user), len(profiles),
                    identity=json.dumps(["ssh", host_name, user.name])))
    profiles.extend(ssh_profiles)
    for host_name, route in https_profile_routes(inventory):
        profiles.extend(chain_profiles.get((host_name, route["name"]), []))
    for pair in https_jump_routes(inventory):
        for user in inventory.users.https:
            profiles.append(https_jump_profile(
                direct_https[(pair["entry"], user.name)], direct_https[(pair["exit"], user.name)],
                f"{pair['title']} / {user.name}", pair["country_code"], len(profiles),
                identity=json.dumps(["https_jump", pair["entry"], pair["exit"], user.name]),
            ))
    if include_all_jumps:
        profiles.extend(_jump_profiles(inventory, len(profiles)))
    for index, item in enumerate(profiles):
        item["color"] = index
    result = configuration(profiles)
    if inventory.settings.https_jump_pairs or any(host.services.https and host.services.https.enabled and (host.services.https.http3 or host.services.https.socks5.enabled) for host in inventory.hosts.values()):
        result["version"] = 8
    from .config_bundle import validate_config
    validate_config(result, allow_legacy=True)
    atomic_write(output, json.dumps(result, indent=2) + "\n")
