from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from .inventory import https_routes
from .models import Host, Inventory, SshUser


def _secret(auth: Any, key: str) -> str:
    if auth.type == "password":
        return auth.password or ""
    path = Path(auth.generated_private_key).expanduser() if auth.generated_private_key else None
    if not path or not path.is_file():
        raise ValueError(f"Private key for {key} is unavailable: {path}")
    return path.read_text(encoding="utf-8")


def _profile_id(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"dev.megaproxy.server/{name}"))


def _profile(name: str, proxy: dict[str, Any], color: int) -> dict[str, Any]:
    return {
        "id": _profile_id(name), "name": name, "color": color, "countryCode": "",
        "proxy": proxy,
        "tls": {"fingerprint": "DEFAULT", "customJa3": ""},
        "dns": {"provider": "CLOUDFLARE", "customDohUrl": ""},
        "routing": {"routeAllApps": True, "selectedPackages": [], "allowIpv6": False, "bypassLocalNetworks": True},
    }


def _ssh_proxy(host_name: str, host: Host, user: SshUser, kind: str = "SSH") -> dict[str, Any]:
    auth = user.authentication
    result: dict[str, Any] = {"type": kind, "host": host.address, "port": host.services.ssh.port, "username": user.name, "allowInvalidProxyCertificate": False, "sshProfile": "DEFAULT", "trustedHostKey": "", "acceptAnyHostKey": False}
    result["password" if auth.type == "password" else "privateKey"] = _secret(auth, f"{host_name}/{user.name}")
    return result


def _ssh_endpoints(inventory: Inventory) -> list[tuple[str, Host, SshUser]]:
    result = []
    for host_name, host in inventory.hosts.items():
        if host.services.ssh and host.services.ssh.enabled:
            result.extend((host_name, host, user) for user in host.services.ssh.users)
    return result


def jump_candidates(inventory: Inventory) -> list[dict[str, Any]]:
    """Build every directed pair at runtime; no jump pairs live in inventory."""
    chains = []
    endpoints = _ssh_endpoints(inventory)
    for dst_name, _, dst_user in endpoints:
        for jump_name, _, jump_user in endpoints:
            if dst_name != jump_name:
                chains.append({"name": f"{jump_name}/{jump_user.name} -> {dst_name}/{dst_user.name}", "destination": dst_name, "destinationUser": dst_user.name, "jump": jump_name, "jumpUser": jump_user.name})
    return chains


def _jump_profiles(inventory: Inventory, start_color: int) -> list[dict[str, Any]]:
    profiles = []
    endpoints = _ssh_endpoints(inventory)
    for dst_name, dst, dst_user in endpoints:
        for jump_name, jump, jump_user in endpoints:
            if dst_name == jump_name:
                continue
            name = f"{jump_name}/{jump_user.name} -> {dst_name}/{dst_user.name}"
            proxy = _ssh_proxy(dst_name, dst, dst_user, "SSH_JUMP")
            jump_auth = jump_user.authentication
            jump_data = {"host": jump.address, "port": jump.services.ssh.port, "sameAuthentication": False, "username": jump_user.name, "trustedHostKey": "", "acceptAnyHostKey": False, "password" if jump_auth.type == "password" else "privateKey": _secret(jump_auth, f"{jump_name}/{jump_user.name}")}
            proxy["jump"] = jump_data
            profiles.append(_profile(name, proxy, start_color + len(profiles)))
    return profiles


def export_profiles(inventory: Inventory, output: Path, include_all_jumps: bool = False) -> None:
    profiles: list[dict[str, Any]] = []
    for host_name, host in inventory.hosts.items():
        https = host.services.https
        if https and https.enabled:
            for route in https_routes(inventory, host_name):
                for user in https.users:
                    title = route["title"] if route["name"] != "direct" or https.title else host_name
                    name = f"{title} / {user.name}"
                    proxy = {"type": "HTTPS", "host": route["hostname"], "port": https.port, "username": user.name, "password": user.password, "allowInvalidProxyCertificate": https.certificate == "self-signed", "sshProfile": "DEFAULT", "trustedHostKey": "", "acceptAnyHostKey": False}
                    profiles.append(_profile(name, proxy, len(profiles)))
        if host.services.ssh and host.services.ssh.enabled:
            for user in host.services.ssh.users:
                name = f"{host_name} / {user.name}"
                profiles.append(_profile(name, _ssh_proxy(host_name, host, user), len(profiles)))
    if include_all_jumps:
        profiles.extend(_jump_profiles(inventory, len(profiles)))
    result = {"schema": "net.megaproxy487.config", "version": 7, "passwordsIncluded": True, "privateKeysIncluded": True, "diagnosticLogLimitMb": 3, "tls": {"fingerprint": "DEFAULT", "customJa3": ""}, "ssh": {"fingerprint": "DEFAULT", "authMode": "AUTO", "keepaliveSeconds": 30, "maxChannels": 32, "rotationMinutes": 0, "rotationMb": 0}, "failover": {"mode": "DISABLED", "profileIds": []}, "routing": {"routeAllApps": True, "selectedPackages": [], "bypassLocalNetworks": True}, "profiles": profiles}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    output.chmod(0o600)
