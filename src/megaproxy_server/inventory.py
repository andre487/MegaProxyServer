from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .models import Inventory

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = Path.cwd() / "inventory.yml"
POINTER_FILE = Path.cwd() / "inventory-path"


def discover(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit).expanduser().resolve()
    if POINTER_FILE.is_file():
        value = POINTER_FILE.read_text(encoding="utf-8").strip()
        if value:
            return Path(value).expanduser().resolve()
    if DEFAULT_INVENTORY.is_file():
        return DEFAULT_INVENTORY.resolve()
    return None


def remember(path: Path) -> None:
    path = path.resolve()
    if path != DEFAULT_INVENTORY.resolve():
        POINTER_FILE.write_text(f"{path}\n", encoding="utf-8")
        os.chmod(POINTER_FILE, 0o600)


def load(path: Path) -> Inventory:
    yaml = YAML(typ="safe")
    with path.open(encoding="utf-8") as stream:
        raw: Any = yaml.load(stream)
    return Inventory.model_validate(raw)


def save(path: Path, inventory: Inventory, *, remember_location: bool = False) -> None:
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = inventory.model_dump(mode="json", exclude_none=True)
    for host in data["hosts"].values():
        if host["services"].get("https"):
            host["services"]["https"].pop("users", None)
        if host["services"].get("ssh"):
            host["services"]["ssh"].pop("users", None)
            host["services"]["ssh"].pop("removed_users", None)
    with path.open("w", encoding="utf-8") as stream:
        yaml.dump(data, stream)
    os.chmod(path, 0o600)
    if remember_location:
        remember(path)


def https_routes(inventory: Inventory, name: str) -> list[dict[str, Any]]:
    host = inventory.hosts[name]
    https = host.services.https
    if not https or not https.enabled:
        return []
    routes: list[dict[str, Any]] = [
        {"name": "direct", "hostname": https.endpoint, "port": inventory.settings.https_chain_backend_port, "chain": None}
    ]
    if inventory.settings.https_chains_enabled and https.chain_entry:
        exits = [
            (exit_name, exit_host.services.https)
            for exit_name, exit_host in sorted(inventory.hosts.items())
            if exit_name != name and exit_host.services.https and exit_host.services.https.enabled and exit_host.services.https.chain_exit
        ]
        for index, (exit_name, exit_https) in enumerate(exits, start=1):
            routes.append({
                "name": f"via-{exit_name}",
                "hostname": f"{_dns_label(name)}-via-{_dns_label(exit_name)}.{inventory.settings.https_chain_domain}",
                "port": inventory.settings.https_chain_backend_port + index,
                "chain": {"host": exit_https.endpoint, "port": exit_https.port, "username": exit_https.chain_username, "password": exit_https.chain_password},
            })
    return routes


def _dns_label(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")


def ansible_inventory(inventory: Inventory) -> dict[str, Any]:
    hosts: dict[str, Any] = {}
    for name, host in inventory.hosts.items():
        services = host.services.model_dump(mode="json", exclude_none=True)
        routes: list[dict[str, Any]] = []
        https = host.services.https
        if https and https.enabled:
            routes = https_routes(inventory, name)
            services["https"]["routes"] = routes
            services["https"]["machine_auth"] = (
                {"username": https.chain_username, "password": https.chain_password}
                if inventory.settings.https_chains_enabled and https.chain_exit else None
            )
        variables: dict[str, Any] = {
            "ansible_host": host.address,
            "ansible_user": host.admin.bootstrap_user or host.admin.user,
            "ansible_port": host.admin.port,
            "megaproxy_admin": host.admin.model_dump(mode="json", exclude_none=True),
            "megaproxy_settings": inventory.settings.model_dump(mode="json"),
            "megaproxy_services": services,
        }
        variables["ansible_ssh_private_key_file"] = host.admin.private_key_file
        if host.services.https:
            try:
                ipaddress.ip_address(host.services.https.endpoint)
                variables["megaproxy_https_san_type"] = "IP"
            except ValueError:
                variables["megaproxy_https_san_type"] = "DNS"
        hosts[name] = variables
    return {"all": {"hosts": hosts}}


def write_ansible_inventory(source: Path, inventory: Inventory) -> Path:
    target = ROOT / ".generated" / f"{source.stem}.ansible.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    yaml = YAML()
    with target.open("w", encoding="utf-8") as stream:
        yaml.dump(ansible_inventory(inventory), stream)
    os.chmod(target, 0o600)
    return target
