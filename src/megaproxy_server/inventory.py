from __future__ import annotations

import ipaddress
import os
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


def ansible_inventory(inventory: Inventory) -> dict[str, Any]:
    hosts: dict[str, Any] = {}
    for name, host in inventory.hosts.items():
        variables: dict[str, Any] = {
            "ansible_host": host.address,
            "ansible_user": host.admin.bootstrap_user or host.admin.user,
            "ansible_port": host.admin.port,
            "megaproxy_admin": host.admin.model_dump(mode="json", exclude_none=True),
            "megaproxy_settings": inventory.settings.model_dump(mode="json"),
            "megaproxy_services": host.services.model_dump(mode="json", exclude_none=True),
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
