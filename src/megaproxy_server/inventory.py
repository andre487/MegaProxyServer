from __future__ import annotations

import getpass
import io
import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from .models import Inventory

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = Path.cwd() / "inventory.yml"
POINTER_FILE = Path.cwd() / "inventory-path"
_vault_secret: VaultSecret | None = None


class VaultValue(str):
    pass


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
    content = path.read_bytes()
    if content.startswith(b"$ANSIBLE_VAULT;"):
        content = _vault().decrypt(content)
    yaml = YAML(typ="safe")
    yaml.constructor.add_constructor(
        "!vault",
        lambda loader, node: _vault().decrypt(loader.construct_scalar(node).encode()).decode(),
    )
    raw: Any = yaml.load(content.decode())
    return Inventory.model_validate(raw)


def save(
    path: Path,
    inventory: Inventory,
    *,
    remember_location: bool = False,
    encrypt: bool | None = None,
    vault_password: str | None = None,
) -> None:
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
    stream = io.StringIO()
    yaml.dump(data, stream)
    previous = path.read_bytes() if path.is_file() else b""
    was_encrypted = previous.startswith(b"$ANSIBLE_VAULT;") or b"!vault" in previous
    should_encrypt = was_encrypted if encrypt is None else encrypt
    if should_encrypt:
        secret = VaultSecret(vault_password.encode()) if vault_password is not None else _vault_secret_value()
        vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, secret)])
        _encrypt_secret_fields(data, vault, secret)
        stream = io.StringIO()
        yaml.representer.add_representer(
            VaultValue,
            lambda representer, value: representer.represent_scalar("!vault", str(value), style="|"),
        )
        yaml.dump(data, stream)
    path.write_text(stream.getvalue(), encoding="utf-8")
    os.chmod(path, 0o600)
    if remember_location:
        remember(path)


def _vault_secret_value() -> VaultSecret:
    global _vault_secret
    if _vault_secret is not None:
        return _vault_secret
    password_file = os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
    if password_file:
        password = Path(password_file).expanduser().read_text(encoding="utf-8").strip()
    else:
        password = getpass.getpass("Ansible Vault password: ")
    _vault_secret = VaultSecret(password.encode())
    return _vault_secret


def _vault() -> VaultLib:
    return VaultLib([(DEFAULT_VAULT_ID_MATCH, _vault_secret_value())])


def _encrypt_secret_fields(data: dict[str, Any], vault: VaultLib, secret: VaultSecret) -> None:
    def encrypted(value: str) -> VaultValue:
        return VaultValue(vault.encrypt(value, secret).decode())

    for user in data.get("users", {}).get("https", []):
        user["password"] = encrypted(user["password"])
    for user in data.get("users", {}).get("ssh", []):
        authentication = user["authentication"]
        for key in ("password", "password_hash"):
            if authentication.get(key):
                authentication[key] = encrypted(authentication[key])
    for host in data.get("hosts", {}).values():
        https = host.get("services", {}).get("https")
        if https and https.get("chain_password"):
            https["chain_password"] = encrypted(https["chain_password"])


def https_routes(inventory: Inventory, name: str) -> list[dict[str, Any]]:
    host = inventory.hosts[name]
    https = host.services.https
    if not https or not https.enabled:
        return []
    routes: list[dict[str, Any]] = []
    entry_title = https.title or _host_title(name)
    if https.direct:
        routes.append({"name": "direct", "hostname": https.endpoint, "title": entry_title, "country_code": name.split("_", 1)[0].upper(), "port": inventory.settings.https_chain_backend_port, "chain": None})
    if inventory.settings.https_chains_enabled and https.chain_entry:
        configured_pairs = [pair for pair in inventory.settings.https_chain_pairs if pair.entry == name]
        allowed_exits = {pair.exit for pair in configured_pairs} if inventory.settings.https_chain_pairs else None
        pair_hostnames = {pair.exit: pair.hostname for pair in configured_pairs}
        pair_titles = {pair.exit: pair.title for pair in configured_pairs}
        pair_country_codes = {pair.exit: pair.country_code for pair in configured_pairs}
        exits = [
            (exit_name, exit_host.services.https)
            for exit_name, exit_host in sorted(inventory.hosts.items())
            if exit_name != name and exit_host.services.https and exit_host.services.https.enabled and exit_host.services.https.chain_exit
            and (allowed_exits is None or exit_name in allowed_exits)
        ]
        for index, (exit_name, exit_https) in enumerate(exits, start=len(routes)):
            routes.append({
                "name": f"via-{exit_name}",
                "hostname": pair_hostnames.get(exit_name) or f"{_dns_label(name)}-via-{_dns_label(exit_name)}.{inventory.settings.https_chain_domain}",
                "title": pair_titles.get(exit_name) or entry_title,
                "country_code": pair_country_codes.get(exit_name) or exit_name.split("_", 1)[0].upper(),
                "port": inventory.settings.https_chain_backend_port + index,
                "chain": {"host": exit_https.endpoint, "port": exit_https.port, "username": exit_https.chain_username, "password": exit_https.chain_password},
            })
    return routes


def _dns_label(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")


def _host_title(name: str) -> str:
    parts = name.split("_")
    if parts[-1:] == ["proxy"]:
        parts.pop()
    return " ".join([parts[0].upper(), *(part.title() for part in parts[1:])])


def ansible_inventory(inventory: Inventory) -> dict[str, Any]:
    hosts: dict[str, Any] = {}
    public_https_hosts: list[dict[str, Any]] = []
    for name, host in inventory.hosts.items():
        services = host.services.model_dump(mode="json", exclude_none=True)
        routes: list[dict[str, Any]] = []
        https = host.services.https
        if https and https.enabled:
            routes = https_routes(inventory, name)
            services["https"]["routes"] = routes
            variables_public_routes = [
                {"name": route["name"], "hostname": route["hostname"], "port": https.port, "backend_port": route["port"]}
                for route in routes
            ]
            services["https"]["machine_auth"] = (
                {"username": https.chain_username, "password": https.chain_password}
                if inventory.settings.https_chains_enabled and https.chain_exit else None
            )
            for route in routes:
                public_https_hosts.append(
                    {
                        "name": name if route["name"] == "direct" else f"{name}_{route['name']}",
                        "host": route["hostname"],
                        "port": https.port,
                        "code": route["country_code"],
                        "title": route["title"],
                    }
                )
        variables: dict[str, Any] = {
            "ansible_host": host.address,
            "ansible_user": host.admin.bootstrap_user or host.admin.user,
            "ansible_port": host.admin.port,
            "megaproxy_admin": host.admin.model_dump(mode="json", exclude_none=True),
            "megaproxy_settings": inventory.settings.model_dump(mode="json"),
            "megaproxy_services": services,
        }
        if https and https.enabled:
            variables["megaproxy_https_public_routes"] = variables_public_routes
        variables["ansible_ssh_private_key_file"] = host.admin.private_key_file
        if host.services.https:
            try:
                ipaddress.ip_address(host.services.https.endpoint)
                variables["megaproxy_https_san_type"] = "IP"
            except ValueError:
                variables["megaproxy_https_san_type"] = "DNS"
        hosts[name] = variables
    return {
        "all": {
            "vars": {
                "megaproxy_users": inventory.users.model_dump(mode="json"),
                "megaproxy_public_https_hosts": public_https_hosts,
            },
            "hosts": hosts,
        }
    }


def write_ansible_inventory(source: Path, inventory: Inventory) -> Path:
    target = ROOT / ".generated" / f"{source.stem}.ansible.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    yaml = YAML()
    with target.open("w", encoding="utf-8") as stream:
        yaml.dump(ansible_inventory(inventory), stream)
    os.chmod(target, 0o600)
    return target
