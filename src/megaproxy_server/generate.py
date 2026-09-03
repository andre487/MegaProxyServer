from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import quote, urlencode

from .export import export_profiles
from .inventory import https_routes, load
from .models import Inventory

COLORS = ["#b9c6f6", "#eef209", "#3100f1", "#8b0000", "#00ced1", "#0f98cf"]


def https_entries(inventory: Inventory) -> list[dict[str, object]]:
    entries = []
    for host_name, host in inventory.hosts.items():
        service = host.services.https
        if not service or not service.enabled:
            continue
        for route in https_routes(inventory, host_name):
            for user in service.users:
                suffix = "" if route["name"] == "direct" else f" / {route['name']}"
                entries.append({"title": f"{host_name}{suffix} / {user.name}", "host": route["hostname"], "port": service.port, "username": user.name, "password": user.password})
    return entries


def proxy_url(entry: dict[str, object]) -> str:
    host = str(entry["host"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = f"{quote(str(entry['username']), safe='')}:{quote(str(entry['password']), safe='')}@{host}"
    port = "" if entry["port"] == 443 else f":{entry['port']}"
    return f"https://{authority}{port}?{urlencode({'title': entry['title']})}"


def render_foxy_proxy(entries: list[dict[str, object]]) -> str:
    data = []
    for index, entry in enumerate(entries):
        data.append({"active": True, "title": entry["title"], "type": "https", "hostname": entry["host"], "port": str(entry["port"]), "username": entry["username"], "password": entry["password"], "cc": "", "city": "", "color": COLORS[index % len(COLORS)], "pac": "", "pacString": "", "proxyDNS": True, "include": [], "exclude": []})
    mode = f"{entries[0]['host']}:{entries[0]['port']}" if entries else "pattern"
    root = {"mode": mode, "sync": False, "autoBackup": False, "passthrough": "", "theme": "", "container": {"incognito": "", "container-1": "", "container-2": "", "container-3": "", "container-4": ""}, "commands": {"setProxy": "", "setTabProxy": "", "quickAdd": ""}, "data": data}
    return json.dumps(root, indent=2) + "\n"


def render_proxy_list(entries: list[dict[str, object]]) -> str:
    return "".join(f"{proxy_url(entry)}\n" for entry in entries)


def render_super_proxy(entries: list[dict[str, object]]) -> str:
    lines = ["# superproxy:proxylist:v1"]
    lines.extend(proxy_url(entry) for entry in entries)
    return "\n".join(lines) + "\n"


def write_if_changed(path: Path, content: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return True


def generate(inventory_path: Path, output_dir: Path) -> bool:
    inventory = load(inventory_path)
    entries = https_entries(inventory)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    changed = False
    megaproxy = output_dir / "MegaProxy.json"
    previous = megaproxy.read_text(encoding="utf-8") if megaproxy.is_file() else None
    export_profiles(inventory, megaproxy, include_all_jumps=True)
    changed |= previous != megaproxy.read_text(encoding="utf-8")
    changed |= write_if_changed(output_dir / "FoxyProxy.json", render_foxy_proxy(entries))
    changed |= write_if_changed(output_dir / "SuperProxy.txt", render_super_proxy(entries))
    changed |= write_if_changed(output_dir / "ProxyList.txt", render_proxy_list(entries))
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    changed = generate(args.inventory.resolve(), args.output_dir.resolve())
    print(json.dumps({"changed": changed, "output_dir": str(args.output_dir.resolve())}))


if __name__ == "__main__":
    main()
