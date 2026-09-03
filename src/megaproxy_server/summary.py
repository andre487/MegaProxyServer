from __future__ import annotations

from typing import Any

from .inventory import https_routes
from .models import Inventory


def _host_lines(inventory: Inventory) -> list[str]:
    endpoints: dict[str, dict[str, Any]] = {}

    def add(hostname: str, title: str, service: str) -> None:
        endpoint = endpoints.setdefault(hostname, {"title": title, "services": []})
        if service not in endpoint["services"]:
            endpoint["services"].append(service)

    for host_name, host in inventory.hosts.items():
        https = host.services.https
        routes = https_routes(inventory, host_name)
        direct = next((route for route in routes if route["name"] == "direct"), None)
        if https and https.enabled and direct:
            add(direct["hostname"], direct["title"], "HTTPS")
        ssh = host.services.ssh
        if ssh and ssh.enabled:
            hostname = https.endpoint if https and https.enabled else host.address
            title = https.title if https and https.enabled and https.title else host_name
            add(hostname, title, "SSH")
        for route in routes:
            if route["name"] != "direct":
                add(route["hostname"], route["title"], "HTTPS")

    return [
        f"{hostname} ({endpoint['title']}, {', '.join(endpoint['services'])})"
        for hostname, endpoint in endpoints.items()
    ]


def render_summary(inventory: Inventory, login: str | None = None) -> str:
    https = [
        f"{user.name}\n{user.password}"
        for user in inventory.users.https
        if login is None or user.name == login
    ]
    ssh = []
    for user in inventory.users.ssh:
        if login is not None and user.name != login:
            continue
        auth = user.authentication
        credential = auth.password if auth.type == "password" else auth.generated_private_key or "<not stored>"
        ssh.append(f"{user.name}\n{credential}")
    if not https and not ssh:
        return ""

    sections = ["Hosts:\n" + "\n".join(_host_lines(inventory))]
    if https:
        sections.append("HTTPS:\n" + "\n\n".join(https))
    if ssh:
        sections.append("SSH:\n" + "\n\n".join(ssh))
    return "\n\n".join(sections) + "\n"
