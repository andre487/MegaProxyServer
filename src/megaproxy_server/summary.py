from __future__ import annotations

from .models import Inventory


def render_summary(inventory: Inventory, login: str | None = None) -> str:
    blocks: list[str] = []
    for host_name, host in inventory.hosts.items():
        admin = host.admin
        if login is None or admin.user == login:
            blocks.append("\n".join([
                f"Name: MegaProxy Admin — {host_name} — {admin.user}",
                "Type: SSH administration",
                f"Host: {host.address}",
                f"Port: {admin.port}",
                f"Login: {admin.user}",
                "Password: <key authentication>",
                f"Private key: {admin.private_key_file}",
                f"URI: ssh://{host.address}:{admin.port}",
            ]))
        https = host.services.https
        if https and https.enabled:
            for user in https.users:
                if login is not None and user.name != login:
                    continue
                blocks.append("\n".join([
                    f"Name: MegaProxy HTTPS — {host_name} — {user.name}",
                    "Type: HTTPS",
                    f"Host: {https.endpoint}",
                    f"Port: {https.port}",
                    f"Login: {user.name}",
                    f"Password: {user.password}",
                    f"URI: https://{https.endpoint}:{https.port}",
                ]))

        ssh = host.services.ssh
        if ssh and ssh.enabled:
            for user in ssh.users:
                if login is not None and user.name != login:
                    continue
                auth = user.authentication
                lines = [
                    f"Name: MegaProxy SSH — {host_name} — {user.name}",
                    "Type: SSH",
                    f"Host: {host.address}",
                    f"Port: {ssh.port}",
                    f"Login: {user.name}",
                ]
                if auth.type == "password":
                    lines.append(f"Password: {auth.password}")
                else:
                    lines.extend([
                        "Password: <key authentication>",
                        f"Private key: {auth.generated_private_key or '<not stored>'}",
                    ])
                lines.append(f"URI: ssh://{host.address}:{ssh.port}")
                blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + ("\n" if blocks else "")
