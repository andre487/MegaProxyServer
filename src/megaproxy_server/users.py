from __future__ import annotations

from dataclasses import dataclass

from .models import Inventory


@dataclass(frozen=True)
class UserRef:
    service: str
    login: str

    @property
    def label(self) -> str:
        return f"ALL HOSTS / {self.service} / {self.login}"


def active_users(inventory: Inventory) -> list[UserRef]:
    result: list[UserRef] = []
    result.extend(UserRef("HTTPS", user.name) for user in inventory.users.https)
    result.extend(UserRef("SSH", user.name) for user in inventory.users.ssh)
    return result


def remove_users(inventory: Inventory, selected: list[UserRef]) -> None:
    for ref in selected:
        if ref.service == "HTTPS":
            inventory.users.https = [user for user in inventory.users.https if user.name != ref.login]
        elif ref.service == "SSH":
            inventory.users.ssh = [user for user in inventory.users.ssh if user.name != ref.login]
            if ref.login not in inventory.users.removed_ssh:
                inventory.users.removed_ssh.append(ref.login)
    for host in inventory.hosts.values():
        if host.services.https:
            host.services.https.users = inventory.users.https
        if host.services.ssh:
            host.services.ssh.users = inventory.users.ssh
            host.services.ssh.removed_users = inventory.users.removed_ssh
