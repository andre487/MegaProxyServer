from __future__ import annotations

import getpass
import ipaddress
from pathlib import Path

import questionary

from .inventory import DEFAULT_INVENTORY, save
from .models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, ProbeResistance, Services, SshAuthentication, SshService, SshUser
from .secrets import generate_key, password_hash, public_key, random_password


def ask_required(message: str, default: str | None = None) -> str:
    value = questionary.text(message, default=default or "").ask()
    if value is None:
        raise KeyboardInterrupt
    if not value.strip():
        print("A value is required.")
        return ask_required(message, default)
    return value.strip()


def ask_password(message: str) -> str:
    value = questionary.password(message).ask()
    if value is None:
        raise KeyboardInterrupt
    if len(value) < 16:
        print("Use at least 16 characters.")
        return ask_password(message)
    return value


def ask_users(kind: str, host_name: str, forbidden_names: set[str] | None = None) -> list:
    users = []
    forbidden_names = forbidden_names or set()
    while True:
        suggested = f"proxy-{next(iter(forbidden_names))}" if kind == "SSH" and not users and forbidden_names else None
        name = ask_required(f"{kind} user login", suggested)
        existing_names = {user.name for user in users}
        if name in forbidden_names:
            print(f"{name!r} is the administrative account. Use a separate SSH proxy login.")
            continue
        if name in existing_names:
            print(f"{name!r} has already been added for {kind}.")
            continue
        if kind == "HTTPS":
            generated = questionary.confirm("Generate a strong password?", default=True).ask()
            password = random_password() if generated else ask_password("Password")
            users.append(HttpsUser(name=name, password=password))
            if generated:
                print(f"Generated HTTPS password for {name}: {password}")
        else:
            auth_type = questionary.select("Authentication", choices=["key", "password"]).ask()
            if auth_type == "key":
                source = questionary.select("Private key", choices=["Generate a dedicated key", "Import an existing key"]).ask()
                if source == "Generate a dedicated key":
                    private = Path.cwd() / ".secrets" / "keys" / host_name / name
                    pub, private = generate_key(private, f"MegaProxy {host_name}/{name}")
                    print(f"Private key: {private}")
                else:
                    candidates = sorted(p for p in (Path.home() / ".ssh").glob("*") if p.is_file() and p.suffix != ".pub" and p.name not in {"config", "known_hosts", "authorized_keys"})
                    selected = questionary.select("Choose a private key", choices=[str(p) for p in candidates] + ["Enter another path"]).ask()
                    private = Path(ask_required("Private key path")).expanduser() if selected == "Enter another path" else Path(selected)
                    pub = public_key(private)
                authentication = SshAuthentication(type="key", public_key=pub, generated_private_key=str(private.resolve()))
            else:
                generated = questionary.confirm("Generate a strong password?", default=True).ask()
                password = random_password() if generated else ask_password("Password")
                authentication = SshAuthentication(type="password", password=password, password_hash=password_hash(password))
                if generated:
                    print(f"Generated SSH password for {name}: {password}")
            users.append(SshUser(name=name, authentication=authentication))
        if not questionary.confirm(f"Add another {kind} user?", default=False).ask():
            return users


def create_inventory(path: Path = DEFAULT_INVENTORY) -> Inventory:
    hosts: dict[str, Host] = {}
    global_https_users = None
    global_ssh_users = None
    while True:
        name = ask_required("Inventory host name (for example proxy_eu)")
        address = ask_required("Public IP address or DNS name")
        bootstrap_user = ask_required("Current SSH login used for the first setup", "root")
        admin_user = ask_required("Permanent administrative user to create or update", getpass.getuser())
        existing_proxy_names = {user.name for user in (global_ssh_users or [])}
        while admin_user == "root" or admin_user in existing_proxy_names:
            reason = "cannot be root" if admin_user == "root" else "is already a global SSH proxy login"
            print(f"The permanent administrator {reason}.")
            admin_user = ask_required("Permanent administrative user to create or update", getpass.getuser())
        admin_port = int(ask_required("Administrative SSH port", "22"))
        key_source = questionary.select(
            "Administrative SSH key",
            choices=["Generate a dedicated key", "Import an existing key"],
        ).ask()
        if key_source == "Generate a dedicated key":
            admin_private = Path.cwd() / ".secrets" / "keys" / name / f"admin-{admin_user}"
            admin_public, admin_private = generate_key(admin_private, f"MegaProxy admin {name}/{admin_user}")
            print(f"Administrative private key: {admin_private}")
        else:
            candidates = sorted(
                p for p in (Path.home() / ".ssh").glob("*")
                if p.is_file() and p.suffix != ".pub" and p.name not in {"config", "known_hosts", "authorized_keys"}
            )
            selected = questionary.select(
                "Choose an administrative private key",
                choices=[str(p) for p in candidates] + ["Enter another path"],
            ).ask()
            admin_private = Path(ask_required("Private key path")).expanduser() if selected == "Enter another path" else Path(selected)
            admin_public = public_key(admin_private)
        choices = questionary.checkbox("Services on this host", choices=[questionary.Choice("HTTPS proxy", "https"), questionary.Choice("SSH proxy", "ssh")], validate=lambda selected: bool(selected) or "Select at least one service").ask()
        if choices is None:
            raise KeyboardInterrupt
        https = None
        ssh = None
        if "https" in choices:
            endpoint = ask_required("HTTPS endpoint", address)
            certificate = questionary.select("Certificate type", choices=[questionary.Choice("ACME domain certificate", "domain"), questionary.Choice("ACME public IP certificate", "ip-acme"), questionary.Choice("Self-signed (expert, weaker)", "self-signed")], default="ip-acme" if _is_ip(endpoint) else "domain").ask()
            email = None if certificate == "self-signed" else ask_required("ACME email")
            probe = questionary.confirm("Enable active-probe resistance with a decoy site?", default=True).ask()
            if global_https_users is None:
                print("These HTTPS users will be configured on every HTTPS-enabled host.")
                global_https_users = ask_users("HTTPS", "all-hosts")
            https = HttpsService(endpoint=endpoint, certificate=certificate, acme_email=email, users=global_https_users, probe_resistance=ProbeResistance(enabled=bool(probe), mode="local_decoy" if probe else "disabled"))
        if "ssh" in choices:
            if global_ssh_users is None:
                print("These SSH proxy users will be configured on every SSH-enabled host.")
                global_ssh_users = ask_users("SSH", "all-hosts", {admin_user})
            ssh = SshService(
                port=int(ask_required("SSH proxy port", str(admin_port))),
                users=global_ssh_users,
            )
        hosts[name] = Host(
            address=address,
            admin=AdminAccess(
                user=admin_user,
                bootstrap_user=bootstrap_user if bootstrap_user != admin_user else None,
                port=admin_port,
                private_key_file=str(admin_private.resolve()),
                public_key=admin_public,
            ),
            services=Services(https=https, ssh=ssh),
        )
        if not questionary.confirm("Add another host?", default=False).ask():
            break
    inventory = Inventory(hosts=hosts)
    save(path, inventory, remember_location=True)
    return inventory


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
