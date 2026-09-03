from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator


Port = Annotated[int, Field(ge=1, le=65535)]


class AdminAccess(BaseModel):
    user: str = Field(min_length=1, pattern=r"^[a-z_][a-z0-9_-]*$")
    bootstrap_user: str | None = None
    port: Port = 22
    private_key_file: str
    public_key: str

    @model_validator(mode="after")
    def forbid_root(self) -> AdminAccess:
        if self.user == "root":
            raise ValueError("the permanent administrative user must not be root")
        return self


class HttpsUser(BaseModel):
    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=16)


class ProbeResistance(BaseModel):
    enabled: bool = True
    mode: Literal["local_decoy", "status", "disabled"] = "local_decoy"
    status_code: int = Field(default=404, ge=400, le=599)
    site_title: str = "Personal site"


class HttpsService(BaseModel):
    enabled: bool = True
    endpoint: str
    port: Port = 443
    certificate: Literal["domain", "ip-acme", "self-signed"] = "domain"
    acme_email: str | None = None
    gost_version: str = "3.2.6"
    certbot_version: str = "v5.4.0"
    users: list[HttpsUser] = Field(min_length=1)
    probe_resistance: ProbeResistance = Field(default_factory=ProbeResistance)
    chain_entry: bool = False
    chain_exit: bool = False
    direct: bool = True
    chain_username: str = "megaproxy-chain"
    chain_password: str | None = None

    @model_validator(mode="after")
    def validate_acme(self) -> HttpsService:
        if self.certificate != "self-signed" and not self.acme_email:
            raise ValueError("acme_email is required for domain and IP certificates")
        return self


class SshAuthentication(BaseModel):
    type: Literal["key", "password"]
    public_key: str | None = None
    password_hash: str | None = None
    password: str | None = None
    generated_private_key: str | None = None

    @model_validator(mode="after")
    def validate_material(self) -> SshAuthentication:
        if self.type == "key" and not self.public_key:
            raise ValueError("public_key is required for key authentication")
        if self.type == "password" and (not self.password_hash or not self.password):
            raise ValueError("password and password_hash are required for password authentication")
        return self


class SshUser(BaseModel):
    name: str = Field(min_length=1, pattern=r"^[a-z_][a-z0-9_-]*$")
    authentication: SshAuthentication

    @model_validator(mode="after")
    def dedicated_account(self) -> SshUser:
        reserved = {"root", "admin", "ansible", "ubuntu", "debian", "ec2-user"}
        if self.name in reserved:
            raise ValueError("use a dedicated SSH proxy login, not a system account")
        return self


class SshService(BaseModel):
    enabled: bool = True
    port: Port = 22
    users: list[SshUser] = Field(min_length=1)
    removed_users: list[str] = Field(default_factory=list)
    max_startups: str = "10:30:60"
    per_source_max_startups: int = Field(default=5, ge=1, le=100)
    fail2ban: bool = True


class Services(BaseModel):
    https: HttpsService | None = None
    ssh: SshService | None = None

    @model_validator(mode="after")
    def any_enabled(self) -> Services:
        if not ((self.https and self.https.enabled) or (self.ssh and self.ssh.enabled)):
            raise ValueError("at least one service must be enabled")
        return self


class Host(BaseModel):
    address: str
    admin: AdminAccess = Field(default_factory=AdminAccess)
    services: Services

    @model_validator(mode="after")
    def validate_users(self) -> Host:
        if self.services.https:
            names = [user.name for user in self.services.https.users]
            if len(names) != len(set(names)):
                raise ValueError("HTTPS user names must be unique per host")
        if self.services.ssh:
            names = [user.name for user in self.services.ssh.users]
            if len(names) != len(set(names)):
                raise ValueError("SSH user names must be unique per host")
            if self.admin.user in names:
                raise ValueError("an SSH proxy user must not be the administrative user")
            if set(names) & set(self.services.ssh.removed_users):
                raise ValueError("an SSH proxy user cannot be both present and removed")
        return self


class HttpsChainPair(BaseModel):
    entry: str
    exit: str
    hostname: str | None = None


class Settings(BaseModel):
    manage_firewall: bool = True
    unattended_upgrades: bool = True
    https_chains_enabled: bool = False
    https_chain_domain: str | None = None
    https_chain_backend_port: Port = 10443
    https_chain_pairs: list[HttpsChainPair] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_https_chains(self) -> Settings:
        if self.https_chains_enabled and not self.https_chain_domain:
            raise ValueError("https_chain_domain is required when HTTPS chains are enabled")
        return self


class ProxyUsers(BaseModel):
    https: list[HttpsUser] = Field(default_factory=list)
    ssh: list[SshUser] = Field(default_factory=list)
    removed_ssh: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    version: int = 1
    settings: Settings = Field(default_factory=Settings)
    users: ProxyUsers = Field(default_factory=ProxyUsers)
    hosts: dict[str, Host]

    @model_validator(mode="before")
    @classmethod
    def migrate_and_distribute_users(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        hosts = {
            name: host.model_dump(mode="python") if isinstance(host, BaseModel) else host
            for name, host in data.get("hosts", {}).items()
        }
        data["hosts"] = hosts
        users = data.get("users")
        if isinstance(users, BaseModel):
            users = users.model_dump(mode="python")
            data["users"] = users
        if users is None:
            collected: dict[str, dict[str, Any]] = {"https": {}, "ssh": {}}
            removed: set[str] = set()
            for host in hosts.values():
                services = host.get("services", {})
                for kind in ("https", "ssh"):
                    service = services.get(kind)
                    if not service:
                        continue
                    for user in service.get("users", []):
                        name = user["name"]
                        previous = collected[kind].get(name)
                        if previous is not None and previous != user:
                            raise ValueError(f"conflicting {kind.upper()} credentials for global user {name!r}")
                        collected[kind][name] = user
                    if kind == "ssh":
                        removed.update(service.get("removed_users", []))
            users = {
                "https": list(collected["https"].values()),
                "ssh": list(collected["ssh"].values()),
                "removed_ssh": sorted(removed),
            }
            data["users"] = users
        for host in hosts.values():
            services = host.get("services", {})
            if services.get("https"):
                services["https"]["users"] = users.get("https", [])
            if services.get("ssh"):
                services["ssh"]["users"] = users.get("ssh", [])
                services["ssh"]["removed_users"] = users.get("removed_ssh", [])
        return data

    @model_validator(mode="after")
    def hosts_not_empty(self) -> Inventory:
        if not self.hosts:
            raise ValueError("at least one host is required")
        if any(host.services.https and host.services.https.enabled for host in self.hosts.values()) and not self.users.https:
            raise ValueError("at least one global HTTPS user is required")
        if any(host.services.ssh and host.services.ssh.enabled for host in self.hosts.values()) and not self.users.ssh:
            raise ValueError("at least one global SSH user is required")
        if self.settings.https_chains_enabled:
            https_hosts = [host for host in self.hosts.values() if host.services.https and host.services.https.enabled]
            for host in https_hosts:
                https = host.services.https
                if (https.chain_entry or https.chain_exit) and https.certificate != "domain":
                    raise ValueError("HTTPS chain hosts require domain ACME certificates")
                if https.chain_exit and not https.chain_password:
                    raise ValueError("every HTTPS chain exit requires chain_password")
            for pair in self.settings.https_chain_pairs:
                if pair.entry == pair.exit:
                    raise ValueError("HTTPS chain entry and exit must differ")
                if pair.entry not in self.hosts or pair.exit not in self.hosts:
                    raise ValueError(f"unknown host in HTTPS chain pair {pair.entry!r} -> {pair.exit!r}")
                entry = self.hosts[pair.entry].services.https
                exit_service = self.hosts[pair.exit].services.https
                if not entry or not entry.enabled or not entry.chain_entry:
                    raise ValueError(f"HTTPS chain entry {pair.entry!r} is not enabled as an entry")
                if not exit_service or not exit_service.enabled or not exit_service.chain_exit:
                    raise ValueError(f"HTTPS chain exit {pair.exit!r} is not enabled as an exit")
        return self
