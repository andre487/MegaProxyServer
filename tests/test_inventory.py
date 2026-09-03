from pathlib import Path

import json

from megaproxy_server.export import export_profiles, jump_candidates
from megaproxy_server.inventory import ansible_inventory, https_routes, load, save
from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services, Settings, SshAuthentication, SshService, SshUser


def ssh_host(address: str, user: str = "mp-proxy") -> Host:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    return Host(address=address, admin=admin, services=Services(ssh=SshService(users=[SshUser(name=user, authentication=SshAuthentication(type="key", public_key="ssh-ed25519 AAAA test"))])))


def test_round_trip_and_ansible_projection(tmp_path: Path) -> None:
    path = tmp_path / "inventory.yml"
    source = Inventory(hosts={"one": ssh_host("192.0.2.1")})
    save(path, source)
    loaded = load(path)
    assert loaded == source
    assert ansible_inventory(loaded)["all"]["hosts"]["one"]["ansible_host"] == "192.0.2.1"
    saved = path.read_text(encoding="utf-8")
    assert "users:\n  https:" in saved
    assert saved.count("users:") == 1


def test_bootstrap_user_is_used_until_promotion() -> None:
    host = ssh_host("192.0.2.1")
    host.admin.bootstrap_user = "root"
    projected = ansible_inventory(Inventory(hosts={"one": host}))["all"]["hosts"]["one"]
    assert projected["ansible_user"] == "root"
    assert projected["megaproxy_admin"]["user"] == "deploy"


def test_encrypted_inventory_stays_encrypted_after_save(tmp_path: Path, monkeypatch) -> None:
    import megaproxy_server.inventory as inventory_module

    password_file = tmp_path / "vault-password"
    password_file.write_text("test-vault-password\n", encoding="utf-8")
    monkeypatch.setenv("ANSIBLE_VAULT_PASSWORD_FILE", str(password_file))
    inventory_module._vault_secret = None
    path = tmp_path / "inventory.yml"
    host = ssh_host("192.0.2.1")
    host.services.ssh.users = [SshUser(name="mp-password", authentication=SshAuthentication(type="password", password="long-password-value", password_hash="$6$long-password-hash"))]
    source = Inventory(hosts={"one": host})
    save(path, source, encrypt=True)
    content = path.read_text(encoding="utf-8")
    assert not content.startswith("$ANSIBLE_VAULT;")
    assert "hosts:" in content
    assert "!vault" in content
    assert "long-password-value" not in content
    loaded = load(path)
    save(path, loaded)
    assert b"!vault" in path.read_bytes()
    assert load(path) == source


def test_jump_candidates_are_all_directed_host_pairs() -> None:
    inventory = Inventory(hosts={"one": ssh_host("192.0.2.1", "a"), "two": ssh_host("192.0.2.2", "b"), "three": ssh_host("192.0.2.3", "c")})
    chains = jump_candidates(inventory)
    assert len(chains) == 54
    assert "one/a -> two/b" in {chain["name"] for chain in chains}
    assert "three/c -> one/a" in {chain["name"] for chain in chains}


def test_same_host_is_never_a_jump_pair() -> None:
    inventory = Inventory(hosts={"one": ssh_host("192.0.2.1")})
    assert jump_candidates(inventory) == []


def test_export_uses_megaproxy_schema_and_dynamic_jump_profiles(tmp_path: Path) -> None:
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n", encoding="utf-8")
    inventory = Inventory(hosts={"one": ssh_host("192.0.2.1", "a"), "two": ssh_host("192.0.2.2", "b")})
    for host in inventory.hosts.values():
        for user in host.services.ssh.users:
            user.authentication.generated_private_key = str(key)
    output = tmp_path / "profiles.json"
    export_profiles(inventory, output, include_all_jumps=True)
    data = json.loads(output.read_text())
    assert data["schema"] == "net.megaproxy487.config"
    assert data["version"] == 7
    assert [item["proxy"]["type"] for item in data["profiles"]].count("SSH_JUMP") == 8


def test_https_sni_routes_are_generated_for_every_exit() -> None:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    user = HttpsUser(name="alice", password="long-password-alice")
    hosts = {
        "proxy_ru": Host(address="ru.example", admin=admin, services=Services(https=HttpsService(endpoint="ru.example", certificate="domain", acme_email="a@example.com", users=[user], chain_entry=True))),
        "proxy_nl": Host(address="nl.example", admin=admin, services=Services(https=HttpsService(endpoint="nl.example", certificate="domain", acme_email="a@example.com", users=[user], chain_exit=True, chain_password="machine-password-long"))),
    }
    inventory = Inventory(
        settings=Settings(
            https_chains_enabled=True,
            https_chain_domain="chains.example",
            https_chain_pairs=[
                {"entry": "proxy_ru", "exit": "proxy_nl", "country_code": "NL", "title": "Russia via Netherlands"}
            ],
        ),
        hosts=hosts,
    )
    routes = https_routes(inventory, "proxy_ru")
    assert [route["hostname"] for route in routes] == ["ru.example", "proxy-ru-via-proxy-nl.chains.example"]
    assert [route["title"] for route in routes] == ["PROXY Ru", "Russia via Netherlands"]
    projected = ansible_inventory(inventory)["all"]["hosts"]["proxy_ru"]["megaproxy_services"]["https"]
    assert projected["routes"][1]["chain"]["host"] == "nl.example"
    public_hosts = ansible_inventory(inventory)["all"]["vars"]["megaproxy_public_https_hosts"]
    assert public_hosts == [
        {"name": "proxy_ru", "host": "ru.example", "port": 443, "code": "PROXY", "title": "PROXY Ru"},
        {
            "name": "proxy_ru_via-proxy_nl",
            "host": "proxy-ru-via-proxy-nl.chains.example",
            "port": 443,
            "code": "NL",
            "title": "Russia via Netherlands",
        },
        {"name": "proxy_nl", "host": "nl.example", "port": 443, "code": "PROXY", "title": "PROXY Nl"},
    ]
    assert ansible_inventory(inventory)["all"]["vars"]["megaproxy_users"]["https"][0]["name"] == "alice"


def test_https_chain_title_falls_back_to_entry_title() -> None:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    user = HttpsUser(name="alice", password="long-password-alice")
    hosts = {
        "proxy_ru": Host(address="ru.example", admin=admin, services=Services(https=HttpsService(endpoint="ru.example", title="Russia Entry", certificate="domain", acme_email="a@example.com", users=[user], chain_entry=True))),
        "proxy_nl": Host(address="nl.example", admin=admin, services=Services(https=HttpsService(endpoint="nl.example", certificate="domain", acme_email="a@example.com", users=[user], chain_exit=True, chain_password="machine-password-long"))),
    }
    inventory = Inventory(settings=Settings(https_chains_enabled=True, https_chain_domain="chains.example"), hosts=hosts)

    assert [route["title"] for route in https_routes(inventory, "proxy_ru")] == [
        "Russia Entry",
        "Russia Entry",
    ]
