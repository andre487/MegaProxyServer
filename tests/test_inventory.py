from pathlib import Path

import json

from megaproxy_server.export import export_profiles, jump_candidates
from megaproxy_server.inventory import ansible_inventory, load, save
from megaproxy_server.models import AdminAccess, Host, Inventory, Services, SshAuthentication, SshService, SshUser


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
    assert data["schema"] == "dev.megaproxy.config"
    assert data["version"] == 6
    assert [item["proxy"]["type"] for item in data["profiles"]].count("SSH_JUMP") == 8
