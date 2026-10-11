import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment
from ruamel.yaml import YAML

from megaproxy_server import inventory as inventory_module, wizard
from megaproxy_server.bootstrap import validate_admin_key
from megaproxy_server.config_bundle import validate_config
from megaproxy_server.export import export_profiles
from megaproxy_server.inventory import ROOT, load, save
from megaproxy_server.models import Inventory
from megaproxy_server.secrets import generate_key


@pytest.fixture
def raw_inventory():
    return {"users": {
        "https": [{"name": "alice", "password": "synthetic-test-password"}],
        "ssh": [{"name": "mp-alice", "authentication": {
            "type": "password", "password": "synthetic-ssh-password", "password_hash": "$6$test"}}]},
        "hosts": {"one": {"address": "192.0.2.1",
            "admin": {"user": "deploy", "private_key_file": "/unused", "public_key": "ssh-ed25519 TEST"},
            "services": {"https": {"title": "ONE", "endpoint": "one.example", "certificate": "self-signed"},
                         "ssh": {"title": "ONE", "generate_profile": True}}}}}


@pytest.mark.parametrize("login", ["deploy", "root", "ubuntu", "first-admin", "../victim", "bad user"])
def test_removal_rejects_administrators_and_invalid_logins(raw_inventory, login):
    raw_inventory["hosts"]["one"]["admin"]["bootstrap_user"] = "first-admin"
    raw_inventory["users"]["removed_ssh"] = [login]
    with pytest.raises(ValueError):
        Inventory.model_validate(raw_inventory)


@pytest.mark.parametrize("port", [443, 10443, 18080])
def test_https_ports_cannot_conflict_with_administrative_ssh(raw_inventory, port):
    raw_inventory["hosts"]["one"]["admin"]["port"] = port
    raw_inventory["hosts"]["one"]["services"]["https"]["probe_resistance"] = {"enabled": True}
    with pytest.raises(ValueError, match="port.*conflicts"):
        Inventory.model_validate(raw_inventory)


def test_routes_must_exist_and_backend_ports_must_fit(raw_inventory):
    source = deepcopy(raw_inventory)
    raw_inventory["hosts"]["one"]["services"]["https"]["direct"] = False
    with pytest.raises(ValueError, match="at least one route"):
        Inventory.model_validate(raw_inventory)
    source["hosts"]["one"]["services"]["https"].update(
        certificate="domain", acme_email="test@example.com", chain_entry=True)
    source["hosts"]["two"] = deepcopy(source["hosts"]["one"])
    source["hosts"]["two"]["services"]["https"].update(
        endpoint="two.example", chain_entry=False, chain_exit=True, chain_password="chain-secret")
    source["settings"] = {"https_chains_enabled": True, "https_chain_domain": "chain.example",
        "https_chain_backend_port": 65535,
        "https_chain_pairs": [{"entry": "one", "exit": "two", "title": "CHAIN", "country_code": "US"}]}
    with pytest.raises(ValueError, match="65536"):
        Inventory.model_validate(source)


@pytest.mark.parametrize("service", ["ssh", "https"])
def test_disabled_only_host_can_be_kept_for_teardown(raw_inventory, service):
    raw_inventory["hosts"]["one"]["services"] = {service: raw_inventory["hosts"]["one"]["services"][service]}
    raw_inventory["hosts"]["one"]["services"][service]["enabled"] = False
    Inventory.model_validate(raw_inventory)


def test_export_validates_before_replacing_file_and_normalizes_country(raw_inventory, tmp_path):
    source = Inventory.model_validate(raw_inventory)
    target = tmp_path / "export.json"
    export_profiles(source, target)
    document = json.loads(target.read_text())
    assert document["profiles"][0]["countryCode"] == ""
    validate_config(document, allow_legacy=True)
    before = target.read_bytes()
    source.hosts["one"].services.https.title = "x" * 300
    with pytest.raises(ValueError, match="name"):
        export_profiles(source, target)
    assert target.read_bytes() == before


def test_inventory_write_failure_keeps_previous_file(raw_inventory, tmp_path, monkeypatch):
    target = tmp_path / "inventory.yml"
    source = Inventory.model_validate(raw_inventory)
    save(target, source)
    before = target.read_bytes()
    def fail_replace(temporary, destination):
        assert Path(temporary).stat().st_mode & 0o777 == 0o600
        assert destination == target
        raise OSError("synthetic write failure")
    monkeypatch.setattr(inventory_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic"):
        save(target, source)
    assert target.read_bytes() == before
    assert list(tmp_path.iterdir()) == [target]
    assert load(target) == source


def test_ssh_only_wizard_publishes_selected_direct_profiles(raw_inventory, tmp_path, monkeypatch):
    answers = {"Inventory host name (for example proxy_eu)": "one",
        "Public IP address or DNS name": "192.0.2.1",
        "Permanent administrative user to create or update": "deploy",
        "Administrative SSH port": "22", "SSH proxy port": "22", "SSH profile title": "ONE"}
    def question(value):
        return SimpleNamespace(ask=lambda: value)
    monkeypatch.setattr(wizard, "ask_required", lambda message, default=None: answers[message])
    monkeypatch.setattr(wizard.questionary, "select", lambda *a, **k: question("Generate a dedicated key"))
    monkeypatch.setattr(wizard.questionary, "checkbox", lambda *a, **k: question(["ssh"]))
    monkeypatch.setattr(wizard.questionary, "confirm", lambda message, **k: question(message.startswith("Publish direct SSH")))
    monkeypatch.setattr(wizard, "generate_key", lambda *a: ("ssh-ed25519 TEST", Path("/unused")))
    monkeypatch.setattr(wizard, "ask_users", lambda *a: Inventory.model_validate(raw_inventory).users.ssh)
    monkeypatch.setattr(wizard, "save", lambda *a, **k: None)
    source = wizard.create_inventory(tmp_path / "inventory.yml", local=True)
    export_profiles(source, tmp_path / "export.json")
    assert [p["proxy"]["type"] for p in json.loads((tmp_path / "export.json").read_text())["profiles"]] == ["SSH"]


def run_tasks(tasks, tmp_path):
    playbook = tmp_path / "tasks.yml"
    with playbook.open("w") as stream:
        YAML().dump([{"hosts": "all", "gather_facts": False, "tasks": tasks}], stream)
    environment = dict(os.environ, ANSIBLE_REMOTE_TEMP=str(tmp_path / "remote"))
    environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment["PATH"]
    return subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)],
                          cwd=ROOT, env=environment, capture_output=True, text=True)


def test_administrative_key_rotation_revokes_previous_key(tmp_path):
    target = tmp_path / "authorized_keys"
    target.write_text("ssh-ed25519 OLD\n")
    task = next(t for t in YAML(typ="safe").load((ROOT / "roles/admin/tasks/account.yml").read_text())
                if t["name"] == "Replace verified administrative public key")
    task["ansible.builtin.copy"].update(dest=str(target), content="ssh-ed25519 NEW\n")
    task["ansible.builtin.copy"].pop("owner")
    result = run_tasks([task], tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.read_text() == "ssh-ed25519 NEW\n"


def test_controller_key_must_match_new_administrative_public_key(raw_inventory, tmp_path):
    old_public, old_key = generate_key(tmp_path / "old-admin", "old")
    new_public, new_key = generate_key(tmp_path / "new-admin", "new")
    source = Inventory.model_validate(raw_inventory)
    host = source.hosts["one"]
    host.admin.private_key_file = str(old_key)
    host.admin.public_key = new_public
    with pytest.raises(ValueError, match="must match"):
        validate_admin_key(host)
    host.admin.public_key = old_public
    validate_admin_key(host)
    host.admin.public_key = new_public
    host.admin.private_key_file = str(new_key)
    host.admin.bootstrap_private_key_file = str(old_key)
    validate_admin_key(host)


def test_unmanaged_account_is_rejected_before_destructive_tasks(tmp_path):
    tasks = YAML(typ="safe").load((ROOT / "roles/ssh_proxy/tasks/validate_accounts.yml").read_text())
    variables = {"megaproxy_admin": {"user": "deploy"},
        "megaproxy_services": {"ssh": {"users": [], "removed_users": ["other-user"]}}}
    for task in tasks:
        task["vars"] = variables
    # Replace only the OS lookup boundary; execute the actual guard before deletion.
    for task in tasks:
        if "ansible.builtin.command" in task and task["ansible.builtin.command"]["argv"][0] == "id":
            task["ansible.builtin.command"]["argv"] = ["echo", "other-group"]
    marker = tmp_path / "deleted"
    tasks.append({"ansible.builtin.copy": {"dest": str(marker), "content": "unsafe"}})
    result = run_tasks(tasks, tmp_path)
    assert result.returncode != 0
    assert "Refusing to modify existing non-proxy account" in result.stdout
    assert not marker.exists()


def test_docker_cleanup_keeps_unrelated_resources(tmp_path):
    docker = tmp_path / "docker"
    calls = tmp_path / "calls.jsonl"
    docker.write_text(f'''#!{sys.executable}
import json, sys
with open({str(calls)!r}, "a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["inspect"]:
    print("keep-gost")
elif sys.argv[1:3] == ["image", "inspect"]:
    print("keep-certbot")
elif sys.argv[1:3] == ["image", "ls"]:
    print("keep-gost gogost/gost\\nold-gost gogost/gost\\nkeep-certbot certbot/certbot\\nother other/project")
''')
    docker.chmod(0o755)
    content = Environment().from_string((ROOT / "roles/https_proxy/templates/megaproxy-docker-clean.sh.j2").read_text()).render(
        megaproxy_services={"https": {"certbot_version": "test"}})
    result = subprocess.run(["sh"], input=content, text=True, capture_output=True,
                            env=dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"]))
    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert ["image", "rm", "old-gost"] in commands
    assert not any("prune" in command or "other" in command for command in commands)
