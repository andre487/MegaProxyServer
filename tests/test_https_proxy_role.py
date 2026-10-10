from pathlib import Path
import json

from jinja2 import Environment, StrictUndefined
from ruamel.yaml import YAML

from megaproxy_server.models import Inventory, ProbeResistance
from megaproxy_server.inventory import ansible_inventory

ROOT = Path(__file__).resolve().parents[1]


def test_rendered_transports_and_firewall_are_opt_in():
    inv = Inventory.model_validate({"hosts": {"one": {"address": "192.0.2.1",
        "admin": {"user": "deploy", "private_key_file": "/keys/admin", "public_key": "ssh-ed25519 TEST"},
        "services": {"https": {"endpoint": "proxy.example", "certificate": "self-signed",
            "users": [{"name": "alice", "password": "long-test-password"}]}}}}})
    env = Environment(undefined=StrictUndefined)
    env.filters["to_json"] = json.dumps
    def render():
        variables = ansible_inventory(inv)["all"]["hosts"]["one"]
        variables["megaproxy_container_certificate_directory"] = "/certs"
        text = env.from_string((ROOT / "roles/https_proxy/templates/gost.yml.j2").read_text()).render(**variables)
        config = YAML(typ="safe").load(text)
        firewall = YAML(typ="safe").load((ROOT / "roles/firewall/tasks/main.yml").read_text())
        expression = next(task["ansible.builtin.set_fact"]["megaproxy_allowed_udp_ports"] for task in firewall if task.get("name") == "Build optional UDP firewall port list")
        udp = env.from_string(expression).render(**variables)
        return config, udp
    config, udp = render()
    assert len(config["services"]) == 1
    assert udp == "[]"
    service = inv.hosts["one"].services.https
    service.http3 = service.socks5.enabled = True
    config, udp = render()
    assert [s["handler"]["type"] for s in config["services"]] == ["http2", "masque", "socks5"]
    masque = config["services"][1]
    assert masque["listener"]["type"] == "http3"
    assert masque["listener"]["metadata"]["enableDatagrams"] is True
    assert masque["handler"]["auther"] == "megaproxy-users"
    assert "443" in udp and "40000:40100" in udp


def test_https_role_loads_a_certificate_newer_than_the_service() -> None:
    tasks = (ROOT / "roles" / "https_proxy" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    reload_task = tasks.split("- name: Load a newer certificate into GOST", 1)[1].split(
        "- name: Install containerized certificate renewal service", 1
    )[0]

    assert "state: restarted" in reload_task
    assert "megaproxy_gost_certificate_is_newer.rc == 0" in reload_task


def test_domain_certificate_detects_openssl_textual_mismatch() -> None:
    tasks = (ROOT / "roles" / "https_proxy" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    decision_task = tasks.split(
        "- name: Decide whether the domain certificate must be issued", 1
    )[1].split("- name: Create self-signed certificate directory", 1)[0]

    # OpenSSL 3.0 on the managed host prints a mismatch but exits with rc=0.
    assert "does NOT match certificate" in decision_task
    # Skipped checks (for example self-signed TLS) have neither rc nor stdout.
    assert "selectattr('rc', 'defined')" in decision_task
    assert "selectattr('stdout', 'defined')" in decision_task


def test_probe_resistance_is_opt_in() -> None:
    resistance = ProbeResistance()
    assert resistance.enabled is False
    assert resistance.mode == "disabled"
    assert resistance.knock == []


def test_probe_resistance_supports_configurable_knock_hosts() -> None:
    template = (ROOT / "roles" / "https_proxy" / "templates" / "gost.yml.j2").read_text(
        encoding="utf-8"
    )

    assert "probe_resistance.knock | join(',')" in template

    assert ProbeResistance(knock=["private.example"]).knock == ["private.example"]


def test_https_proxy_uses_http2() -> None:
    template = (ROOT / "roles" / "https_proxy" / "templates" / "gost.yml.j2").read_text(
        encoding="utf-8"
    )

    assert "type: http2" in template
    assert "alpn: [h2, http/1.1]" in template
    assert "rejectUnknownSNI: {{ (not route.is_ip) | lower }}" in template

    verify = (ROOT / "playbooks" / "verify.yml").read_text(encoding="utf-8")
    assert "--proxy-http2" not in verify


def test_docker_cleanup_runs_after_docker_service_changes() -> None:
    tasks = (ROOT / "roles" / "https_proxy" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    handlers = (ROOT / "roles" / "https_proxy" / "handlers" / "main.yml").read_text(
        encoding="utf-8"
    )
    cleanup = (ROOT / "roles" / "https_proxy" / "templates" / "megaproxy-docker-clean.sh.j2").read_text(
        encoding="utf-8"
    )

    service_task = tasks.split("- name: Install GOST systemd service", 1)[1].split(
        "- name: Install Docker cleanup helper", 1
    )[0]
    assert "Restart MegaProxy GOST" in service_task
    assert "Clean MegaProxy Docker resources" in service_task
    assert "/usr/local/sbin/megaproxy-docker-clean" in handlers
    assert 'gost_image_id="$(docker inspect' in cleanup
    assert "megaproxy-gost 2>/dev/null || true" in cleanup
    assert "cleanup_old_images gogost/gost" in cleanup
    assert "cleanup_old_images certbot/certbot" in cleanup
    assert "megaproxy_services.https.certbot_version" in cleanup
    assert "docker image prune --force" in cleanup
    assert "docker volume prune --force" in cleanup
    assert "docker network prune --force" in cleanup
