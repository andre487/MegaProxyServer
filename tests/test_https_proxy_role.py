from pathlib import Path

from megaproxy_server.models import ProbeResistance

ROOT = Path(__file__).resolve().parents[1]


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
