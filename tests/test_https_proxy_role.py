from pathlib import Path

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
