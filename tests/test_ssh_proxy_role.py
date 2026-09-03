from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_key_only_account_is_not_locked_before_public_key_authentication() -> None:
    tasks = (ROOT / "roles" / "ssh_proxy" / "tasks" / "main.yml").read_text(encoding="utf-8")
    user_task = tasks.split("- name: Create restricted SSH proxy users", 1)[1].split(
        "- name: Explain deferred SSH user planning", 1
    )[0]

    assert "else 'x'" in user_task
    assert "password_lock: false" in user_task
