from pathlib import Path

from ruamel.yaml import YAML


def test_admin_password_does_not_redact_home_path():
    tasks = YAML(typ='safe').load(Path('roles/admin/tasks/account.yml'))
    user = next(task['ansible.builtin.user'] for task in tasks if 'ansible.builtin.user' in task)
    assert "password_hash('sha512')" in user['password']
    assert "lookup('ansible.builtin.password', '/dev/null', length=64)" in user['password']
    assert user['update_password'] == 'on_create'
