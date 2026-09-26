import subprocess as sp
from pathlib import Path
from types import SimpleNamespace

import pytest
from ruamel.yaml import YAML

from megaproxy_server import bootstrap, cli, inventory, local_setup, wizard
from megaproxy_server.models import Inventory


def local_inventory():
    return Inventory.model_validate({
        'hosts': {'local_proxy': {
            'address': '192.0.2.1', 'local': True,
            'admin': {'user': 'deploy', 'bootstrap_user': 'root',
                      'private_key_file': '/keys/admin', 'public_key': 'ssh-ed25519 AAAA'},
            'services': {'https': {'endpoint': '192.0.2.1', 'certificate': 'self-signed',
                                  'users': [{'name': 'alice', 'password': 'long-test-password'}]}},
        }},
    })


def test_local_transport_preserves_public_endpoint_and_checks_host_key(monkeypatch):
    inv = local_inventory()
    variables = inventory.ansible_inventory(inv)['all']['hosts']['local_proxy']
    assert variables['ansible_host'] == '127.0.0.1'
    assert variables['megaproxy_services']['https']['endpoint'] == '192.0.2.1'
    assert 'StrictHostKeyChecking=yes' in variables['ansible_ssh_common_args']
    calls = []
    monkeypatch.setattr(bootstrap.sp, 'run', lambda command, **kwargs: (
        calls.append(command) or SimpleNamespace(returncode=0)
    ))
    assert bootstrap.check_admin(inv.hosts['local_proxy'])
    assert calls[0][-2] == '127.0.0.1'
    assert 'StrictHostKeyChecking=yes' in calls[0]


def test_only_account_phase_runs_locally_as_root(monkeypatch):
    inv = local_inventory()
    monkeypatch.setattr(bootstrap.os, 'geteuid', lambda: 0)
    phases = []

    def run(command, **kwargs):
        data = YAML(typ='safe').load(Path(command[command.index('-i') + 1]))
        phases.append(data['all']['hosts']['local_proxy'])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bootstrap.sp, 'run', run)
    assert bootstrap.run_phase(inv, 'local_proxy', 'account') == 0
    assert bootstrap.run_phase(inv, 'local_proxy', 'policy') == 0
    assert phases[0]['ansible_connection'] == 'local'
    assert phases[0]['ansible_python_interpreter'] == bootstrap.sys.executable
    assert 'ansible_connection' not in phases[1]
    assert phases[1]['ansible_user'] == 'deploy'
    monkeypatch.setattr(bootstrap.os, 'geteuid', lambda: 1000)
    with pytest.raises(ValueError, match='root'):
        bootstrap.run_phase(inv, 'local_proxy', 'account')


@pytest.mark.parametrize('confirm,bootstrap_code,expected', [
    (False, 0, []), (True, 2, ['bootstrap']),
    (True, 0, ['bootstrap', 'site.yml', 'verify.yml', 'configs']),
])
def test_setup_resume_confirmation_and_failure(monkeypatch, tmp_path, confirm, bootstrap_code, expected):
    inv = local_inventory()
    path = tmp_path / 'inventory.yml'
    path.touch()
    key = tmp_path / 'host.pub'
    key.write_text('ssh-ed25519 HOSTKEY\n')
    monkeypatch.setattr(local_setup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(local_setup.os, 'umask', lambda mask: None)
    monkeypatch.setattr(local_setup, 'ROOT', tmp_path)
    monkeypatch.setattr(Path, 'glob', lambda *args: [key])
    monkeypatch.setattr(local_setup, 'load', lambda path: inv)
    monkeypatch.setattr(local_setup, 'create_inventory', lambda *args, **kwargs: pytest.fail('Overwrites inventory'))
    monkeypatch.setattr(local_setup.questionary, 'confirm', lambda *args, **kwargs: SimpleNamespace(ask=lambda: confirm))
    calls = []
    monkeypatch.setattr(local_setup, 'bootstrap', lambda *args: calls.append('bootstrap') or bootstrap_code)
    monkeypatch.setattr(cli, 'run_ansible', lambda path, playbook: calls.append(playbook) or 0)
    monkeypatch.setattr(local_setup, 'generate', lambda *args: calls.append('configs'))
    assert local_setup.setup_local(path) == (bootstrap_code if confirm else 0)
    assert calls == expected
    known = tmp_path / '.secrets/local-known-hosts'
    assert known.read_text() == '127.0.0.1,[127.0.0.1]:22 ssh-ed25519 HOSTKEY\n'
    assert known.stat().st_mode & 0o777 == 0o600


def test_local_wizard_skips_remote_bootstrap_questions(monkeypatch, tmp_path):
    answers = {
        'Inventory host name (for example proxy_eu)': 'local_proxy',
        'Public IP address or DNS name': '192.0.2.1',
        'Permanent administrative user to create or update': 'deploy',
        'Administrative SSH port': '22',
        'HTTPS endpoint': '192.0.2.1',
    }
    monkeypatch.setattr(wizard, 'ask_required', lambda message, default=None: answers[message])
    selections = {'Administrative SSH key': 'Generate a dedicated key', 'Certificate type': 'self-signed'}
    monkeypatch.setattr(wizard.questionary, 'select', lambda message, **kwargs: SimpleNamespace(ask=lambda: selections[message]))
    monkeypatch.setattr(wizard.questionary, 'checkbox', lambda *args, **kwargs: SimpleNamespace(ask=lambda: ['https']))
    monkeypatch.setattr(wizard.questionary, 'confirm', lambda message, **kwargs: SimpleNamespace(ask=lambda: False))
    monkeypatch.setattr(wizard, 'generate_key', lambda *args: ('ssh-ed25519 AAAA', tmp_path / 'key'))
    monkeypatch.setattr(wizard, 'ask_users', lambda *args: local_inventory().users.https)
    monkeypatch.setattr(wizard, 'save', lambda *args, **kwargs: None)
    inv = wizard.create_inventory(tmp_path / 'inventory.yml', local=True)
    assert len(inv.hosts) == 1
    assert inv.hosts['local_proxy'].local
    assert inv.hosts['local_proxy'].admin.bootstrap_user == 'root'
    assert inv.hosts['local_proxy'].admin.bootstrap_auth == 'key'
    assert not inv.settings.https_chains_enabled


def test_setup_rejects_non_root_and_remote_inventory(monkeypatch, tmp_path):
    path = tmp_path / 'inventory.yml'
    path.touch()
    inv = local_inventory()
    monkeypatch.setattr(local_setup.os, 'geteuid', lambda: 1000)
    with pytest.raises(ValueError, match='root'):
        local_setup.setup_local(path)
    monkeypatch.setattr(local_setup.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(local_setup.os, 'umask', lambda mask: None)
    monkeypatch.setattr(local_setup, 'load', lambda path: inv)
    inv.hosts['local_proxy'].local = False
    with pytest.raises(ValueError, match='exactly one local host'):
        local_setup.setup_local(path)


def test_installer_can_be_piped_and_is_valid_bash():
    script = Path('install.sh').read_text()
    sp.run(['bash', '-n'], input=script, text=True, check=True)
    result = sp.run(['bash', '-s', '--', '--help'], input=script, text=True, capture_output=True)
    assert result.returncode == 0
    assert 'Interactive Debian/Ubuntu' in result.stdout
