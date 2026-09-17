from pathlib import Path
from types import SimpleNamespace

import pytest
from ruamel.yaml import YAML

from megaproxy_server import bootstrap as module
from megaproxy_server.cli import parser
from megaproxy_server.models import HttpsUser, Inventory


def inventory():
    return Inventory.model_validate({
        'hosts': {'new': {
            'address': '192.0.2.1',
            'admin': {'user': 'deploy', 'bootstrap_user': 'root', 'bootstrap_auth': 'password',
                      'private_key_file': '/keys/admin', 'public_key': 'ssh-ed25519 AAAA'},
            'services': {'ssh': {'users': [{'name': 'proxy-user', 'authentication': {
                'type': 'password', 'password': 'proxy-password-long', 'password_hash': '$6$hash',
            }}]}},
        }},
    })


def setup(monkeypatch, checks, phase_code=0):
    calls = []
    iterator = iter(checks)
    monkeypatch.setattr(module, 'check_admin', lambda host, **kwargs: next(iterator))
    monkeypatch.setattr(module.getpass, 'getpass', lambda prompt: 'root-secret')
    monkeypatch.setattr(module, 'run_phase', lambda inv, name, phase, password=None: calls.append((phase, password)) or phase_code)
    monkeypatch.setattr(module, 'save', lambda path, inv: calls.append(('save', inv.hosts['new'].admin.bootstrap_user)))
    return calls


def test_bootstrap_checks_access_before_policy_and_promotes(monkeypatch):
    inv = inventory()
    calls = setup(monkeypatch, [False, True, True])
    assert module.bootstrap(Path('unused'), inv) == 0
    assert calls == [('account', 'root-secret'), ('policy', None), ('save', None)]
    assert inv.hosts['new'].admin.bootstrap_user is None
    assert inv.users.ssh[0].authentication.type == 'password'


def test_failed_admin_login_keeps_root_policy_and_inventory(monkeypatch):
    inv = inventory()
    calls = setup(monkeypatch, [False, False])
    with pytest.raises(ValueError, match='policy was not changed'):
        module.bootstrap(Path('unused'), inv)
    assert calls == [('account', 'root-secret')]
    assert inv.hosts['new'].admin.bootstrap_user == 'root'


def test_retry_uses_existing_administrator_without_root_password(monkeypatch):
    calls = setup(monkeypatch, [True, True])
    monkeypatch.setattr(module.getpass, 'getpass', lambda prompt: pytest.fail('Must not ask for root password'))
    assert module.bootstrap(Path('unused'), inventory()) == 0
    assert calls == [('policy', None), ('save', None)]


def test_failed_post_reload_probe_does_not_promote(monkeypatch):
    calls = setup(monkeypatch, [True, False])
    with pytest.raises(ValueError, match='bootstrap remains pending'):
        module.bootstrap(Path('unused'), inventory())
    assert calls == [('policy', None)]


def test_phase_failure_stops_without_promotion(monkeypatch):
    calls = setup(monkeypatch, [False], phase_code=2)
    assert module.bootstrap(Path('unused'), inventory()) == 2
    assert calls == [('account', 'root-secret')]


def test_limit_rejects_patterns_before_connecting(monkeypatch):
    setup(monkeypatch, [])
    with pytest.raises(ValueError, match='exact inventory host names'):
        module.bootstrap(Path('unused'), inventory(), 'new*')


def test_password_inventory_is_private_temporary_and_host_scoped(monkeypatch):
    paths = []
    def run(command, **kwargs):
        path = Path(command[command.index('-i') + 1])
        paths.append(path)
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        variables = YAML(typ='safe').load(path)['all']['hosts']['new']
        assert variables['ansible_password'] == 'root-secret'
        assert variables['ansible_user'] == 'root'
        assert 'root-secret' not in ' '.join(command)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.sp, 'run', run)
    assert module.run_phase(inventory(), 'new', 'account', 'root-secret') == 0
    assert not paths[0].exists()


def test_probe_disables_shared_connections_and_passwords(monkeypatch):
    def run(command, **kwargs):
        for option in ['ControlPath=none', 'BatchMode=yes', 'IdentitiesOnly=yes', 'PreferredAuthentications=publickey']:
            assert option in command
        assert command[-1] == 'sudo -n true'
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.sp, 'run', run)
    assert module.check_admin(inventory().hosts['new'])


def test_cli_bootstrap_and_add_host():
    assert parser().parse_args(['bootstrap', '--limit', 'new']).limit == 'new'
    assert parser().parse_args(['add-host']).command == 'add-host'


def test_add_host_preserves_existing_settings_and_users(monkeypatch, tmp_path):
    from megaproxy_server import wizard
    original = inventory()
    original.settings.manage_firewall = False
    original.users.https = [HttpsUser(name='unused-https-user', password='long-existing-password')]
    original.users.removed_ssh = ['retired-proxy']
    original.hosts['new'].services.ssh.removed_users = ['retired-proxy']
    before = original.model_dump()
    answers = {
        'Inventory host name (for example proxy_eu)': 'second',
        'Public IP address or DNS name': '192.0.2.2',
        'Current SSH login used for the first setup': 'root',
        'Permanent administrative user to create or update': 'deploy',
        'Administrative SSH port': '22',
        'SSH proxy port': '22',
    }
    monkeypatch.setattr(wizard, 'ask_required', lambda message, default=None: answers[message])
    monkeypatch.setattr(wizard.questionary, 'select', lambda message, **kwargs: SimpleNamespace(ask=lambda: 'password' if message == 'Initial SSH authentication' else 'Generate a dedicated key'))
    monkeypatch.setattr(wizard.questionary, 'checkbox', lambda *args, **kwargs: SimpleNamespace(ask=lambda: ['ssh']))
    monkeypatch.setattr(wizard.questionary, 'confirm', lambda *args, **kwargs: SimpleNamespace(ask=lambda: False))
    monkeypatch.setattr(wizard, 'generate_key', lambda *args: ('ssh-ed25519 NEW', tmp_path / 'admin-key'))
    saved = []
    monkeypatch.setattr(wizard, 'save', lambda path, inv, **kwargs: saved.append(inv))
    result = wizard.create_inventory(tmp_path / 'inventory.yml', existing=original)
    assert set(result.hosts) == {'new', 'second'}
    assert result.settings == original.settings
    assert result.users == original.users
    assert result.hosts['new'] == original.hosts['new']
    assert result.hosts['second'].services.ssh.users == original.users.ssh
    assert result.hosts['second'].admin.bootstrap_auth == 'password'
    assert original.model_dump() == before
    assert saved == [result]


def test_probe_respects_custom_known_hosts(monkeypatch):
    monkeypatch.setenv('ANSIBLE_SSH_ARGS', '-o UserKnownHostsFile=/tmp/test-known-hosts')
    def run(command, **kwargs):
        assert 'UserKnownHostsFile=/tmp/test-known-hosts' in command
        assert command.index('ControlPath=none') < command.index('UserKnownHostsFile=/tmp/test-known-hosts')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.sp, 'run', run)
    assert module.check_admin(inventory().hosts['new'])


@pytest.mark.parametrize('command', ['bootstrap', 'apply', 'plan', 'verify'])
def test_repeated_limits_include_all_requested_hosts(command):
    args = parser().parse_args([command, '--limit', 'proxy_hk', '--limit', 'proxy_sg,proxy_eu'])
    assert args.limit == 'proxy_hk,proxy_sg,proxy_eu'


def test_probe_preserves_ssh_host_key_configuration(monkeypatch):
    def run(command, **kwargs):
        assert not any(option.startswith('StrictHostKeyChecking=') for option in command)
        assert not any(option.startswith('UserKnownHostsFile=') for option in command)
        return SimpleNamespace(returncode=0)
    for variable in ['ANSIBLE_SSH_ARGS', 'ANSIBLE_SSH_COMMON_ARGS', 'ANSIBLE_SSH_EXTRA_ARGS']:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(module.sp, 'run', run)
    assert module.check_admin(inventory().hosts['new'])


def test_failed_probe_reports_actual_ssh_error(monkeypatch, capsys):
    monkeypatch.setattr(module.sp, 'run', lambda *args, **kwargs: SimpleNamespace(
        returncode=255, stderr='Host key verification failed.\n', stdout='',
    ))
    host = inventory().hosts['new']
    assert not module.check_admin(host)
    assert capsys.readouterr().err == ''
    assert not module.check_admin(host, report_error=True)
    assert 'Host key verification failed.' in capsys.readouterr().err


def test_probe_reports_timeout(monkeypatch, capsys):
    def run(command, **kwargs):
        raise module.sp.TimeoutExpired(command, 30)
    monkeypatch.setattr(module.sp, 'run', run)
    assert not module.check_admin(inventory().hosts['new'], report_error=True)
    assert 'timed out' in capsys.readouterr().err
