from __future__ import annotations

import getpass
import os
import shlex
import subprocess as sp
import tempfile
import sys
from pathlib import Path

from ruamel.yaml import YAML

from .inventory import ROOT, ansible_inventory, save
from .models import Host, Inventory


def check_admin(host: Host, *, report_error: bool = False) -> bool:
    command = [
        'ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ConnectTimeout=10',
        '-p', str(host.admin.port), '-i', str(Path(host.admin.private_key_file).expanduser()),
        *shlex.split(os.environ.get('ANSIBLE_SSH_ARGS', '')),
        *shlex.split(os.environ.get('ANSIBLE_SSH_COMMON_ARGS', '')),
        *shlex.split(os.environ.get('ANSIBLE_SSH_EXTRA_ARGS', '')),
        '-l', host.admin.user, '--', host.address, 'sudo -n true',
    ]
    try:
        result = sp.run(command, capture_output=True, text=True, timeout=30)
    except sp.TimeoutExpired:
        if report_error:
            print('Administrative SSH probe timed out after 30 seconds', file=sys.stderr)
        return False
    if result.returncode and report_error:
        print(f'Administrative SSH probe failed (exit {result.returncode}):', file=sys.stderr)
        print(result.stderr.strip() or result.stdout.strip() or 'SSH returned no diagnostic output', file=sys.stderr)
    return result.returncode == 0


def run_phase(inventory: Inventory, name: str, phase: str, password: str | None = None) -> int:
    host = inventory.hosts[name]
    data = ansible_inventory(inventory)
    variables = data['all']['hosts'][name]
    data['all']['hosts'] = {name: variables}
    variables['ansible_user'] = host.admin.user if phase == 'policy' else host.admin.bootstrap_user
    variables['ansible_ssh_private_key_file'] = (
        host.admin.private_key_file if phase == 'policy'
        else host.admin.bootstrap_private_key_file or host.admin.private_key_file
    )
    if password is not None:
        variables['ansible_password'] = password
        variables['ansible_become_password'] = password
        variables['ansible_ssh_common_args'] = '-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive'
    variables['megaproxy_bootstrap_phase'] = phase
    # Bootstrap passwords exist only in a private temporary directory for this subprocess.
    with tempfile.TemporaryDirectory(prefix='megaproxy-bootstrap-') as directory:
        path = Path(directory) / 'inventory.yml'
        with open(path, 'w', encoding='utf-8', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
            YAML().dump(data, stream)
        return sp.run([
            'ansible-playbook', '-i', str(path), str(ROOT / 'playbooks/bootstrap.yml'),
        ], cwd=ROOT).returncode


def bootstrap(path: Path, inventory: Inventory, limit: str | None = None) -> int:
    names = list(inventory.hosts) if not limit else [name.strip() for name in limit.split(',')]
    if not names or any(name not in inventory.hosts for name in names):
        raise ValueError('Bootstrap requires exact inventory host names in --limit')
    for name in dict.fromkeys(names):
        host = inventory.hosts[name]
        if not host.admin.bootstrap_user:
            continue
        print(f'Bootstrapping administrative access: {name}', flush=True)
        if not check_admin(host):
            password = None
            if host.admin.bootstrap_auth == 'password':
                password = getpass.getpass(f'Initial SSH password for {host.admin.bootstrap_user}@{host.address}: ')
                if not password:
                    raise ValueError('Initial SSH password must not be empty')
            code = run_phase(inventory, name, 'account', password)
            password = None
            if code:
                return code
            if not check_admin(host, report_error=True):
                raise ValueError(f'Administrative key login or sudo failed for {name}; SSH policy was not changed')
        code = run_phase(inventory, name, 'policy')
        if code:
            return code
        if not check_admin(host, report_error=True):
            raise ValueError(f'Administrative access verification failed after SSH reload for {name}; bootstrap remains pending')
        host.admin.bootstrap_user = None
        host.admin.bootstrap_private_key_file = None
        host.admin.bootstrap_auth = 'key'
        save(path, inventory)
        print(f'Administrative connection activated for: {name}', flush=True)
    return 0
