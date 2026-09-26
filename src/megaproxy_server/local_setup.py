from __future__ import annotations

import os
from pathlib import Path

import questionary

from .bootstrap import bootstrap
from .generate import generate
from .inventory import ROOT, load
from .wizard import create_inventory


def setup_local(path: Path) -> int:
    from .cli import run_ansible

    if os.geteuid() != 0:
        raise ValueError('Local setup must run as root; use sudo')
    os.umask(0o077)
    inventory = load(path) if path.exists() else create_inventory(path, local=True)
    if len(inventory.hosts) != 1 or not next(iter(inventory.hosts.values())).local:
        raise ValueError('Local setup requires an inventory with exactly one local host')
    host = next(iter(inventory.hosts.values()))
    # Trust the host's own keys, without a network scan or disabling SSH verification.
    keys = list(Path('/etc/ssh').glob('ssh_host_*_key.pub'))
    if not keys:
        raise ValueError('No SSH host keys found in /etc/ssh; start openssh-server first')
    known_hosts = ROOT / '.secrets/local-known-hosts'
    known_hosts.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    known_hosts.write_text(''.join(
        f'127.0.0.1,[127.0.0.1]:{host.admin.port} {key.read_text().strip()}\n'
        for key in keys
    ))
    known_hosts.chmod(0o600)
    print(f'Inventory: {path}\nAdministrative private key: {host.admin.private_key_file}')
    print('Copy this private key securely to your computer before continuing. Keep this session open.')
    print(f'Future SSH login: {host.admin.user}@{host.address}, port {host.admin.port}')
    print('Setup disables root/password administrative SSH login and configures the host firewall.')
    if not questionary.confirm('Key saved outside this server; apply configuration now?', default=False).ask():
        print('Configuration saved. Run setup-local again to continue.')
        return 0
    code = bootstrap(path, inventory)
    if code:
        return code
    for playbook in ('site.yml', 'verify.yml'):
        code = run_ansible(path, playbook)
        if code:
            return code
    output = ROOT / '.generated/configs'
    generate(path, output)
    print(f'Setup verified. Client configurations (contain secrets): {output}')
    return 0
