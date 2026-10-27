"""Run the release binary against controller-generated password hashes."""
import json
import socket
import subprocess as sp
import time
from pathlib import Path

from megaproxy_server.gost_auth import hash_users


def start_hashed_auth(binary, root, name, variables, processes, logs):
    https = variables['megaproxy_services']['https']
    users = {user['name']: user['password'] for user in https['users']}
    machine = https['machine_auth']
    if machine:
        users[machine['username']] = machine['password']
    path = root / f'{name}-hashes.json'
    path.write_text(json.dumps(hash_users(users, {})))
    path.chmod(0o600)
    log = (root / f'{name}-auth.log').open('w+')
    logs.append(log)
    port = variables['megaproxy_gost_auth_port']
    process = sp.Popen([str(Path(binary).resolve()), '-listen', f'127.0.0.1:{port}', '-users', str(path)],
                       stdout=log, stderr=log)
    processes.append(process)
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(f'{name} hashed authentication stopped')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return process
        except OSError:
            time.sleep(.05)
    raise AssertionError(f'{name} hashed authentication did not start')
