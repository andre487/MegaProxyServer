import hashlib
import json
from pathlib import Path

import pytest
from jinja2 import Environment, StrictUndefined
from ruamel.yaml import YAML

from megaproxy_server import inventory as inventory_module
from megaproxy_server.gost_auth import GOST_AUTH_PORT, hash_users, matches
from megaproxy_server.inventory import write_ansible_inventory
from megaproxy_server.models import Inventory


def test_hashed_auth_generation_rotation_and_gost_config(tmp_path, monkeypatch):
    password = 'пароль:%' * 20
    users = {'alice': password, 'removed': 'old-password'}
    hashes = hash_users(users, {})
    assert matches(password, hashes['alice'])
    assert not matches('incorrect', hashes['alice'])
    assert not matches(password, '$pbkdf2-sha256$1$00$00')
    assert hash_users(users, hashes) == hashes
    changed = hash_users({'alice': 'new-password'}, hashes)
    assert set(changed) == {'alice'}
    assert changed['alice'] != hashes['alice']
    assert matches('new-password', changed['alice'])
    _, _, rounds, salt, expected = hashes['alice'].split('$')
    assert hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds)).hex() == expected

    monkeypatch.setattr(inventory_module, 'ROOT', tmp_path)
    inventory = Inventory.model_validate({
        'users': {'https': [{'name': 'alice', 'password': password}]},
        'hosts': {'entry': {
            'address': '192.0.2.1',
            'admin': {'user': 'deploy', 'private_key_file': '/unused', 'public_key': 'ssh-ed25519 TEST'},
            'services': {'https': {'title': 'Test', 'endpoint': 'proxy.example', 'certificate': 'self-signed'}}}},
    })
    path = write_ansible_inventory(tmp_path / 'inventory.yml', inventory, prepare_services=True)
    projected = YAML(typ='safe').load(path.read_text())['all']['hosts']['entry']
    auth_path = Path(projected['megaproxy_gost_auth_users_file'])
    content = auth_path.read_text()
    assert password not in content
    assert matches(password, json.loads(content)['alice'])
    assert auth_path.stat().st_mode & 0o777 == 0o600
    before = auth_path.stat().st_mtime_ns
    write_ansible_inventory(tmp_path / 'inventory.yml', inventory, prepare_services=True)
    assert auth_path.stat().st_mtime_ns == before
    root = Path(__file__).resolve().parents[1]
    env = Environment(undefined=StrictUndefined)
    env.filters['to_json'] = json.dumps
    projected['megaproxy_container_certificate_directory'] = '/certs'
    template = (root / 'roles/https_proxy/templates/gost.yml.j2').read_text()
    rendered = env.from_string(template).render(**projected)
    config = YAML(typ='safe').load(rendered)
    assert password not in rendered
    assert config['authers'] == [{'name': 'megaproxy-users', 'plugin': {
        'type': 'http', 'addr': f'http://127.0.0.1:{GOST_AUTH_PORT}/auth'}}]
    assert 'auths' not in rendered
    raw = inventory.model_dump()
    raw['hosts']['entry']['services']['https']['port'] = GOST_AUTH_PORT
    with pytest.raises(ValueError, match='conflicts'):
        Inventory.model_validate(raw)
