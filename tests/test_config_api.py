import base64
import hashlib
import json
from copy import deepcopy
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

import pytest
from jsonschema import Draft202012Validator

from megaproxy_server import config_api, config_bundle
from megaproxy_server.config_api import AccessDenied, render_config, serve, user_id
from megaproxy_server.config_bundle import build_bundle, public_url, validate_config, write_bundle
from megaproxy_server.inventory import ansible_inventory, write_ansible_inventory
from megaproxy_server.models import ConfigApiService, Inventory, ProbeResistance


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    # Exercise real authentication/encryption; only reduce the KDF cost for this suite.
    def fast_kdf(value, salt):
        return hashlib.scrypt(value, salt=salt, n=2**10, r=8, p=1, dklen=32)
    monkeypatch.setattr(config_api, "derive_key", fast_kdf)
    monkeypatch.setattr(config_bundle, "derive_key", fast_kdf)
    key = tmp_path / "private-key"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-secret\n-----END OPENSSH PRIVATE KEY-----\n")
    admin = {"user": "deploy", "private_key_file": "/secret/admin-key", "public_key": "ssh-ed25519 ADMIN"}
    hosts = {
        "de_entry": {"address": "192.0.2.1", "admin": admin, "services": {
            "https": {"title": "DE ENTRY", "endpoint": "entry.example", "certificate": "domain", "acme_email": "a@example.com",
                      "chain_entry": True, "probe_resistance": {"enabled": True, "knock": ["knock.example"]}},
            "ssh": {"title": "DE ENTRY", "generate_profile": True}}},
        "us_exit": {"address": "192.0.2.2", "admin": admin, "services": {
            "https": {"title": "US EXIT", "endpoint": "exit.example", "certificate": "domain", "acme_email": "a@example.com",
                      "chain_exit": True, "chain_password": "machine-chain-secret"}, "ssh": {"title": "US EXIT", "generate_profile": True}}},
        "configs_one": {"address": "192.0.2.3", "admin": admin, "services": {
            "config_api": {"endpoint": "configs.example", "acme_email": "a@example.com"}}},
        "configs_two": {"address": "2001:db8::4", "admin": admin, "services": {
            "config_api": {"endpoint": "2001:db8::4", "certificate": "ip-acme", "acme_email": "a@example.com"}}},
    }
    return Inventory.model_validate({"hosts": hosts, "users": {
        "https": [{"name": "alice", "password": "café-long-password:123", "ssh_users": ["tun-alice", "tun-db"]},
                  {"name": "bob", "password": "bob-long-password-123"}],
        "ssh": [{"name": "tun-alice", "authentication": {"type": "key", "public_key": "ssh-ed25519 ALICE", "generated_private_key": str(key)}},
                {"name": "tun-db", "authentication": {"type": "password", "password": "ssh-password-secret", "password_hash": "$6$test-hash"}},
                {"name": "tun-bob", "authentication": {"type": "key", "public_key": "ssh-ed25519 BOB"}}]},
        "settings": {"https_chains_enabled": True, "https_chain_domain": "chains.example",
                     "https_chain_pairs": [{"entry": "de_entry", "exit": "us_exit", "country_code": "US", "title": "DE ENTRY"}],
                     "ssh_jump_pairs": [{"entry": "de_entry", "exit": "us_exit", "title": "DE ENTRY -> US EXIT"}]}})



@pytest.mark.parametrize("target", ["https", "ssh", "https_chain_pairs", "https_jump_pairs", "ssh_jump_pairs"])
@pytest.mark.parametrize("value", [None, "", "   ", "missing"])
def test_profile_titles_must_be_explicit_and_nonblank(inventory, target, value):
    raw = inventory.model_dump()
    if target in {"https", "ssh"}:
        item = raw["hosts"]["de_entry"]["services"][target]
    else:
        item = {"entry": "de_entry", "exit": "us_exit", "country_code": "US"}
        raw["settings"][target] = [item]
    if value == "missing":
        item.pop("title", None)
    else:
        item["title"] = value
    with pytest.raises(ValueError, match="title"):
        Inventory.model_validate(raw)


def test_production_kdf_parameters():
    salt = bytes(range(16))
    assert config_api.derive_key(b"test", salt) == hashlib.scrypt(
        b"test", salt=salt, n=2**17, r=8, p=1, dklen=32, maxmem=256 * 1024 * 1024)


def test_generated_transports_are_opt_in_and_client_compatible(inventory, tmp_path):
    alice = inventory.users.https[0]
    entry = inventory.hosts["de_entry"].services.https
    exit_service = inventory.hosts["us_exit"].services.https
    entry.http3 = exit_service.http3 = True
    entry.socks5.enabled = True
    bundle = build_bundle(inventory)
    document = render_config(bundle, alice.name, alice.password)
    https = [p["proxy"] for p in document["profiles"] if p["proxy"]["type"] == "HTTPS"]
    assert all("preferHttp3" not in proxy for proxy in https)
    assert all(p["proxy"]["type"] != "MASQUE" for p in document["profiles"])
    assert sum(p["proxy"]["type"] == "SOCKS5" for p in document["profiles"]) == 1
    entry.masque_profiles = True
    bundle = build_bundle(inventory)
    document = render_config(bundle, alice.name, alice.password)
    masque = [p for p in document["profiles"] if p["proxy"]["type"] == "MASQUE"]
    assert len(masque) == 1
    assert masque[0]["name"] == "DE ENTRY MASQUE"
    assert all("browser" not in p and "preferHttp3" not in p["proxy"] for p in masque)
    assert masque[0]["proxy"]["password"] == alice.password
    firefox = render_config(bundle, alice.name, alice.password, "browser_firefox")
    chromium = render_config(bundle, alice.name, alice.password, "browser_chromium")
    assert any(p["proxy"]["type"] == "SOCKS5" for p in firefox["profiles"])
    assert not any(p["proxy"]["type"] == "SOCKS5" for p in chromium["profiles"])
    android = render_config(bundle, alice.name, alice.password, "android")
    assert any(p["proxy"]["type"] == "SOCKS5" for p in android["profiles"])
    Draft202012Validator(json.loads((config_bundle.ROOT / "schemas/android-v8.schema.json").read_text())).validate(android)
    from megaproxy_server.export import export_profiles
    exported_inventory = inventory.model_copy(deep=True)
    exported_inventory.settings.ssh_jump_pairs = []
    for host in exported_inventory.hosts.values():
        host.services.ssh = None
    path = tmp_path / "export.json"
    export_profiles(exported_inventory, path)
    exported = json.loads(path.read_text())
    assert exported["version"] == 8
    validate_config(exported)
    assert all("preferHttp3" not in p["proxy"] for p in exported["profiles"])
    assert {p["proxy"]["type"] for p in exported["profiles"]} >= {"SOCKS5", "MASQUE"}



def test_knock_host_reaches_api_and_export_routes_without_affecting_masque(inventory, tmp_path):
    from megaproxy_server.export import export_profiles
    raw = inventory.model_dump()
    raw["users"]["ssh"] = raw["users"]["ssh"][:2]
    raw["settings"]["https_jump_pairs"] = [
        {"entry": "de_entry", "exit": "us_exit", "title": "Jump"}]
    inventory = Inventory.model_validate(raw)
    entry = inventory.hosts["de_entry"].services.https
    entry.http3 = entry.masque_profiles = True
    inventory.settings.https_chain_pairs[0].probe_resistance = ProbeResistance(
        enabled=True, knock=["chain-knock.example"])
    inventory = Inventory.model_validate(inventory.model_dump())
    user = inventory.users.https[0]
    api = render_config(build_bundle(inventory), user.name, user.password)
    path = tmp_path / "export.json"
    export_profiles(inventory, path)
    exported = json.loads(path.read_text())
    for document in (api, exported):
        validate_config(document)
        https = [p for p in document["profiles"]
                 if p["proxy"]["type"] == "HTTPS" and p["proxy"]["username"] == user.name]
        assert [p.get("browser", {}).get("knockHost") for p in https] == [
            "knock.example", None, "chain-knock.example"]
        assert all("knockHost" not in p.get("browser", {}) for p in document["profiles"]
                   if p["proxy"]["type"] == "MASQUE")


def test_http3_flag_cannot_be_advertised_without_a_listener(inventory):
    inventory.hosts["de_entry"].services.https.client_profile = {"proxy": {"preferHttp3": True}}
    with pytest.raises(ValueError, match="preferHttp3 requires HTTP/3"):
        build_bundle(inventory)


def test_profile_order_groups_direct_hosts_then_pairs_in_inventory_order(inventory, tmp_path):
    raw = inventory.model_dump()
    raw["users"]["ssh"] = raw["users"]["ssh"][:2]
    raw["hosts"]["de_entry"]["services"]["https"].update(chain_exit=True, chain_password="chain-password-long")
    raw["hosts"]["us_exit"]["services"]["https"]["chain_entry"] = True
    pairs = [{"entry": "us_exit", "exit": "de_entry", "title": "US EXIT -> DE ENTRY"}, {"entry": "de_entry", "exit": "us_exit", "title": "DE ENTRY -> US EXIT"}]
    raw["settings"]["ssh_jump_pairs"] = pairs
    raw["settings"]["https_jump_pairs"] = pairs
    raw["settings"]["https_chain_pairs"] = [
        dict(pairs[0], country_code="DE", hostname="first-chain.example"),
        dict(pairs[1], country_code="US", hostname="second-chain.example"),
    ]
    inventory = Inventory.model_validate(raw)
    alice = inventory.users.https[0]
    document = render_config(build_bundle(inventory), alice.name, alice.password)
    expected = [
        ("HTTPS", "entry.example"), ("HTTPS", "exit.example"),
        ("SSH", "192.0.2.1"), ("SSH", "192.0.2.1"),
        ("SSH", "192.0.2.2"), ("SSH", "192.0.2.2"),
        ("HTTPS", "first-chain.example"), ("HTTPS", "second-chain.example"),
        ("HTTPS_JUMP", "entry.example"), ("HTTPS_JUMP", "exit.example"),
        ("SSH_JUMP", "192.0.2.1"), ("SSH_JUMP", "192.0.2.1"),
        ("SSH_JUMP", "192.0.2.2"), ("SSH_JUMP", "192.0.2.2"),
    ]
    assert [(p["proxy"]["type"], p["proxy"]["host"]) for p in document["profiles"]] == expected
    assert [p["color"] for p in document["profiles"]] == list(range(len(expected)))
    from megaproxy_server.export import export_profiles
    output = tmp_path / "export.json"
    export_profiles(inventory, output)
    exported = json.loads(output.read_text())
    assert [(p["proxy"]["type"], p["proxy"]["host"]) for p in exported["profiles"]
            if p["proxy"]["username"] != "bob"] == expected
    assert [p["color"] for p in exported["profiles"]] == list(range(len(exported["profiles"])))
    from megaproxy_server.generate import https_entries
    assert [p["host"] for p in https_entries(inventory) if p["username"] == "alice"] == [
        "entry.example", "exit.example", "first-chain.example", "second-chain.example",
    ]


def test_ssh_profile_flags_select_direct_hosts_without_disabling_jumps(inventory, tmp_path):
    raw = inventory.model_dump()
    raw["hosts"]["us_exit"]["services"]["ssh"].pop("generate_profile")
    raw["users"]["ssh"] = raw["users"]["ssh"][:2]
    inventory = Inventory.model_validate(raw)
    assert inventory.hosts["us_exit"].services.ssh.generate_profile is False
    alice = inventory.users.https[0]
    document = render_config(build_bundle(inventory), alice.name, alice.password)
    direct = [p for p in document["profiles"] if p["proxy"]["type"] == "SSH"]
    assert len(direct) == 2
    assert all(p["proxy"]["host"] == "192.0.2.1" for p in direct)
    assert sum(p["proxy"]["type"] == "SSH_JUMP" for p in document["profiles"]) == 2
    from megaproxy_server.export import export_profiles
    output = tmp_path / "export.json"
    export_profiles(inventory, output)
    exported = json.loads(output.read_text())
    assert [(p["proxy"]["host"], p["proxy"]["username"]) for p in exported["profiles"]
            if p["proxy"]["type"] == "SSH"] == [("192.0.2.1", "tun-alice"), ("192.0.2.1", "tun-db")]
    assert sum(p["proxy"]["type"] == "SSH_JUMP" for p in exported["profiles"]) == 2
    inventory.hosts["de_entry"].services.ssh.generate_profile = False
    inventory.settings.ssh_jump_pairs = []
    inventory.users.ssh[0].authentication.generated_private_key = None
    bundle = build_bundle(inventory)
    assert bundle["ssh_hosts"] == []
    assert all(not p["proxy"]["type"].startswith("SSH")
               for p in render_config(bundle, alice.name, alice.password)["profiles"])


def test_jump_profiles_use_only_declared_pairs_and_linked_accounts(inventory, tmp_path):
    raw = inventory.model_dump()
    raw["settings"]["https_jump_pairs"] = [{"entry": "de_entry", "exit": "us_exit", "title": "DE ENTRY -> US EXIT"}]
    raw["settings"]["ssh_jump_pairs"][0].update(title="SSH via DE", country_code="US")
    raw["users"]["ssh"][2]["authentication"]["generated_private_key"] = raw["users"]["ssh"][0]["authentication"]["generated_private_key"]
    inventory = Inventory.model_validate(raw)
    alice = inventory.users.https[0]
    bundle = build_bundle(inventory)
    document = render_config(bundle, alice.name, alice.password)
    jumps = [p for p in document["profiles"] if p["proxy"]["type"].endswith("_JUMP")]
    assert [p["proxy"]["type"] for p in jumps] == ["HTTPS_JUMP", "SSH_JUMP", "SSH_JUMP"]
    https = jumps[0]
    assert (https["proxy"]["host"], https["proxy"]["jump"]["host"]) == ("exit.example", "entry.example")
    assert (https["name"], https["countryCode"]) == ("DE ENTRY -> US EXIT", "US")
    assert https["proxy"]["jump"]["sameAuthentication"] is True
    for item in jumps[1:]:
        assert (item["name"], item["countryCode"]) == ("SSH via DE", "US")
        assert item["proxy"]["username"] == item["proxy"]["jump"]["username"]
        assert item["proxy"]["jump"]["sameAuthentication"] is True
    assert [p["proxy"]["type"] for p in render_config(bundle, "bob", inventory.users.https[1].password)["profiles"]] == ["HTTPS"] * 3 + ["HTTPS_JUMP"]
    assert all(p["proxy"]["type"] == "HTTPS" for p in render_config(bundle, alice.name, alice.password, "browser_firefox")["profiles"])
    from megaproxy_server.export import export_profiles
    output = tmp_path / "export.json"
    export_profiles(inventory, output)
    exported = json.loads(output.read_text())
    validate_config(exported)
    assert sum(p["proxy"]["type"] == "SSH_JUMP" for p in exported["profiles"]) == 3
    assert all(p["countryCode"] == "US" and p["name"].startswith("SSH via DE / ")
               for p in exported["profiles"] if p["proxy"]["type"] == "SSH_JUMP")
    assert sum(p["proxy"]["type"] == "HTTPS_JUMP" for p in exported["profiles"]) == 2
    alice.ssh_users = ["tun-alice"]
    restricted = render_config(build_bundle(inventory), alice.name, alice.password)
    ssh_jumps = [p for p in restricted["profiles"] if p["proxy"]["type"] == "SSH_JUMP"]
    assert len(ssh_jumps) == 1
    assert ssh_jumps[0]["proxy"]["username"] == "tun-alice"
    assert ssh_jumps[0]["proxy"]["jump"]["username"] == "tun-alice"
    inventory.settings.ssh_jump_pairs = []
    inventory.settings.https_jump_pairs = []
    without_jumps = render_config(build_bundle(inventory), alice.name, alice.password)
    assert all(not p["proxy"]["type"].endswith("_JUMP") for p in without_jumps["profiles"])


@pytest.mark.parametrize("kind,pair", [
    ("ssh_jump_pairs", {"entry": "missing", "exit": "us_exit"}),
    ("ssh_jump_pairs", {"entry": "de_entry", "exit": "de_entry"}),
    ("ssh_jump_pairs", {"entry": "de_entry", "exit": "us_exit", "country_code": "invalid"}),
    ("https_jump_pairs", {"entry": "missing", "exit": "us_exit"}),
    ("https_jump_pairs", {"entry": "de_entry", "exit": "de_entry"}),
])
def test_invalid_jump_pairs_are_rejected(inventory, kind, pair):
    raw = inventory.model_dump()
    raw["settings"][kind] = [dict(pair, title="Jump")]
    with pytest.raises(ValueError):
        Inventory.model_validate(raw)


@pytest.mark.parametrize("kind", ["ssh_jump_pairs", "https_jump_pairs", "https_chain_pairs"])
def test_duplicate_pairs_are_rejected(inventory, kind):
    raw = inventory.model_dump()
    pair = {"entry": "de_entry", "exit": "us_exit", "title": "DE ENTRY -> US EXIT"}
    if kind == "https_chain_pairs":
        pair["country_code"] = "US"
    raw["settings"][kind] = [pair, pair]
    with pytest.raises(ValueError, match="duplicate"):
        Inventory.model_validate(raw)


@pytest.mark.parametrize("kind,service", [("ssh_jump_pairs", "ssh"), ("https_jump_pairs", "https")])
def test_jump_hosts_must_be_enabled(inventory, kind, service):
    raw = inventory.model_dump()
    if kind == "https_jump_pairs":
        raw["settings"][kind] = [{"entry": "de_entry", "exit": "us_exit", "title": "DE ENTRY -> US EXIT"}]
    raw["hosts"]["de_entry"]["services"][service]["enabled"] = False
    with pytest.raises(ValueError, match="enabled"):
        Inventory.model_validate(raw)


@pytest.mark.parametrize("change", [
    {"masque_profiles": True},
    {"socks5": {"enabled": True, "port": 443}},
    {"socks5": {"enabled": True, "port": 10443}},
    {"socks5": {"enabled": True, "udp_port_min": 40001, "udp_port_max": 40000}},
])
def test_invalid_transport_settings(inventory, change):
    raw = inventory.model_dump()
    raw["hosts"]["de_entry"]["services"]["https"].update(change)
    with pytest.raises(ValueError):
        Inventory.model_validate(raw)


def test_socks5_validates_utf8_credential_byte_length(inventory):
    raw = inventory.model_dump()
    raw["users"]["https"][0]["password"] = "я" * 130
    raw["hosts"]["de_entry"]["services"]["https"]["socks5"]["enabled"] = True
    with pytest.raises(ValueError, match="255 UTF-8 bytes"):
        Inventory.model_validate(raw)


def test_bundle_has_no_plaintext_secrets_and_is_idempotent(inventory, tmp_path):
    path = tmp_path / "bundle.json"
    write_bundle(inventory, path)
    original = path.read_bytes()
    modified = path.stat().st_mtime_ns
    for secret in ("alice", "bob", "tun-db", "café-long-password:123", "private-key-secret", "ssh-password-secret", "machine-chain-secret", "/secret/admin-key", "ssh-ed25519", "knock.example"):
        assert secret not in original.decode()
    assert path.stat().st_mode & 0o777 == 0o600
    write_bundle(inventory, path)
    assert path.read_bytes() == original
    assert path.stat().st_mtime_ns == modified
    bundle = json.loads(original)
    alice = inventory.users.https[0]
    document = render_config(bundle, alice.name, alice.password)
    assert document["version"] == 8
    assert len(document["profiles"]) == 9
    for item in document["profiles"]:
        proxy = item["proxy"]
        assert proxy["username"] in {"alice", "tun-alice", "tun-db"}
        if proxy["type"] == "HTTPS":
            assert proxy["password"] == alice.password
        if "jump" in proxy:
            assert proxy["jump"]["username"] in alice.ssh_users
    assert "private-key-secret" in json.dumps(document)
    bob = inventory.users.https[1]
    assert all(item["proxy"]["type"] == "HTTPS" for item in render_config(bundle, bob.name, bob.password)["profiles"])


def test_password_rotation_and_tampered_ciphertext_fail_closed(inventory):
    original = build_bundle(inventory)
    alice = inventory.users.https[0]
    tampered = deepcopy(original)
    entry = tampered["users"][user_id(alice.name)]
    entry["ciphertext"] = (bytes.fromhex(entry["ciphertext"])[0] ^ 1).to_bytes(1).hex() + entry["ciphertext"][2:]
    with pytest.raises(AccessDenied):
        render_config(tampered, alice.name, alice.password)
    previous_password = alice.password
    alice.password = "new-user-password-456"
    updated = build_bundle(inventory, original)
    with pytest.raises(AccessDenied):
        render_config(updated, alice.name, previous_password)
    assert "private-key-secret" in json.dumps(render_config(updated, alice.name, alice.password))
    inventory.users.https = [alice]
    assert user_id("bob") not in build_bundle(inventory, updated)["users"]


def test_profile_ids_survive_title_and_endpoint_changes(inventory):
    alice = inventory.users.https[0]
    original = render_config(build_bundle(inventory), alice.name, alice.password)
    inventory.hosts["de_entry"].services.https.title = "Renamed entry"
    inventory.hosts["de_entry"].services.https.endpoint = "new-entry.example"
    inventory.hosts["de_entry"].address = "192.0.2.99"
    updated = render_config(build_bundle(inventory), alice.name, alice.password)
    assert [item["id"] for item in original["profiles"]] == [item["id"] for item in updated["profiles"]]
    assert original["profiles"][0]["name"] != updated["profiles"][0]["name"]


def test_https_titles_do_not_follow_host_names(inventory):
    inventory.hosts["proxy_de"] = inventory.hosts.pop("de_entry")
    inventory.settings.https_chain_pairs[0].entry = "proxy_de"
    inventory.settings.ssh_jump_pairs[0].entry = "proxy_de"
    inventory.hosts["us_exit"].services.https.title = "US custom title"
    alice = inventory.users.https[0]
    document = render_config(build_bundle(inventory), alice.name, alice.password)
    profiles = [p for p in document["profiles"] if p["proxy"]["type"] == "HTTPS"]
    assert [(p["name"], p["countryCode"]) for p in profiles] == [
        ("US custom title", "US"), ("DE ENTRY", "DE"), ("DE ENTRY", "US"),
    ]
    assert [p["color"] for p in profiles] == [0, 1, 6]
    assert profiles[1]["browser"]["knockHost"] == "knock.example"


def test_ssh_titles_are_independent_and_preserve_ids(inventory, tmp_path):
    raw = inventory.model_dump()
    raw["users"]["ssh"] = raw["users"]["ssh"][:2]
    inventory = Inventory.model_validate(raw)
    inventory.hosts["de_entry"].services.ssh.title = "SSH Entry"
    inventory.hosts["us_exit"].services.https.title = "US custom title"
    alice = inventory.users.https[0]
    original = render_config(build_bundle(inventory), alice.name, alice.password)
    ssh = [p for p in original["profiles"] if p["proxy"]["type"] == "SSH"]
    assert [p["name"] for p in ssh] == ["SSH Entry"] * 2 + ["US EXIT"] * 2
    from megaproxy_server.export import export_profiles
    output = tmp_path / "export.json"
    export_profiles(inventory, output)
    exported = json.loads(output.read_text())
    assert [p["name"] for p in exported["profiles"] if p["proxy"]["type"] == "SSH"] == [
        "SSH Entry / tun-alice", "SSH Entry / tun-db",
        "US EXIT / tun-alice", "US EXIT / tun-db",
    ]
    inventory.hosts["de_entry"].services.ssh.title = "Renamed SSH"
    inventory.hosts["us_exit"].services.https.title = "Renamed HTTPS"
    changed = render_config(build_bundle(inventory), alice.name, alice.password)
    assert [p["name"] for p in changed["profiles"] if p["proxy"]["type"] == "SSH"] == ["Renamed SSH"] * 2 + ["US EXIT"] * 2
    assert [p["id"] for p in changed["profiles"]] == [p["id"] for p in original["profiles"]]
    export_profiles(inventory, output)
    assert [p["id"] for p in json.loads(output.read_text())["profiles"]] == [p["id"] for p in exported["profiles"]]


def test_http_access_robots_and_conditional_authentication(inventory, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    write_bundle(inventory, path)
    url = public_url(inventory.hosts["configs_one"].services.config_api)
    server = serve(path, 0, "/api/config", url)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    alice = inventory.users.https[0]
    authorization = "Basic " + base64.b64encode(f"{alice.name}:{alice.password}".encode()).decode()

    def request(method="GET", target="/api/config", headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(method, target, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        assert result[1]["X-Robots-Tag"] == "noindex, nofollow, noarchive"
        assert result[1]["Cache-Control"] == "private, no-store"
        assert "WWW-Authenticate" not in result[1]
        return result
    try:
        for method, target, headers in [
            ("GET", "/", {}), ("GET", "/api/config", {}),
            ("GET", "/api/config?x=1", {"Authorization": authorization}),
            ("GET", "/api/config/", {"Authorization": authorization}),
            ("GET", "//api/config", {"Authorization": authorization}),
            ("GET", "/api/../api/config", {"Authorization": authorization}),
            ("GET", "/%61pi/config", {"Authorization": authorization}),
            ("POST", "/api/config", {"Authorization": authorization}),
            ("HEAD", "/api/config", {"Authorization": authorization}),
            ("CONNECT", "/api/config", {"Authorization": authorization}),
            ("BREW", "/api/config", {"Authorization": authorization}),
            ("GET", "/api/config", {"Authorization": "Basic !invalid"}),
            ("GET", "/api/config", {"Authorization": "Basic " + base64.b64encode(b"alice:wrong-password").decode()}),
            ("GET", "/api/config", {"Authorization": "Basic " + base64.b64encode(b"unknown:wrong-password").decode()}),
            ("GET", "/api/config", {"Authorization": authorization, "Content-Length": "1"}),
        ]:
            assert request(method, target, headers)[0] == 403
        status, headers, body = request(target="/robots.txt")
        assert status == 200 and body == config_api.ROBOTS
        assert request(target="/robots.txt?x=1")[0] == 403
        status, headers, body = request(headers={"Authorization": authorization})
        assert status == 200
        document = json.loads(body)
        validate_config(document)
        assert document["subscription"]["url"] == url
        assert document["subscription"]["fallbackUrls"] == ["https://[2001:db8::4]/api/config"]
        assert document["subscription"]["password"] == alice.password
        etag = headers["ETag"]
        assert request(headers={"Authorization": authorization, "If-None-Match": etag})[0] == 304
        assert request(headers={"Authorization": "Basic YWxpY2U6d3Jvbmc=", "If-None-Match": etag})[0] == 403
        status, headers, body = request(headers={"Authorization": authorization, "X-MegaProxy-Client": "browser_chromium", "If-None-Match": etag})
        assert status == 200 and headers["ETag"] != etag
        assert all(item["proxy"]["type"] == "HTTPS" for item in json.loads(body)["profiles"])
        assert "private-key-secret" not in body.decode()
        assert request(headers={"Authorization": authorization, "X-MegaProxy-Version": "new", "If-None-Match": etag})[0] == 200
        # A freshly replaced bundle is read by the next request, without retaining old secrets.
        inventory.users.https[0].password = "rotated-password-789"
        write_bundle(inventory, path)
        assert request(headers={"Authorization": authorization})[0] == 403
        inventory.users.https[0].client_config = {"passwordsIncluded": False, "privateKeysIncluded": False}
        write_bundle(inventory, path)
        current_auth = "Basic " + base64.b64encode(b"alice:rotated-password-789").decode()
        status, headers, before = request(headers={"Authorization": current_auth})
        assert status == 200
        previous_tag = headers["ETag"]
        inventory.users.https[0].password = "another-password-456"
        write_bundle(inventory, path)
        current_auth = "Basic " + base64.b64encode(b"alice:another-password-456").decode()
        status, headers, after = request(headers={"Authorization": current_auth, "If-None-Match": previous_tag})
        assert status == 200 and after == before and headers["ETag"] != previous_tag
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("client", ["", "android", "android_megaproxy", "browser_chromium", "browser_firefox", "unknown"])
def test_api_omits_local_defaults_and_app_routing(inventory, client):
    alice = inventory.users.https[0]
    bundle = build_bundle(inventory)
    document = render_config(bundle, alice.name, alice.password, client, url=bundle["urls"][0])
    validate_config(document)
    assert not {"routing", "tls", "ssh", "failover", "diagnosticLogLimitMb"} & document.keys()
    assert all(not {"routing", "tls", "dns"} & item.keys() for item in document["profiles"])
    assert document["subscription"]["fallbackUrls"] == bundle["urls"][1:]
    inventory.settings.client_config = {
        "routing": {"routeAllApps": True, "selectedPackages": []},
        "profiles": [{"id": "manual", "proxy": {"type": "HTTPS", "host": "manual.example", "port": 443},
                      "routing": {"routeAllApps": True, "selectedPackages": []}}],
    }
    inventory.hosts["de_entry"].services.https.client_profile = {"routing": {"routeAllApps": True}}
    document = render_config(build_bundle(inventory), alice.name, alice.password, client)
    validate_config(document)
    assert "routing" not in document
    assert all("routing" not in item for item in document["profiles"])


def test_all_config_fields_and_client_projection(inventory):
    inventory.settings.client_config = {
        "activeProfileId": "manual-jump", "alwaysOnProfileId": "manual-masque", "diagnosticLogLimitMb": 20,
        "tls": {"fingerprint": "CUSTOM", "customJa3": "771,4865-4866-4867,0-10-13-16-43-51,29-23,0"},
        "ssh": {"fingerprint": "OPENSSH_TERMUX", "authMode": "KEY_ONLY", "keepaliveSeconds": 30, "maxChannels": 32, "rotationMinutes": 15, "rotationMb": 256},
        "failover": {"mode": "SELECTED", "profileIds": ["manual-jump", "manual-masque"]},
        "routing": {"routeAllApps": False, "selectedPackages": ["org.example.app"], "bypassLocalNetworks": False},
        "browser": {"theme": "dark", "language": "ru", "webRTC": "proxy_only", "routing": {
            "enabled": True, "mode": "tabs", "strategy": "tabs", "domains": ["**.example.com"], "sites": ["site.example.com"],
            "subscriptions": {"domainSources": ["youtube"], "siteSources": ["discord"], "autoUpdate": True, "throughProxy": True},
            "assignments": [{"domain": "example.com", "profileId": "manual-jump", "includeSubdomains": True}]}},
        "profiles": [
            {"id": "manual-jump", "name": "Jump", "proxy": {"type": "HTTPS_JUMP", "host": "dst.example", "port": 443, "preferHttp3": True, "jump": {"host": "jump.example", "port": 443, "sameAuthentication": True}}},
            {"id": "manual-socks", "proxy": {"type": "SOCKS5", "host": "socks.example", "port": 1080}},
            {"id": "manual-masque", "proxy": {"type": "MASQUE", "host": "quic.example", "port": 443},
             "tls": {"fingerprint": "CUSTOM", "customJa3": "771,4865-4866-4867,0-10-13-16-43-51-57,29-23,0"},
             "browser": {"masqueTemplate": "/.well-known/masque/udp/{target_host}/{target_port}/"}},
        ],
    }
    inventory.hosts["de_entry"].services.https.client_profile = {
        "proxy": {"preferHttp3": False}, "dns": {"provider": "CUSTOM", "customDohUrl": "https://dns.example/dns-query"},
        "browser": {"bypass": ["intranet.example"], "authMode": "challenge"},
        "routing": {"allowIpv6": True, "bypassLocalNetworks": False}}
    bundle = build_bundle(inventory)
    alice = inventory.users.https[0]
    full = render_config(bundle, alice.name, alice.password)
    validate_config(full)
    assert {item["proxy"]["type"] for item in full["profiles"]} == {"HTTPS", "SSH", "SSH_JUMP", "HTTPS_JUMP", "SOCKS5", "MASQUE"}
    assert not {"activeProfileId", "alwaysOnProfileId", "ssh", "failover", "browser", "diagnosticLogLimitMb", "routing"} & full.keys()
    assert all("dns" not in item and "routing" not in item for item in full["profiles"])
    assert "bypass" not in full["profiles"][0]["browser"]
    assert full["profiles"][0]["browser"]["authMode"] == "challenge"
    assert full["profiles"][0]["browser"]["knockHost"] == "knock.example"
    assert full["tls"]["customJa3"] != full["profiles"][-1]["tls"]["customJa3"]
    browser = render_config(bundle, alice.name, alice.password, "browser_firefox")
    assert {item["proxy"]["type"] for item in browser["profiles"]} == {"HTTPS", "SOCKS5"}
    assert "activeProfileId" not in browser and "browser" not in browser
    assert "browser" not in render_config(bundle, alice.name, alice.password, "android")
    baseline = json.loads((Path(__file__).parents[1] / "schemas/android-v8.schema.json").read_text())
    Draft202012Validator(baseline).validate(render_config(bundle, alice.name, alice.password, "android"))


@pytest.mark.parametrize("override", [{"tls": {"fingerprint": "INVALID"}}, {"subscription": {"url": "https://untrusted.example"}}, {"profiles": [{"id": "bad", "proxy": {"type": "HTTP", "host": "example.com", "port": 80}}]}])
def test_invalid_config_fields_fail_before_deployment(inventory, override):
    inventory.settings.client_config = override
    with pytest.raises(ValueError):
        build_bundle(inventory)


def test_extra_ssh_profiles_cannot_bypass_account_links(inventory):
    inventory.users.https[1].client_config = {"profiles": [{
        "id": "unlinked-ssh", "proxy": {"type": "SSH", "host": "external.example", "port": 22,
                                        "username": "tun-alice", "privateKey": "must-not-be-published"}}]}
    with pytest.raises(ValueError, match="explicitly linked SSH accounts"):
        build_bundle(inventory)


def test_api_only_host_and_ansible_bundle_preparation(inventory, tmp_path, monkeypatch):
    assert inventory.hosts["configs_one"].services.https is None
    assert public_url(inventory.hosts["configs_two"].services.config_api) == "https://[2001:db8::4]/api/config"
    projected = ansible_inventory(inventory)["all"]["hosts"]["configs_one"]
    assert projected["megaproxy_config_api_url"] == "https://configs.example/api/config"
    import megaproxy_server.inventory as module
    monkeypatch.setattr(module, "ROOT", tmp_path)
    generated = write_ansible_inventory(tmp_path / "inventory.yml", inventory, prepare_services=True)
    assert generated.with_suffix(".config-api.json").is_file()


def test_bootstrap_pause_and_secret_export_preferences(inventory):
    inventory.users.https[0].client_config = {
        "passwordsIncluded": False, "privateKeysIncluded": False,
        "subscription": {"enabled": False, "intervalMinutes": 15},
    }
    bundle = build_bundle(inventory)
    alice = inventory.users.https[0]
    document = render_config(bundle, alice.name, alice.password, url=bundle["urls"][0])
    assert document["subscription"]["enabled"] is False
    assert document["subscription"]["intervalMinutes"] == 15
    assert "password" not in document["subscription"]
    for item in document["profiles"]:
        for node in (item["proxy"], item["proxy"].get("jump", {})):
            assert "password" not in node and "privateKey" not in node
    inventory.users.https[0].client_config = {"subscription": None}
    bundle = build_bundle(inventory)
    assert render_config(bundle, alice.name, alice.password, url=bundle["urls"][0])["subscription"]["url"] == bundle["urls"][0]


def test_schema_lock_is_pinned_and_matches_committed_files():
    directory = Path(__file__).parents[1] / "schemas"
    lock = json.loads((directory / "megaproxy-config.lock.json").read_text())
    assert len(lock["commit"]) == 40
    for filename, digest in lock["sha256"].items():
        assert hashlib.sha256((directory / filename).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("changes", [
    {"endpoint": "192.0.2.1", "certificate": "domain"},
    {"endpoint": "configs.example", "certificate": "ip-acme"},
    {"certificate": "self-signed"}, {"endpoint": "bad;host"},
    {"path": "/robots.txt"}, {"path": "/api/config?token=1"},
    {"backend_port": 80}, {"port": 80}, {"interval_minutes": 10081},
])
def test_api_requires_safe_https_settings(changes):
    with pytest.raises(ValueError):
        ConfigApiService.model_validate({"endpoint": "configs.example", "acme_email": "a@example.com", **changes})


def test_disabled_api_only_host_can_be_kept_for_teardown(inventory):
    raw = inventory.model_dump()
    raw["hosts"] = {"configs_one": raw["hosts"]["configs_one"]}
    raw["settings"]["ssh_jump_pairs"] = []
    raw["settings"]["https_chain_pairs"] = []
    raw["hosts"]["configs_one"]["services"]["config_api"]["enabled"] = False
    Inventory.model_validate(raw)
