import json
import stat
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from megaproxy_server.generate import generate
from megaproxy_server.inventory import load, save
from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services, Settings


def inventory_file(tmp_path: Path) -> Path:
    inventory = Inventory(
        hosts={
            "amsterdam": Host(
                address="192.0.2.10",
                admin=AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin"),
                services=Services(
                    https=HttpsService(
                        endpoint="proxy.example",
                        port=8443,
                        certificate="self-signed",
                        users=[HttpsUser(name="user-one", password="long p@ssword:1234")],
                    )
                ),
            )
        }
    )
    path = tmp_path / "inventory.yml"
    save(path, inventory)
    return path


def test_generates_all_four_formats_and_is_idempotent(tmp_path: Path) -> None:
    source = inventory_file(tmp_path)
    output = tmp_path / "configs"
    assert generate(source, output) is True
    assert generate(source, output) is False
    assert {path.name for path in output.iterdir()} == {
        "MegaProxy.json", "FoxyProxy.json", "SuperProxy.txt", "ProxyList.txt"
    }
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())


def test_generated_formats_contain_https_credentials(tmp_path: Path) -> None:
    source = inventory_file(tmp_path)
    output = tmp_path / "configs"
    generate(source, output)

    megaproxy = json.loads((output / "MegaProxy.json").read_text())
    assert megaproxy["schema"] == "dev.megaproxy.config"
    assert megaproxy["profiles"][0]["proxy"]["type"] == "HTTPS"

    foxy = json.loads((output / "FoxyProxy.json").read_text())
    assert foxy["data"][0]["type"] == "https"
    assert foxy["data"][0]["password"] == "long p@ssword:1234"

    proxy_line = (output / "ProxyList.txt").read_text().strip()
    parsed = urlsplit(proxy_line)
    assert parsed.username == "user-one"
    assert unquote(parsed.password or "") == "long p@ssword:1234"
    assert parse_qs(parsed.query)["title"] == ["amsterdam / user-one"]

    super_proxy = (output / "SuperProxy.txt").read_text().splitlines()
    assert super_proxy == ["# superproxy:proxylist:v1", proxy_line]


def test_https_service_title_names_direct_client_profiles(tmp_path: Path) -> None:
    source = inventory_file(tmp_path)
    inventory = load(source)
    inventory.hosts["amsterdam"].services.https.title = "AM2"
    save(source, inventory)
    output = tmp_path / "configs"

    generate(source, output)

    megaproxy = json.loads((output / "MegaProxy.json").read_text())
    assert megaproxy["profiles"][0]["name"] == "AM2 / user-one"
    foxy = json.loads((output / "FoxyProxy.json").read_text())
    assert foxy["data"][0]["title"] == "AM2 / user-one"


def test_chain_pair_title_is_used_in_all_client_formats(tmp_path: Path) -> None:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    user = HttpsUser(name="user-one", password="long-password-value")
    inventory = Inventory(
        settings=Settings(
            https_chains_enabled=True,
            https_chain_domain="chains.example",
            https_chain_pairs=[
                {"entry": "entry_proxy", "exit": "exit_proxy", "title": "Amsterdam via Turkey"}
            ],
        ),
        hosts={
            "entry_proxy": Host(address="entry.example", admin=admin, services=Services(https=HttpsService(endpoint="entry.example", certificate="domain", acme_email="a@example.com", users=[user], chain_entry=True, direct=False))),
            "exit_proxy": Host(address="exit.example", admin=admin, services=Services(https=HttpsService(endpoint="exit.example", certificate="domain", acme_email="a@example.com", users=[user], chain_exit=True, chain_password="machine-password-long"))),
        },
    )
    source = tmp_path / "inventory.yml"
    output = tmp_path / "configs"
    save(source, inventory)

    generate(source, output)

    megaproxy = json.loads((output / "MegaProxy.json").read_text())
    chain_profile = next(profile for profile in megaproxy["profiles"] if profile["proxy"]["host"].endswith("chains.example"))
    assert chain_profile["name"] == "Amsterdam via Turkey / user-one"
    foxy = json.loads((output / "FoxyProxy.json").read_text())
    chain_entry = next(entry for entry in foxy["data"] if entry["hostname"].endswith("chains.example"))
    assert chain_entry["title"] == "Amsterdam via Turkey / user-one"
