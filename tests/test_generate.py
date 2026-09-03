import json
import stat
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from megaproxy_server.generate import generate
from megaproxy_server.inventory import save
from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services


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
