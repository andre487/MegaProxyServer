from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services, SshAuthentication, SshService, SshUser
from megaproxy_server.summary import render_summary


def sample_inventory() -> Inventory:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    return Inventory(hosts={
        "one": Host(address="192.0.2.1", admin=admin, services=Services(
            https=HttpsService(endpoint="proxy.example", certificate="self-signed", users=[HttpsUser(name="alice", password="alice-password-long")]),
            ssh=SshService(users=[SshUser(name="mp-alice", authentication=SshAuthentication(type="password", password="ssh-password-long", password_hash="$6$secret-hash"))]),
        )),
        "two": Host(address="192.0.2.2", admin=admin, services=Services(
            https=HttpsService(endpoint="proxy-two.example", certificate="self-signed", users=[HttpsUser(name="bob", password="bob-password-long")]),
            ssh=SshService(users=[SshUser(name="mp-bob", authentication=SshAuthentication(type="key", public_key="ssh-ed25519 AAAA", generated_private_key="/keys/bob"))]),
        )),
    })


def test_summary_contains_passwords_but_not_hashes() -> None:
    output = render_summary(sample_inventory())
    assert "alice-password-long" in output
    assert "ssh-password-long" in output
    assert "/keys/bob" in output
    assert "$6$secret-hash" not in output
    assert "MegaProxy Admin" in output


def test_summary_filters_exact_login() -> None:
    output = render_summary(sample_inventory(), "alice")
    assert "proxy.example" in output
    assert "proxy-two.example" in output
    assert "mp-alice" not in output


def test_summary_returns_empty_for_unknown_login() -> None:
    assert render_summary(sample_inventory(), "nobody") == ""
