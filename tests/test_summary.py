from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services, Settings, SshAuthentication, SshService, SshUser
from megaproxy_server.summary import render_summary


def sample_inventory() -> Inventory:
    admin = AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin")
    return Inventory(settings=Settings(
        https_chains_enabled=True,
        https_chain_domain="chains.example",
        https_chain_pairs=[{"entry": "one", "exit": "two", "country_code": "US", "hostname": "chain.example", "title": "ONE -> TWO"}],
    ), hosts={
        "one": Host(address="192.0.2.1", admin=admin, services=Services(
            https=HttpsService(endpoint="proxy.example", title="ONE", certificate="domain", acme_email="a@example.com", users=[HttpsUser(name="alice", password="alice-password-long")], chain_entry=True),
            ssh=SshService(users=[SshUser(name="mp-alice", authentication=SshAuthentication(type="password", password="ssh-password-long", password_hash="$6$secret-hash"))]),
        )),
        "two": Host(address="192.0.2.2", admin=admin, services=Services(
            https=HttpsService(endpoint="proxy-two.example", title="TWO", certificate="domain", acme_email="a@example.com", users=[HttpsUser(name="bob", password="bob-password-long")], chain_exit=True, chain_password="machine-password-long"),
            ssh=SshService(users=[SshUser(name="mp-bob", authentication=SshAuthentication(type="key", public_key="ssh-ed25519 AAAA", generated_private_key="/keys/bob"))]),
        )),
    })


def test_summary_lists_hosts_then_global_credentials_once() -> None:
    output = render_summary(sample_inventory())
    assert "proxy.example (ONE, HTTPS, SSH)" in output
    assert "proxy-two.example (TWO, HTTPS, SSH)" in output
    assert "chain.example (ONE -> TWO, HTTPS)" in output
    assert output.count("alice-password-long") == 1
    assert output.count("ssh-password-long") == 1
    assert "/keys/bob" in output
    assert "$6$secret-hash" not in output
    assert "MegaProxy Admin" not in output
    assert output.index("Hosts:") < output.index("HTTPS:") < output.index("SSH:")


def test_summary_filters_exact_login_without_hiding_hosts() -> None:
    output = render_summary(sample_inventory(), "alice")
    assert "proxy.example" in output
    assert "chain.example" in output
    assert "alice-password-long" in output
    assert "mp-alice" not in output
    assert "bob-password-long" not in output


def test_summary_returns_empty_for_unknown_login() -> None:
    assert render_summary(sample_inventory(), "nobody") == ""
