from megaproxy_server.models import AdminAccess, Host, HttpsService, HttpsUser, Inventory, Services, SshAuthentication, SshService, SshUser
from megaproxy_server.users import active_users, remove_users


def test_remove_https_and_ssh_users() -> None:
    inventory = Inventory(hosts={
        "one": Host(
            address="192.0.2.1",
            admin=AdminAccess(user="deploy", private_key_file="/keys/admin", public_key="ssh-ed25519 AAAA admin"),
            services=Services(
                https=HttpsService(
                    endpoint="proxy.example",
                    certificate="self-signed",
                    users=[HttpsUser(name="alice", password="long-password-alice"), HttpsUser(name="bob", password="long-password-bob")],
                ),
                ssh=SshService(users=[
                    SshUser(name="mp-alice", authentication=SshAuthentication(type="key", public_key="ssh-ed25519 AAAA alice")),
                    SshUser(name="mp-bob", authentication=SshAuthentication(type="key", public_key="ssh-ed25519 AAAA bob")),
                ]),
            ),
        )
    })
    refs = {item.label: item for item in active_users(inventory)}
    remove_users(inventory, [refs["ALL HOSTS / HTTPS / alice"], refs["ALL HOSTS / SSH / mp-alice"]])
    assert [user.name for user in inventory.hosts["one"].services.https.users] == ["bob"]
    assert [user.name for user in inventory.hosts["one"].services.ssh.users] == ["mp-bob"]
    assert inventory.hosts["one"].services.ssh.removed_users == ["mp-alice"]
