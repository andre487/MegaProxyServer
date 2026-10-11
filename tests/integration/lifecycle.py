"""Exercise changes on an already provisioned LXD host, without creating more guests."""
import argparse
import os
import subprocess
from pathlib import Path

from megaproxy_server.inventory import load, save
from megaproxy_server.models import SshAuthentication, SshUser
from megaproxy_server.secrets import generate_key, password_hash
from megaproxy_server.users import UserRef, remove_users


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    source = load(args.inventory)
    host = source.hosts["one"]
    original = source.model_copy(deep=True)
    old_admin_key = host.admin.private_key_file
    old_proxy_key = source.users.ssh[0].authentication.generated_private_key
    public, admin_key = generate_key(args.work_dir / "rotated-admin", "CI admin rotation")
    _, proxy_key = generate_key(args.work_dir / "rotated-proxy", "CI proxy rotation")
    proxy_public = proxy_key.with_suffix(".pub").read_text().strip()
    environment = os.environ.copy()
    environment["SSH_ASKPASS_REQUIRE"] = "force"
    environment["DISPLAY"] = ":0"
    askpass = args.work_dir / "askpass"
    askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$MEGAPROXY_TEST_PASSWORD"\n')
    askpass.chmod(0o700)
    environment["SSH_ASKPASS"] = str(askpass)

    def ssh(user, key=None, *, password=None, forwarding=False):
        command = ["ssh", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=5",
                   "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.work_dir}/known_hosts"]
        if password is None:
            command += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", str(key)]
        else:
            command += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1"]
        command += (["-W", "127.0.0.1:18082"] if forwarding else []) + [f"{user}@{host.address}"]
        if not forwarding:
            command += ["sudo -n true"]
        return subprocess.run(command, input=b"GET / HTTP/1.0\r\n\r\n" if forwarding else None,
            capture_output=True, timeout=15, env=dict(environment, MEGAPROXY_TEST_PASSWORD=password or ""))

    def apply(tags):
        save(args.inventory, source)
        subprocess.run(["./mega-proxy", "--no-hooks", "-i", str(args.inventory), "apply", "--limit", "one", "--tags", tags], check=True)

    def tunnel(user, key=None, password=None, *, accepted=True):
        result = ssh(user, key, password=password, forwarding=True)
        if accepted:
            assert result.returncode == 0 and b"CI local target" in result.stdout, result.stderr
        else:
            assert result.returncode != 0 and b"CI local target" not in result.stdout

    host.admin.public_key = public
    host.admin.private_key_file = str(admin_key)
    host.admin.bootstrap_user = host.admin.user
    host.admin.bootstrap_private_key_file = old_admin_key
    apply("admin")  # Verify the new key before revoking the old one, without relying on multiplexing.
    source = load(args.inventory)
    host = source.hosts["one"]
    save(args.inventory, source)
    assert ssh(host.admin.user, admin_key).returncode == 0
    assert ssh(host.admin.user, old_admin_key).returncode != 0
    source.users.ssh[0].authentication.public_key = proxy_public
    source.users.ssh[0].authentication.generated_private_key = str(proxy_key)
    password = "ci-password-authentication-123"
    source.users.ssh.append(SshUser(name="mp-password", authentication=SshAuthentication(
        type="password", password=password, password_hash=password_hash(password))))
    apply("ssh")
    tunnel("mp-ci", proxy_key)
    tunnel("mp-ci", old_proxy_key, accepted=False)
    tunnel("mp-password", password=password)
    tunnel("mp-password", password="incorrect-password", accepted=False)
    rotated_password = "ci-rotated-password-456"
    source.users.ssh[-1].authentication = SshAuthentication(
        type="password", password=rotated_password, password_hash=password_hash(rotated_password))
    apply("ssh")
    tunnel("mp-password", password=rotated_password)
    tunnel("mp-password", password=password, accepted=False)
    remove_users(source, [UserRef("SSH", "mp-ci")])
    apply("ssh")
    tunnel("mp-ci", proxy_key, accepted=False)
    host.services.ssh.enabled = False
    host.services.https.enabled = False
    apply("ssh,https,firewall")
    tunnel("mp-password", password=rotated_password, accepted=False)
    assert ssh(host.admin.user, admin_key).returncode == 0
    state = subprocess.run(["sudo", "lxc", "exec", "megaproxy-ci-one", "--", "systemctl", "is-active", "megaproxy-gost"], capture_output=True)
    assert state.returncode != 0
    firewall = subprocess.check_output(["sudo", "lxc", "exec", "megaproxy-ci-one", "--", "ufw", "status"])
    assert b"443/tcp" not in firewall and b"22/tcp" in firewall
    # Leave the guest ready for the existing on-server setup scenario.
    original.hosts["one"].admin.public_key = public
    original.hosts["one"].admin.private_key_file = str(admin_key)
    original.users.removed_ssh.append("mp-password")
    source = original
    host = source.hosts["one"]
    apply("ssh,https,firewall")
    tunnel("mp-ci", old_proxy_key)
    print("Lifecycle passed: admin/proxy key rotation, real SSH passwords, removal, disable/re-enable and administrative access.")


if __name__ == "__main__":
    main()
