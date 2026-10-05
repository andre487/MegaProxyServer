#!/usr/bin/env bash
set -euo pipefail

image=${1:-ubuntu:24.04}
host_count=${2:-1}
work_dir=$(mktemp -d)
key_file="$work_dir/ci_ed25519"
inventory_file="$work_dir/inventory.yml"
instances=()

# LXD guests need forwarding through the managed bridge. Some GitHub runner images default to DROP.
sudo iptables -P FORWARD ACCEPT
sudo ip6tables -P FORWARD ACCEPT

cleanup() {
  for instance in "${instances[@]}"; do
    sudo lxc delete --force "$instance" >/dev/null 2>&1 || true
  done
  rm -rf "$work_dir"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "$key_file"
public_key=$(<"$key_file.pub")

launch_host() {
  local name=$1
  sudo lxc launch "$image" "$name" \
    -c security.nesting=true \
    -c security.privileged=true
  instances+=("$name")

  for _ in $(seq 1 60); do
    if sudo lxc exec "$name" -- sh -c 'systemctl is-system-running >/dev/null 2>&1 || systemctl is-system-running | grep -q degraded'; then
      break
    fi
    sleep 2
  done

  # GitHub-hosted runners may block plain HTTP from nested LXD guests.
  sudo lxc exec "$name" -- sh -c \
    "sed -i 's|http://|https://|g' /etc/apt/sources.list 2>/dev/null || true; sed -i 's|http://|https://|g' /etc/apt/sources.list.d/*.sources 2>/dev/null || true"
  sudo lxc exec "$name" -- apt-get update -o APT::Update::Error-Mode=any
  sudo lxc exec "$name" -- env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssh-server sudo curl
  sudo lxc exec "$name" -- install -d -m 0700 /root/.ssh
  printf '%s\n' "$public_key" | sudo lxc exec "$name" -- tee /root/.ssh/authorized_keys >/dev/null
  sudo lxc exec "$name" -- chmod 0600 /root/.ssh/authorized_keys
  sudo lxc exec "$name" -- systemctl enable --now ssh
}

host_ip() {
  sudo lxc list "$1" -c 4 --format csv | awk '{print $1}'
}

launch_host megaproxy-ci-one
ip_one=$(host_ip megaproxy-ci-one)
if [[ "$host_count" -ge 2 ]]; then
  launch_host megaproxy-ci-two
  ip_two=$(host_ip megaproxy-ci-two)
fi

for instance in "${instances[@]}"; do
  address=$(host_ip "$instance")
  for _ in $(seq 1 30); do
    ssh-keyscan -T 2 -H "$address" >> "$work_dir/known_hosts" 2>/dev/null && break
    sleep 1
  done
done
export ANSIBLE_HOST_KEY_CHECKING=True
export ANSIBLE_SSH_ARGS="-o UserKnownHostsFile=$work_dir/known_hosts"

# ProxyJump's child ssh reads -F too, but does not inherit command-line -i/-o options.
cat > "$work_dir/ssh_config" <<EOF
Host *
  IdentityFile $key_file
  IdentitiesOnly yes
  UserKnownHostsFile $work_dir/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
EOF

{
  printf '%s\n' 'version: 1' 'settings:' '  manage_firewall: true' '  unattended_upgrades: true' 'hosts:'
  printf '%s\n' '  one:' "    address: $ip_one" '    admin:' '      user: ci-admin' '      bootstrap_user: root' '      port: 22' "      private_key_file: $key_file" "      public_key: \"$public_key\"" '    services:'
  printf '%s\n' '      https:' '        endpoint: '"$ip_one" '        certificate: self-signed' '        users:' '          - name: ci-user' '            password: ci-password-is-long-and-random' '        probe_resistance:' '          enabled: true'
  printf '%s\n' '      ssh:' '        port: 22' '        users:' '          - name: mp-ci' '            authentication:' '              type: key' "              public_key: \"$public_key\"" "              generated_private_key: $key_file"
  if [[ "$host_count" -ge 2 ]]; then
    printf '%s\n' '  two:' "    address: $ip_two" '    admin:' '      user: ci-admin' '      bootstrap_user: root' '      port: 22' "      private_key_file: $key_file" "      public_key: \"$public_key\"" '    services:' '      ssh:' '        port: 22' '        users:' '          - name: mp-ci' '            authentication:' '              type: key' "              public_key: \"$public_key\"" "              generated_private_key: $key_file"
  fi
} > "$inventory_file"
chmod 0600 "$inventory_file"

./mega-proxy --inventory "$inventory_file" apply
./mega-proxy --inventory "$inventory_file" verify

for instance in "${instances[@]}"; do
  sudo lxc exec "$instance" -- sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -x 'permitrootlogin no' >/dev/null
  sudo lxc exec "$instance" -- sshd -T -C user=ci-admin,host=localhost,addr=127.0.0.1 | grep -x 'passwordauthentication no' >/dev/null
  sudo lxc exec "$instance" -- sshd -T -C user=mp-ci,host=localhost,addr=127.0.0.1 | grep -x 'passwordauthentication yes' >/dev/null
done

second_run="$work_dir/second-run.log"
./mega-proxy --inventory "$inventory_file" apply | tee "$second_run"
if grep -Eq 'changed=[1-9][0-9]*' "$second_run"; then
  echo "The second provisioning run was not idempotent" >&2
  exit 1
fi

control_socket="$work_dir/direct-control"
printf '%s\n' 'LogLevel DEBUG1' | sudo lxc exec megaproxy-ci-one -- tee /etc/ssh/sshd_config.d/00-ci-debug.conf >/dev/null
sudo lxc exec megaproxy-ci-one -- systemctl reload ssh
if ! ssh -vvv -fNT -M -S "$control_socket" -i "$key_file" -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o UserKnownHostsFile="$work_dir/known_hosts" -L 18443:example.com:443 "mp-ci@$ip_one"; then
  sudo lxc exec megaproxy-ci-one -- getent passwd mp-ci || true
  sudo lxc exec megaproxy-ci-one -- passwd -S mp-ci || true
  sudo lxc exec megaproxy-ci-one -- namei -l /etc/ssh/megaproxy_authorized_keys/mp-ci || true
  ssh-keygen -lf "$key_file.pub" || true
  sudo lxc exec megaproxy-ci-one -- ssh-keygen -lf /etc/ssh/megaproxy_authorized_keys/mp-ci || true
  sudo lxc exec megaproxy-ci-one -- sh -c "sshd -T -C user=mp-ci,host=localhost,addr=127.0.0.1 | grep -E 'authorizedkeysfile|authenticationmethods|pubkeyauthentication|allowtcpforwarding|maxsessions'" || true
  sudo lxc exec megaproxy-ci-one -- sh -c "journalctl -u ssh --since=-2min --no-pager | grep -E 'mp-ci|Authentication refused|bad ownership|auth_openkey' | sed -E 's/(from |port )[0-9a-fA-F:.]+/\1<redacted>/g'" || true
  exit 1
fi
echo | openssl s_client -connect 127.0.0.1:18443 -servername example.com -verify_return_error >/dev/null
ssh -S "$control_socket" -O exit "mp-ci@$ip_one"

if [[ "$host_count" -ge 2 ]]; then
  jump_socket="$work_dir/jump-control"
  if ! ssh -vvv -F "$work_dir/ssh_config" -fNT -M -S "$jump_socket" -o ExitOnForwardFailure=yes -o "ProxyJump=mp-ci@$ip_one" -L 19443:example.com:443 "mp-ci@$ip_two"; then
    sudo lxc exec megaproxy-ci-two -- journalctl -u ssh --since=-2min --no-pager
    sudo lxc exec megaproxy-ci-two -- namei -l /etc/ssh/megaproxy_authorized_keys/mp-ci
    exit 1
  fi
  echo | openssl s_client -connect 127.0.0.1:19443 -servername example.com -verify_return_error >/dev/null
  ssh -S "$jump_socket" -O exit "mp-ci@$ip_two"
fi

# Exercise on-server bootstrap with a new administrator, so the local account phase must run.
if [[ "$host_count" -eq 1 ]]; then
  sudo lxc exec megaproxy-ci-one -- mkdir -p /opt/megaproxy-server
  git archive HEAD | sudo lxc exec megaproxy-ci-one -- tar -xf - -C /opt/megaproxy-server
  sudo lxc file push "$(command -v uv)" megaproxy-ci-one/usr/local/bin/uv
  sudo lxc exec megaproxy-ci-one -- chmod +x /usr/local/bin/uv
  sudo lxc file push "$inventory_file" megaproxy-ci-one/opt/megaproxy-server/local.yml
  sudo lxc exec megaproxy-ci-one --cwd /opt/megaproxy-server -- uv run --frozen --python 3.12 python - <<'PY'
from pathlib import Path
from unittest.mock import patch

from megaproxy_server.inventory import load, save
from megaproxy_server.local_setup import setup_local
from megaproxy_server.secrets import generate_key

path = Path('local.yml').resolve()
inventory = load(path)
host = inventory.hosts['one']
host.local = True
host.admin.user = 'ci-local-admin'
host.admin.bootstrap_user = 'root'
public, private = generate_key(Path('/root/local-admin'), 'local setup test')
host.admin.public_key = public
host.admin.private_key_file = str(private)
for user in inventory.users.ssh:
    user.authentication.public_key = public
    user.authentication.generated_private_key = str(private)
save(path, inventory)
with patch('questionary.confirm') as confirm:
    confirm.return_value.ask.return_value = True
    assert setup_local(path) == 0
assert load(path).hosts['one'].admin.bootstrap_user is None
assert Path('.generated/configs/MegaProxy.json').is_file()
PY
  sudo lxc file pull megaproxy-ci-one/root/local-admin "$work_dir/local-admin"
  sudo chown "$(id -u):$(id -g)" "$work_dir/local-admin"
  chmod 0600 "$work_dir/local-admin"
  ssh -i "$work_dir/local-admin" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$work_dir/known_hosts" "ci-local-admin@$ip_one" 'sudo -n true'
fi
