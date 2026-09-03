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
  sudo lxc exec "$instance" -- sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -qx 'permitrootlogin no'
  sudo lxc exec "$instance" -- sshd -T -C user=ci-admin,host=localhost,addr=127.0.0.1 | grep -qx 'passwordauthentication no'
  sudo lxc exec "$instance" -- sshd -T -C user=mp-ci,host=localhost,addr=127.0.0.1 | grep -qx 'passwordauthentication yes'
done

second_run="$work_dir/second-run.log"
./mega-proxy --inventory "$inventory_file" apply | tee "$second_run"
if grep -Eq 'changed=[1-9][0-9]*' "$second_run"; then
  echo "The second provisioning run was not idempotent" >&2
  exit 1
fi

control_socket="$work_dir/direct-control"
ssh -fNT -M -S "$control_socket" -i "$key_file" -o UserKnownHostsFile="$work_dir/known_hosts" -L 18443:example.com:443 "mp-ci@$ip_one"
echo | openssl s_client -connect 127.0.0.1:18443 -servername example.com -verify_return_error >/dev/null
ssh -S "$control_socket" -O exit "mp-ci@$ip_one"

if [[ "$host_count" -ge 2 ]]; then
  jump_socket="$work_dir/jump-control"
  ssh -fNT -M -S "$jump_socket" -i "$key_file" -o UserKnownHostsFile="$work_dir/known_hosts" -o "ProxyJump=mp-ci@$ip_one" -L 19443:example.com:443 "mp-ci@$ip_two"
  echo | openssl s_client -connect 127.0.0.1:19443 -servername example.com -verify_return_error >/dev/null
  ssh -S "$jump_socket" -O exit "mp-ci@$ip_two"
fi
