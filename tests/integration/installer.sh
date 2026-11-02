#!/usr/bin/env bash
set -euo pipefail
image=${1:-ubuntu:24.04}
guest=megaproxy-ci-installer
work_dir=$(mktemp -d)
cleanup() {
  sudo lxc delete --force "$guest" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT
sudo iptables -P FORWARD ACCEPT
sudo ip6tables -P FORWARD ACCEPT
sudo lxc launch "$image" "$guest" -c security.nesting=true -c security.privileged=true
for _ in $(seq 1 60); do
  state=$(sudo lxc exec "$guest" -- systemctl is-system-running || true)
  [[ "$state" == running || "$state" == degraded ]] && break
  sleep 2
done
sudo lxc exec "$guest" -- sh -c "sed -i 's|http://|https://|g' /etc/apt/sources.list 2>/dev/null || true; sed -i 's|http://|https://|g' /etc/apt/sources.list.d/*.sources 2>/dev/null || true"
# Clone the exact tested revision, including PR merge commits not available as a remote branch.
git clone --bare . "$work_dir/source.git"
git --git-dir="$work_dir/source.git" update-ref refs/heads/installer-ci HEAD
sudo lxc file push -r "$work_dir/source.git" "$guest/tmp/"
sudo lxc exec "$guest" -- chown -R root:root /tmp/source.git
sudo lxc file push install.sh "$guest/tmp/install.sh"
address=$(sudo lxc list "$guest" -c 4 --format csv | awk '{print $1}')
if ! expect tests/integration/installer.exp "$guest" "$address" "$work_dir/admin-key"; then
  sudo lxc exec "$guest" -- journalctl -u ssh -b --no-pager -n 40 || true
  sudo lxc exec "$guest" -- namei -l /home/megaproxy-admin/.ssh/authorized_keys || true
  sudo lxc exec "$guest" -- passwd -S megaproxy-admin || true
  sudo lxc exec "$guest" -- find /root /home -name authorized_keys -printf "%p %u %m\n" || true
  exit 1
fi
sudo chown "$(id -u):$(id -g)" "$work_dir/admin-key"
chmod 600 "$work_dir/admin-key"
sudo lxc exec "$guest" -- cat /etc/ssh/ssh_host_ed25519_key.pub | awk -v host="$address" '{print host " " $0}' > "$work_dir/known_hosts"
ssh -i "$work_dir/admin-key" -o BatchMode=yes -o IdentitiesOnly=yes -o UserKnownHostsFile="$work_dir/known_hosts" "megaproxy-admin@$address" 'sudo -n true; sudo sshd -T | grep -x "permitrootlogin no"'
sudo lxc exec "$guest" -- test -s /opt/megaproxy-server/.generated/configs/MegaProxy.json
sudo lxc exec "$guest" -- systemctl is-active gost-hashed-auth megaproxy-gost haproxy
sudo lxc exec "$guest" -- sh -c 'mkdir -p /tmp/installer-target; echo installer-ok > /tmp/installer-target/index.html'
sudo lxc exec "$guest" -- systemd-run --unit=installer-target python3 -m http.server 18082 --bind 127.0.0.1 --directory /tmp/installer-target
for _ in $(seq 1 20); do
  if response=$(curl --silent --show-error --fail --max-time 10 --noproxy '' --proxy-insecure --proxy "https://$address:443" --proxy-user installer-user:installer-test-password-only http://127.0.0.1:18082/); then
    [[ "$response" == installer-ok ]]
    break
  fi
  sleep 1
done
[[ "${response:-}" == installer-ok ]]
if curl --silent --fail --max-time 10 --noproxy '' --proxy-insecure --proxy "https://$address:443" --proxy-user installer-user:wrong-password http://127.0.0.1:18082/; then
  echo 'Incorrect proxy password accepted' >&2
  exit 1
fi
