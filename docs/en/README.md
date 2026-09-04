# MegaProxyServer guide

[Русская версия](../ru/README.md) · [Project overview](../../README.md)

## Overview

MegaProxyServer provisions HTTPS and SSH proxies on multiple Debian or Ubuntu servers. The Python
CLI validates one inventory and produces Ansible variables, client configurations and a compact
credential summary. Ansible installs and maintains the server-side components.

HTTPS is provided by GOST in a pinned container. HAProxy routes TLS by SNI when one entry server
publishes several chain hostnames. SSH proxy users are restricted to local TCP forwarding and cannot
open a shell, TTY, subsystem, remote forwarding or tunnel device.

## Requirements

The control machine needs macOS or Linux, `uv`, OpenSSH and Python 3.12+. Managed machines need a
current Debian or Ubuntu release and a sudo-capable SSH account. Open TCP 443 for HTTPS and TCP 80
during standalone ACME validation in both the provider firewall and the host firewall.

Public-IP ACME certificates require Certbot 5.4+ and Let's Encrypt's short-lived profile.

## First deployment

```shell
./mega-proxy inventory
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

The wizard can create administrative keys, proxy credentials and an encrypted inventory. An
inventory outside the repository is remembered in the ignored `inventory-path` file. Override it
at any time with `--inventory PATH`.

For bootstrap, `admin.bootstrap_user` is used for the initial connection. A successful full apply
creates the permanent administrator, installs its key and removes `bootstrap_user` from inventory.
Keep the original SSH session open until the permanent login has been tested.

## CLI reference

| Command | Purpose |
| --- | --- |
| `inventory` | Create an inventory interactively |
| `validate` | Validate the data model and Ansible syntax |
| `plan` | Run provisioning in check/diff mode |
| `apply` | Provision or update servers |
| `verify` | Verify a completed deployment |
| `summary [LOGIN]` | Print endpoints and global proxy credentials |
| `configs` | Generate all supported client formats |
| `export [--all-jumps]` | Export MegaProxy JSON |
| `jumps` | List possible directed SSH jump combinations |
| `remove-users` | Mark global proxy users for removal |
| `vault-secrets` | Encrypt secret inventory fields |
| `check` | Run the local/CI test suite |

`plan`, `apply` and `verify` accept `--limit HOST` and `--tags`. Provisioning tags are `common`,
`admin`, `firewall`, `ssh` and `https`:

```shell
./mega-proxy apply --limit proxy_eu --tags https
```

Pass `--no-hooks` before or after the command to skip local post-change integrations.

## Inventory

Start from [`inventory.example.yml`](../../inventory.example.yml). Proxy users are global and are
installed on every host where their service is enabled. This prevents credentials for one login
from silently diverging between servers.

```yaml
version: 1
settings:
  manage_firewall: true
  unattended_upgrades: true
  https_chains_enabled: true
  https_chain_domain: chains.example.com
  https_chain_backend_port: 10443
  https_chain_pairs:
    - entry: entry_eu
      exit: exit_us
      country_code: US
      hostname: eu-via-us.example.com
      title: EU -> US

users:
  https:
    - name: alice
      password: REPLACE_WITH_AT_LEAST_16_CHARACTERS
  ssh:
    - name: tun-alice
      authentication:
        type: key
        public_key: ssh-ed25519 REPLACE_WITH_PUBLIC_KEY
        generated_private_key: ~/.ssh/megaproxy_alice
  removed_ssh: []

hosts:
  entry_eu:
    address: 203.0.113.10
    admin:
      user: deploy
      bootstrap_user: root
      port: 22
      private_key_file: ~/.ssh/id_ed25519
      public_key: ssh-ed25519 REPLACE_WITH_ADMIN_PUBLIC_KEY
    services:
      https:
        endpoint: proxy-eu.example.com
        title: EU
        certificate: domain
        acme_email: admin@example.com
        chain_entry: true
        chain_exit: false
        direct: true
      ssh:
        port: 22
```

### Global settings

- `manage_firewall`: manage UFW rules.
- `unattended_upgrades`: enable automatic security updates.
- `https_chains_enabled`: enable HTTPS entry/exit routes.
- `https_chain_domain`: base domain for automatically generated chain names.
- `https_chain_backend_port`: first loopback port allocated to chain backends.
- `https_chain_pairs`: optional route allow-list. Every declared pair requires the exit proxy's
  two-letter `country_code` and may override `hostname` and `title`.

An empty `https_chain_pairs` creates every compatible entry-to-exit combination. A non-empty list
creates only the declared pairs.

### HTTPS service

- `endpoint`: public DNS name or IP address.
- `title`: display name for px-manager, summary and client exports.
- `port`: public port; default `443`.
- `certificate`: `domain`, `ip-acme` or `self-signed`.
- `acme_email`: required for `domain` and `ip-acme`.
- `gost_version` and `certbot_version`: pinned container versions.
- `chain_entry` and `chain_exit`: allow participation in HTTPS chains.
- `direct`: expose the host's own direct HTTPS route.
- `chain_username` and `chain_password`: machine credentials between chain nodes. Every exit needs a
  password; it is excluded from user-facing exports.
- `probe_resistance`: optional decoy response for unauthenticated requests. It is disabled by
  default because browsers obtain stored proxy credentials only after a `407` response, which the
  decoy suppresses. Explicitly enabling it may break browser proxy authentication.
  The optional `knock` list specifies hostnames for which GOST returns the normal `407` response.

Chain title precedence is pair `title`, entry HTTPS service `title`, then a title derived from the
inventory host name.

### SSH service

The service supports `port`, `max_startups`, `per_source_max_startups` and `fail2ban`. Users may use
`key` or `password` authentication. Password users retain plaintext for client export and a hash for
the server. Key users retain the public key and the local private-key path used in MegaProxy exports.

## HTTPS certificates and chains

Domain certificates are issued with Certbot standalone ACME. An entry certificate contains its
direct endpoint, when enabled, and all configured chain hostnames. After a pair is added, the role
detects a missing SAN, expands the certificate and restarts GOST to load it.

Every chain hostname must resolve to its entry server before `apply`. HAProxy reads SNI without
terminating TLS and forwards the connection to a dedicated loopback GOST HTTP/2 listener. The entry
then connects to the selected exit with machine credentials. A pair in `https_chain_pairs` may
override `probe_resistance` for that chain route only.

Certificate renewal runs from a systemd timer. Self-signed mode is an explicit fallback and requires
clients to allow an invalid proxy certificate.

## Client configurations

```shell
./mega-proxy configs
./mega-proxy configs --output-dir /secure/path
```

The default `.generated/configs` directory contains:

- `MegaProxy.json`: HTTPS, direct SSH and every dynamic SSH jump profile;
- `FoxyProxy.json`: HTTPS profiles;
- `SuperProxy.txt`: HTTPS URLs with the Super Proxy v1 header;
- `ProxyList.txt`: URL-encoded HTTPS proxy URLs.

Directories use mode `0700` and files `0600`. Generation is idempotent and does not contact managed
servers. Exports contain plaintext passwords and private keys; handle them as secrets.

## Summary

`./mega-proxy summary` prints endpoints once and then each global credential once:

```text
Hosts:
proxy-eu.example.com (EU, HTTPS, SSH)
eu-via-us.example.com (EU -> US, HTTPS)

HTTPS:
alice
PASSWORD

SSH:
tun-alice
/path/to/private/key
```

`summary alice` selects an exact proxy login. Administrative users are omitted. Never write this
output to an unprotected file or CI log.

## Users, Vault and hooks

`remove-users` removes HTTPS users from all GOST configurations. Removed SSH users also enter the
global `removed_ssh` tombstone list; the next apply deletes their system accounts and root-owned
authorized-key files on every SSH host. The last user of an enabled service cannot be removed.

`vault-secrets` encrypts individual secrets as tagged Ansible Vault values while leaving hosts,
ports and flags readable. Existing encryption is preserved. Set `ANSIBLE_VAULT_PASSWORD_FILE` for
unattended use; otherwise the CLI prompts for a password.

After a successful apply, executable `.hooks/post-config-change` and files in
`.hooks/post-config-change.d/` run in name order. They receive `MEGAPROXY_INVENTORY`,
`MEGAPROXY_ANSIBLE_INVENTORY`, `MEGAPROXY_ROOT` and `MEGAPROXY_EVENT`. The ignored `.hooks`
directory is suitable for machine-local integrations such as px-manager.

## Security and operations

- Treat inventory, `.secrets`, `.generated`, summaries and exports as secrets.
- Use one proxy account/key per person or device for independent revocation.
- Verify SSH fingerprints through a trusted channel.
- Root SSH login is disabled; the permanent administrator is key-only and has sudo.
- Provider firewall rules remain the operator's responsibility.
- Optional probe resistance hides the protocol from unauthenticated HTTP probes, not the server IP
  or SNI; enable it only after testing the required clients.

## Development and troubleshooting

`./mega-proxy check` runs Ruff, pytest, byte-compilation and Ansible syntax checks. CI runs the same
suite; integration jobs provision isolated Ubuntu/Debian LXD systems.

- **ACME fails:** check DNS, TCP 80 and provider firewall rules.
- **A chain domain serves an old certificate:** run `apply --limit ENTRY --tags https`, then inspect
  certificate SANs and `megaproxy-gost` status.
- **Unexpected inventory:** pass `--inventory PATH` or inspect `inventory-path`.
- **px-manager did not update:** ensure the post-change hook is executable and `--no-hooks` is absent.
