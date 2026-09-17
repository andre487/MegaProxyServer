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
./mega-proxy bootstrap
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

The wizard can create administrative keys, proxy credentials and an encrypted inventory. An
inventory outside the repository is remembered in the ignored `inventory-path` file. Override it
at any time with `--inventory PATH`.

The wizard supports an initial password or a separate SSH key. Bootstrap prompts for the password
without echoing it. The password is kept only in a private temporary connection file, removed after
Ansible exits. Verify the server fingerprint and add its key to `known_hosts` first. Load
passphrase-protected administrative keys with `ssh-add`.

`bootstrap` creates the administrator and sudo access, checks a fresh key-only login and `sudo -n`,
then disables root and password-based administrative login. It verifies access again after SSH
reload and immediately updates inventory per host. SSH proxy users keep password authentication.
Retrying uses the administrator if already accessible, without requesting the initial password.
Keep the original SSH session open until verification succeeds. `apply` automatically bootstraps
selected pending hosts, including when tags are specified. Run bootstrap before planning new hosts.

To add a server while preserving existing settings and proxy users:

```shell
./mega-proxy add-host
./mega-proxy bootstrap --limit proxy_new
./mega-proxy plan --limit proxy_new
./mega-proxy apply --limit proxy_new
```

Bootstrap accepts comma-separated exact inventory host names for `--limit`; the flag can be repeated.
The fresh login check respects local SSH configuration and reports SSH or sudo errors. A later proxy
installation failure does not switch completed hosts back to root.

## Commands and inventory

Use `./mega-proxy --help` and `./mega-proxy COMMAND --help` for commands and options.
Pass the global inventory option **before** the command:

```shell
./mega-proxy --inventory /secure/inventory.yml validate
./mega-proxy --inventory /secure/inventory.yml apply --limit proxy_eu --tags https
```

Inventory lookup uses the explicit path, then `inventory-path`, then `inventory.yml`. The launcher
runs from the repository root, so relative paths are resolved there. `--no-hooks` can appear before
or after the command.

Start with [inventory.example.yml](../../inventory.example.yml), replace the example addresses and
keys, and validate before applying. For a server-side HTTPS chain, use the complete two-host
[inventory.chains.example.yml](../../inventory.chains.example.yml). Accepted fields, validation rules
and defaults are defined in [models.py](../../src/megaproxy_server/models.py); container versions
are pinned there and can be overridden in inventory.

Proxy users live in the global `users` section and apply to every host with that service enabled.
Use dedicated SSH proxy logins, separate from the administrator. SSH key exports read the file at
`generated_private_key` on the control machine and embed its contents; a public key alone is not
enough to generate a client configuration. Android MegaProxy requires an unencrypted private key.

For country flags, start host identifiers with a two-letter country code followed by `_`, such as
`de_entry` and `us_exit`. Explicit HTTPS chain pairs supply the exit country in `country_code`.
The code is a display hint; use the client connection test to check the observed exit country.
Give exported profiles distinct names: their IDs are derived from those names.

An empty `https_chain_pairs` enables all compatible directed entry/exit combinations; a non-empty
list limits routes to the declared pairs. Each exit needs separate machine credentials in
`chain_password`, which are excluded from client exports. Chain titles use the pair title, then
the entry service title, then a name derived from the inventory host identifier.

Probe resistance suppresses the normal authentication challenge and can break browser clients
that wait for `407` before sending credentials. Keep it disabled unless tested with the required
clients. A route can override the entry setting; `knock` allows selected hostnames to receive the
normal challenge.

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

## Android MegaProxy

Compatibility was reviewed on 2026-09-08 against AndroidMegaProxy
[revision c8190e9](https://github.com/andre487/AndroidMegaProxy/tree/c8190e97b705a2c4578d278c40a690e97c5d5f27).
The client [importer](https://github.com/andre487/AndroidMegaProxy/blob/c8190e97b705a2c4578d278c40a690e97c5d5f27/app/src/main/java/net/megaproxy487/data/ConfigTransfer.kt)
accepts the JSON produced by this repository's [exporter](../../src/megaproxy_server/export.py):
the server currently writes schema `net.megaproxy487.config` v7; the app writes v8 and reads v1–v8.
Changing the server's version number alone would not add HTTPS jump profiles.

### Import and connect

1. Install MegaProxy using the client [installation guide](https://github.com/andre487/AndroidMegaProxy#installation).
2. Run `./mega-proxy configs` and privately transfer `MegaProxy.json` to the device. The app can also
   import the generated FoxyProxy, SuperProxy and ProxyList files, but those contain HTTPS routes only.
   Prefer MegaProxy JSON to retain SSH profiles, IDs and certificate settings.
3. Import the file and select the intended profile. Review routing, DNS and failover settings.
4. Choose **Test** from the main-screen menu. For SSH, compare the displayed host-key fingerprint
   with one obtained through the server console or an already trusted administrative connection.
   SSH jump profiles require verification of both hosts. On the server, inspect public host keys with:

   ```shell
   for key in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$key" -E sha256; done
   ```

5. Connect and approve Android's VPN permission. The app test checks the route and observed exit IP;
   `./mega-proxy verify` checks server deployment and does not replace this device test.

Exports leave SSH trust fingerprints empty and keep host-key checking enabled. Self-signed HTTPS
routes explicitly allow an invalid proxy certificate in MegaProxy JSON; the other export formats
cannot carry that setting. Prefer ACME certificates for normal operation.

### Updating imported profiles

Repeat `configs` after server or credential changes, then reimport the JSON. Matching IDs update
existing profiles; new IDs add profiles. IDs remain stable while generated profile names remain
unchanged. Renaming a host, login or HTTPS title can change IDs. Distinct routes must not share the
same generated name: duplicate IDs are rejected by the Android importer.

The app offers optional removal of local profiles missing from the file; they are not deleted
automatically. Removing a profile on the phone does not revoke access: use `remove-users` and
`apply` to revoke server credentials.

The client preserves stored passwords and private keys when their JSON fields are omitted; explicit
empty fields clear them. This generator includes credentials, so reimport replaces them. It also
imports global connection settings, including routing and disabled failover, and replaces profile
settings. Review device customizations after importing. Because generated SSH trust fields are
empty, reimport can require host-key confirmation again.

### Two ways to chain HTTPS proxies

| Route | Setup | What the phone imports |
| --- | --- | --- |
| Server-side SNI chain | Configure entry/exit and DNS using the chain inventory example, then apply | An ordinary `HTTPS` profile pointing to the entry's chain hostname; GOST selects the exit |
| Client-side HTTPS with Jump | Provision two direct HTTPS endpoints, then create **HTTPS with Jump** in the app | Not generated by MegaProxyServer; the app stores it as `HTTPS_JUMP` in JSON v8 |

For **HTTPS with Jump**, enter the exit in the main proxy fields and the entry in **Jump HTTPS
proxy**. Use global HTTPS user credentials on each hop; machine `chain_password` credentials belong
to server-side chains. The entry must resolve and allow CONNECT to the exit hostname and port.
Each hop verifies its own certificate. This mode does not require a chain domain or server-side
`https_chains_enabled`. A failed hop does not cause a direct fallback to the exit.

See the client's [HTTPS with Jump guide](https://github.com/andre487/AndroidMegaProxy#https-with-jump).
Client-side HTTPS jump profiles require a v8-capable app; older clients reject v8 files. Server-side
SNI routes remain usable through the HTTPS-only export formats. SSH jump profiles are generated by
`configs`; for a separate JSON export, request them with `./mega-proxy export --all-jumps`.

### Client limits and diagnostics

The Android client forwards TCP application traffic; general UDP and QUIC forwarding are not
implemented. SSH keys protected by a passphrase are unsupported. DNS, per-app routing, failover
and Android Always-on VPN are configured in the app. Exported profiles do not enable failover.

Use **Test** to distinguish proxy setup, destination access and exit-IP failures. It contacts
external test services through the proxy; proxy-hostname bootstrap may query external DoH providers
directly before the tunnel exists. Diagnostic logs stay on the device unless shared explicitly.
See the client's [privacy policy](https://github.com/andre487/AndroidMegaProxy/blob/main/PRIVACY.md)
for destinations and handling of shared reports. Review reports before sharing and keep generated
credentials out of issue trackers.

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

`remove-users` marks users for removal in inventory; run `apply` to remove HTTPS users from GOST. Removed SSH users also enter the
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
