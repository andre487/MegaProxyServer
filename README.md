# MegaProxyServer

Ansible roles and an interactive Python launcher for hardened MegaProxy HTTPS and SSH servers.

The project supports multiple hosts, multiple users per service, HTTPS and SSH on the same host,
ACME certificates for domains or public IP addresses, a probe-resistant HTTPS decoy, and arbitrary
SSH jump chains. Jump pairs are not stored: any SSH-enabled host can be selected as the jump for
any other SSH-enabled host when profiles are exported.

Proxy users are global: the top-level `users.https` and `users.ssh` lists are applied to every host
where the corresponding service is enabled. Credentials therefore cannot silently diverge between
hosts. Inventories using the older per-host lists are migrated in memory; conflicting credentials
for the same login are rejected instead of being chosen implicitly.

## Requirements

- macOS or Linux control machine with `uv`, OpenSSH and Python available;
- a current Debian or Ubuntu server reachable by a sudo-capable SSH account;
- TCP 80 reachable for ACME issuance and TCP 443 for HTTPS;
- Certbot 5.4 or newer on servers using public-IP certificates.

All Python and Ansible dependencies are declared in `pyproject.toml`, locked in `uv.lock`, and
installed by `uv`. Do not install them manually with pip.

## Start

```shell
./mega-proxy
```

When no inventory exists, the launcher offers to create `inventory.yml` in the current directory
or use another path. An external path is remembered in `inventory-path`. Both files, generated
profiles and generated keys are excluded by `.gitignore`.

`vault-secrets` encrypts password fields with tagged inline Ansible Vault values while keeping
hosts, ports, domains and flags editable as ordinary YAML. `mega-proxy` prompts for the Vault
password when it encounters the first encrypted value. For unattended runs, set
`ANSIBLE_VAULT_PASSWORD_FILE` to a protected password file. Subsequent inventory updates preserve
field-level encryption. Whole-file Ansible Vault inventories remain readable and are converted to
field-level encryption by `vault-secrets`.

Useful commands:

```shell
./mega-proxy inventory
./mega-proxy check
./mega-proxy --inventory ./inventory.yml validate
./mega-proxy --inventory ./inventory.yml plan
./mega-proxy --inventory ./inventory.yml apply
./mega-proxy --inventory ./inventory.yml verify
./mega-proxy --inventory ./inventory.yml jumps
./mega-proxy --inventory ./inventory.yml summary
./mega-proxy --inventory ./inventory.yml summary alice
./mega-proxy --inventory ./inventory.yml remove-users
./mega-proxy --inventory ./inventory.yml configs
./mega-proxy --inventory ./inventory.yml export --all-jumps
```

`configs` writes four sensitive import files to `.generated/configs` by default:

- `MegaProxy.json` — HTTPS, direct SSH, and every dynamic SSH Jump combination;
- `FoxyProxy.json` — HTTPS entries only;
- `SuperProxy.txt` — HTTPS entries only, with the Super Proxy v1 header;
- `ProxyList.txt` — URL-encoded HTTPS proxy URLs.

Choose another directory with `configs --output-dir PATH`. Directories use mode `0700` and files
use mode `0600`. Generation is idempotent and never contacts configured servers.

`summary` prints copy-friendly blocks containing host, port, login, password and URI. With a login
as its first positional argument, only exact matches are shown. Key-only SSH accounts show the
private-key path instead of a password; administrative accounts are included too. This command deliberately writes plaintext secrets to
stdout; do not run it in CI or redirect it to an unprotected file.

`remove-users` selects one or more global proxy accounts. HTTPS accounts are removed from every
generated GOST configuration; SSH accounts are additionally retained in a global inventory
tombstone list so the next `apply` deletes the corresponding system accounts and root-owned
authorized-key files from every SSH-enabled host.

Use `--limit HOST` and `--tags common,admin,firewall,ssh,https` with plan, apply, or verify. Always run
`plan` before applying to an existing server and keep the current administrative SSH session open.

After a successful `apply`, executable `.hooks/post-config-change` and files in
`.hooks/post-config-change.d/` are run in name order. The ignored `.hooks` directory is intended for
machine-local integrations and secrets. Hooks receive `MEGAPROXY_INVENTORY`,
`MEGAPROXY_ANSIBLE_INVENTORY`, `MEGAPROXY_ROOT`, and `MEGAPROXY_EVENT`. Use `--no-hooks` before or
after the command to skip them, for example `./mega-proxy apply --no-hooks`.

## HTTPS

HTTPS uses a pinned GOST v3 container, TLS 1.2/1.3, Basic authentication and HTTP/2 CONNECT. Invalid
credentials receive a decoy page instead of the identifying `407 Proxy Authentication Required`
response. Domain deployments also reject missing or unrelated SNI before exposing a certificate.
GOST's API, metrics, profiling and destination access logs are not exposed.

Domain certificates use Certbot standalone ACME. Public-IP certificates use Let's Encrypt's
short-lived profile and therefore require reliable automatic renewal. Self-signed certificates are
an explicit fallback and require disabling certificate validation in MegaProxy.

Use a neutral hostname rather than one containing `proxy`, `vpn`, or `gost`. Probe resistance hides
the proxy role from unauthenticated scans; it cannot hide the IP or prevent IP/SNI-based blocking.

### HTTPS chains and SNI routing

When `settings.https_chains_enabled` is enabled, HTTPS hosts may opt into `chain_entry` and
`chain_exit`. Every valid directed entry-to-exit pair is generated automatically. HAProxy listens
on the single public HTTPS port, inspects TLS SNI without terminating TLS, and forwards each name to
a dedicated loopback GOST listener. For example, `proxy_ru -> proxy_nl` becomes
`proxy-ru-via-proxy-nl.<https_chain_domain>`; underscores are converted to DNS-safe hyphens.

All generated names must resolve to their entry host before `apply`. Chain hosts require domain
ACME certificates; Certbot expands the entry certificate to include every generated SNI hostname.
The exit authenticates entry nodes with a generated machine password that is never included in
summary or client exports. Client exports expose chain routes as ordinary HTTPS proxies on port 443.
An explicit `title` on an `https_chain_pairs` item names that route in client exports and px-manager;
without it, the entry HTTPS service `title` is used. When the service title is also absent, it is
derived from the inventory host name.

## SSH

The inventory distinguishes the provider's initial `bootstrap_user` from the permanent administrator.
The wizard defaults the administrator name to the local OS user and installs the selected public key
whether that account is new or already exists. After a successful full apply, `bootstrap_user` is
removed from inventory automatically and subsequent runs connect as the permanent administrator.
Keep the initial SSH session open until a new administrative login has been tested.

SSH proxy accounts are separate from the administrative account. They cannot open a shell, TTY,
subsystem, agent forwarding, X11, remote forwarding, or a tunnel device. They can only create local
`direct-tcpip` channels. Key authentication is preferred; generated keys are dedicated Ed25519 keys
without a passphrase because MegaProxy currently accepts only unencrypted private keys.

SSH remains recognizable as SSH. Passwords and private keys are included in exported client
profiles, so inventory, `.secrets`, and `.generated` must be treated as sensitive data.

Root SSH login is disabled completely. Password and keyboard-interactive login are disabled globally;
password authentication is enabled only inside the restricted `megaproxy` group. Key-only proxy
accounts have a locked password, so that exception applies effectively only to proxy accounts whose
inventory authentication type is `password`. The administrator is key-only and receives sudo access.

## Jump chains

There is intentionally no `jump_pairs` section. Given SSH hosts A, B, and C, the CLI can produce all
directed combinations `A -> B`, `A -> C`, `B -> A`, and so on. A host is never its own jump. Each
side may use a different user and authentication method.

This flexible model cannot apply pair-specific `PermitOpen` or source-IP firewall rules. Those
restrictions require declaring exact pairs and contradict dynamic chains. Every SSH account remains
restricted to local TCP forwarding and no interactive session.

## Security notes

- Inventory and exports have mode `0600`, but are plaintext local secrets, not a secret manager.
- Use one account/key per person or device so credentials can be revoked independently.
- Verify SSH host fingerprints in MegaProxy through a trusted channel on first connection.
- Review `.generated/megaproxy-profiles.json` before transferring it and delete it after import.
- Provider firewalls must match the host firewall; the project only manages UFW inside the VM.
- Administrative SSH ports are allowed before UFW is enabled to reduce lockout risk.

See `inventory.example.yml` for the complete data shape.

## Continuous integration

The GitHub Actions workflow runs the same `./mega-proxy check` command available locally. It verifies
Ruff, pytest, Python byte-compilation, and Ansible syntax on every push and pull request using the
locked dependency set. It needs no inventory, secrets, network hosts, or privileged containers.

`Host provisioning` additionally creates an isolated privileged LXD system and applies the real
playbook. It checks systemd, Docker, UFW, SSH forwarding, GOST, the HTTPS decoy, authenticated
CONNECT, and a second idempotent run. Ubuntu 24.04 runs on pushes and pull requests. A scheduled or
manually dispatched Debian 12 job provisions two hosts and verifies an SSH Jump tunnel between
them. CI uses self-signed TLS because hosted runners do not have a stable public address for ACME.
