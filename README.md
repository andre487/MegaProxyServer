# MegaProxyServer

Incoming GOST authentication uses [GostHashedAuth](https://github.com/andre487/GostHashedAuth):
Ansible installs a pinned release with SHA-256 verification and copies only salted password hashes
to the proxy host. Outgoing server-chain connectors still need their machine passwords.

Optional [HTTP/3, MASQUE and SOCKS5 transports](docs/ru/transports.md) are controlled per host.
SOCKS5 is disabled by default and is not recommended because it does not encrypt proxy authentication or transport.

Provision and operate hardened HTTPS and SSH proxy servers with Ansible.

MegaProxyServer manages multiple Debian/Ubuntu hosts from one inventory, keeps proxy users global,
issues and renews TLS certificates, supports SNI-routed HTTPS chains and exports ready-to-import
client configurations for [MegaProxy for Android](https://github.com/andre487/AndroidMegaProxy),
FoxyProxy and SuperProxy.

Documentation: **[English](docs/en/README.md)** · **[Русский](docs/ru/README.md)**

## Quick start

To configure the Debian/Ubuntu server you are logged into, run the interactive installer:

```shell
curl -fsSL https://raw.githubusercontent.com/andre487/MegaProxyServer/main/install.sh | sudo bash
```

It installs dependencies and starts the setup wizard. Keep your SSH session open and save the
administrative key on your computer before confirming provisioning. See the
[English](docs/en/README.md#install-on-the-server) or
[Russian](docs/ru/README.md#установка-на-самом-сервере) walkthrough.

### Manage servers from another machine

Requirements: macOS or Linux, Git, Python 3.12+, `uv`, OpenSSH, and a Debian or Ubuntu server reachable through a
sudo-capable SSH account.

```shell
git clone https://github.com/andre487/MegaProxyServer.git
cd MegaProxyServer
./mega-proxy inventory
./mega-proxy bootstrap
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

For an existing inventory, pass `--inventory PATH` before the command. Generate client files and display credentials:

```shell
./mega-proxy configs
./mega-proxy summary
```

Optional personalized configuration feeds can run on separate HTTPS hosts using the same
inventory and user credentials. See [config API setup](docs/ru/config-api.md) and the
[inventory example](inventory.config-api.example.yml).

Inventory and generated exports contain secrets. Keep them private and do not commit them.

## Connect with Android MegaProxy

Install the client using its [installation guide](https://github.com/andre487/AndroidMegaProxy#installation),
transfer `.generated/configs/MegaProxy.json` privately, and import it in the app. Select a profile,
run **Test**, verify any SSH host-key prompt, then connect and approve Android VPN access.

The exporter produces JSON v7 for basic profiles and v8 when HTTPS Jump, HTTP/3 or SOCKS5
is configured; the configuration API always returns v8. Server-side SNI chains are ordinary
HTTPS profiles. Client-side SSH and HTTPS Jump profiles use only declared inventory pairs.
Direct SSH profiles require `services.ssh.generate_profile: true` (default: false).
See the [complete jump inventory example](inventory.jumps.example.yml) and the
[English](docs/en/README.md#android-megaproxy) or [Russian](docs/ru/README.md#android-megaproxy)
guide for chain setup and reimport behavior.

## Highlights

- HTTPS CONNECT proxy with TLS 1.2/1.3 and optional probe-resistant decoy responses
- ACME certificates for DNS names and public IP addresses, plus a self-signed fallback
- SNI-based HTTPS chains through independently selected entry and exit servers
- Restricted SSH forwarding accounts and explicit SSH and HTTPS jump profiles
- Global HTTPS and SSH users, with safe removal across every managed host
- Inline Ansible Vault encryption that leaves non-secret inventory settings readable
- Idempotent provisioning and integration tests on Ubuntu and Debian

See [`inventory.example.yml`](inventory.example.yml) and the
[English](docs/en/README.md) or [Russian](docs/ru/README.md) guide for all options.

## Development

```shell
./mega-proxy check
```

This runs Ruff, pytest, Python byte-compilation and Ansible syntax checks with dependencies locked
in `uv.lock`. Separate GitHub Actions jobs test real GOST/nginx and Ubuntu/Debian LXD
provisioning; `check` does not run these integrations. See the
[English](docs/en/README.md#development-and-troubleshooting) or
[Russian](docs/ru/README.md#разработка-и-диагностика) guide for coverage and `main` protection.

## License

See [LICENSE](LICENSE).
