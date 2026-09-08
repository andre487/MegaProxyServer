# MegaProxyServer

Provision and operate hardened HTTPS and SSH proxy servers with Ansible.

MegaProxyServer manages multiple Debian/Ubuntu hosts from one inventory, keeps proxy users global,
issues and renews TLS certificates, supports SNI-routed HTTPS chains and exports ready-to-import
client configurations for [MegaProxy for Android](https://github.com/andre487/AndroidMegaProxy),
FoxyProxy and SuperProxy.

Documentation: **[English](docs/en/README.md)** · **[Русский](docs/ru/README.md)**

## Quick start

Requirements: macOS or Linux, Python 3.12+, `uv`, OpenSSH, and a Debian or Ubuntu server reachable through a
sudo-capable SSH account.

```shell
./mega-proxy inventory
./mega-proxy plan
./mega-proxy apply
./mega-proxy verify
```

For an existing inventory, pass `--inventory PATH` before the command. Generate client files and display credentials:

```shell
./mega-proxy configs
./mega-proxy summary
```

Inventory and generated exports contain secrets. Keep them private and do not commit them.

## Connect with Android MegaProxy

Install the client using its [installation guide](https://github.com/andre487/AndroidMegaProxy#installation),
transfer `.generated/configs/MegaProxy.json` privately, and import it in the app. Select a profile,
run **Test**, verify any SSH host-key prompt, then connect and approve Android VPN access.

The current server exporter produces JSON v7, accepted by the current Android v8 importer.
Server-side SNI chains are exported as ordinary HTTPS profiles. The app also supports client-side
**HTTPS with Jump**, which must currently be configured in the app. See the
[English](docs/en/README.md#android-megaproxy) or [Russian](docs/ru/README.md#android-megaproxy)
guide for chain setup and reimport behavior.

## Highlights

- HTTPS CONNECT proxy with TLS 1.2/1.3 and optional probe-resistant decoy responses
- ACME certificates for DNS names and public IP addresses, plus a self-signed fallback
- SNI-based HTTPS chains through independently selected entry and exit servers
- Restricted SSH forwarding accounts and dynamic SSH jump profiles
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
in `uv.lock`.

## License

See [LICENSE](LICENSE).
