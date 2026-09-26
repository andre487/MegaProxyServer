#!/usr/bin/env bash
# Keep execution after the complete function definition for curl | bash.
main() {
    set -euo pipefail
    umask 077
    if [[ ${1:-} == --help ]]; then
        echo 'Usage: curl -fsSL https://raw.githubusercontent.com/andre487/MegaProxyServer/main/install.sh | sudo bash'
        echo 'Interactive Debian/Ubuntu installation into /opt/megaproxy-server. Requires a terminal.'
        echo 'Set MEGAPROXY_REF to select a branch or tag for a fresh checkout (default: main).'
        return
    fi
    if [[ $# -ne 0 ]]; then
        echo 'Unexpected arguments; use --help.' >&2
        return 2
    fi
    if [[ $EUID -ne 0 ]]; then
        echo 'Run as root: curl -fsSL URL | sudo bash' >&2
        return 1
    fi
    if [[ ! -r /etc/os-release ]]; then
        echo 'Only Debian and Ubuntu are supported.' >&2
        return 1
    fi
    . /etc/os-release
    case "$ID" in
        debian|ubuntu) ;;
        *) echo 'Only Debian and Ubuntu are supported.' >&2; return 1 ;;
    esac
    # stdin contains the script when piped; all prompts must read the terminal.
    if ! exec </dev/tty; then
        echo 'An interactive terminal is required (connect with ssh -t).' >&2
        return 1
    fi
    local install_dir=/opt/megaproxy-server answer
    echo "Install dependencies and MegaProxyServer into $install_dir, then start the setup wizard."
    read -r -p 'Continue? [y/N] ' answer
    [[ "$answer" == [yY] ]] || return 0
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git python3 python3-venv openssh-server sudo
    systemctl enable --now ssh
    if [[ ! -e "$install_dir" ]]; then
        git clone --depth 1 --branch "${MEGAPROXY_REF:-main}" https://github.com/andre487/MegaProxyServer.git "$install_dir"
    elif [[ ! -f "$install_dir/src/megaproxy_server/local_setup.py" ]]; then
        echo "$install_dir already exists without local setup support; move it aside or update it manually." >&2
        return 1
    fi
    cd "$install_dir"
    if ! command -v uv >/dev/null 2>&1; then
        python3 -m venv .bootstrap
        .bootstrap/bin/pip install 'uv==0.12.5'
        ln -s "$install_dir/.bootstrap/bin/uv" /usr/local/bin/uv
    fi
    uv sync --frozen --python 3.12
    ./mega-proxy setup-local
}

main "$@"
