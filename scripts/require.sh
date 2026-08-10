#!/usr/bin/env bash
# Preflight shared by reproduce.sh and scripts/scan_smoke.sh.
#
# The requirements used to live only in a header comment, so a missing one showed
# up as "command not found" from whatever stage happened to reach it first -- for
# `analysis`, that was after a 138 MB download. Check up front, and name the
# package rather than the tool: the two are not the same string on every
# distribution.

_pkg_mgr() {
    local m
    for m in apt-get dnf pacman zypper; do
        if command -v "$m" >/dev/null 2>&1; then printf '%s\n' "$m"; return 0; fi
    done
    printf 'unknown\n'
}

# _pkg_for <tool> <mgr>
_pkg_for() {
    case "$1/$2" in
        docker/apt-get)     printf 'docker.io\n' ;;
        docker/*)           printf 'docker\n' ;;
        python3/pacman)     printf 'python\n' ;;
        python3/*)          printf 'python3\n' ;;
        sha256sum/*)        printf 'coreutils\n' ;;
        zstd/*)             printf 'zstd\n' ;;
        *)                  printf '%s\n' "$1" ;;
    esac
}

# require_tools <tool>...
require_tools() {
    local t missing="" mgr pkgs="" p
    for t in "$@"; do
        command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
    done
    [ -z "$missing" ] && return 0
    mgr="$(_pkg_mgr)"
    for t in $missing; do
        p="$(_pkg_for "$t" "$mgr")"
        case " $pkgs " in *" $p "*) ;; *) pkgs="$pkgs $p" ;; esac
    done
    {
        echo "missing required tool(s):$missing"
        case "$mgr" in
            apt-get) echo "  sudo apt-get update && sudo apt-get install -y$pkgs" ;;
            dnf)     echo "  sudo dnf install -y$pkgs" ;;
            pacman)  echo "  sudo pacman -Sy --needed$pkgs" ;;
            zypper)  echo "  sudo zypper install -y$pkgs" ;;
            *)       echo "  install the equivalent of:$pkgs" ;;
        esac
    } >&2
    exit 1
}

require_uv() {
    command -v "${UV:-uv}" >/dev/null 2>&1 && return 0
    {
        echo "missing required tool: uv"
        echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        echo "  it installs into ~/.local/bin, which the CURRENT shell picks up only"
        echo "  after: export PATH=\"\$HOME/.local/bin:\$PATH\""
    } >&2
    exit 1
}

require_docker() {
    require_tools docker
    docker info >/dev/null 2>&1 || {
        {
            echo "need: a running docker daemon reachable by this user"
            echo "  start it:  sudo systemctl start docker"
            echo "  and allow this user without sudo:"
            echo "    sudo usermod -aG docker \"\$USER\" && newgrp docker"
            echo "  (no newgrp? it is in util-linux-extra on recent Ubuntu, util-linux"
            echo "   elsewhere; logging out and back in has the same effect)"
        } >&2
        exit 1
    }
}
