#!/bin/bash
# POOL module installation script
# Usage: ./install.sh [--dkms] [--systemd]
set -euo pipefail

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

install_binaries() {
    echo "Installing POOL binaries..."
    install -D -m 755 poolctl "${PREFIX}/sbin/poolctl"
    install -D -m 755 pool_test "${PREFIX}/sbin/pool_test"
    install -D -m 755 poold "${PREFIX}/sbin/poold"

    if [ -f ../bridge/pool_bridge ]; then
        install -D -m 755 ../bridge/pool_bridge "${PREFIX}/sbin/pool_bridge"
    fi
    if [ -f ../bridge/pool_migrate ]; then
        install -D -m 755 ../bridge/pool_migrate "${PREFIX}/sbin/pool_migrate"
    fi
    if [ -f ../vault/pool_vault ]; then
        install -D -m 755 ../vault/pool_vault "${PREFIX}/sbin/pool_vault"
    fi
    if [ -f ../relay/pool_relay ]; then
        install -D -m 755 ../relay/pool_relay "${PREFIX}/sbin/pool_relay"
    fi

    mkdir -p /var/lib/pool /var/log/pool
}

install_systemd() {
    echo "Installing systemd units..."
    install -D -m 644 packaging/pool-module.service "${SYSTEMD_UNIT_DIR}/pool-module.service"
    install -D -m 644 packaging/poold.service "${SYSTEMD_UNIT_DIR}/poold.service"
    install -D -m 644 packaging/pool-relay.service "${SYSTEMD_UNIT_DIR}/pool-relay.service"
    install -D -m 644 packaging/pool-bridge.service "${SYSTEMD_UNIT_DIR}/pool-bridge.service"

    systemctl daemon-reload
    echo "Systemd units installed. Enable with:"
    echo "  systemctl enable --now pool-module"
    echo "  systemctl enable --now poold"
}

install_dkms() {
    echo "Installing POOL DKMS module..."
    local version
    version=$(grep PACKAGE_VERSION packaging/dkms.conf | cut -d'"' -f2)

    local dkms_src="/usr/src/pool-${version}"
    mkdir -p "${dkms_src}"
    cp -r ../linux "${dkms_src}/"
    cp -r ../common "${dkms_src}/" 2>/dev/null || true
    cp packaging/dkms.conf "${dkms_src}/dkms.conf"

    dkms add -m pool -v "${version}"
    dkms build -m pool -v "${version}"
    dkms install -m pool -v "${version}"
    echo "DKMS module installed. Module will auto-rebuild on kernel updates."
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "  --dkms      Install kernel module via DKMS"
    echo "  --systemd   Install systemd service units"
    echo "  --all       Install everything"
    echo "  --help      Show this help"
}

DO_DKMS=0
DO_SYSTEMD=0

for arg in "$@"; do
    case "$arg" in
        --dkms)    DO_DKMS=1 ;;
        --systemd) DO_SYSTEMD=1 ;;
        --all)     DO_DKMS=1; DO_SYSTEMD=1 ;;
        --help)    usage; exit 0 ;;
        *)         echo "Unknown option: $arg"; usage; exit 1 ;;
    esac
done

install_binaries
[ "$DO_DKMS" -eq 1 ] && install_dkms
[ "$DO_SYSTEMD" -eq 1 ] && install_systemd

echo "POOL installation complete."
