#!/bin/bash
set -e

# Create the TUN device so in-kernel WireGuard (wg-quick) can bring up interfaces.
mkdir -p /dev/net
if [ ! -e /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi
chmod 600 /dev/net/tun

# Ensure the WireGuard kernel module is available (no-op if built-in).
modprobe wireguard 2>/dev/null || true

exec "$@"
