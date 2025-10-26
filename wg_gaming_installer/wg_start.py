"""
This script sets up nftables rules for WireGuard VPN. It is intended to be used
as a startup script for WireGuard.

It flushes existing rules, creates necessary chains with default accept policies,
and sets up NAT masquerading for outbound traffic on the WireGuard interface.

Modify the rules as needed to fit your security requirements.
"""

import logging
from pathlib import Path

import nftables
from install_scripts import server_conf_db_path, sysctl_conf_path
from shell_scripts import enable_forwarding_sysctl
from sqlite_scripts import (
    PeerConfig,
    ServerConfig,
    WGConfig,
    conf_db_connected,
    read_all_peer_configs,
    read_server_config,
    read_wg_config,
)

nft = nftables.Nftables()

# Read info from database
db_path: Path = server_conf_db_path()
with conf_db_connected(db_path) as conn:
    wg_cfg: WGConfig = read_wg_config(conn)
    server_cfg: ServerConfig = read_server_config(conn)
    peer_cfgs: list[PeerConfig] = read_all_peer_configs(conn)


# Flush existing rules
nft.cmd('flush ruleset')

# Set sysctl to allow IP forwarding
sysctl_path: Path = sysctl_conf_path()

# Enable IPv4 forwarding
enable_forwarding_sysctl()

# Add builtin chains with default accept policy
# You can customize the priority and policy as needed
nft.cmd(
    'add chain inet filter input '
    '{ type filter hook input  priority 0 ; policy accept ; }'
)
nft.cmd(
    'add chain inet filter forward '
    '{ type filter hook forward priority 0 ; policy accept ; }'
)
nft.cmd(
    'add chain inet filter output '
    '{ type filter hook output priority 0 ; policy accept ; }'
)

# # Example of adding specific input rules
# First change the default input policy to drop
# nft.cmd('flush chain inet filter input')
# nft.cmd(
#   'add chain inet filter input '
#   '{ type filter hook input  priority 0 ; policy drop ; }'
# )

# # Allow established and related connections
# nft.cmd('add rule inet filter input ct state established,related accept')

# # Allow loopback interface
# nft.cmd('add rule inet filter input iif "lo" accept')

# # Allow WireGuard interface (wg0)
# nft.cmd('add rule inet filter input iif "wg0" accept')

# # Allow SSH (port 22)
# nft.cmd('add rule inet filter input tcp dport 22 accept')

# Set MASQUERADE for outbound traffic on wg0 interface (both IPv4 and IPv6)
nft.cmd('add table ip nat')
nft.cmd('add chain ip nat postrouting { type nat hook postrouting priority srcnat ; }')
nft.cmd(f'add rule ip nat postrouting oif {server_cfg.server_nic_name} masquerade')

# Add DNAT rules for each peer
for peer in peer_cfgs:
    if len(peer.peer_ipv4) > 0:
        nft.cmd(
            f'add rule ip nat prerouting iif {server_cfg.server_nic_name} '
            f'tcp dport {peer.forward_ports} dnat to {peer.peer_ipv4}'
        )
    else:
        logging.error(
            f'Peer {peer.peer_name} does not have an IPv4 address configured, '
            f'skipping DNAT rule.'
        )

# IPv6 NAT (NAT66) — only if kernel supports it; otherwise use routing/PD
if len(server_cfg.server_ipv6) > 0:
    nft.cmd('add table ip6 nat')
    nft.cmd(
        'add chain ip6 nat postrouting { type nat hook postrouting priority srcnat ; }'
    )
    nft.cmd(f'add rule ip6 nat postrouting oif {server_cfg.server_nic_name} masquerade')
    # Add DNAT rules for each peer (IPv6)
    for peer in peer_cfgs:
        if len(peer.peer_ipv6) > 0:
            nft.cmd(
                f'add rule ip6 nat prerouting iif {server_cfg.server_nic_name} '
                f'tcp dport {peer.forward_ports} dnat to {peer.peer_ipv6}'
            )
        else:
            logging.error(
                f'Peer {peer.peer_name} does not have an IPv6 address configured, '
                f'skipping DNAT rule.'
            )
