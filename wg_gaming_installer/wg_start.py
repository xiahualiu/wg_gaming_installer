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
from install_scripts import server_conf_db_path
from shell_scripts import enable_forwarding_sysctl
from sqlite_scripts import (
    PeerConfig,
    ServerIFConfig,
    conf_db_connected,
    read_all_peer_configs,
    read_server_nic_config,
)


def main() -> None:
    nft = nftables.Nftables()

    # Read info from database at runtime (not at import time)
    db_path: Path = server_conf_db_path()
    with conf_db_connected(db_path) as conn:
        server_cfg: ServerIFConfig = read_server_nic_config(conn)
        peer_cfgs: list[PeerConfig] = read_all_peer_configs(conn)

    # Flush existing rules
    nft.cmd('flush ruleset')

    # Enable IPv4 forwarding
    enable_forwarding_sysctl()

    # create tables / chains and NAT rules
    nft.cmd('add table ip nat')
    nft.cmd(
        'add chain ip nat postrouting { type nat hook postrouting priority srcnat ; }'
    )
    nft.cmd(f'add rule ip nat postrouting oifname "{server_cfg.nic_name}" masquerade')

    # IPv4 DNAT
    nft.cmd(
        'add chain ip nat prerouting { type nat hook prerouting priority dstnat ; }'
    )
    for peer in peer_cfgs:
        if peer.ipv4:
            ports_str = peer.forward_ports_str()
            if ports_str:
                nft.cmd(
                    f'add rule ip nat prerouting iifname "{server_cfg.nic_name}" '
                    f'tcp dport {{{ports_str}}} dnat to {peer.ipv4}'
                )
        else:
            raise ValueError(f'Peer {peer.name} has no IPv4, cannot setup IPv4 DNAT.')

    # IPv6 NAT
    if server_cfg.nic_ipv6:
        nft.cmd('add table ip6 nat')
        nft.cmd(
            'add chain ip6 nat postrouting '
            '{ type nat hook postrouting priority srcnat ; }'
        )
        nft.cmd(
            f'add rule ip6 nat postrouting oifname '
            f'"{server_cfg.nic_name}" masquerade'
        )
        # IPv6 DNAT
        nft.cmd(
            "add chain ip6 nat prerouting "
            "{ type nat hook prerouting priority dstnat ; }"
        )
        for peer in peer_cfgs:
            if peer.ipv6:
                ports_str = peer.forward_ports_str()
                if ports_str:
                    nft.cmd(
                        f'add rule ip6 nat prerouting iifname "{server_cfg.nic_name}" '
                        f'tcp dport {{{ports_str}}} dnat to {peer.ipv6}'
                    )
            else:
                logging.error(f'Peer {peer.name} has no IPv6, skipping IPv6 DNAT.')


if __name__ == "__main__":
    main()
