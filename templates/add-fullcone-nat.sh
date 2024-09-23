#!/bin/sh

# Clear all rules
nft flush ruleset
# Add chains
nft add table ip filter
nft add table ip6 filter
nft add table ip nat
nft add table ip6 nat
nft 'add chain ip filter INPUT { type filter hook input priority filter ; policy accept; }'
nft 'add chain ip6 filter INPUT { type filter hook input priority filter ; policy accept; }'
nft 'add chain ip filter FORWARD { type filter hook forward priority filter ; policy accept; }'
nft 'add chain ip6 filter FORWARD { type filter hook forward priority filter ; policy accept; }'
nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority srcnat ; policy accept; }'
nft 'add chain ip6 nat POSTROUTING { type nat hook postrouting priority srcnat ; policy accept; }'
nft 'add chain ip nat PREROUTING { type nat hook prerouting priority dstnat ; policy accept; }'
nft 'add chain ip6 nat PREROUTING { type nat hook prerouting priority dstnat ; policy accept; }'

nft add rule ip nat POSTROUTING oifname $SERVER_PUB_NIC counter masquerade comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat POSTROUTING oifname $SERVER_PUB_NIC counter masquerade comment "WireGuardGamingInstaller" || true

# DNAT from 53,80,88,500, 1024 to 65000"
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC udp dport 53 counter dnat to $CLIENT_WG_IPV4:53 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 53 counter dnat to $CLIENT_WG_IPV4:53 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC udp dport 80 counter dnat to $CLIENT_WG_IPV4:80 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 80 counter dnat to $CLIENT_WG_IPV4:80 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC udp dport 88 counter dnat to $CLIENT_WG_IPV4:88 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 88 counter dnat to $CLIENT_WG_IPV4:88 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC udp dport 500 counter dnat to $CLIENT_WG_IPV4:500 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 500 counter dnat to $CLIENT_WG_IPV4:500 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC udp dport 1024-65000 counter dnat to $CLIENT_WG_IPV4:1024-65000 comment "WireGuardGamingInstaller" || true
nft add rule ip nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 1024-65000 counter dnat to $CLIENT_WG_IPV4:1024-65000 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC udp dport 53 counter dnat to [$CLIENT_WG_IPV6]:53 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 53 counter dnat to [$CLIENT_WG_IPV6]:53 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC udp dport 80 counter dnat to [$CLIENT_WG_IPV6]:80 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 80 counter dnat to [$CLIENT_WG_IPV6]:80 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC udp dport 88 counter dnat to [$CLIENT_WG_IPV6]:88 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 88 counter dnat to [$CLIENT_WG_IPV6]:88 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC udp dport 500 counter dnat to [$CLIENT_WG_IPV6]:500 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 500 counter dnat to [$CLIENT_WG_IPV6]:500 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC udp dport 1024-65000 counter dnat to [$CLIENT_WG_IPV6]:1024-65000 comment "WireGuardGamingInstaller" || true
nft add rule ip6 nat PREROUTING iifname $SERVER_PUB_NIC tcp dport 1024-65000 counter dnat to [$CLIENT_WG_IPV6]:1024-65000 comment "WireGuardGamingInstaller" || true
