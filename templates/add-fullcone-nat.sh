#!/bin/bash

# Clear all existing rules to prevent conflicts
nft flush ruleset

# Add chains
nft add table inet filter
nft add table inet nat
nft 'add chain inet filter INPUT { type filter hook input priority filter ; policy accept; }'
nft 'add chain inet filter FORWARD { type filter hook forward priority filter ; policy accept; }'
nft 'add chain inet nat POSTROUTING { type nat hook postrouting priority srcnat ; policy accept; }'
nft 'add chain inet nat PREROUTING { type nat hook prerouting priority dstnat ; policy accept; }'

# Masquerade SNAT
nft add rule inet nat POSTROUTING oifname $SERVER_PUB_NIC counter masquerade comment "WireGuardGamingInstaller"

# Client DNAT rules
