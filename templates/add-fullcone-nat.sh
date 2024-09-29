#!/usr/sbin/nft -f

# Clear all existing rules to prevent conflicts
flush ruleset

# Add chains
add table inet filter
add table inet nat
add chain inet filter INPUT { type filter hook input priority filter ; policy accept; }
add chain inet filter FORWARD { type filter hook forward priority filter ; policy accept; }
add chain inet nat POSTROUTING { type nat hook postrouting priority srcnat ; policy accept; }
add chain inet nat PREROUTING { type nat hook prerouting priority dstnat ; policy accept; }

# Masquerade SNAT
add rule inet nat POSTROUTING oifname $SERVER_PUB_NIC counter masquerade comment "WireGuardGamingInstaller"

# Client DNAT rules