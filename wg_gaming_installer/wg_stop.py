"""
WireGuard stop script to remove nftables rules and sysctl rules.
"""

import nftables
from shell_scripts import disable_forwarding_sysctl

nft = nftables.Nftables()

# Flush existing rules
nft.cmd('flush ruleset')

# Disable IP forwarding
disable_forwarding_sysctl()
