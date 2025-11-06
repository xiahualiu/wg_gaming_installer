"""
WireGuard stop script to remove nftables rules and sysctl rules.
"""

import nftables

from wg_gaming_installer.shell_scripts import disable_forwarding_sysctl


def main():
    nft = nftables.Nftables()

    # Flush existing rules
    nft.cmd('flush ruleset')

    # Disable IP forwarding
    disable_forwarding_sysctl()


if __name__ == "__main__":
    main()
