#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain INPUT {
        type filter hook input priority filter; policy accept;
    }

    chain FORWARD {
        type filter hook forward priority filter; policy accept;
    }
}

table ip nat {
    chain POSTROUTING {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$SERVER_PUB_NIC" counter masquerade comment "WireGuardGamingInstaller"
    }

    chain PREROUTING {
        type nat hook prerouting priority dstnat; policy accept;
        # WG_Installer_IP_Rule_Starts (Do not remove)
    }
}

table ip6 nat {
    chain POSTROUTING {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$SERVER_PUB_NIC" counter masquerade comment "WireGuardGamingInstaller"
    }

    chain PREROUTING {
        type nat hook prerouting priority dstnat; policy accept;
        # WG_Installer_IP6_Rule_Starts (Do not remove)
    }
}