#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain INPUT {
        type filter hook input priority filter; policy accept;
        # You can change default policy to drop and add your own rules for INPUT
        # For example:
        # - tcp dport {ssh,http} accept # Allow SSH HTTP etc.
        # - udp dport <wg_udp_port> accept # Allow WG public port
        # - ct state vmap { invalid : drop, established : accept, related : accept } # Allow ESTABLISHED, RELATED state
        # - iifname "lo" accept # Allow packets sent from lo
        #
        # You need to make sure these rules are added before running the install script.
    }

    chain FORWARD {
        type filter hook forward priority filter; policy drop;
        iifname "$SERVER_PUB_NIC" oifname "$SERVER_WG_NIC" accept
        iifname "$SERVER_WG_NIC" oifname "$SERVER_PUB_NIC" accept
    }
}

table ip nat {
    chain POSTROUTING {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$SERVER_PUB_NIC" counter masquerade comment "WireGuardGamingInstaller"
        oifname "$SERVER_WG_NIC" counter masquerade comment "WireGuardGamingInstaller"
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
        oifname "$SERVER_WG_NIC" counter masquerade comment "WireGuardGamingInstaller"
    }

    chain PREROUTING {
        type nat hook prerouting priority dstnat; policy accept;
        # WG_Installer_IP6_Rule_Starts (Do not remove)
    }
}