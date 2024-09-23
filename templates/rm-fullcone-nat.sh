#!/bin/sh
while ! nft -a list chain ip filter INPUT | grep -q "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip filter INPUT | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip filter INPUT handle "${HANDLE}"
done
while ! nft -a list chain ip6 filter INPUT | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip6 filter INPUT | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip6 filter INPUT handle "${HANDLE}"
done
while ! nft -a list chain ip filter FORWARD | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip filter FORWARD | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip filter FORWARD handle "${HANDLE}"
done
while ! nft -a list chain ip6 filter FORWARD | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip6 filter FORWARD | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip6 filter FORWARD handle "${HANDLE}"
done
while ! nft -a list chain ip nat POSTROUTING | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip nat POSTROUTING | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip nat POSTROUTING handle "${HANDLE}"
done
while ! nft -a list chain ip6 nat POSTROUTING | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip6 nat POSTROUTING | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip6 nat POSTROUTING handle "${HANDLE}"
done
while ! nft -a list chain ip nat PREROUTING | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip nat PREROUTING | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip nat PREROUTING handle "${HANDLE}"
done
while ! nft -a list chain ip6 nat PREROUTING | grep "WireGuardGamingInstaller"; do
    HANDLE=$(nft -a list chain ip6 nat PREROUTING | grep "WireGuardGamingInstaller" | head -1 | grep -oE 'handle\s+[0-9]+' | cut -d ' ' -f 2)
    nft delete rule ip6 nat PREROUTING handle "${HANDLE}"
done
