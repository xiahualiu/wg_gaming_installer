"""
Prompt scripts for WireGuard gaming installer.
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Callable
from functools import partial
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
)
from typing import Any

from prompt_toolkit import prompt

from wg_gaming_installer.shell_scripts import (
    gen_wg_keypair,
    gen_wg_preshared_key,
    get_default_interface,
    ifname_exists,
    nic_ipv4_ipv6,
    validate_port_not_in_use,
)
from wg_gaming_installer.sqlite_scripts import (
    ForwardPort,
    PeerConfig,
    PortRange,
    ServerIFConfig,
    ServerWGConfig,
    SinglePort,
)


def _prompt_until(prompt_fn: Callable[[], Any], error_msg: str | None = None) -> Any:
    """
    Repeatedly call prompt_fn until it returns a truthy value.

    Args:
        prompt_fn (Callable[[], Any]): The function that produces the value.
        error_msg (str | None): Optional message printed when the value is
        falsy. If None, nothing is printed (the prompt function is expected
        to print its own error).
    """
    while True:
        value = prompt_fn()
        if value:
            return value
        if error_msg:
            print(error_msg, file=sys.stderr)


def _server_if_name_prompt() -> str | None:
    """
    Prompt the user for the server's network interface name.

    Returns:
        str | None: The validated network interface name or None if invalid.
    """
    default_nic_name: str | None = get_default_interface()
    server_nic_name: str = prompt(
        "Input the public interface name: ", default=default_nic_name or ""
    ).strip()
    if ifname_exists(server_nic_name):
        return server_nic_name
    return None


def _server_if_ipv4_ipv6_prompt(
    server_nic_name: str,
) -> tuple[IPv4Address, IPv6Address | None] | None:
    """
    Prompt the user for the server's public IPv4 and IPv6 addresses.

    Args:
        server_nic_name (str): The server's network interface name.
    Returns:
        tuple[IPv4Address, IPv6Address | None] | None: The validated
        public IPv4 and IPv6 addresses of the server, or None if invalid.
    """
    default_ipv4, default_ipv6 = nic_ipv4_ipv6(server_nic_name)

    server_nic_ipv4_input: str = prompt(
        "Input the public IPv4 address of the server: ",
        default=str(default_ipv4) if default_ipv4 else "",
    ).strip()
    try:
        server_nic_ipv4 = IPv4Address(server_nic_ipv4_input)
    except ValueError:
        return None

    use_ipv6: str = (
        prompt("Does the server have a public IPv6 address? (yes/no): ", default="no")
        .strip()
        .lower()
    )
    server_nic_ipv6: IPv6Address | None = None
    if use_ipv6 in ['yes', 'y']:
        server_nic_ipv6_input: str = prompt(
            "Input the public IPv6 address of the server: ",
            default=str(default_ipv6) if default_ipv6 else "",
        ).strip()
        try:
            server_nic_ipv6 = IPv6Address(server_nic_ipv6_input)
        except ValueError:
            return None

    return (server_nic_ipv4, server_nic_ipv6)


def server_if_prompt() -> ServerIFConfig:
    """
    Prompt the user for the server's public IPv4 and IPv6 addresses.
    """
    while True:
        # First get server NIC name
        server_nic_name: str = _prompt_until(
            _server_if_name_prompt, 'Invalid network interface name, please try again.'
        )

        # Next get server NIC IPv4 and IPv6
        server_if_ips: tuple[IPv4Address, IPv6Address | None] = _prompt_until(
            partial(_server_if_ipv4_ipv6_prompt, server_nic_name),
            'Invalid IP address(es), please try again.',
        )
        server_nic_ipv4, server_nic_ipv6 = server_if_ips

        # Review inputs
        print()
        print("Please review the server network configuration:")
        print(f"└─ Interface Name: {server_nic_name}")
        if server_nic_ipv6:
            print(f"   ├─ IPv4 Address: {server_nic_ipv4!s}")
            print(f"   └─ IPv6 Address: {server_nic_ipv6!s}")
        else:
            print(f"   └─ IPv4 Address: {server_nic_ipv4!s}")
        confirm: str = prompt("Is this information correct? (yes/no): ").strip().lower()
        if confirm in ['yes', 'y']:
            return ServerIFConfig(
                nic_name=server_nic_name,
                nic_ipv4=server_nic_ipv4,
                nic_ipv6=server_nic_ipv6,
            )
        else:
            print("Let's try again.\n")
            continue


def validate_name(name: str) -> bool:
    if not name:
        return False
    # match legacy script behavior: maximum 16 chars
    if len(name) > 16:
        return False
    # allow letters, digits, underscore, hyphen and dot (no leading-char restriction)
    return all(c.isalnum() or c in {'_', '-', '.'} for c in name)


def _wg_if_name_prompt() -> str | None:
    """
    Prompt the user for the WireGuard interface name.

    Returns:
        str | None: The validated WireGuard interface name or None if invalid.
    """
    default_wg_nic_name: str = 'wg0'
    wg_nic_name: str = prompt(
        "Input the WireGuard interface name: ", default=default_wg_nic_name
    ).strip()
    if validate_name(wg_nic_name):
        return wg_nic_name
    else:
        return None


def _wg_if_ipv4_prompt() -> IPv4Interface | None:
    """
    Prompt the user for the WireGuard IPv4 interface.

    Returns:
        IPv4Interface | None: The validated WireGuard IPv4 interface or None if invalid.
    """
    default_wg_ipv4: str = '10.66.66.1/24'
    wg_ipv4: str = prompt(
        "Input the WireGuard IPv4 interface of the server: ",
        default=default_wg_ipv4,
    ).strip()
    try:
        return IPv4Interface(wg_ipv4)
    except ValueError:
        return None


def _wg_if_ipv6_prompt() -> IPv6Interface | None:
    """
    Prompt the user for the WireGuard IPv6 interface.

    Returns:
        IPv6Interface | None: The validated WireGuard IPv6 interface or None if invalid.
    """
    default_wg_ipv6: str = 'fd42:42:42::1/120'
    wg_ipv6: str = prompt(
        "Input the WireGuard IPv6 interface of the server: ",
        default=default_wg_ipv6,
    ).strip()
    try:
        return IPv6Interface(wg_ipv6)
    except ValueError:
        return None


def _wg_if_listen_port_prompt(check_ipv6: bool) -> int | None:
    """
    Prompt the user for the WireGuard listen port.
    Args:
        check_ipv6 (bool): Whether to check if the port is in use for IPv6.

    Returns:
        int | None: The validated WireGuard listen port or None if invalid.
    """
    default_wg_listen_port: int = 51820
    wg_listen_port_str: str = prompt(
        "Input the WireGuard listen port: ", default=str(default_wg_listen_port)
    ).strip()
    try:
        wg_listen_port: int = int(wg_listen_port_str)
    except ValueError:
        print("Invalid listen port.", file=sys.stderr)
        return None
    if not validate_port_not_in_use(wg_listen_port, socket.AddressFamily.AF_INET):
        print(f"Port {wg_listen_port} is already in use (IPv4).", file=sys.stderr)
        return None
    if check_ipv6 and not validate_port_not_in_use(
        wg_listen_port, socket.AddressFamily.AF_INET6
    ):
        print(f"Port {wg_listen_port} is already in use (IPv6).", file=sys.stderr)
        return None
    return wg_listen_port


def _wg_if_mtu_prompt() -> int | None:
    """
    Prompt the user for the WireGuard MTU.

    Returns:
        int | None: The validated MTU value or None if invalid.
    """
    default_wg_mtu: int = 1420
    wg_mtu_str: str = prompt(
        "Input the WireGuard MTU: ", default=str(default_wg_mtu)
    ).strip()
    try:
        wg_mtu: int = int(wg_mtu_str)
    except ValueError:
        print("Invalid MTU.", file=sys.stderr)
        return None
    if wg_mtu < 576 or wg_mtu > 65535:
        print("MTU must be between 576 and 65535.", file=sys.stderr)
        return None
    return wg_mtu


def server_wg_prompt(has_ipv6: bool) -> ServerWGConfig:
    while True:
        # First get WireGuard NIC name
        wg_nic_name: str = _prompt_until(
            _wg_if_name_prompt, "Invalid WireGuard interface name, please try again."
        )

        # WireGuard IPv4 addresses
        wg_ipv4: IPv4Interface = _prompt_until(
            _wg_if_ipv4_prompt, "Invalid IPv4 address, please try again."
        )

        # WireGuard IPv6 address (if applicable)
        wg_ipv6: IPv6Interface | None = None
        if has_ipv6:
            wg_ipv6 = _prompt_until(
                _wg_if_ipv6_prompt, "Invalid IPv6 address, please try again."
            )
        else:
            print(
                "Skipping IPv6 configuration as server has no IPv6 address configured."
            )

        # WireGuard listen port
        wg_listen_port: int = _prompt_until(
            partial(_wg_if_listen_port_prompt, check_ipv6=bool(wg_ipv6)),
            "Invalid listen port, please try again.",
        )

        # WireGuard MTU
        wg_mtu: int = _prompt_until(_wg_if_mtu_prompt, "Invalid MTU, please try again.")

        # Review inputs
        print()
        print("Please review the WireGuard configuration:")
        print(f"└─ Interface Name: {wg_nic_name}")
        print(f"   ├─ IPv4 Interface: {wg_ipv4!s}")
        if wg_ipv6:
            print(f"   ├─ IPv6 Interface: {wg_ipv6!s}")
        print(f"   ├─ Listen Port: {wg_listen_port}")
        print(f"   └─ MTU: {wg_mtu}")
        confirm: str = prompt("Is this information correct? (yes/no): ").strip().lower()
        if confirm in ['yes', 'y']:
            try:
                wg_private_key, wg_public_key = gen_wg_keypair()
            except Exception as e:
                print(f"Error generating WireGuard keypair: {e}")
                raise
            return ServerWGConfig(
                wg_name=wg_nic_name,
                ipv4=wg_ipv4,
                ipv6=wg_ipv6,
                listen_port=wg_listen_port,
                private_key=wg_private_key,
                public_key=wg_public_key,
                mtu=wg_mtu,
            )
        else:
            print("Let's try again.\n")
            continue


def _peer_name_prompt(
    wg_config: ServerWGConfig,
    existing_peers: list[PeerConfig],
    default_name: str | None = None,
) -> str | None:
    """
    Prompt the user for the peer's name.
    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid name conflicts.
        default_name (str | None): Optional default name for the peer.

    Returns:
        str | None: The validated peer name or None if invalid.
    """
    peer_name: str = prompt(
        "Input the name of the new peer: ", default=default_name or ""
    ).strip()
    if not validate_name(peer_name):
        print("Invalid peer name.")
        return None
    if peer_name == wg_config.wg_name:
        print("Peer name cannot be the same as the WireGuard interface name.")
        return None
    if any(peer.name == peer_name for peer in existing_peers):
        print("Peer name already exists.")
        return None
    return peer_name


def _peer_ip_prompt(
    wg_config: ServerWGConfig,
    existing_peers: list[PeerConfig],
    version: int,
) -> IPv4Interface | IPv6Interface | None:
    """
    Generic prompt for a peer's WireGuard IPv4 or IPv6 interface.

    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid IP conflicts.
        version (int): 4 for IPv4 or 6 for IPv6.

    Returns:
        IPv4Interface | IPv6Interface | None: The validated interface or None.
    """
    if version == 4:
        addr_cls: type[IPv4Address] | type[IPv6Address] = IPv4Address
        iface_cls: type[IPv4Interface] | type[IPv6Interface] = IPv4Interface
        server_addr: IPv4Address | IPv6Address = wg_config.ipv4.ip
        network: IPv4Network | IPv6Network = wg_config.ipv4.network
        label: str = 'IPv4'
    else:
        assert wg_config.ipv6 is not None, "Server WireGuard IPv6 config is required."
        addr_cls = IPv6Address
        iface_cls = IPv6Interface
        server_addr = wg_config.ipv6.ip
        network = wg_config.ipv6.network
        label = 'IPv6'

    # Build set of used addresses
    used_addrs: set[int] = {int(server_addr)}
    for peer in existing_peers:
        if version == 4:
            used_addrs.add(int(peer.ipv4.ip))
        elif peer.ipv6:
            used_addrs.add(int(peer.ipv6.ip))

    # Suggest a default IP based on existing peers and server config
    default_if: IPv4Address | IPv6Address | None = None
    for host in network.hosts():
        if int(host) not in used_addrs:
            default_if = host
            break

    # If no available IPs
    if not default_if:
        print(
            f"No available {label} addresses left in the WireGuard network.",
            file=sys.stderr,
        )
        return None

    # Prompt user for peer interface
    peer_ip_input: str = prompt(
        f"Input the WireGuard {label} interface of the new peer: ",
        default=str(default_if),
        rprompt=f"/{network.prefixlen}",
    ).strip()

    # Validate input
    try:
        peer_ip: IPv4Address | IPv6Address = addr_cls(peer_ip_input)
    except ValueError:
        print(f"Invalid {label} interface.", file=sys.stderr)
        return None

    # Check for IP conflicts
    if int(peer_ip) in used_addrs:
        print(f"{label} interface already in use.", file=sys.stderr)
        return None

    # Verify that the interface is within the server's WireGuard network
    if peer_ip not in network:
        print(
            f"{label} interface is not within the server's WireGuard "
            f"{label} network.",
            file=sys.stderr,
        )
        return None
    return iface_cls(f"{peer_ip}/{network.prefixlen}")


def _peer_ipv4_prompt(
    wg_config: ServerWGConfig, existing_peers: list[PeerConfig]
) -> IPv4Interface | None:
    """
    Prompt the user for the peer's WireGuard IPv4 interface.

    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid IP conflicts.

    Returns:
        IPv4Interface | None: The validated WireGuard IPv4 interface or None if invalid.
    """
    result = _peer_ip_prompt(wg_config, existing_peers, version=4)
    if isinstance(result, IPv4Interface):
        return result
    return None


def _peer_ipv6_prompt(
    wg_config: ServerWGConfig, existing_peers: list[PeerConfig]
) -> IPv6Interface | None:
    """
    Prompt the user for the peer's WireGuard IPv6 interface.

    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid IP conflicts.

    Returns:
        IPv6Interface | None: The validated WireGuard IPv6 interface or None if invalid.
    """
    result = _peer_ip_prompt(wg_config, existing_peers, version=6)
    if isinstance(result, IPv6Interface):
        return result
    return None


def _peer_forward_ports_prompt(
    wg_config: ServerWGConfig,
    existing_peers: list[PeerConfig],
    default_ports: str | None = None,
) -> list[ForwardPort]:
    """
    Prompt the user whether to enable port forwarding for the peer.

    Returns:
        bool: True if port forwarding is enabled, False otherwise.
    """

    def check_port_unused(single_port: SinglePort) -> bool:
        """
        Check if a single port conflicts with existing forwarded ports.
        """
        port: int = single_port.port
        # Check for valid port range
        if port < 1 or port > 65535:
            print(f"Invalid port: {port}", file=sys.stderr)
            return False

        # Check if port is in use
        if not validate_port_not_in_use(port, socket.AddressFamily.AF_INET):
            print(f"Port {port} is already in use.", file=sys.stderr)
            return False

        # Check for conflicts with WireGuard listen port
        if port == wg_config.listen_port:
            print(
                f"Port {port} conflicts with WireGuard listen port.",
                file=sys.stderr,
            )
            return False

        # Check for conflicts with existing forwarded ports
        for peer in existing_peers:
            if peer.forward_ports:
                for fp in peer.forward_ports:
                    if isinstance(fp, SinglePort) and fp.port == port:
                        print(
                            f"Port {port} is already forwarded by {peer.name}.",
                            file=sys.stderr,
                        )
                        return False
                    elif isinstance(fp, PortRange):
                        if fp.start <= port <= fp.end:
                            print(
                                f"Port {port} is already forwarded in range "
                                f"{fp.start}-{fp.end} by {peer.name}.",
                                file=sys.stderr,
                            )
                            return False
        return True

    def check_port_range_unused(port_range: PortRange) -> bool:
        """
        Check if a port or port range conflicts with existing forwarded ports.
        """
        start_port: int = port_range.start
        end_port: int = port_range.end

        # Check for valid port range
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print(f"Invalid port range: {start_port}-{end_port}", file=sys.stderr)
            return False

        # Check if ports in use
        for p in range(start_port, end_port + 1):
            if not validate_port_not_in_use(p, socket.AddressFamily.AF_INET):
                print(
                    f"Port {p} is already in use in port range "
                    f"{start_port}-{end_port}.",
                    file=sys.stderr,
                )
                return False

        # Check for conflicts with WireGuard listen port
        if start_port <= wg_config.listen_port <= end_port:
            print(
                f"Port range {start_port}-{end_port} conflicts with "
                f"WireGuard server listen port {wg_config.listen_port}.",
                file=sys.stderr,
            )
            return False

        # Check for conflicts with existing forwarded ports
        for peer in existing_peers:
            if peer.forward_ports:
                for fp in peer.forward_ports:
                    if isinstance(fp, SinglePort):
                        if start_port <= fp.port <= end_port:
                            print(
                                f"Port {fp.port} is already forwarded by {peer.name}.",
                                file=sys.stderr,
                            )
                            return False
                    else:
                        # detect any overlap between ranges
                        if not (fp.end < start_port or fp.start > end_port):
                            print(
                                f"Port range {start_port}-{end_port} conflicts with "
                                f"existing forwarded range {fp.start}-{fp.end} "
                                f"by {peer.name}.",
                                file=sys.stderr,
                            )
                            return False
        return True

    user_input: str = prompt(
        "Input the ports to forward (comma-separated, e.g., 80,443,27000-27050): ",
        default=default_ports or "",
    ).strip()

    if not user_input:
        print("No ports specified for forwarding.", file=sys.stderr)
        return []

    # Seperate and validate ports
    ports = user_input.split(',')
    forward_ports: list[ForwardPort] = []
    for port in ports:
        port = port.strip()
        if '-' not in port:
            # Single port
            try:
                port_num: int = int(port)
            except ValueError:
                print(f"Invalid port: {port}", file=sys.stderr)
                return []
            single_port = SinglePort(port=port_num)
            if check_port_unused(single_port=single_port):
                forward_ports.append(single_port)
            else:
                return []  # Conflict detected
        else:
            # Port range
            try:
                start_str, end_str = port.split('-', 1)
                start_port: int = int(start_str.strip())
                end_port: int = int(end_str.strip())
            except ValueError:
                print(f"Invalid port range: {port}", file=sys.stderr)
                return []
            port_range: PortRange = PortRange(start=start_port, end=end_port)
            if check_port_range_unused(port_range=port_range):
                forward_ports.append(port_range)
            else:
                return []  # Conflict detected

    return forward_ports


def _peer_dns_prompt() -> list[IPv4Address | IPv6Address]:
    """
    Prompt the user for the peer's DNS servers.

    Returns:
        list[IPv4Address | IPv6Address]: The list of DNS server IP addresses.
    """
    dns_input: str = prompt(
        "Input the DNS servers for the peer (comma-separated IPs): ",
        default="1.1.1.1, 1.0.0.1",
    ).strip()
    dns_list: list[IPv4Address | IPv6Address] = []
    if not dns_input:
        return dns_list

    entries = dns_input.split(",")
    for entry in entries:
        entry = entry.strip()
        try:
            dns_ip: IPv4Address | IPv6Address = ip_address(entry)
        except ValueError:
            print(f"Invalid DNS IP address: {entry}", file=sys.stderr)
            continue
        dns_list.append(dns_ip)
    return dns_list


def print_peer_summary(
    index: int,
    peer_name: str,
    peer_ipv4: IPv4Interface,
    peer_ipv6: IPv6Interface | None,
    peer_dns: list[IPv4Address | IPv6Address],
    peer_forward_ports: list[ForwardPort],
) -> None:
    """
    Print a concise summary of a peer configuration with index.
    """
    print(f"Peer #{index}: {peer_name}")
    print(f"  ├─ IPv4 Interface: {peer_ipv4!s}")
    if peer_ipv6:
        print(f"  ├─ IPv6 Interface: {peer_ipv6!s}")
    print("  ├─ DNS Servers: ")
    for dns in peer_dns:
        print(f"  │   └─ {dns!s}")
    if peer_forward_ports:
        print("  └─ Forwarded Ports:")
        for fp in peer_forward_ports:
            if isinstance(fp, SinglePort):
                print(f"    └─ Port: {fp.port}")
            else:
                print(f"    └─ Port Range: {fp.start}-{fp.end}")
    else:
        print("  └─ Forwarded Ports: None")


def add_peer_prompt(
    wg_config: ServerWGConfig,
    existing_peers: list[PeerConfig],
    base_peer: PeerConfig | None = None,
) -> PeerConfig:
    """
    Prompt the user to add a new peer, optionally similar to an existing one.

    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid name and IP conflicts.
        base_peer (PeerConfig | None): Optional base peer configuration to
        copy defaults (name, ports, keys) from.

    Returns:
        PeerConfig: The configuration for the new peer.
    """
    if base_peer:
        print(f"Adding a new WireGuard peer similar to '{base_peer.name}'...")

    while True:
        peer_name: str = _prompt_until(
            lambda: _peer_name_prompt(
                wg_config=wg_config,
                existing_peers=existing_peers,
                default_name=base_peer.name if base_peer else None,
            ),
        )

        peer_ipv4: IPv4Interface = _prompt_until(
            lambda: _peer_ipv4_prompt(wg_config, existing_peers),
        )

        peer_ipv6: IPv6Interface | None = None
        if wg_config.ipv6:
            peer_ipv6 = _prompt_until(
                lambda: _peer_ipv6_prompt(wg_config, existing_peers),
            )

        peer_dns: list[IPv4Address | IPv6Address] = _prompt_until(
            _peer_dns_prompt, "At least one valid DNS server must be provided."
        )

        peer_forward_ports: list[ForwardPort] = []
        default_enable_pf: str = (
            "yes" if (base_peer and base_peer.forward_ports) else "no"
        )
        while True:
            enable_pf: str = (
                prompt(
                    "Enable port forwarding for this peer? (yes/no): ",
                    default=default_enable_pf,
                )
                .strip()
                .lower()
            )
            if enable_pf in ['yes', 'y']:
                peer_forward_ports = _peer_forward_ports_prompt(
                    wg_config=wg_config,
                    existing_peers=existing_peers,
                    default_ports=base_peer.forward_ports_str if base_peer else None,
                )
                if peer_forward_ports:
                    break
                # Conflict detected, re-prompt
                continue
            # No port forwarding
            break

        # Review inputs
        print()
        print("Please review the new peer configuration:")
        print_peer_summary(
            index=len(existing_peers),
            peer_name=peer_name,
            peer_ipv4=peer_ipv4,
            peer_ipv6=peer_ipv6,
            peer_dns=peer_dns,
            peer_forward_ports=peer_forward_ports,
        )
        user_confirm: str = (
            prompt("Is this information correct? (yes/no): ").strip().lower()
        )
        if user_confirm in ['yes', 'y']:
            break
        print("Let's try again.\n")

    if base_peer:
        # Prompt user to reuse keys or generate new ones
        while True:
            reuse_keys: str = (
                prompt("Generate new WireGuard keys? (yes/no): ", default="no")
                .strip()
                .lower()
            )
            if reuse_keys in ['yes', 'y']:
                peer_private_key, peer_public_key = gen_wg_keypair()
                peer_preshared_key = gen_wg_preshared_key()
                break
            if reuse_keys in ['no', 'n']:
                peer_private_key = base_peer.private_key
                peer_public_key = base_peer.public_key
                peer_preshared_key = base_peer.preshared_key
                break
    else:
        # Generate WireGuard keypair for the peer
        try:
            peer_private_key, peer_public_key = gen_wg_keypair()
            peer_preshared_key = gen_wg_preshared_key()
        except Exception as e:
            print(f"Error generating WireGuard keypair: {e}")
            raise

    return PeerConfig(
        name=peer_name,
        ipv4=peer_ipv4,
        ipv6=peer_ipv6,
        dns=peer_dns,
        public_key=peer_public_key,
        private_key=peer_private_key,
        preshared_key=peer_preshared_key,
        forward_ports=peer_forward_ports,
    )


def rm_peer_prompt(existing_peers: list[PeerConfig]) -> PeerConfig | None:
    """
    Prompt the user to remove an existing peer.

    Args:
        existing_peers (list[PeerConfig]): List of existing peers.

    Returns:
        PeerConfig | None: The peer configuration to be removed or None if cancelled.
    """
    if not existing_peers:
        print("No existing peers to remove.", file=sys.stderr)
        return None

    print("Existing peers:")
    for idx, peer in enumerate(existing_peers):
        print_peer_summary(
            index=idx,
            peer_name=peer.name,
            peer_ipv4=peer.ipv4,
            peer_ipv6=peer.ipv6,
            peer_dns=peer.dns,
            peer_forward_ports=peer.forward_ports,
        )
        print()

    while True:
        selection_str: str = prompt(
            "Input the number of the peer to remove (or 'cancel' to abort): "
        ).strip()
        if selection_str.lower() == 'cancel':
            print("Peer removal cancelled.")
            return None
        try:
            selection: int = int(selection_str)
            if 0 <= selection < len(existing_peers):
                break
            else:
                print("Invalid selection, please try again.", file=sys.stderr)
                continue
        except ValueError:
            print("Invalid input, please enter a number.", file=sys.stderr)
            continue

    # Ask for confirmation
    confirm: str = (
        prompt(
            "Are you sure you want to remove peer "
            f"'{existing_peers[selection].name}'? (yes/no): "
        )
        .strip()
        .lower()
    )
    if confirm in ['yes', 'y']:
        return existing_peers[selection]
    else:
        print("Peer removal cancelled.")
        return None


def select_peer_config_prompt(peers: list[PeerConfig]) -> PeerConfig | None:
    """
    Prompt the user to select an existing peer.

    Args:
        existing_peers (list[PeerConfig]): List of existing peers.

    Returns:
        PeerConfig | None: The selected peer configuration or None if cancelled.
    """
    if not peers:
        print("No existing peers to select.", file=sys.stderr)
        return None

    print("Select a peer to continue:")
    for idx, peer in enumerate(peers):
        print_peer_summary(
            index=idx,
            peer_name=peer.name,
            peer_ipv4=peer.ipv4,
            peer_ipv6=peer.ipv6,
            peer_dns=peer.dns,
            peer_forward_ports=peer.forward_ports,
        )
        print()
    selected_idx: int
    while True:
        user_input = prompt(f"Please select a peer [0-{len(peers)-1}] => ")
        try:
            selected_idx = int(user_input)
        except ValueError:
            print("Invalid input, please enter a valid number.")
            continue
        if selected_idx < 0 or selected_idx >= len(peers):
            print("Invalid option, please try again.")
            continue
        break
    return peers[selected_idx]


def uninstall_wg_prompt() -> bool:
    """
    Prompt the user to confirm uninstallation of WireGuard Gaming Installer.

    Returns:
        bool: True if uninstallation is confirmed, False otherwise.
    """
    while True:
        confirm = (
            prompt(
                "Are you sure you want to uninstall WireGuard service?"
                "This action cannot be undone. (yes/no) => "
            )
            .strip()
            .lower()
        )
        # accept both full and short answers, consistent with other prompts
        if confirm in ['yes', 'y', 'no', 'n']:
            break
        print("Invalid input, please enter 'yes'/'y' or 'no'/'n'.")
    return confirm not in ['no', 'n']


def reconfigure_wg_prompt() -> bool:
    """
    Prompt the user to confirm re-configuring the WireGuard server.

    Re-configuring purges the server NIC/WG settings and all peer
    configurations, so this is a destructive action.

    Returns:
        bool: True if re-configuration is confirmed, False otherwise.
    """
    while True:
        confirm = (
            prompt(
                "Are you sure you want to re-configure the WireGuard server?"
                "This will delete the server settings and all peers, "
                "and cannot be undone. (yes/no) => "
            )
            .strip()
            .lower()
        )
        if confirm in ['yes', 'y', 'no', 'n']:
            break
        print("Invalid input, please enter 'yes'/'y' or 'no'/'n'.")
    return confirm not in ['no', 'n']
