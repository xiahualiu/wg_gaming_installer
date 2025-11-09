import socket
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, ip_address

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


def server_if_name_prompt() -> str | None:
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


def server_if_ipv4_ipv6_prompt(
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
        while True:
            server_nic_name: str | None = server_if_name_prompt()
            if not server_nic_name:
                print('Invalid network interface name, please try again.')
                continue
            break

        # Next get server NIC IPv4 and IPv6
        while True:
            server_if_ips: tuple[
                IPv4Address, IPv6Address | None
            ] | None = server_if_ipv4_ipv6_prompt(server_nic_name)
            if not server_if_ips:
                print('Invalid IP address(es), please try again.')
                continue
            server_nic_ipv4, server_nic_ipv6 = server_if_ips
            break

        # Review inputs
        print("")
        print("Please review the server network configuration:")
        print(f"└─ Interface Name: {server_nic_name}")
        if server_nic_ipv6:
            print(f"   ├─ IPv4 Address: {str(server_nic_ipv4)}")
            print(f"   └─ IPv6 Address: {str(server_nic_ipv6)}")
        else:
            print(f"   └─ IPv4 Address: {str(server_nic_ipv4)}")
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
    if not all(c.isalnum() or c in {'_', '-', '.'} for c in name):
        return False
    return True


def wg_if_name_prompt() -> str | None:
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


def wg_if_ipv4_prompt() -> IPv4Interface | None:
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


def wg_if_ipv6_prompt() -> IPv6Interface | None:
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


def wg_if_listen_port_prompt(check_ipv6: bool) -> int | None:
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


def server_wg_prompt(has_ipv6: bool) -> ServerWGConfig:
    while True:
        # First get WireGuard NIC name
        while True:
            wg_nic_name: str | None = wg_if_name_prompt()
            if not wg_nic_name:
                print("Invalid WireGuard interface name, please try again.")
                continue
            break

        # WireGuard IPv4 addresses
        while True:
            wg_ipv4: IPv4Interface | None = wg_if_ipv4_prompt()
            if not wg_ipv4:
                print("Invalid IPv4 address, please try again.")
                continue
            break

        # WireGuard IPv6 address (if applicable)
        wg_ipv6: IPv6Interface | None = None
        if has_ipv6:
            while True:
                wg_ipv6 = wg_if_ipv6_prompt()
                if not wg_ipv6:
                    print("Invalid IPv6 address, please try again.")
                    continue
                break
        else:
            print(
                "Skipping IPv6 configuration as server has no IPv6 address configured."
            )

        # WireGuard listen port
        while True:
            wg_listen_port: int | None = wg_if_listen_port_prompt(
                check_ipv6=bool(wg_ipv6)
            )
            if not wg_listen_port:
                print("Invalid listen port, please try again.")
                continue
            break

        # Review inputs
        print("")
        print("Please review the WireGuard configuration:")
        print(f"└─ Interface Name: {wg_nic_name}")
        print(f"   ├─ IPv4 Interface: {str(wg_ipv4)}")
        if wg_ipv6:
            print(f"   ├─ IPv6 Interface: {str(wg_ipv6)}")
        print(f"   └─ Listen Port: {wg_listen_port}")
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
            )
        else:
            print("Let's try again.\n")
            continue


def peer_name_prompt(
    wg_config: ServerWGConfig, existing_peers: list[PeerConfig]
) -> str | None:
    """
    Prompt the user for the peer's name.
    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid name conflicts.

    Returns:
        str | None: The validated peer name or None if invalid.
    """
    peer_name: str = prompt("Input the name of the new peer: ").strip()
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


def peer_ipv4_prompt(
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
    # Suggest a default IP based on existing peers and server config
    used_ips: set[int] = {int(wg_config.ipv4.ip)}
    for peer in existing_peers:
        used_ips.add(int(peer.ipv4.ip))

    # Find the first unused IP address in the range
    default_ipv4_if: IPv4Address | None = None
    for host in wg_config.ipv4.network.hosts():
        host_int: int = int(host)
        if host_int not in used_ips:
            default_ipv4_if = host
            break

    # If no available IPs
    if not default_ipv4_if:
        print(
            "No available IPv4 addresses left in the WireGuard network.",
            file=sys.stderr,
        )
        return None

    # Prompt user for peer IPv4 interface
    peer_ipv4_input: str = prompt(
        "Input the WireGuard IPv4 interface of the new peer: ",
        default=(f"{str(default_ipv4_if)}"),
        rprompt=f"/{wg_config.ipv4.network.prefixlen}",
    ).strip()

    # Validate input
    try:
        peer_ipv4: IPv4Address = IPv4Address(peer_ipv4_input)
    except ValueError:
        print("Invalid IPv4 interface.", file=sys.stderr)
        return None

    # Check for IP conflicts
    if int(peer_ipv4) in used_ips:
        print("IPv4 interface already in use.", file=sys.stderr)
        return None

    # Verify that the IPv4 interface is within the server's WireGuard IPv4 network
    if peer_ipv4 not in wg_config.ipv4.network:
        print(
            "IPv4 interface is not within the server's WireGuard IPv4 network.",
            file=sys.stderr,
        )
        return None
    return IPv4Interface(f"{peer_ipv4}/{wg_config.ipv4.network.prefixlen}")


def peer_ipv6_prompt(
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
    # Ensure server has IPv6 config when calling this function
    assert wg_config.ipv6 is not None, "Server WireGuard IPv6 config is required."

    # Build set of used addresses
    used_addrs: set[int] = {int(wg_config.ipv6.ip)}
    for peer in existing_peers:
        if peer.ipv6:
            used_addrs.add(int(peer.ipv6.ip))

    # Suggest a default IP based on existing peers and server config
    default_ipv6_if: IPv6Address | None = None
    for host in wg_config.ipv6.network.hosts():
        if int(host) not in used_addrs:
            default_ipv6_if = host
            break

    # If no available IPs
    if not default_ipv6_if:
        print(
            "No available IPv6 addresses left in the WireGuard network.",
            file=sys.stderr,
        )
        return None

    # Prompt user for peer IPv6 interface
    peer_ipv6_input: str = prompt(
        "Input the WireGuard IPv6 interface of the new peer: ",
        default=(f"{str(default_ipv6_if)}"),
        rprompt=f"/{wg_config.ipv6.network.prefixlen}",
    ).strip()

    # Validate input
    try:
        peer_ipv6 = IPv6Address(peer_ipv6_input)
    except ValueError:
        print("Invalid IPv6 interface.", file=sys.stderr)
        return None

    # Check for IP conflicts
    if int(peer_ipv6) in used_addrs:
        print("IPv6 interface already in use.", file=sys.stderr)
        return None

    # Verify that the IPv6 interface is within the server's WireGuard IPv6 network
    if peer_ipv6 not in wg_config.ipv6.network:
        print(
            "IPv6 interface is not within the server's WireGuard IPv6 network.",
            file=sys.stderr,
        )
        return None
    return IPv6Interface(f"{peer_ipv6}/{wg_config.ipv6.network.prefixlen}")


def peer_forward_ports_prompt(
    wg_config: ServerWGConfig, existing_peers: list[PeerConfig]
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
                    elif isinstance(fp, PortRange):
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
        "Input the ports to forward (comma-separated, e.g., 80,443,27000-27050): "
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


def peer_dns_prompt() -> list[IPv4Address | IPv6Address]:
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
    print(f"  ├─ IPv4 Interface: {str(peer_ipv4)}")
    if peer_ipv6:
        print(f"  ├─ IPv6 Interface: {str(peer_ipv6)}")
    print("  ├─ DNS Servers: ")
    for dns in peer_dns:
        print(f"  │   └─ {str(dns)}")
    if peer_forward_ports:
        print("  └─ Forwarded Ports:")
        for fp in peer_forward_ports:
            if isinstance(fp, SinglePort):
                print(f"    └─ Port: {fp.port}")
            elif isinstance(fp, PortRange):
                print(f"    └─ Port Range: {fp.start}-{fp.end}")
    else:
        print("  └─ Forwarded Ports: None")


def add_peer_prompt(
    wg_config: ServerWGConfig, existing_peers: list[PeerConfig]
) -> PeerConfig:
    """
    Prompt the user to add another peer.

    Args:
        wg_config (ServerWGConfig): The server's WireGuard configuration.
        existing_peers (list[PeerConfig]): List of existing peers to
        avoid name and IP conflicts.

    Returns:
        PeerConfig: The configuration for the new peer.
    """
    print("Adding a new WireGuard peer...")
    while True:
        while True:
            peer_name: str | None = peer_name_prompt(
                wg_config=wg_config, existing_peers=existing_peers
            )
            if peer_name:
                break
            continue

        while True:
            peer_ipv4: IPv4Interface | None = peer_ipv4_prompt(
                wg_config, existing_peers
            )
            if peer_ipv4:
                break
            continue

        peer_ipv6: IPv6Interface | None = None
        if wg_config.ipv6:
            while True:
                peer_ipv6 = peer_ipv6_prompt(wg_config, existing_peers)
                if peer_ipv6:
                    break
                continue

        while True:
            peer_dns: list[IPv4Address | IPv6Address] = peer_dns_prompt()
            if peer_dns:
                break
            print("At least one valid DNS server must be provided.", file=sys.stderr)
            continue

        peer_forward_ports: list[ForwardPort] = []
        while True:
            enable_pf: str = (
                prompt("Enable port forwarding for this peer? (yes/no): ", default="no")
                .strip()
                .lower()
            )
            if enable_pf in ['yes', 'y']:
                peer_forward_ports = peer_forward_ports_prompt(
                    wg_config=wg_config, existing_peers=existing_peers
                )
                if peer_forward_ports:
                    break
                # Conflict detected, re-prompt
                continue
            else:
                # No port forwarding
                break

        # Review inputs
        print("")
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
        else:
            print("Let's try again.\n")
            continue

    # Generate WireGuard keypair for the peer
    try:
        peer_private_key, peer_public_key = gen_wg_keypair()
        peer_preshared_key: str = gen_wg_preshared_key()
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
        print("")

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
        print("")
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
    if confirm in ['no', 'n']:
        return False
    else:
        return True
