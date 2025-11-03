import socket

from prompt_toolkit import prompt
from shell_scripts import (
    gen_wg_keypair,
    get_default_interface,
    ifname_ipv4_ipv6,
    validate_ifname,
    validate_ipv4_address,
    validate_ipv6_address,
    validate_port_not_in_use,
)
from sqlite_scripts import ServerIFConfig, ServerWGConfig


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
    if validate_ifname(server_nic_name):
        return server_nic_name
    return None


def server_if_ipv4_ipv6_prompt(
    server_nic_name: str,
) -> tuple[str, str | None] | None:
    """
    Prompt the user for the server's public IPv4 and IPv6 addresses.

    Args:
        server_nic_name (str): The server's network interface name.
    """
    default_nic_ipv4s, default_nic_ipv6s = ifname_ipv4_ipv6(server_nic_name)

    server_nic_ipv4: str = prompt(
        "Input the public IPv4 address of the server: ",
        default=default_nic_ipv4s[0] if default_nic_ipv4s else "",
    ).strip()
    if not validate_ipv4_address(server_nic_ipv4):
        return None

    server_nic_ipv6: str | None = None
    use_ipv6: str = (
        prompt("Does the server have a public IPv6 address? (yes/no): ", default="no")
        .strip()
        .lower()
    )
    if use_ipv6 in ['yes', 'y']:
        server_nic_ipv6_input: str = prompt(
            "Input the public IPv6 address of the server: ",
            default=default_nic_ipv6s[0] if default_nic_ipv6s else "",
        ).strip()
        if not validate_ipv6_address(server_nic_ipv6_input):
            return None
        server_nic_ipv6 = server_nic_ipv6_input

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
            input_str: tuple[str, str | None] | None = server_if_ipv4_ipv6_prompt(
                server_nic_name
            )
            if not input_str:
                print('Invalid IP address(es), please try again.')
                continue
            server_nic_ipv4, server_nic_ipv6 = input_str
            break

        # Review inputs
        print("")
        print("Please review the server network configuration:")
        print(f"└─ Interface Name: {server_nic_name}")
        if server_nic_ipv6:
            print(f"   ├─ IPv4 Address: {server_nic_ipv4}")
            print(f"   └─ IPv6 Address: {server_nic_ipv6}")
        else:
            print(f"   └─ IPv4 Address: {server_nic_ipv4}")
        confirm: str = prompt("Is this information correct? (yes/no): ").strip().lower()
        if confirm in ['yes', 'y']:
            return ServerIFConfig(
                nic_name=server_nic_name,
                nic_ipv4=server_nic_ipv4,
                nic_ipv6=server_nic_ipv6 or None,
            )
        else:
            print("Let's try again.\n")
            continue


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
    if not wg_nic_name:
        return None
    if len(wg_nic_name) > 15:
        return None
    if not all(c.isalnum() or c == '_' for c in wg_nic_name):
        return None
    return wg_nic_name


def wg_if_ipv4_prompt() -> str | None:
    """
    Prompt the user for the WireGuard IPv4 address.

    Returns:
        str | None: The validated WireGuard IPv4 address or None if invalid.
    """
    default_wg_ipv4: str = '10.66.66.1'
    wg_ipv4: str = prompt(
        "Input the WireGuard IPv4 address of the server: ",
        default=default_wg_ipv4,
    ).strip()
    if validate_ipv4_address(wg_ipv4):
        return wg_ipv4
    return None


def wg_if_ipv6_prompt() -> str | None:
    """
    Prompt the user for the WireGuard IPv6 address.

    Returns:
        str | None: The validated WireGuard IPv6 address or None if invalid.
    """
    default_wg_ipv6: str = 'fd42:42:42::1'
    wg_ipv6: str = prompt(
        "Input the WireGuard IPv6 address of the server: ",
        default=default_wg_ipv6,
    ).strip()
    if validate_ipv6_address(wg_ipv6):
        return wg_ipv6
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
        return None
    if not validate_port_not_in_use(wg_listen_port, socket.AddressFamily.AF_INET):
        return None
    if check_ipv6 and not validate_port_not_in_use(
        wg_listen_port, socket.AddressFamily.AF_INET6
    ):
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
            wg_ipv4: str | None = wg_if_ipv4_prompt()
            if not wg_ipv4:
                print("Invalid IPv4 address, please try again.")
                continue
            break

        # WireGuard IPv6 address (if applicable)
        wg_ipv6: str | None = None
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
        print(f"   ├─ IPv4 Address: {wg_ipv4}")
        if wg_ipv6:
            print(f"   ├─ IPv6 Address: {wg_ipv6}")
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
