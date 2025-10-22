"""
Main installation logic for WireGuard gaming installer.
"""

from __future__ import annotations

import logging
import random
import socket
from pathlib import Path

from prompt_toolkit import prompt
from shell_scripts import (
    delete_folders,
    get_default_interface,
    ifname_ipv4_ipv6,
    validate_ifname,
    validate_ipv4_address,
    validate_ipv6_address,
    validate_port_not_in_use,
    wg_gen_keypair,
)
from sqlite_scripts import (
    ServerConfig,
    WGConfig,
    conf_db_connected,
    read_server_config,
    write_server_config,
    write_wg_config,
)


def script_temp_folder() -> Path:
    """
    Returns the path to the temporary folder used by the script.
    Customizable.
    """
    return Path.home() / '.wireguard'


def server_conf_db_path() -> Path:
    """
    Returns the path to the server configuration file.
    Customizable.
    """
    return script_temp_folder() / 'server_conf.db'


def wg_conf_folder() -> Path:
    """
    Returns the path to the WireGuard configuration folder.
    Customizable.
    """
    return Path('/etc/wireguard')


def tun_dev_path() -> Path:
    """
    Returns the path to the TUN device.
    Customizable.
    """
    return Path('/dev/net/tun')


def script_root_dir() -> Path:
    """
    Returns the path to the root directory of the script.
    """
    return Path(__file__).resolve().parent


def uninstall_delete_folders() -> None:
    """
    Delete folders created by the installer.
    """
    delete_folders([wg_conf_folder(), script_temp_folder()])


def server_if_conf() -> None:
    while True:
        # First get server NIC name
        default_nic_name: str | None = get_default_interface()
        server_nic_name: str = prompt(
            "Input the public interface name: ", default=default_nic_name or ""
        ).strip()
        if not validate_ifname(server_nic_name):
            logging.warning('Invalid network interface name, please try again.')
            continue

        # Then get server IP addresses
        default_nic_ipv4_list, default_nic_ipv6_list = ifname_ipv4_ipv6(server_nic_name)
        default_nic_ipv4 = default_nic_ipv4_list[0] if default_nic_ipv4_list else None
        default_nic_ipv6 = default_nic_ipv6_list[0] if default_nic_ipv6_list else None
        server_nic_ipv4: str = prompt(
            "Input the public IPv4 address of the server: ",
            default=default_nic_ipv4 or "",
        ).strip()
        if not validate_ipv4_address(server_nic_ipv4):
            logging.warning('IPv4 address is required, please try again.')
            continue

        # IPv6 is optional, but if provided must be valid
        server_nic_ipv6: str = prompt(
            "Input the public IPv6 address of the server (leave blank if none): ",
            default=default_nic_ipv6 or "",
        ).strip()
        if server_nic_ipv6 and not validate_ipv6_address(server_nic_ipv6):
            logging.warning('Invalid IPv6 address, please try again.')
            continue

        # All inputs are valid, break the loop
        break

    # Save parameters to config db
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        write_server_config(
            conn,
            ServerConfig(
                server_nic_name=server_nic_name,
                server_ipv4=server_nic_ipv4,
                server_ipv6=server_nic_ipv6,
            ),
        )


def server_wg_conf() -> None:
    while True:
        # First get WireGuard NIC name
        default_wg_nic_name: str = 'wg0'
        wg_nic_name: str = prompt(
            "Input the WireGuard interface name: ", default=default_wg_nic_name
        ).strip()
        # If empty or longer than 15 chars, invalid
        if not wg_nic_name or len(wg_nic_name) > 15:
            logging.warning('Invalid network interface name, please try again.')
            continue
        else:
            break

    while True:
        # Then get WireGuard IPv4 addresses
        default_wg_ipv4: str = '10.66.66.1'
        wg_ipv4: str = prompt(
            "Input the WireGuard IPv4 address of the server: ",
            default=default_wg_ipv4,
        ).strip()
        if not validate_ipv4_address(wg_ipv4):
            logging.warning("Invalid IPv4 address, please try again.")
            continue
        break

    # Check if IPv6 is set in the server config
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        server_conf: ServerConfig | None = read_server_config(conn)
        if not server_conf:
            raise RuntimeError("Server configuration not found in database.")

    wg_ipv6: str = ""
    if len(server_conf.server_ipv6) != 0:
        while True:
            default_wg_ipv6: str = 'fd42:42:42::1'
            wg_ipv6 = prompt(
                "Input the WireGuard IPv6 address of the server: ",
                default=default_wg_ipv6,
            ).strip()
            if not validate_ipv6_address(wg_ipv6):
                logging.warning("Invalid IPv6 address, please try again.")
                continue
            break
    else:
        logging.info(
            "Skipping IPv6 configuration as server has no IPv6 address configured."
        )

    while True:
        default_wg_listen_port: int = random.randint(60000, 65535)
        wg_listen_port_str: str = prompt(
            "Input the WireGuard listen port: ", default=str(default_wg_listen_port)
        ).strip()
        try:
            wg_listen_port: int = int(wg_listen_port_str)
        except ValueError:
            logging.warning("Invalid port input, please try again.")
            continue
        if wg_listen_port < 1 or wg_listen_port > 65535:
            logging.warning("Invalid port, please try again.")
            continue
        if not validate_port_not_in_use(
            wg_listen_port, socket.AddressFamily.AF_INET
        ) or not validate_port_not_in_use(
            wg_listen_port, socket.AddressFamily.AF_INET6
        ):
            logging.warning(
                f"Port {wg_listen_port} is already in use, please try another port."
            )
            continue
        break

    # Create a WireGuard private/public key pair
    server_priv, server_pub = wg_gen_keypair()

    # Save parameters to config db
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        write_wg_config(
            conn,
            WGConfig(
                wg_nic_name=wg_nic_name,
                wg_ipv4=wg_ipv4,
                wg_ipv6=wg_ipv6,
                wg_listen_port=wg_listen_port,
                wg_private_key=server_priv,
                wg_public_key=server_pub,
            ),
        )
