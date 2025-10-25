"""
Main installation logic for WireGuard gaming installer.
"""

from __future__ import annotations

import logging
import random
import socket
from collections.abc import Callable
from pathlib import Path

from prompt_toolkit import prompt
from shell_scripts import (
    delete_folders,
    get_default_interface,
    get_os_info,
    ifname_ipv4_ipv6,
    install_wg_dependencies,
    install_wireguard_go,
    need_userspace_wireguard,
    validate_ifname,
    validate_ipv4_address,
    validate_ipv6_address,
    validate_port_not_in_use,
    wg_gen_keypair,
)
from sqlite_scripts import (
    InstallStatus,
    ServerConfig,
    WGConfig,
    conf_db_connected,
    create_config_db,
    read_install_status,
    read_server_config,
    update_install_status,
    update_server_config,
    update_wg_config,
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
        update_server_config(
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
        update_wg_config(
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


def is_os_supported(os_id: str, os_version: str) -> bool:
    """
    Check if the operating system is supported.
    """
    # store minimums as (major, minor) tuples
    supported_os_min_version: dict[str, tuple[int, int]] = {
        'ubuntu': (20, 10),  # in-kernel from 20.10 (22.04 recommended)
        'debian': (11, 0),  # Bullseye
        'centos': (9, 0),  # CentOS Stream 9 / RHEL 9
        'rocky': (9, 0),
        'almalinux': (9, 0),
        'fedora': (32, 0),
        'arch': (0, 0),  # rolling
    }

    os_id_lower = os_id.lower()
    if os_id_lower not in supported_os_min_version:
        return False

    os_version_tuple = tuple(int(part) for part in os_version.split('.')[:2])

    if os_id_lower not in supported_os_min_version:
        logging.error(f"Operating system {os_id_lower} is not supported.")
        return False

    if os_version_tuple < supported_os_min_version[os_id_lower]:
        logging.error(
            f"Detected OS version {os_version_tuple} is lower than the "
            f"minimum supported version {supported_os_min_version[os_id_lower]} "
            f"for {os_id_lower}."
        )
        return False
    return True


def continue_install(state: InstallStatus) -> list[Callable[[], None]]:
    """
    Continue the installation process.
    Returns a list of functions to be executed in order.
    """

    full_install_steps: list[Callable[[], None]] = [
        db_setup,
        install_wg_package,
        server_if_conf,
        server_wg_conf,
    ]

    if state == InstallStatus.NOT_STARTED:
        return full_install_steps
    elif state == InstallStatus.DB_CREATED:
        return full_install_steps[1:]
    elif state == InstallStatus.SW_INSTALLED:
        return full_install_steps[2:]
    elif state == InstallStatus.SERVER_IF_CONFIGURED:
        return full_install_steps[3:]
    elif state == InstallStatus.SERVER_WG_CONFIGURED:
        logging.info("Installation already completed. No further action needed.")
        return []
    else:
        raise RuntimeError("Unknown installation state.")


def db_setup() -> None:
    """
    Pre-installation setup tasks.
    """
    logging.info("Step 1: Setting up configuration database...")

    # Create temporary folder
    temp_folder = script_temp_folder()
    temp_folder.mkdir(parents=True, exist_ok=True)

    # Create or reset the configuration database
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        create_config_db(conn)
        update_install_status(db_conn=conn, new_state=InstallStatus.DB_CREATED)


def db_setup_failure_cleanup() -> None:
    """
    Cleanup tasks in case of database setup failure.
    """
    logging.info("Cleaning up after database setup failure...")
    uninstall_delete_folders()


def install_wg_package() -> None:
    """
    Main installation function for WireGuard server.
    """
    logging.info("Step 2: Starting WireGuard server installation...")

    # Step 1: Get OS information
    os_id, os_version = get_os_info()

    if not is_os_supported(os_id, os_version):
        raise RuntimeError(f"Operating system {os_id} {os_version} is not supported.")

    logging.info(f"Detected operating system: {os_id} {os_version}")

    # Step 2: Install WireGuard and dependencies
    logging.info("Installing WireGuard and dependencies...")
    install_wg_dependencies(os_id, os_version)

    # Check if userspace WireGuard is needed
    logging.info("Checking if userspace WireGuard is needed...")
    if need_userspace_wireguard(tun_dev_path()):
        logging.info(
            "OS virtualization type requires userspace WireGuard implementation."
        )
        prompt("Press Enter to continue with WireGuard-Go installation...")
        install_wireguard_go()
    else:
        logging.info("In-kernel WireGuard implementation is supported.")

    # Step 3: update install status in database
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        update_install_status(db_conn=conn, new_state=InstallStatus.SW_INSTALLED)


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )
    # Check if db exists
    logging.info("Checking if configuration database exists...")
    if not server_conf_db_path().exists():
        db_setup()

    # Continue installation from the beginning
    logging.info("Reading installation status from database...")
    with conf_db_connected(db_path=server_conf_db_path()) as conn:
        status: InstallStatus = read_install_status(conn)
        steps: list[Callable[[], None]] = continue_install(status)

    # Execute installation steps
    for step in steps:
        step()
