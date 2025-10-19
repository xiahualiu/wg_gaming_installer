#!/usr/bin/env python3
from __future__ import annotations

import logging
import random
import shutil
import socket
import sqlite3
import subprocess
from contextlib import contextmanager
from pathlib import Path
from textwrap import dedent
from typing import TYPE_CHECKING, Generator

import psutil
from prompt_toolkit import prompt

if TYPE_CHECKING:
    from psutil._common import snicaddr


def script_temp_folder() -> Path:
    """
    Returns the path to the temporary folder used by the script.
    Customizable.
    """
    return Path.home() / '.wireguard'


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


def create_config_db() -> None:
    """
    Create or reset the SQLite database table used to store WireGuard configurations.
    If any table exists it will be dropped and recreated with the schema:

    Table : server_config
        id INTEGER PRIMARY KEY CHECK (id = 1),
        server_nic_name TEXT,
        server_ipv4     TEXT,
        server_ipv6     TEXT

    Table : wg_server_config
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wg_nic_name     TEXT,
        wg_ipv4         TEXT,
        wg_ipv6         TEXT,
        wg_listen_port  INTEGER CHECK (wg_listen_port BETWEEN 1 AND 65535),
        wg_private_key TEXT,
        wg_public_key  TEXT

    Table : wg_peer_config
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name     TEXT,
        client_ipv4     TEXT,
        client_ipv6     TEXT,
        public_key      TEXT,
        preshared_key   TEXT,
        forward_ports   TEXT

    Table : install_status
        step_name       TEXT PRIMARY KEY,
    """
    db_path: Path = script_temp_folder() / "wg_config.db"

    # Lazy create parent folder
    if not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)

    # Drop existing table if exists and create new one
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS server_config;")
    cur.execute("DROP TABLE IF EXISTS wg_config;")
    cur.execute("DROP TABLE IF EXISTS peers;")
    cur.execute("DROP TABLE IF EXISTS install_status;")

    cur.execute(
        dedent(
            """
        CREATE TABLE server_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            server_nic_name TEXT,
            server_ipv4     TEXT,
            server_ipv6     TEXT
        );
        """
        )
    )
    cur.execute(
        """
        CREATE TABLE wg_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            wg_nic_name     TEXT,
            wg_ipv4         TEXT,
            wg_ipv6         TEXT,
            wg_listen_port  INTEGER
            CHECK (wg_listen_port BETWEEN 1 AND 65535),
            wg_private_key  TEXT,
            wg_public_key   TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE wg_peer_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name     TEXT,
            client_ipv4     TEXT,
            client_ipv6     TEXT,
            public_key      TEXT,
            preshared_key   TEXT,
            forward_ports   TEXT
        );
        """
    )
    cur.execute(
        dedent(
            """
        CREATE TABLE install_status (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL DEFAULT 'not_started'
            CHECK (state IN (
                'not_started',
                'sw_installed',
                'server_if_configured'
            ))
        );
        """
        )
    )
    # set initial state to 'not_started'
    cur.execute(
        """
        INSERT OR REPLACE INTO install_status (id, state)
        VALUES (1, 'not_started');
        """
    )
    conn.commit()


@contextmanager
def conf_db_connected() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager to connect to the SQLite database.
    Args:
        db_path (Path): The path to the SQLite database file.
    Yields:
        sqlite3.Connection: The database connection object.
    """
    conn: sqlite3.Connection = sqlite3.connect(script_temp_folder() / "wg_config.db")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def delete_folders(folders: list[Path]) -> None:
    """
    Safely delete a list of folders.
    If a folder is not empty, it will be removed recursively.
    Raises RuntimeError if a path is not a directory.
    """
    for folder in folders:
        if not folder.exists():
            logging.warning(f"Folder {folder} does not exist, skipping deletion.")
            continue
        folder = folder.resolve()
        if folder.is_dir():
            try:
                folder.rmdir()
            except OSError:
                shutil.rmtree(folder)
        else:
            raise RuntimeError(f"Path {folder} is not a directory")


def uninstall_delete_folders() -> None:
    """
    Delete folders created by the installer.
    """
    delete_folders([wg_conf_folder(), script_temp_folder()])


def get_virtualization_type() -> str:
    """
    Return the type of virtualization detected by systemd-detect-virt.
    Returns:
        str: The type of virtualization, or 'none' if not virtualized.
    """
    if shutil.which('systemd-detect-virt') is None:
        logging.warning("systemd-detect-virt not found, assuming no virtualization.")
        return 'none'

    virt_type: str = subprocess.run(
        ['systemd-detect-virt'], capture_output=True, text=True
    ).stdout.strip()
    return virt_type


def if_userspace_wireguard() -> bool:
    """
    Return True if userspace WireGuard (wireguard-go) is required.
    Returns:
        bool: True if userspace WireGuard is needed, False otherwise.
    Raises:
        RuntimeError: If TUN device is not found when userspace WireGuard is required.
    """

    virt_type: str = get_virtualization_type()
    if virt_type in ('openvz', 'lxc', 'lxd'):
        logging.info(
            f"Detected virtualization type: {virt_type}. "
            "Userspace WireGuard is required."
        )
        if not tun_dev_path().exists():
            raise RuntimeError(
                "TUN device not found; "
                "cannot proceed with userspace WireGuard installation."
            )
        else:
            logging.info(
                "TUN device found. Proceeding with userspace WireGuard installation."
            )
        return True
    return False


def ifname_ipv4_ipv6(ifname: str) -> tuple[str | None, str | None]:
    """
    Return IPv4 address and IPv6 address of a given network interface.
    Args:
        ifname (str): The name of the network interface.
    Returns:
        tuple[str | None, str | None]: A tuple containing the IPv4 and IPv6 addresses,
        or None if not found.
    """
    ipv4: str | None = None
    ipv6: str | None = None
    addrs: list[snicaddr] | tuple[()] = psutil.net_if_addrs().get(ifname, ())
    for a in addrs:
        if getattr(a, "family", None) == socket.AF_INET and not ipv4:
            ipv4 = a.address
        # AF_INET6 may include a "%scope" suffix on Linux; strip it
        if getattr(a, "family", None) == socket.AF_INET6 and not ipv6:
            ipv6 = a.address.split('%')[0]
    return ipv4, ipv6


def validate_ipv4_address(ip: str) -> bool:
    """
    Validate if the given string is a valid IPv4 address.
    Args:
        ip (str): The IP address string to validate.
    Returns:
        bool: True if valid IPv4 address, False otherwise.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except OSError:
        return False


def validate_ifname(name: str) -> bool:
    """
    Validate if the given string is a valid network interface name.
    Args:
        name (str): The network interface name to validate.
    Returns:
        bool: True if valid network interface name, False otherwise.
    """
    return name in psutil.net_if_addrs()


def validate_ipv6_address(ip: str) -> bool:
    """
    Validate if the given string is a valid IPv6 address.
    Args:
        ip (str): The IP address string to validate.
    Returns:
        bool: True if valid IPv6 address, False otherwise.
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def get_default_interface() -> str | None:
    """
    Return the name of the default gateway interface.
    Returns:
        str | None: The name of the default gateway interface. None if not found.
    """
    with open('/proc/net/route', 'r') as fh:
        for line in fh:
            parts: list[str] = line.strip().split()
            if len(parts) >= 2 and parts[1] == '00000000':
                iface: str = parts[0]
                stats: psutil._common.snicstats | None = psutil.net_if_stats().get(
                    iface
                )
                if stats and stats.isup:
                    return iface
    return None


def validate_port_not_in_use(port: int, sock_type: socket.AddressFamily) -> bool:
    """
    Validate if the given port is not in use for IPv4.
    Args:
        port (int): The port number to validate.
    Returns:
        bool: True if the port is not in use, False otherwise.
    """
    with socket.socket(sock_type, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False


def server_if_conf() -> None:
    # replicate the interactive questions from the shell script
    print('Next, I need to ask you a few questions to set up WireGuard server.')

    while True:
        # First get server NIC name
        default_nic_name: str | None = get_default_interface()
        server_nic_name: str = prompt(
            "Input the public interface name: ", default=default_nic_name or ""
        ).strip()
        if not validate_ifname(server_nic_name):
            print('Invalid network interface name, please try again.')
            continue

        # Then get server IP addresses
        default_nic_ipv4, default_nic_ipv6 = ifname_ipv4_ipv6(server_nic_name)
        server_nic_ipv4: str = prompt(
            "Input the public IPv4 address of the server: ",
            default=default_nic_ipv4 or "",
        ).strip()
        if not validate_ipv4_address(server_nic_ipv4):
            print('IPv4 address is required, please try again.')
            continue

        # IPv6 is optional, but if provided must be valid
        server_nic_ipv6: str = prompt(
            "Input the public IPv6 address of the server (leave blank if none): ",
            default=default_nic_ipv6 or "",
        ).strip()
        if server_nic_ipv6 and not validate_ipv6_address(server_nic_ipv6):
            print('Invalid IPv6 address, please try again.')
            continue

        # All inputs are valid, break the loop
        break

    # Save parameters to config db
    with conf_db_connected() as conn:
        cur = conn.cursor()
        # Write server network interface information
        cur.execute(
            """
            INSERT OR REPLACE INTO server_config
            (id, server_nic_name, server_ipv4, server_ipv6)
            VALUES (1, ?, ?, ?);
            """,
            (server_nic_name, server_nic_ipv4, server_nic_ipv6),
        )
        # Update install status
        cur.execute(
            """
            REPLACE INTO install_status (id, state)
            VALUES (1, 'server_if_configured');
            """
        )
        conn.commit()


def wg_gen_keypair() -> tuple[str, str]:
    # Create a WireGuard private/public key pair
    if shutil.which('wg') is None:
        raise RuntimeError("WireGuard 'wg' command not found in PATH.")
    priv = subprocess.run(
        ['wg', 'genkey'], capture_output=True, text=True
    ).stdout.strip()
    assert priv, "Failed to generate WireGuard private key."
    pub = subprocess.run(
        ['sh', '-c', f"echo '{priv}' | wg pubkey"], capture_output=True, text=True
    ).stdout.strip()
    assert pub, "Failed to generate WireGuard public key."
    return priv, pub


def server_wg_conf() -> None:
    # replicate the interactive questions from the shell script
    print(
        'Next, I need to ask you a few questions to set up WireGuard server interface.'
    )

    while True:
        # First get WireGuard NIC name
        default_wg_nic_name: str = 'wg0'
        wg_nic_name: str = prompt(
            "Input the WireGuard interface name: ", default=default_wg_nic_name
        ).strip()
        # If empty or longer than 15 chars, invalid
        if not wg_nic_name or len(wg_nic_name) > 15:
            print('Invalid network interface name, please try again.')
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
            print("Invalid IPv4 address, please try again.")
            continue

        # Check if IPv6 is set in the server config
        with conf_db_connected() as conn:
            cur: sqlite3.Cursor = conn.cursor()
            cur.execute("SELECT server_ipv6 FROM server_config WHERE id = 1;")
            row: dict = cur.fetchone()
            assert row is not None, "Server configuration not found in database."
            server_ipv6: str | None = row['server_ipv6']

        if server_ipv6:
            default_wg_ipv6: str = 'fd42:42:42::1'
            wg_ipv6: str = prompt(
                "Input the WireGuard IPv6 address of the server: ",
                default=default_wg_ipv6,
            ).strip()
            if not validate_ipv6_address(wg_ipv6):
                print("Invalid IPv6 address, please try again.")
                continue
        break

    while True:
        default_wg_listen_port: int = random.randint(60000, 65535)
        wg_listen_port_str: str = prompt(
            "Input the WireGuard listen port: ", default=str(default_wg_listen_port)
        ).strip()
        try:
            wg_listen_port: int = int(wg_listen_port_str)
        except ValueError:
            print("Invalid port input, please try again.")
            continue
        if wg_listen_port < 1 or wg_listen_port > 65535:
            print("Invalid port, please try again.")
            continue
        if not validate_port_not_in_use(
            wg_listen_port, socket.AddressFamily.AF_INET
        ) or not validate_port_not_in_use(
            wg_listen_port, socket.AddressFamily.AF_INET6
        ):
            print(f"Port {wg_listen_port} is already in use, please try another port.")
            continue
        break

    # Create a WireGuard private/public key pair
    server_priv, server_pub = wg_gen_keypair()

    # Save parameters to config db
