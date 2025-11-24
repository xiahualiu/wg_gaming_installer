"""
SQLite related utility functions for WireGuard gaming installer.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface, ip_address
from pathlib import Path
from textwrap import dedent
from typing import Generator, Union


@dataclass(frozen=True, slots=True)
class OSInfo:
    os_name: str
    os_version: str
    userspace_wg: bool


@dataclass(frozen=True, slots=True)
class ServerIFConfig:
    nic_name: str
    nic_ipv4: IPv4Address
    nic_ipv6: IPv6Address | None


@dataclass(frozen=True, slots=True)
class ServerWGConfig:
    wg_name: str
    ipv4: IPv4Interface
    ipv6: IPv6Interface | None
    listen_port: int
    private_key: str
    public_key: str


@dataclass(frozen=True, slots=True)
class SinglePort:
    port: int


@dataclass(frozen=True, slots=True)
class PortRange:
    start: int
    end: int


ForwardPort = Union[SinglePort, PortRange]


@dataclass(frozen=True, slots=True)
class PeerConfig:
    name: str
    ipv4: IPv4Interface
    ipv6: IPv6Interface | None
    dns: list[IPv4Address | IPv6Address]
    public_key: str
    private_key: str
    preshared_key: str
    forward_ports: list[ForwardPort]

    @property
    def forward_ports_str(self) -> str:
        """
        Serialize forward_ports to the DB string format:
            - single ports: "80"
            - ranges: "1000-2000"
        multiple entries joined by commas
        """
        ports_str_list: list[str] = []
        for item in self.forward_ports:
            if isinstance(item, SinglePort):
                ports_str_list.append(str(item.port))
            elif isinstance(item, PortRange):
                ports_str_list.append(f"{item.start}-{item.end}")
        return ",".join(ports_str_list)

    def dns_str(self) -> str:
        """
        Serialize DNS list to a comma-separated string.
        """
        return ",".join(str(dns_ip) for dns_ip in self.dns)

    @staticmethod
    def parse_dns(dns_str: str) -> list[IPv4Address | IPv6Address]:
        """
        Parse a comma-separated DNS string into a list of IP addresses.
        """
        dns_list: list[IPv4Address | IPv6Address] = []
        if not dns_str:
            return dns_list
        entries = dns_str.split(",")
        for entry in entries:
            entry = entry.strip()
            dns_ip = ip_address(entry)
            dns_list.append(dns_ip)
        return dns_list


def parse_forward_ports(ports_str: str) -> list[ForwardPort]:
    """
    Parse the forward_ports string from the DB into a list of ForwardPort objects.
    Args:
        ports_str (str): The forward_ports string from the DB.
    Returns:
        list[ForwardPort]: The parsed list of ForwardPort objects.
    """
    forward_ports: list[ForwardPort] = []
    if not ports_str:
        return forward_ports

    entries = ports_str.split(",")
    for entry in entries:
        entry = entry.strip()
        if "-" in entry:
            start_str, end_str = entry.split("-", 1)
            forward_ports.append(PortRange(start=int(start_str), end=int(end_str)))
        else:
            forward_ports.append(SinglePort(port=int(entry)))
    return forward_ports


class InstallStatus(IntEnum):
    NOT_STARTED = auto()
    DB_CREATED = auto()
    SW_INSTALLED = auto()
    SERVER_IF_CONFIGURED = auto()
    SERVER_WG_CONFIGURED = auto()
    UNKNOWN = auto()


def create_config_db(db_conn: sqlite3.Connection) -> None:
    """
    Create or reset the SQLite database table used to store WireGuard configurations.
    If any table exists it will be dropped and recreated with the schema:

    Table : os_info
        id INTEGER PRIMARY KEY CHECK (id = 1),
        os_name         TEXT,
        os_version      TEXT,
        userspace_wg    BOOLEAN

    Table : server_nic_config
        id INTEGER PRIMARY KEY CHECK (id = 1),
        nic_name        TEXT,
        nic_ipv4        TEXT,
        nic_ipv6        TEXT

    Table : server_wg_config
        id INTEGER PRIMARY KEY CHECK (id = 1),
        wg_name     TEXT,
        ipv4        TEXT,
        ipv6        TEXT,
        listen_port INTEGER CHECK (listen_port BETWEEN 1 AND 65535),
        private_key TEXT,
        public_key  TEXT

    Table : peer_config
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT,
        ipv4            TEXT,
        ipv6            TEXT,
        dns             TEXT,
        public_key      TEXT,
        private_key     TEXT,
        preshared_key   TEXT,
        forward_ports   TEXT

    Table : install_status
        id INTEGER PRIMARY KEY CHECK (id = 1),
        state TEXT NOT NULL DEFAULT 'not_started'
    """

    # Drop existing table if exists and create new one
    cur = db_conn.cursor()
    cur.execute("DROP TABLE IF EXISTS os_info;")
    cur.execute("DROP TABLE IF EXISTS server_nic_config;")
    cur.execute("DROP TABLE IF EXISTS server_wg_config;")
    cur.execute("DROP TABLE IF EXISTS peer_config;")
    cur.execute("DROP TABLE IF EXISTS install_status;")

    cur.execute(
        dedent(
            """
            CREATE TABLE os_info (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                os_name TEXT,
                os_version TEXT,
                userspace_wg BOOLEAN
            );
            """
        )
    )

    cur.execute(
        dedent(
            """
            CREATE TABLE server_nic_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                nic_name TEXT,
                nic_ipv4 TEXT,
                nic_ipv6 TEXT
            );
            """
        )
    )
    cur.execute(
        dedent(
            """
            CREATE TABLE server_wg_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                wg_name      TEXT,
                ipv4         TEXT,
                ipv6         TEXT,
                listen_port  INTEGER CHECK (listen_port BETWEEN 1 AND 65535),
                private_key  TEXT,
                public_key   TEXT
            );
            """
        )
    )
    cur.execute(
        dedent(
            """
            CREATE TABLE peer_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name     TEXT,
                ipv4     TEXT,
                ipv6     TEXT,
                dns      TEXT,
                public_key      TEXT,
                private_key     TEXT,
                preshared_key   TEXT,
                forward_ports   TEXT
            );
            """
        )
    )
    cur.execute(
        dedent(
            """
            CREATE TABLE install_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL DEFAULT 'not_started'
                CHECK (state IN (
                    'not_started',
                    'db_created',
                    'sw_installed',
                    'server_if_configured',
                    'server_wg_configured'
                ))
            );
            """
        )
    )
    # set initial state to 'not_started'
    cur.execute(
        dedent(
            """
            INSERT OR REPLACE INTO install_status (id, state)
            VALUES (1, 'not_started');
            """
        )
    )


@contextmanager
def conf_db_connected(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager to connect to the SQLite database. The context manager also starts
    a transaction and ensures that the connection is properly closed after use.

    Args:
        db_path (Path): The path to the SQLite database file.
    Yields:
        sqlite3.Connection: The database connection object.
    """
    if not db_path.parent.exists():
        raise FileNotFoundError(f"Directory {db_path.parent} does not exist.")
    conn: sqlite3.Connection = sqlite3.connect(database=db_path)
    conn.execute("BEGIN;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def read_install_status(db_conn: sqlite3.Connection) -> InstallStatus:
    """
    Read the current installation status from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        InstallStatus: The current installation status.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            SELECT state FROM install_status WHERE id = 1;
            """
        )
    )
    row: sqlite3.Row = cur.fetchone()
    if row and row["state"].upper() in InstallStatus.__members__:
        return InstallStatus[row["state"].upper()]
    else:
        return InstallStatus.UNKNOWN


def update_install_status(
    db_conn: sqlite3.Connection, new_state: InstallStatus
) -> None:
    """
    Update the installation status in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        new_state (InstallStatus): The new installation status to set.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO install_status (id, state)
            VALUES (1, ?);
            """
        ),
        (new_state.name.lower(),),
    )


def read_os_info(db_conn: sqlite3.Connection) -> OSInfo | None:
    """
    Read the OS information from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        OSInfo | None: The OS information if set, otherwise None.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM os_info WHERE id = 1;")
    row: sqlite3.Row | None = cur.fetchone()
    if row:
        return OSInfo(
            os_name=row["os_name"],
            os_version=row["os_version"],
            userspace_wg=bool(row["userspace_wg"]),
        )
    return None


def update_os_info(db_conn: sqlite3.Connection, os_info: OSInfo) -> None:
    """
    Update the OS information in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        os_info (OSInfo): The OS information data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO os_info
            (id, os_name, os_version, userspace_wg)
            VALUES (1, ?, ?, ?);
            """
        ),
        (
            os_info.os_name,
            os_info.os_version,
            int(os_info.userspace_wg),
        ),
    )


def read_server_nic_config(db_conn: sqlite3.Connection) -> ServerIFConfig | None:
    """
    Read the server NIC configuration from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        ServerNICConfig | None: The server NIC configuration if set, otherwise None.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM server_nic_config WHERE id = 1;")
    row: sqlite3.Row | None = cur.fetchone()
    if row:
        return ServerIFConfig(
            nic_name=row["nic_name"],
            nic_ipv4=IPv4Address(row["nic_ipv4"]),
            nic_ipv6=IPv6Address(row["nic_ipv6"]) if row["nic_ipv6"] else None,
        )
    return None


def update_server_config(
    db_conn: sqlite3.Connection, server_config: ServerIFConfig
) -> None:
    """
    Update the server NIC configuration in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        server_config (ServerNICConfig): The server NIC configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO server_nic_config
            (id, nic_name, nic_ipv4, nic_ipv6)
            VALUES (1, ?, ?, ?);
            """
        ),
        (
            server_config.nic_name,
            str(server_config.nic_ipv4),
            str(server_config.nic_ipv6) if server_config.nic_ipv6 else "",
        ),
    )


def read_wg_config(db_conn: sqlite3.Connection) -> ServerWGConfig | None:
    """
    Read the WireGuard server configuration from the database.

    Args:
        db_conn (sqlite3.Connection): The database connection object.

    Returns:
        ServerWGConfig | None: The WireGuard server configuration if set,
        otherwise None.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM server_wg_config WHERE id = 1;")
    row: sqlite3.Row | None = cur.fetchone()
    if row:
        return ServerWGConfig(
            wg_name=row["wg_name"],
            ipv4=IPv4Interface(row["ipv4"]),
            ipv6=IPv6Interface(row["ipv6"]) if row["ipv6"] else None,
            listen_port=row["listen_port"],
            private_key=row["private_key"],
            public_key=row["public_key"],
        )
    return None


def update_wg_config(db_conn: sqlite3.Connection, wg_config: ServerWGConfig) -> None:
    """
    Update the WireGuard server configuration in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        wg_config (ServerWGConfig): The WireGuard configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO server_wg_config (
                id,
                wg_name,
                ipv4,
                ipv6,
                listen_port,
                private_key,
                public_key
            )
            VALUES (1, ?, ?, ?, ?, ?, ?);
            """
        ),
        (
            wg_config.wg_name,
            str(wg_config.ipv4),
            str(wg_config.ipv6) if wg_config.ipv6 else "",
            wg_config.listen_port,
            wg_config.private_key,
            wg_config.public_key,
        ),
    )


def read_all_peer_configs(db_conn: sqlite3.Connection) -> list[PeerConfig]:
    """
    Read all peer configurations from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        list[PeerConfig]: A list of all peer configurations.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM peer_config;")
    rows: list[sqlite3.Row] = cur.fetchall()
    peer_configs: list[PeerConfig] = []
    for row in rows:
        peer_configs.append(
            PeerConfig(
                name=row["name"],
                ipv4=IPv4Interface(row["ipv4"]),
                ipv6=IPv6Interface(row["ipv6"]) if row["ipv6"] else None,
                dns=PeerConfig.parse_dns(row["dns"]),
                public_key=row["public_key"],
                private_key=row["private_key"],
                preshared_key=row["preshared_key"],
                forward_ports=parse_forward_ports(row["forward_ports"]),
            )
        )
    return peer_configs


def is_peer_exist(db_conn: sqlite3.Connection, peer_name: str) -> bool:
    """
    Check if a peer configuration exists in the database by peer name.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        peer_name (str): The name of the peer to check.
    Returns:
        bool: True if the peer exists, otherwise False.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            SELECT 1 FROM peer_config WHERE name = ?;
            """
        ),
        (peer_name,),
    )
    row: sqlite3.Row | None = cur.fetchone()
    return row is not None


def add_peer_config(db_conn: sqlite3.Connection, peer_config: PeerConfig) -> None:
    """
    Add a new peer configuration to the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        peer_config (PeerConfig): The peer configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    # Make sure peer with same name does not already exist
    if is_peer_exist(db_conn, peer_config.name):
        raise ValueError(f"Peer with name '{peer_config.name}' already exists.")

    cur.execute(
        dedent(
            """
            INSERT INTO peer_config (
                name,
                ipv4,
                ipv6,
                dns,
                public_key,
                private_key,
                preshared_key,
                forward_ports
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """
        ),
        (
            peer_config.name,
            str(peer_config.ipv4),
            str(peer_config.ipv6) if peer_config.ipv6 else "",
            peer_config.dns_str(),
            peer_config.public_key,
            peer_config.private_key,
            peer_config.preshared_key,
            peer_config.forward_ports_str,
        ),
    )


def delete_peer_config(db_conn: sqlite3.Connection, peer_name: str) -> None:
    """
    Delete a peer configuration from the database by peer name.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        peer_name (str): The name of the peer to delete.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            DELETE FROM peer_config WHERE name = ?;
            """
        ),
        (peer_name,),
    )
