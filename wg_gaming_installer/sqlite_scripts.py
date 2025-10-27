"""
SQLite related utility functions for WireGuard gaming installer.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from pathlib import Path
from textwrap import dedent
from typing import Generator


@dataclass(frozen=True, slots=True)
class OSInfo:
    os_name: str
    os_version: str
    userspace_wg: bool


@dataclass(frozen=True, slots=True)
class ServerConfig:
    server_nic_name: str
    server_ipv4: str
    server_ipv6: str


@dataclass(frozen=True, slots=True)
class WGConfig:
    wg_nic_name: str
    wg_ipv4: str
    wg_ipv6: str | None
    wg_listen_port: int
    wg_private_key: str
    wg_public_key: str


class WGForwardPortEnum(Enum):
    SINGLE: int
    RANGE: tuple[int, int]


@dataclass(frozen=True, slots=True)
class PeerConfig:
    peer_name: str
    peer_ipv4: str
    peer_ipv6: str
    public_key: str
    preshared_key: str
    forward_ports: list[WGForwardPortEnum]

    def forward_ports_str(self) -> str:
        ports_str_list: list[str] = []
        for port in self.forward_ports:
            if isinstance(port, WGForwardPortEnum) and port == WGForwardPortEnum.SINGLE:
                ports_str_list.append(str(port.value))
            elif (
                isinstance(port, WGForwardPortEnum) and port == WGForwardPortEnum.RANGE
            ):
                ports_str_list.append(f"{port.value[0]}-{port.value[1]}")
        return ",".join(ports_str_list)


class InstallStatus(IntEnum):
    NOT_STARTED = auto()
    DB_CREATED = auto()
    SW_INSTALLED = auto()
    SERVER_IF_CONFIGURED = auto()
    SERVER_WG_CONFIGURED = auto()


def create_config_db(db_conn: sqlite3.Connection) -> None:
    """
    Create or reset the SQLite database table used to store WireGuard configurations.
    If any table exists it will be dropped and recreated with the schema:

    Table : os_info
        id INTEGER PRIMARY KEY CHECK (id = 1),
        os_name TEXT,
        os_version TEXT

    Table : server_config
        id INTEGER PRIMARY KEY CHECK (id = 1),
        server_nic_name TEXT,
        server_ipv4     TEXT,
        server_ipv6     TEXT,
        userspace_wg    BOOLEAN

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
        peer_name     TEXT,
        peer_ipv4     TEXT,
        peer_ipv6     TEXT,
        public_key      TEXT,
        preshared_key   TEXT,
        forward_ports   TEXT

    Table : install_status
        step_name       TEXT PRIMARY KEY,
    """

    # Drop existing table if exists and create new one
    cur = db_conn.cursor()
    cur.execute("DROP TABLE IF EXISTS os_info;")
    cur.execute("DROP TABLE IF EXISTS server_config;")
    cur.execute("DROP TABLE IF EXISTS wg_config;")
    cur.execute("DROP TABLE IF EXISTS wg_peer_config;")
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
            CREATE TABLE server_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                server_nic_name TEXT,
                server_ipv4     TEXT,
                server_ipv6     TEXT,
            );
            """
        )
    )
    cur.execute(
        dedent(
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
    )
    cur.execute(
        dedent(
            """
            CREATE TABLE wg_peer_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_name     TEXT,
                peer_ipv4     TEXT,
                peer_ipv6     TEXT,
                public_key      TEXT,
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
                    'server_wg_configured',
                    'peers_configured'
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
    conn: sqlite3.Connection = sqlite3.connect(db_path)
    conn.execute("BEGIN;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()


def read_install_status(db_conn: sqlite3.Connection) -> InstallStatus:
    """
    Read the current installation status from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        str: The current installation status.
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
    if row:
        return InstallStatus[row['state'].upper()]
    else:
        return InstallStatus.NOT_STARTED


def update_install_status(
    db_conn: sqlite3.Connection, new_state: InstallStatus
) -> None:
    """
    Update the installation status in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        new_state (str): The new installation status to set.
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


def read_server_config(db_conn: sqlite3.Connection) -> ServerConfig | None:
    """
    Read the server configuration from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        ServerConfig | None: The server configuration if set, otherwise None.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM server_config WHERE id = 1;")
    row: sqlite3.Row | None = cur.fetchone()
    if row:
        return ServerConfig(
            server_nic_name=row["server_nic_name"],
            server_ipv4=row["server_ipv4"],
            server_ipv6=row["server_ipv6"],
        )
    return None


def update_server_config(
    db_conn: sqlite3.Connection, server_config: ServerConfig
) -> None:
    """
    Update the server configuration in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        server_config (ServerConfig): The server configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO server_config
            (id, server_nic_name, server_ipv4, server_ipv6, userspace_wg)
            VALUES (1, ?, ?, ?);
            """
        ),
        (
            server_config.server_nic_name,
            server_config.server_ipv4,
            server_config.server_ipv6,
        ),
    )


def read_wg_config(db_conn: sqlite3.Connection) -> WGConfig | None:
    """
    Read the server configuration from the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
    Returns:
        dict[str, str] | None: The server configuration if set, otherwise None.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute("SELECT * FROM wg_config WHERE id = 1;")
    row: sqlite3.Row | None = cur.fetchone()
    if row:
        return WGConfig(
            wg_nic_name=row["wg_nic_name"],
            wg_ipv4=row["wg_ipv4"],
            wg_ipv6=row["wg_ipv6"],
            wg_listen_port=row["wg_listen_port"],
            wg_private_key=row["wg_private_key"],
            wg_public_key=row["wg_public_key"],
        )
    return None


def update_wg_config(db_conn: sqlite3.Connection, wg_config: WGConfig) -> None:
    """
    Update the WireGuard server configuration in the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        wg_config (WGConfig): The WireGuard configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    cur.execute(
        dedent(
            """
            REPLACE INTO wg_config (
                id,
                wg_nic_name,
                wg_ipv4,
                wg_ipv6,
                wg_listen_port,
                wg_private_key,
                wg_public_key
            )
            VALUES (1, ?, ?, ?, ?, ?, ?);
            """
        ),
        (
            wg_config.wg_nic_name,
            wg_config.wg_ipv4,
            wg_config.wg_ipv6 or "",
            wg_config.wg_listen_port,
            wg_config.wg_private_key,
            wg_config.wg_public_key,
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
    cur.execute("SELECT * FROM wg_peer_config;")
    rows: list[sqlite3.Row] = cur.fetchall()
    peer_configs: list[PeerConfig] = []
    for row in rows:
        peer_configs.append(
            PeerConfig(
                peer_name=row["peer_name"],
                peer_ipv4=row["peer_ipv4"],
                peer_ipv6=row["peer_ipv6"],
                public_key=row["public_key"],
                preshared_key=row["preshared_key"],
                forward_ports=row["forward_ports"],
            )
        )
    return peer_configs


def add_peer_config(db_conn: sqlite3.Connection, peer_config: PeerConfig) -> None:
    """
    Add a new peer configuration to the database.
    Args:
        db_conn (sqlite3.Connection): The database connection object.
        peer_config (PeerConfig): The peer configuration data.
    """
    cur: sqlite3.Cursor = db_conn.cursor()
    # Make sure peer with same peer_name does not already exist
    existing_peer = read_all_peer_configs(db_conn)
    if any(p.peer_name == peer_config.peer_name for p in existing_peer):
        raise ValueError(
            f"Peer with client_name '{peer_config.peer_name}' already exists."
        )

    cur.execute(
        dedent(
            """
            INSERT INTO wg_peer_config (
                peer_name,
                peer_ipv4,
                peer_ipv6,
                public_key,
                preshared_key,
                forward_ports
            )
            VALUES (?, ?, ?, ?, ?, ?);
            """
        ),
        (
            peer_config.peer_name,
            peer_config.peer_ipv4,
            peer_config.peer_ipv6,
            peer_config.public_key,
            peer_config.preshared_key,
            peer_config.forward_ports,
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
            DELETE FROM wg_peer_config WHERE peer_name = ?;
            """
        ),
        (peer_name,),
    )
