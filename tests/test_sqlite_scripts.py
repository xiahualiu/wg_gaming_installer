"""Tests for wg_gaming_installer.sqlite_scripts."""

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from pathlib import Path

import pytest

from wg_gaming_installer.sqlite_scripts import (
    ForwardPort,
    InstallStatus,
    OSInfo,
    PeerConfig,
    PortRange,
    ServerIFConfig,
    ServerWGConfig,
    SinglePort,
    add_peer_config,
    conf_db_connected,
    create_config_db,
    delete_peer_config,
    ensure_wg_mtu_column,
    parse_forward_ports,
    purge_server_config,
    read_all_peer_configs,
    read_install_status,
    read_os_info,
    read_server_nic_config,
    read_wg_config,
    update_install_status,
    update_os_info,
    update_server_config,
    update_wg_config,
)


def make_peer(
    name: str = "peer1",
    ipv4: str = "10.66.66.2/24",
    ipv6: str | None = "fd42:42:42::2/120",
    dns: list[IPv4Address | IPv6Address] | None = None,
    forward_ports: list[SinglePort | PortRange] | None = None,
) -> PeerConfig:
    return PeerConfig(
        name=name,
        ipv4=IPv4Interface(ipv4),
        ipv6=IPv6Interface(ipv6) if ipv6 else None,
        dns=dns or [IPv4Address("1.1.1.1")],
        public_key="public_key",
        private_key="private_key",
        preshared_key="preshared_key",
        forward_ports=forward_ports or [],
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "server_conf.db"
    with conf_db_connected(path) as conn:
        create_config_db(conn)
    return path


def test_forward_ports_str() -> None:
    peer = make_peer(
        forward_ports=[
            SinglePort(port=80),
            PortRange(start=1000, end=2000),
            SinglePort(port=443),
        ]
    )
    assert peer.forward_ports_str == "80,1000-2000,443"


def test_forward_ports_str_empty() -> None:
    assert make_peer().forward_ports_str == ""


def test_parse_forward_ports() -> None:
    assert parse_forward_ports("80,1000-2000,443") == [
        SinglePort(port=80),
        PortRange(start=1000, end=2000),
        SinglePort(port=443),
    ]


def test_parse_forward_ports_empty() -> None:
    assert parse_forward_ports("") == []


def test_forward_ports_round_trip() -> None:
    ports: list[ForwardPort] = [SinglePort(port=80), PortRange(start=1000, end=2000)]
    peer = make_peer(forward_ports=ports)
    assert parse_forward_ports(peer.forward_ports_str) == ports


def test_dns_round_trip() -> None:
    dns: list[IPv4Address | IPv6Address] = [
        IPv4Address("1.1.1.1"),
        IPv4Address("1.0.0.1"),
    ]
    peer = make_peer(dns=dns)
    assert peer.dns_str() == "1.1.1.1,1.0.0.1"
    assert PeerConfig.parse_dns(peer.dns_str()) == dns


def test_install_status_round_trip(db_path: Path) -> None:
    with conf_db_connected(db_path) as conn:
        assert read_install_status(conn) == InstallStatus.NOT_STARTED
        update_install_status(conn, InstallStatus.SW_INSTALLED)
    with conf_db_connected(db_path) as conn:
        assert read_install_status(conn) == InstallStatus.SW_INSTALLED


def test_os_info_round_trip(db_path: Path) -> None:
    info = OSInfo(os_name="ubuntu", os_version="22.04", userspace_wg=True)
    with conf_db_connected(db_path) as conn:
        update_os_info(conn, info)
    with conf_db_connected(db_path) as conn:
        assert read_os_info(conn) == info


def test_server_if_config_round_trip(db_path: Path) -> None:
    cfg = ServerIFConfig(
        nic_name="eth0",
        nic_ipv4=IPv4Address("192.168.1.10"),
        nic_ipv6=IPv6Address("2001:db8::10"),
    )
    with conf_db_connected(db_path) as conn:
        update_server_config(conn, cfg)
    with conf_db_connected(db_path) as conn:
        assert read_server_nic_config(conn) == cfg


def test_wg_config_round_trip(db_path: Path) -> None:
    cfg = ServerWGConfig(
        wg_name="wg0",
        ipv4=IPv4Interface("10.66.66.1/24"),
        ipv6=None,
        listen_port=51820,
        private_key="private",
        public_key="public",
        mtu=1280,
    )
    with conf_db_connected(db_path) as conn:
        update_wg_config(conn, cfg)
    with conf_db_connected(db_path) as conn:
        assert read_wg_config(conn) == cfg


def test_wg_config_mtu_default(db_path: Path) -> None:
    cfg = ServerWGConfig(
        wg_name="wg0",
        ipv4=IPv4Interface("10.66.66.1/24"),
        ipv6=None,
        listen_port=51820,
        private_key="private",
        public_key="public",
    )
    with conf_db_connected(db_path) as conn:
        update_wg_config(conn, cfg)
    with conf_db_connected(db_path) as conn:
        stored = read_wg_config(conn)
        assert stored is not None
        assert stored.mtu == 1420


def test_ensure_wg_mtu_column_migrates(db_path: Path) -> None:
    with conf_db_connected(db_path) as conn:
        conn.execute("DROP TABLE server_wg_config;")
        conn.execute("""
            CREATE TABLE server_wg_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                wg_name      TEXT,
                ipv4         TEXT,
                ipv6         TEXT,
                listen_port  INTEGER CHECK (listen_port BETWEEN 1 AND 65535),
                private_key  TEXT,
                public_key   TEXT
            );
            """)
        conn.execute("""
            INSERT INTO server_wg_config (
                id, wg_name, ipv4, listen_port, private_key, public_key
            ) VALUES (1, 'wg0', '10.66.66.1/24', 51820, 'priv', 'pub');
            """)
    with conf_db_connected(db_path) as conn:
        ensure_wg_mtu_column(conn)
        columns = [
            row[1] for row in conn.execute("PRAGMA table_info(server_wg_config);")
        ]
        assert "mtu" in columns
        cfg = read_wg_config(conn)
        assert cfg is not None and cfg.mtu == 1420


def test_ensure_wg_mtu_column_noop(db_path: Path) -> None:
    with conf_db_connected(db_path) as conn:
        ensure_wg_mtu_column(conn)
        columns = [
            row[1] for row in conn.execute("PRAGMA table_info(server_wg_config);")
        ]
        assert "mtu" in columns


def test_peer_crud(db_path: Path) -> None:
    peer = make_peer(
        forward_ports=[SinglePort(port=80), PortRange(start=1000, end=2000)]
    )
    with conf_db_connected(db_path) as conn:
        add_peer_config(conn, peer)
    with conf_db_connected(db_path) as conn:
        assert read_all_peer_configs(conn) == [peer]
    with conf_db_connected(db_path) as conn:
        delete_peer_config(conn, peer.name)
    with conf_db_connected(db_path) as conn:
        assert read_all_peer_configs(conn) == []


def test_add_peer_duplicate_name_raises(db_path: Path) -> None:
    peer = make_peer()
    with conf_db_connected(db_path) as conn:
        add_peer_config(conn, peer)
        with pytest.raises(ValueError):
            add_peer_config(conn, make_peer(name=peer.name, ipv4="10.66.66.3/24"))


def test_purge_server_config(db_path: Path) -> None:
    wg_cfg = ServerWGConfig(
        wg_name="wg0",
        ipv4=IPv4Interface("10.66.66.1/24"),
        ipv6=None,
        listen_port=51820,
        private_key="private",
        public_key="public",
    )
    nic_cfg = ServerIFConfig(
        nic_name="eth0",
        nic_ipv4=IPv4Address("192.168.1.10"),
        nic_ipv6=None,
    )
    with conf_db_connected(db_path) as conn:
        update_wg_config(conn, wg_cfg)
        update_server_config(conn, nic_cfg)
        add_peer_config(conn, make_peer())

    with conf_db_connected(db_path) as conn:
        purge_server_config(conn)

    with conf_db_connected(db_path) as conn:
        assert read_wg_config(conn) is None
        assert read_server_nic_config(conn) is None
        assert read_all_peer_configs(conn) == []
