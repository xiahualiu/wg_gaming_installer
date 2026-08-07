"""Tests for wg_gaming_installer.exec_scripts."""

from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface
from pathlib import Path

from wg_gaming_installer.exec_scripts import (
    create_nftables_config,
    create_start_script,
    create_stop_script,
    create_wg_config,
)
from wg_gaming_installer.sqlite_scripts import (
    PeerConfig,
    PortRange,
    ServerIFConfig,
    ServerWGConfig,
    SinglePort,
)


def make_wg_config(has_ipv6: bool = True) -> ServerWGConfig:
    return ServerWGConfig(
        wg_name="wg0",
        ipv4=IPv4Interface("10.66.66.1/24"),
        ipv6=IPv6Interface("fd42:42:42::1/120") if has_ipv6 else None,
        listen_port=51820,
        private_key="private_key",
        public_key="public_key",
    )


def make_server_config() -> ServerIFConfig:
    return ServerIFConfig(
        nic_name="eth0",
        nic_ipv4=IPv4Address("192.168.1.10"),
        nic_ipv6=IPv6Address("2001:db8::10"),
    )


def make_peer() -> PeerConfig:
    return PeerConfig(
        name="peer1",
        ipv4=IPv4Interface("10.66.66.2/24"),
        ipv6=IPv6Interface("fd42:42:42::2/120"),
        dns=[IPv4Address("1.1.1.1")],
        public_key="public_key",
        private_key="private_key",
        preshared_key="preshared_key",
        forward_ports=[SinglePort(port=80), PortRange(start=1000, end=2000)],
    )


def test_create_wg_config(tmp_path: Path) -> None:
    path = tmp_path / "wg0.conf"
    create_wg_config(
        path, make_wg_config(), [make_peer()], tmp_path / "s.sh", tmp_path / "e.sh"
    )
    content = path.read_text()
    assert "[Interface]" in content
    assert "ListenPort = 51820" in content
    assert "MTU = 1420" in content
    assert "Address = 10.66.66.1/24, fd42:42:42::1/120" in content
    assert "[Peer] # peer1" in content
    assert "AllowedIPs = 10.66.66.2/32, fd42:42:42::2/128" in content
    assert path.stat().st_mode & 0o777 == 0o600


def test_create_wg_config_custom_mtu(tmp_path: Path) -> None:
    path = tmp_path / "wg0.conf"
    create_wg_config(
        path,
        ServerWGConfig(
            wg_name="wg0",
            ipv4=IPv4Interface("10.66.66.1/24"),
            ipv6=None,
            listen_port=51820,
            private_key="private_key",
            public_key="public_key",
            mtu=1280,
        ),
        [make_peer()],
        tmp_path / "s.sh",
        tmp_path / "e.sh",
    )
    content = path.read_text()
    assert "MTU = 1280" in content


def test_create_wg_config_no_ipv6(tmp_path: Path) -> None:
    path = tmp_path / "wg0.conf"
    peer = make_peer()
    peer_no_v6 = PeerConfig(
        name=peer.name,
        ipv4=peer.ipv4,
        ipv6=None,
        dns=peer.dns,
        public_key=peer.public_key,
        private_key=peer.private_key,
        preshared_key=peer.preshared_key,
        forward_ports=peer.forward_ports,
    )
    create_wg_config(
        path,
        make_wg_config(has_ipv6=False),
        [peer_no_v6],
        tmp_path / "s.sh",
        tmp_path / "e.sh",
    )
    content = path.read_text()
    assert "Address = 10.66.66.1/24" in content
    assert "AllowedIPs = 10.66.66.2/32" in content


def test_create_start_script(tmp_path: Path) -> None:
    path = tmp_path / "wg_start.sh"
    create_start_script(True, Path("/bin/sh"), path, tmp_path / "wg.nft")
    content = path.read_text()
    assert content.startswith("#!")
    assert "net.ipv4.ip_forward=1" in content
    assert "net.ipv6.conf.all.forwarding=1" in content
    assert path.stat().st_mode & 0o777 == 0o700


def test_create_stop_script(tmp_path: Path) -> None:
    path = tmp_path / "wg_stop.sh"
    create_stop_script(True, Path("/bin/sh"), path)
    content = path.read_text()
    assert content.startswith("#!")
    assert "nft delete table ip wg_nat || true" in content
    assert "nft delete table ip6 wg_nat || true" in content
    assert path.stat().st_mode & 0o777 == 0o700


def test_create_nftables_config(tmp_path: Path) -> None:
    path = tmp_path / "wg.nft"
    create_nftables_config(make_wg_config(), make_server_config(), [make_peer()], path)
    content = path.read_text()
    assert "table ip wg_nat {" in content
    assert "table ip6 wg_nat {" in content
    assert "dnat to 10.66.66.2;" in content
    assert "dnat to fd42:42:42::2;" in content
    assert path.stat().st_mode & 0o777 == 0o600
