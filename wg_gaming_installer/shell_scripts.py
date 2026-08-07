"""
Shell script related utility functions for WireGuard gaming installer.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from socket import AddressFamily
from typing import Any

import distro
import psutil
from prompt_toolkit import prompt


class ServiceStatus(IntEnum):
    ACTIVE = auto()
    INACTIVE = auto()
    ACTIVATING = auto()
    DEACTIVATING = auto()
    FAILED = auto()
    RELOADING = auto()
    UNKNOWN = auto()


_SERVICE_STATUS_MAP: dict[str, ServiceStatus] = {
    'active': ServiceStatus.ACTIVE,
    'inactive': ServiceStatus.INACTIVE,
    'activating': ServiceStatus.ACTIVATING,
    'deactivating': ServiceStatus.DEACTIVATING,
    'failed': ServiceStatus.FAILED,
    'reloading': ServiceStatus.RELOADING,
    'unknown': ServiceStatus.UNKNOWN,
}


# Pinned Go toolchain version and SHA-256 checksums used when installing
# wireguard-go. When bumping _GO_VERSION, update the matching hashes from
# https://go.dev/dl/?mode=json
_GO_VERSION: str = "1.26.5"

_GO_ARCH_MAP: dict[str, str] = {
    'x86_64': 'amd64',
    'aarch64': 'arm64',
    'i686': '386',
}

_GO_SHA256: dict[str, str] = {
    'amd64': '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053',
    'arm64': 'fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49',
    '386': '88c162b204e6eefcc32499453b492e80209f4a4c78c33092636901c540fb0d05',
}


def _go_arch() -> str:
    """
    Return the Go architecture name for the current machine.
    Raises:
        RuntimeError: If the current CPU architecture is not supported.
    """
    go_arch: str | None = _GO_ARCH_MAP.get(platform.machine().lower())
    if go_arch is None:
        raise RuntimeError(
            f"Unsupported CPU architecture for Go installation: {platform.machine()}"
        )
    return go_arch


def go_tarball_name() -> str:
    """
    Return the official Go toolchain tarball filename for this platform.
    """
    return f"go{_GO_VERSION}.linux-{_go_arch()}.tar.gz"


def _verify_go_checksum(tarball: Path) -> None:
    """
    Verify the SHA-256 checksum of a downloaded Go tarball against the pinned value.
    Raises:
        RuntimeError: If the checksum does not match.
    """
    sha256 = hashlib.sha256()
    with tarball.open('rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            sha256.update(chunk)
    expected: str = _GO_SHA256[_go_arch()]
    actual: str = sha256.hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"Go tarball checksum mismatch for {tarball.name}: "
            f"expected {expected}, got {actual}"
        )


def _check_usr_local_bin_on_path() -> bool:
    """
    Check if /usr/local/bin is on the system PATH.
    Returns:
        bool: True if /usr/local/bin is on PATH, False otherwise.
    """
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    return any(Path('/usr/local/bin').resolve() == Path(p).resolve() for p in path_dirs)


def delete_folders(folders: list[Path]) -> None:
    """
    Safely delete a list of folders.
    If a folder is not empty, it will be removed recursively.
    Raises RuntimeError if a path is not a directory.
    """
    for folder in folders:
        if not folder.exists():
            print(f"Folder {folder} does not exist, skipping deletion.")
            continue
        folder = folder.resolve()
        if folder.is_dir():
            try:
                folder.rmdir()
            except OSError:
                shutil.rmtree(folder)
        else:
            raise RuntimeError(f"Path {folder} is not a directory")


def _get_virtualization_type() -> str:
    """
    Return the type of virtualization detected by systemd-detect-virt.
    Returns:
        str: The type of virtualization, or 'none' if not virtualized.
    """
    if shutil.which('systemd-detect-virt') is None:
        print("systemd-detect-virt not found, assuming no virtualization.")
        return 'none'

    virt_type: str = subprocess.run(
        ['systemd-detect-virt'], check=False, capture_output=True, text=True
    ).stdout.strip()
    return virt_type


def need_userspace_wireguard(tun_dev_path: Path) -> bool:
    """
    Return True if userspace WireGuard (wireguard-go) is required.
    Returns:
        bool: True if userspace WireGuard is needed, False otherwise.
    Raises:
        RuntimeError: If TUN device is not found when userspace WireGuard is required.
    """

    virt_type: str = _get_virtualization_type()
    if virt_type in ('openvz', 'lxc', 'lxd'):
        print(
            f"Detected virtualization type: {virt_type}. "
            "Userspace WireGuard is required."
        )
        if not tun_dev_path.exists():
            raise RuntimeError(
                "TUN device not found; "
                "cannot proceed with userspace WireGuard installation."
            )
        else:
            print("TUN device found. Proceeding with userspace WireGuard installation.")
        return True
    return False


def nic_ipv4_ipv6(ifname: str) -> tuple[IPv4Address | None, IPv6Address | None]:
    """
    Return IPv4 address and IPv6 address of a given network interface.
    Args:
        ifname (str): The name of the network interface.
    Returns:
        tuple[IPv4Address | None, IPv6Address | None]: A tuple containing the
        IPv4 address and IPv6 address of the interface, or None if not found.
    """
    ipv4: IPv4Address | None = None
    ipv6: IPv6Address | None = None

    nic_addrs_dict: dict[str, list[Any]] = psutil.net_if_addrs()
    if ifname not in nic_addrs_dict:
        return None, None
    addrs: list[Any] = nic_addrs_dict[ifname]
    for a in addrs:
        if a.family == AddressFamily.AF_INET and not ipv4:
            ipv4 = IPv4Address(a.address)
        # AF_INET6 may include a "%scope" suffix on Linux; strip it
        if a.family == AddressFamily.AF_INET6 and not ipv6:
            ipv6 = IPv6Address(a.address.split('%')[0])
    return ipv4, ipv6


def ifname_exists(name: str) -> bool:
    """
    Validate if the given string is a valid network interface name.
    Args:
        name (str): The network interface name to validate.
    Returns:
        bool: True if valid network interface name, False otherwise.
    """
    return name in psutil.net_if_addrs()


def get_default_interface() -> str | None:
    """
    Return the name of the default gateway interface.
    Returns:
        str | None: The name of the default gateway interface. None if not found.
    """
    with open('/proc/net/route') as fh:
        for line in fh:
            parts: list[str] = line.strip().split()
            if len(parts) >= 2 and parts[1] == '00000000':
                iface: str = parts[0]
                stats = psutil.net_if_stats().get(iface)
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


def gen_wg_keypair() -> tuple[str, str]:
    # Create a WireGuard private/public key pair
    if shutil.which('wg') is None:
        raise RuntimeError("WireGuard 'wg' command not found in PATH.")
    priv = subprocess.run(
        ['wg', 'genkey'], check=False, capture_output=True, text=True
    ).stdout.strip()
    assert priv, "Failed to generate WireGuard private key."
    pub = subprocess.run(
        ['wg', 'pubkey'], input=priv, check=False, capture_output=True, text=True
    ).stdout.strip()
    assert pub, "Failed to generate WireGuard public key."
    return priv, pub


def gen_wg_preshared_key() -> str:
    # Create a WireGuard preshared key
    if shutil.which('wg') is None:
        raise RuntimeError("WireGuard 'wg' command not found in PATH.")
    psk = subprocess.run(
        ['wg', 'genpsk'], check=False, capture_output=True, text=True
    ).stdout.strip()
    assert psk, "Failed to generate WireGuard preshared key."
    return psk


def get_os_info() -> tuple[str, str]:
    """
    Get the operating system ID and version.
    Returns:
        tuple[str, str]: A tuple containing the OS ID and version.
    """
    os_id: str = distro.id()
    os_version: str = distro.version(pretty=False, best=False)
    return os_id, os_version


def _parse_version_tuple(version: str) -> tuple[int, int]:
    """
    Parse an OS version string into a (major, minor) tuple of integers.
    Non-numeric parts (e.g. "rolling") are treated as zero so rolling
    distributions satisfy the minimum-version check.
    """
    nums: list[int] = [0, 0]
    for i, part in enumerate(version.split('.')[:2]):
        try:
            nums[i] = int(part)
        except ValueError:
            break
    return (nums[0], nums[1])


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
        print(f"Operating system {os_id_lower} is not supported.", file=sys.stderr)
        return False

    os_version_tuple = _parse_version_tuple(os_version)

    if os_version_tuple < supported_os_min_version[os_id_lower]:
        print(
            f"Detected OS version {os_version_tuple} is lower than the "
            f"minimum supported version {supported_os_min_version[os_id_lower]} "
            f"for {os_id_lower}.",
            file=sys.stderr,
        )
        return False
    return True


def qrencode_text_to_terminal(text: str) -> None:
    """
    Generate and display a QR code in the terminal using qrencode.
    Args:
        text (str): The text to encode in the QR code.
    Raises:
        RuntimeError: If qrencode command is not found.
    """
    if shutil.which('qrencode') is None:
        raise RuntimeError("qrencode command not found in PATH.")

    # Send text to qrencode on stdin; let qrencode write ANSI QR to stdout
    subprocess.run(
        ["qrencode", "-t", "ansiutf8", "-l", "L"],
        input=text,
        text=True,
        check=True,
    )


def _run_sudo_commands(commands: list[list[str]]) -> None:
    """
    Run a sequence of sudo subprocess commands, stopping on the first failure.
    """
    for cmd in commands:
        subprocess.run(cmd, check=True, capture_output=True)


# os_id -> (install command sequences, uninstall command sequences)
_PKG_GROUPS: dict[str, tuple[list[list[str]], list[list[str]]]] = {
    'debian': (
        [
            ['sudo', 'apt-get', 'update'],
            [
                'sudo',
                'apt-get',
                'install',
                '-y',
                '--no-install-recommends',
                'wireguard-tools',
                'nftables',
                'python3-nftables',
                'qrencode',
                'curl',
                'git',
                'make',
                'wget',
            ],
        ],
        [['sudo', 'apt-get', 'autoremove', '-y', 'wireguard-tools', 'qrencode']],
    ),
    'rhel': (
        [
            ['sudo', 'dnf', 'install', '-y', 'epel-release', 'elrepo-release'],
            [
                'sudo',
                'dnf',
                'install',
                '-y',
                'kmod-wireguard',
                'wireguard-tools',
                'nftables',
                'python3-nftables',
                'qrencode',
                'curl',
                'git',
                'make',
                'wget',
            ],
        ],
        [
            [
                'sudo',
                'dnf',
                'remove',
                '-y',
                'kmod-wireguard',
                'wireguard-tools',
                'qrencode',
            ]
        ],
    ),
    'fedora': (
        [
            [
                'sudo',
                'dnf',
                'install',
                '-y',
                'wireguard-tools',
                'nftables',
                'python3-nftables',
                'qrencode',
                'curl',
                'git',
                'make',
                'wget',
            ],
        ],
        [['sudo', 'dnf', 'remove', '-y', 'wireguard-tools', 'qrencode']],
    ),
    'arch': (
        [
            [
                'sudo',
                'pacman',
                '-Syu',
                '--noconfirm',
                '--needed',
                'wireguard-tools',
                'nftables',
                'python-nftables',
                'qrencode',
                'curl',
                'git',
                'make',
                'wget',
            ],
        ],
        [['sudo', 'pacman', '-Rns', '--noconfirm', 'wireguard-tools', 'qrencode']],
    ),
}

_OS_TO_PKG_GROUP: dict[str, str] = {
    'ubuntu': 'debian',
    'debian': 'debian',
    'centos': 'rhel',
    'rocky': 'rhel',
    'almalinux': 'rhel',
    'fedora': 'fedora',
    'arch': 'arch',
}


def install_wg_dependencies(os_id: str, os_version: str) -> None:
    """
    Install kernel WireGuard using the system's package manager.
    """
    group: str | None = _OS_TO_PKG_GROUP.get(os_id.lower())
    if group is None:
        print(f"No package manager defined for OS '{os_id}'.", file=sys.stderr)
        return
    _run_sudo_commands(_PKG_GROUPS[group][0])


def uninstall_wg_dependencies(os_id: str, os_version: str) -> None:
    """
    Uninstall kernel WireGuard using the system's package manager.
    """
    group: str | None = _OS_TO_PKG_GROUP.get(os_id.lower())
    if group is None:
        print(f"No package manager defined for OS '{os_id}'.", file=sys.stderr)
        return
    _run_sudo_commands(_PKG_GROUPS[group][1])


def install_wireguard_go() -> None:
    """
    Install userspace WireGuard (wireguard-go).
    """
    # Check if /usr/local/bin is on PATH because we will create symlinks there
    if not _check_usr_local_bin_on_path():
        raise RuntimeError("/usr/local/bin is not on PATH.")

    # Check if wireguard-go is already installed
    if shutil.which('wireguard-go') is not None:
        print("wireguard-go is already installed, skipping installation.")
        return

    # Check if Go is installed
    if shutil.which('go') is None:
        print(f"Go not found, installing Go {_GO_VERSION} from go.dev/dl.")
        prompt("Press Enter to continue...")
        print(
            "Downloading the official Go toolchain... "
            "It could take several minutes. Please wait."
        )

        # Install the official Go toolchain from go.dev/dl (pinned version)
        tarball_name = go_tarball_name()
        url = f"https://go.dev/dl/{tarball_name}"
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_tarball = Path(tmpdir) / tarball_name
                subprocess.run(
                    ['curl', '-fL', '-o', str(tmp_tarball), url],
                    check=True,
                    capture_output=True,
                )
                # Verify integrity against the pinned SHA-256 before extracting
                _verify_go_checksum(tmp_tarball)
                # Remove any previous installation, then extract to /usr/local
                subprocess.run(
                    ['sudo', 'rm', '-rf', '/usr/local/go'],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ['sudo', 'tar', '-C', '/usr/local', '-xzf', str(tmp_tarball)],
                    check=True,
                    capture_output=True,
                )
                # Symlink the go binary for immediate use
                subprocess.run(
                    [
                        'sudo',
                        'ln',
                        '-sf',
                        '/usr/local/go/bin/go',
                        '/usr/local/bin/go',
                    ],
                    check=True,
                    capture_output=True,
                )
        except subprocess.CalledProcessError as e:
            print(
                "Failed to install Go programming language: "
                f"{e.stderr.decode().strip()}",
                file=sys.stderr,
            )
            raise RuntimeError("Go installation failed.") from e

    # Verify Go installation again
    if shutil.which('go') is None:
        raise RuntimeError("Go command not found after installation.")

    # Clone the wireguard-go repository to a temporary directory and build it
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        try:
            subprocess.run(
                [
                    'git',
                    'clone',
                    'https://git.zx2c4.com/wireguard-go',
                    str(tmpdir_path / 'wireguard-go'),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ['make', '-C', str(tmpdir_path / 'wireguard-go')],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    'sudo',
                    'mv',
                    str(tmpdir_path / 'wireguard-go' / 'wireguard-go'),
                    '/usr/local/bin/wireguard-go',
                ],
                check=True,
                capture_output=True,
            )
            return
        except subprocess.CalledProcessError as e:
            print(
                "Failed to build or move wireguard-go binary: "
                f"{e.stderr.decode().strip()}",
                file=sys.stderr,
            )
    raise RuntimeError("wireguard-go installation failed.")


def uninstall_wireguard_go() -> None:
    """
    Uninstall userspace WireGuard (wireguard-go).
    """
    wg_go_path = Path('/usr/local/bin/wireguard-go')
    if wg_go_path.exists():
        wg_go_path.unlink()
        print("wireguard-go uninstalled successfully.")
    else:
        print("wireguard-go is not installed, skipping uninstallation.")


def start_wg_service(wg_nic_name: str) -> None:
    """
    Start and enable the WireGuard service.
    """
    print("Starting and enabling WireGuard service")

    subprocess.run(
        ['systemctl', 'enable', '--now', f'wg-quick@{wg_nic_name}'],
        check=True,
        capture_output=True,
    )

    # Verify service started successfully
    status = get_wg_service_status(wg_nic_name)
    if status != ServiceStatus.ACTIVE:
        raise RuntimeError("Failed to start WireGuard service.")


def stop_wg_service(wg_nic_name: str) -> None:
    """
    Stop and disable the WireGuard service.
    """
    print("Stopping and disabling WireGuard service...")

    subprocess.run(
        ['systemctl', 'disable', '--now', f'wg-quick@{wg_nic_name}'],
        check=True,
        capture_output=True,
    )

    status = get_wg_service_status(wg_nic_name)
    if status != ServiceStatus.INACTIVE:
        raise RuntimeError("Failed to stop WireGuard service.")


def get_wg_service_status(wg_nic_name: str) -> ServiceStatus:
    """
    Get the status of the WireGuard service and return a ServiceStatus enum.
    Possible returned values: ACTIVE, INACTIVE, ACTIVATING, DEACTIVATING,
    FAILED, RELOADING, UNKNOWN.
    """
    if shutil.which('systemctl') is None:
        print("systemctl not found, cannot get service status.", file=sys.stderr)
        return ServiceStatus.UNKNOWN

    try:
        result = subprocess.run(
            ['systemctl', 'is-active', f'wg-quick@{wg_nic_name}'],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as e:
        print(f"Failed to run systemctl: {e}", file=sys.stderr)
        return ServiceStatus.UNKNOWN

    status = result.stdout.strip().lower()
    return _SERVICE_STATUS_MAP.get(status, ServiceStatus.UNKNOWN)
