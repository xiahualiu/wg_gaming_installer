"""
Shell script related utility functions for WireGuard gaming installer.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from socket import AddressFamily
from typing import TYPE_CHECKING

import distro
import psutil
from prompt_toolkit import prompt

if TYPE_CHECKING:
    from psutil._common import snicaddr


def go_path() -> Path:
    """
    Return the expected installation path of Go programming language.
    Returns:
        Path: The expected installation path of Go. It is $Home/.go/bin/go
    """
    return Path.home() / '.go' / 'bin' / 'go'


def check_usr_local_bin_on_path() -> bool:
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


def need_userspace_wireguard(tun_dev_path: Path) -> bool:
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
        if not tun_dev_path.exists():
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


def ifname_ipv4_ipv6(ifname: str) -> tuple[list[str], list[str]]:
    """
    Return IPv4 address and IPv6 address of a given network interface.
    Args:
        ifname (str): The name of the network interface.
    Returns:
        tuple[list[str], list[str]]: A tuple containing two lists:
            - List of IPv4 addresses associated with the interface.
            - List of IPv6 addresses associated with the interface.
    """
    ipv4: list[str] = []
    ipv6: list[str] = []
    addrs: list[snicaddr] | tuple[()] = psutil.net_if_addrs().get(ifname, ())
    for a in addrs:
        if a.family == AddressFamily.AF_INET and not ipv4:
            ipv4.append(a.address)
        # AF_INET6 may include a "%scope" suffix on Linux; strip it
        if a.family == AddressFamily.AF_INET6 and not ipv6:
            ipv6.append(a.address.split('%')[0])
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


def get_os_info() -> tuple[str, str]:
    """
    Retrieve the operating system name and version.
    Returns:
        tuple[str, str]: A tuple containing the OS name and version.
    """

    os_id: str = distro.id()
    os_version: str = distro.version(pretty=False, best=False)
    return os_id, os_version


def install_wg_dependencies(os_id: str, os_version: str) -> None:
    """
    Install kernel WireGuard using the system's package manager.
    """
    os_l = os_id.lower()
    if os_l in ['ubuntu', 'debian']:
        pkgs = [
            'wireguard-tools',
            'nftables',
            'python3-nftables',
            'qrencode',
            'curl',
            'git',
            'make',
            'wget',
        ]
        subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
        subprocess.run(
            ['sudo', 'apt-get', 'install', '-y', '--no-install-recommends'] + pkgs,
            check=True,
            capture_output=True,
        )
        return

    if os_l in ['centos', 'rocky', 'almalinux']:
        pkgs = ['epel-release', 'elrepo-release']
        subprocess.run(
            ['sudo', 'dnf', 'install', '-y'] + pkgs, check=True, capture_output=True
        )
        subprocess.run(
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
            check=True,
            capture_output=True,
        )
        return

    if os_l == 'fedora':
        pkgs = [
            'wireguard-tools',
            'nftables',
            'python3-nftables',
            'qrencode',
            'curl',
            'git',
            'make',
            'wget',
        ]
        subprocess.run(
            ['sudo', 'dnf', 'install', '-y'] + pkgs, check=True, capture_output=True
        )
        return

    if os_l == 'arch':
        pkgs = [
            'wireguard-tools',
            'nftables',
            'python-nftables',
            'qrencode',
            'curl',
            'git',
            'make',
            'wget',
        ]
        # --needed prevents reinstall of already-installed packages
        subprocess.run(
            ['sudo', 'pacman', '-Syu', '--noconfirm', '--needed'] + pkgs,
            check=True,
            capture_output=True,
        )
        return


def install_wireguard_go() -> None:
    """
    Install userspace WireGuard (wireguard-go).
    """
    # Check if /usr/local/bin is on PATH because we will create symlinks there
    if not check_usr_local_bin_on_path():
        raise RuntimeError("/usr/local/bin is not on PATH.")

    # Check if wireguard-go is already installed
    if shutil.which('wireguard') is not None:
        logging.info("wireguard-go is already installed, skipping installation.")
        return

    # Check if Go is installed
    if shutil.which('go') is None:
        logging.info(
            "Go not found, installing Go programming language using go-installer."
        )
        prompt("Press Enter to continue...")
        logging.info(
            "Installing latest Go compiler... "
            "It could take several minutes. Please wait."
        )

        # Install Go using go-installer script
        try:
            subprocess.run(
                r"curl -sSL https://git.io/go-installer | bash",
                shell=True,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed to install Go programming language: "
                f"{e.stderr.decode().strip()}"
            )
            raise RuntimeError("Go installation failed.") from e

        # Create symlink to /usr/local/bin/go for immediate use
        try:
            subprocess.run(
                ['sudo', 'ln', '-s', go_path(), '/usr/local/bin/go'],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed to create symlink for Go binary: {e.stderr.decode().strip()}"
            )
            raise RuntimeError("Creating Go symlink failed.") from e

    # Verify Go installation again
    if shutil.which('go') is None:
        raise RuntimeError("Go command not found after installation.")

    # Clone the wireguard-go repository
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
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to build wireguard-go: {e.stderr.decode().strip()}")
            raise RuntimeError("Build wireguard-go failed.") from e

        # Move the wireguard-go binary to /usr/local/bin
        try:
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
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed to move wireguard-go binary to /usr/local/bin: "
                f"{e.stderr.decode().strip()}"
            )
            raise RuntimeError("Moving wireguard-go binary failed.") from e


def enable_forwarding_sysctl() -> None:
    """
    Enable IP forwarding for both IPv4 and IPv6.
    """
    logging.info("Set sysctl to allow IP forwarding")

    subprocess.run(
        ['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['sudo', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'],
        check=True,
        capture_output=True,
    )


def disable_forwarding_sysctl() -> None:
    """
    Disable IP forwarding for both IPv4 and IPv6.
    """
    logging.info("Unset sysctl to disable IP forwarding")

    subprocess.run(
        ['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=0'],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ['sudo', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=0'],
        check=True,
        capture_output=True,
    )
