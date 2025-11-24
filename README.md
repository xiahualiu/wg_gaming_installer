[![ShellCheck](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml)

# wg_gaming_installer — WireGuard installer & manager

Lightweight installer/manager for a personal WireGuard server with optional port forwarding for gaming and similar use-cases. This repository contains the original bash installer (in the `legacy_script` branch) and a rewritten Python package `wg_gaming_installer` (recommended).

## Table of Contents

- [Quick Start](#quick-start)
- [Why the Python version](#why-the-python-version)
- [Supported platforms](#supported-platforms)
- [Prerequisites](#prerequisites)
- [Main menu](#main-menu)
- [Port forwarding](#port-forwarding)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Legacy installer](#legacy-installer)
- [License](#license)

## Quick Start

Clone, create a venv, install, and run the installer (as `root`, `sudo -i` before running the following):

```bash
git clone https://github.com/xiahualiu/wg_gaming_installer.git
cd wg_gaming_installer
python3 -m venv .venv --system-site-packages
source .venv/bin/activate
pip install -e .
python -m wg_gaming_installer.install_scripts
```

## Why the Python version

- Safer, clearer prompts and input validation.
- SQLite-backed config for persistent server & peer metadata.
- More portable across distributions using Python libraries.

## Supported platforms

Officially supported minimums:

| Distribution | Minimum | Notes |
|---|---:|---|
| `ubuntu` | 20.10 | 22.04 recommended |
| `debian` | 11 | Bullseye |

Also commonly compatible: `centos`/`rocky`/`almalinux` (9), `fedora` (32), `arch` (rolling).

- Requires a Linux host with a public IP or correct NAT/public endpoint.
- On OpenVZ/LXC you may need TUN/TAP enabled and `wireguard-go` will be installed.

## Prerequisites

- Root privileges.
- Python 3.10+ and `python3-venv`.
- A non-production host is recommended; the installer modifies networking and firewall rules.

## Main menu

After installation, the interactive menu provides these actions:

- Stop/Start WireGuard service
- Uninstall and remove generated files
- List peers; show peer config + QR code
- Add / Remove / Edit peers

## Port forwarding

The installer can add nftables DNAT rules that forward chosen public ports to a peer's WireGuard IP (IPv4/IPv6 supported). This is useful to host game servers or fix client NAT.

Example: forward TCP `25565` to `10.66.66.2:25565` so `SERVER_PUBLIC_IP:25565` reaches the peer.

Important: do not forward ports already used by server-local services (SSH, etc.).

## Customization

Recommended safe workflow:

1. Stop the service from the management menu.
2. Edit `wg_gaming_installer/exec_scripts.py` to change what the installer generates.
4. Restart the service using the management menu.

## Troubleshooting

- If the installer detects a non-public IP (e.g. `10.x.x.x`), supply your public IP when prompted (common on cloud providers).

## Legacy installer

The original bash installer is in the `legacy_script` branch:

```bash
git switch legacy_script
./install.sh
```

Note: the legacy installer is not compatible with the Python version; choose one approach.

## License

This project is licensed under the MIT License — see `LICENSE` for details.
