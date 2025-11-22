[![ShellCheck](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml)

# wg_gaming_installer — WireGuard installer and manager

Small installer/manager for a WireGuard server, focused on personal gaming and lightweight use-cases. The repository contains the original `install.sh` (on `legacy_script` branch) and a rewritten Python package `wg_gaming_installer` (recommended).

## Why use the Python version

- Safer, clearer user prompts and input validation.
- Uses SQLite to persist server and peer metadata.
- Easier portability across Linux distributions via `distro` and other Python libraries.

> Note: This project is in active development (alpha). Use on non-production systems only.

## Supported platforms

The installer detects and supports the following distributions and minimum versions:

| Distribution | Minimum version | Notes |
| :---: | :---:| :---: |
| `ubuntu` | 20.10 | 22.04 recommended |
| `debian` | 11 | Bullseye |

- Requires a Linux host with a public IP address (or correctly configured NAT/public endpoint).
- Works with both KVM and OpenVZ/LXC; on OpenVZ/LXC the implementation may use `wireguard-go` instead of the kernel module.

## Port forwarding

The installer can optionally forward chosen ports from the server's public IP to a peer's WireGuard address. This makes it easy to host a game server or fix NAT-related connectivity problems for a client.

### How it works

The installer adds `nftables` DNAT rules on the server so incoming traffic on a public port is forwarded to the peer's WireGuard IP (IPv4 and IPv6 supported).

### Game example

Forwarding Minecraft TCP port `25565` to peer `10.66.66.2` makes `SERVER_PUBLIC_IP:25565` reach `10.66.66.2:25565`.

**Note:** Do not forward a port that is already used by a local service on the server (SSH, etc.).

## Prerequisites

- A Linux host that meets the Supported platforms listed above.
- Python 3.10 or newer and `python3-venv` package.
- `root` privileges for installation.

Recommended: a fresh, non-production system. The installer modifies networking and firewall rules; avoid running on production hosts unless you understand the changes.


## Installation

**Important:** All commands in this section assume you are running as the `root` user. To become root, run `sudo -i` or `sudo su -` before proceeding.

Clone the repo.

```bash
git clone https://github.com/xiahualiu/wg_gaming_installer.git
cd wg_gaming_installer
```

Create a virtual environment and install the package in editable mode:

```bash
python3 -m venv .venv --system-site-packages
source .venv/bin/activate
pip install -e .
```

Run the installer (inside the virtualenv):

```bash
python -m wg_gaming_installer.install_scripts
```

## After installation

Start the installer management menu (run inside the virtualenv and as `root`):

```bash
source .venv/bin/activate
python -m wg_gaming_installer.install_scripts
```

The command opens an interactive WireGuard management menu with the following options:

- `1` Stop WireGuard service (and disable it at OS startup)
- `2` Start WireGuard service (and enable it at OS startup)
- `3` Uninstall WireGuard service and remove generated files
- `4` List all configured peers (shows IPv4/IPv6, DNS, forwarded ports)
- `5` Show a peer's WireGuard configuration and display a QR code
- `6` Add a new peer
- `7` Remove an existing peer
- `8` Edit a peer's configuration
- `9` Exit the menu

Notes:

- Adding, removing, or editing peers will restart the WireGuard service automatically when necessary.
- Peer configurations are printed to the terminal as well as a QR code so you can quickly import them on mobile clients.
- The server WireGuard configuration file is written to `/etc/wireguard/<WG_NAME>.conf`. `PostUp/PostDown` hooks call the bundled `wg_start.py` and `wg_stop.py` scripts to apply nftables rules and IP forwarding.
- The script stores runtime configuration in the local database at `~/.wireguard/server_conf.db` — you can inspect or back this up if desired.

## Intallation (legacy)

The legacy bash script can be found in the `legacy_script` branch if you prefer it.

```bash
git switch legacy_script
./install.sh
```

**Note:** The legacy installer is NOT compatible with the latest Python script, you need to stick to one after the installation.

## Troubleshooting

If the installer auto-detects a non-public IP (for example `10.x.x.x`), provide your public IP manually when prompted. 
> This is highly likely to happen when you are using a cloud provider such as Google Cloud Platform, AWS, or Oracle Cloud.

On virtualized hosts (LXC/OpenVZ) you may need to **enable TUN/TAP** in your provider control panel.



## License

This project is licensed under the MIT License — see `LICENSE` for details.
