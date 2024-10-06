[![ShellCheck](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/xiahualiu/wg_gaming_installer/actions/workflows/shellcheck.yml)
# WireGuard installer for Gaming

**Thank you for all the stars!**

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN that is specified for PERSONAL gaming or torrenting use. It supports multiple WireGuard peers now!**

## Update Logs

- 09/29/2024 Major update.
    - Added multi-peer support.

- 09/23/2024 Major update.
    - Added support for OpenVZ, LXC by installing wireguard-go.
    - Switched from legacy `iptables` to `nftables` rules.
    - Added shellcheck GitHub Action.

## What it does

#### Before using WireGuard

![](./imgs/before_wireguard.png)

#### After using WireGuard

![](./imgs/after_wireguard.png)

### NAT Improvement

Client connects to it will immediately achieve a **Full Cone** NAT, the optimal network type for gaming and torrenting. (How to check my NAT type in Win10 ? Use this tool [NatTypeTester](https://github.com/HMBSbige/NatTypeTester)).

With this script, you do not need to enable port forwarding on your router, you do not need the DMZ setting. All the magic happens inside Wireguard. Simply speaking: 

>The local ports will be forwarded to the server directly.

It solves connection problems due to strict NAT in these scenarios:

1. You want to host a Minecraft/Terraria, etc. server online and play with your friend, but you cannot figure out how to enable port forwarding on your router, or your ISP just did not give you a public IP address.

2. You play a P2P game like Monster Hunter: World or Overcooked! but your NAT type prevents you from connecting with other players. 

For a better gaming experience, the server should be close to your living region and has a low ping value. You should ping the provider's looking glass datacenter IP first before purchasing a VPS.

## Port Forwarding

The script **Port Forwards** the client ports to the corresponding ports on the server side. **Please make sure that there are no other applications (such as SSH) using these ports on the server, otherwise It will deafen any application that listens to these ports.** I highly suggest running this script on an new empty system. 

The script supports both IPv4 and IPv6.

### Customize preset `nftables` rules

You can customize the nftables rules by editing the `add-fullcone-nat.sh` file **BEFORE** running the installer script.

The detailed explanations of these `nftables` rules can be found in my blog post [Understand routing and NAT with WireGuard VPN](https://xiahua.pages.dev/wg-route-nat/).

## Requirements

Supported distributions:

- Debian >= 11
- Ubuntu >= 20.04 (*Preferred*)
- AlmaLinux
- RockyLinux
- ArchLinux
- Fedora

Theoretically any OS that supports `nftables` can run this script without too much trouble. It will support more Linux distributions in the future after I test them out one by one.

This script supports both **KVM** and **OpenVZ**, **LXC** machine virtualization types. 

For **OpenVZ**, **LXC** typed machine, [`wireguard-go`](https://github.com/WireGuard/wireguard-go) will be installed instead of the kernel WireGuard implementation.

In this case, you need to enable TUN/TAP driver on your provider's managment panal first.

## Usage

### 1st Step: Upgrade OS

Because WireGuard is a kernel module, you **MUST** upgrade the kernel to latest first and reboot your server once.

```bash
# If you are using Ubuntu/Debian, etc
sudo apt update && sudo apt upgrade -y

# If you are using Fedora, AlmaLinux, etc
sudo dnf update -y

# Arch, etc.
sudo pacman -Syu

# Reboot once
sudo reboot
```

### 2nd Step: Download and run the script.

Download and execute the script. Script user needs to be able to use `sudo` command.

Answer the questions asked by the script and it will take care of the rest. For most VPS providers, you can just enter through all the questions.

```bash
git clone https://github.com/xiahualiu/wg_gaming_installer.git
cd ./wg_gaming_installer
./install.sh
```

## Server Public IP problem

This script needs to run on a server with a public IP address to work.

Typically the server public IP should be populated automatically. However for some cloud providers like Google Cloud Platform and Oracle Cloud, the auto-populated public IP address is NOT correct, but instead a subnet IP address (usually starts with `10.*.*.*`).

In these cases you need to change the value to what your server's acutal public IP is.

## Stop / Restart / Uninstall / List clients / Add/Remove a client 

Run the script again will give you these options!
