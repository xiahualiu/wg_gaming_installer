# WireGuard installer for Gaming

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN that is specified for PERSONAL gaming or torrenting use. It supports only ONE client!**

If you are looking for a common WireGuard install script that supports multi-client connections, i.e. multiple devices connect to the VPN at the same time, please visit [this repository](https://github.com/angristan/wireguard-install/) to continue.

The script **Port Forwards** the local port `53`, `88`, `80`, `500`(4 ports for XBOX LIVE) and `1024-65000` to the corresponding ports on the server side. These ports covered most of the ports used by any games. **Please make sure that there is no other application using these ports on the server**. I highly suggest running this script on an new empty system. **It will deafen any application that listens to these ports.**


Specifically, if the SSH port is inside the range, the script will automatically move the it to `65432` for not losing access to the server after installation.

The script supports both IPv4 and IPv6.

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

Most part of this script is based on the angristan's [wireguard-install](https://github.com/angristan/wireguard-install/), because I am a new shell programmer so any improvement pull request is welcomed!

## NAT Improvement

Client connects to it will immediately achieve a **Full Cone** NAT, the optimal network type for gaming and torrenting. (How to check my NAT type in Win10 ? Type "xbox networking" in the search bar and enter).

You do not need to enable port forwarding on your router, you do not need the DMZ setting. All the magic happens inside Wireguard. Simply speaking: 

>The local ports will be forwarded to the server directly.

It solves the following scenarios:

1. You want to host a Minecraft/Terraria, etc. server online and play with your friend, but you cannot figure out how to enable port forwarding on your router, or your ISP just did not give you a public IP address.

2. You play a P2P game like Monster Hunter: World or Overcooked! but your NAT type prevents you from connecting with other players. 

For a better gaming experience, the server should be close to your living region and has a low ping value. You should ping the provider's looking glass datacenter IP first before purchasing a VPS.

## Requirements

Supported distributions:

- Ubuntu >= 16.04
- Debian 10
- Fedora
- CentOS
- Arch Linux

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest. For most VPS providers, you can just enter through all the questions.

```bash
wget https://raw.githubusercontent.com/xiahualiu/wg_gaming_installer/main/wg-gaming-installer.sh 
chmod +x wireguard-install.sh
./wireguard-install.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.



## Stop / Restart / Uninstal

Run the script again will give you these options!