#!/bin/bash

set -eu

RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m'

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported!"
		echo "For more information of using userspace WireGuard, check README.md"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if (( ${VERSION_ID} < 11 )); then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
		return 0
	fi
	if [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if (( ${RELEASE_YEAR} < 20 )); then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
		return 0
	fi
	echo "Your Linux distribution (${OS}) is not supported. Please use Ubuntu 20.04 or later"
	exit 1
}

function initialCheck() {
	checkVirt
	checkOS
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/xiahualiu/wg_gaming_installer"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	SERVER_PUB_NIC=''
	SERVER_WG_NIC=''
	SERVER_WG_IPV4=''
	SERVER_WG_IPV6=''
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done
	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done
	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server's WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done
	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server's WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Check if ssh is in range
	if (( ${SSH_CLIENT##* } == 53 || ${SSH_CLIENT##* } == 80 || ${SSH_CLIENT##* } == 88 || ${SSH_CLIENT##* } == 500 || \
		(${SSH_CLIENT##* } > 1023 && ${SSH_CLIENT##* } < 65000 ) )); then
		read -p "BE ADVISED! SSH Port will be changed from ${SSH_CLIENT##* } to 65432!"
		sudo sed -i 's/Port\s\+[0-9]\+/Port 65432/' /etc/ssh/sshd_config
		# Restart ssh service
		sudo systemctl restart ssh.service || true
		sudo systemctl restart sshd.service || true
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i65001-65535 -n1)
	SERVER_PORT=''
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ && "${SERVER_PORT}" -ge 1 && "${SERVER_PORT}" -le 65535 && ${SERVER_PORT} -ne 65432 ]]; do
		read -rp "Server's WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Cloudflare DNS by default
	CLIENT_DNS_1=''
	CLIENT_DNS_2=''
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		sudo apt-get update
		sudo apt-get install -y wireguard iptables resolvconf qrencode
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	sudo mkdir -p /etc/wireguard
	sudo chmod 700 /etc/wireguard
	# Store user information
	mkdir -p $HOME/.wireguard

	# Server keygen
	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Add server interface
	echo "[Interface]" | sudo tee "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "ListenPort = ${SERVER_PORT}" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "PrivateKey = ${SERVER_PRIV_KEY}" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "PostUp = $HOME/.wireguard/add-fullcone-nat.sh" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "PostDown = $HOME/.wireguard/rm-fullcone-nat.sh" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Create new client conf, must do this before creating following sh scripts
	newClient

	# add-fullcone-nat.sh
	echo "#!/bin/bash" | tee "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -I INPUT 1 -i ${SERVER_PUB_NIC} -p udp --dport ${SERVER_PORT} -j ACCEPT" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -I FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -I FORWARD 1 -i ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -I FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -I FORWARD 1 -i ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "# DNAT from 53,80,88,500, 1024 to 65000" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 53 -j DNAT --to-destination ${CLIENT_WG_IPV4}:53" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 80 -j DNAT --to-destination ${CLIENT_WG_IPV4}:80" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 88 -j DNAT --to-destination ${CLIENT_WG_IPV4}:88" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 500 -j DNAT --to-destination ${CLIENT_WG_IPV4}:500" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 1024:65000 -j DNAT --to-destination ${CLIENT_WG_IPV4}:1024-65000" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 53 -j DNAT --to-destination ${CLIENT_WG_IPV4}:53" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 80 -j DNAT --to-destination ${CLIENT_WG_IPV4}:80" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 88 -j DNAT --to-destination ${CLIENT_WG_IPV4}:88" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 500 -j DNAT --to-destination ${CLIENT_WG_IPV4}:500" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "iptables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 1024:65000 -j DNAT --to-destination ${CLIENT_WG_IPV4}:1024-65000" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 53 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:53" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 80 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:80" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 88 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:88" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 500 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:500" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 1024:65000 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:1024-65000" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 53 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:53" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 80 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:80" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 88 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:88" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 500 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:500" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"
	echo "ip6tables -t nat -A PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 1024:65000 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:1024-65000" | tee -a "$HOME/.wireguard/add-fullcone-nat.sh"

  # rm-fullcone-nat.sh
	sudo echo "#!/bin/bash" | tee "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -D INPUT -i ${SERVER_PUB_NIC} -p udp --dport ${SERVER_PORT} -j ACCEPT" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "# DNAT from 53,80,88,500, 1024 to 65000" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 53 -j DNAT --to-destination ${CLIENT_WG_IPV4}:53" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 80 -j DNAT --to-destination ${CLIENT_WG_IPV4}:80" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 88 -j DNAT --to-destination ${CLIENT_WG_IPV4}:88" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 500 -j DNAT --to-destination ${CLIENT_WG_IPV4}:500" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 1024:65000 -j DNAT --to-destination ${CLIENT_WG_IPV4}:1024-65000" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 53 -j DNAT --to-destination ${CLIENT_WG_IPV4}:53" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 80 -j DNAT --to-destination ${CLIENT_WG_IPV4}:80" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 88 -j DNAT --to-destination ${CLIENT_WG_IPV4}:88" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 500 -j DNAT --to-destination ${CLIENT_WG_IPV4}:500" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "iptables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 1024:65000 -j DNAT --to-destination ${CLIENT_WG_IPV4}:1024-65000" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 53 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:53" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 80 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:80" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 88 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:88" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 500 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:500" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p udp --dport 1024:65000 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:1024-65000" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 53 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:53" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 80 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:80" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 88 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:88" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 500 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:500" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"
	sudo echo "ip6tables -t nat -D PREROUTING -i ${SERVER_PUB_NIC} -p tcp --dport 1024:65000 -j DNAT --to-destination [${CLIENT_WG_IPV6}]:1024-65000" | tee -a "$HOME/.wireguard/rm-fullcone-nat.sh"

	# Add exec permission
	sudo chmod +x "$HOME/.wireguard/add-fullcone-nat.sh"
	sudo chmod +x "$HOME/.wireguard/rm-fullcone-nat.sh"

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" | sudo tee /etc/sysctl.d/wg.conf
	sudo sysctl --system

	sudo systemctl start "wg-quick@${SERVER_WG_NIC}"
	sudo systemctl enable "wg-quick@${SERVER_WG_NIC}"

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" | sudo tee /etc/sysctl.d/wg.conf

	sudo sysctl --system

	sudo systemctl start "wg-quick@${SERVER_WG_NIC}"
	sudo systemctl enable "wg-quick@${SERVER_WG_NIC}"

	# Check if WireGuard is running
	sudo systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else
		echo -e "\nHere is your client config file as a QR Code:"
		qrencode -t ansiutf8 -l L <"$HOME/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo "It is also available in $HOME/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo "SERVER_WG_NIC=${SERVER_WG_NIC}" > $HOME/.wireguard/.installed
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	CLIENT_NAME=''
	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(sudo grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	IPV4_EXISTS=''
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(sudo grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	IPV6_EXISTS=''
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(sudo grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	echo "[Interface]" > "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "PrivateKey = ${CLIENT_PRIV_KEY}" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "[Peer]" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "PublicKey = ${SERVER_PUB_KEY}" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo "Endpoint = ${ENDPOINT}" >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	echo 'AllowedIPs = 0.0.0.0/0,::/0' >> "${HOME}/.wireguard/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo "" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "[Peer]" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "PublicKey = ${CLIENT_PUB_KEY}" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
	echo "AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" | sudo tee -a "/etc/wireguard/${SERVER_WG_NIC}.conf"
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		sudo systemctl stop "wg-quick@${SERVER_WG_NIC}"
		sudo systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			sudo apt-get autoremove -y wireguard wireguard-tools qrencode
		fi

		sudo rm -rf /etc/wireguard
		sudo rm -rf $HOME/.wireguard
		sudo rm -f /etc/sysctl.d/wg.conf

		# Reload sysctl
		sudo sysctl --system

		# Check if WireGuard is running
		sudo systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Stop WireGuard"
	echo "   2) Restart WireGuard"
	echo "   3) Uninstall WireGuard"
	echo "   4) Exit"
	MENU_OPTION=''
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		sudo systemctl stop "wg-quick@${SERVER_WG_NIC}"
		;;
	2)
		sudo systemctl restart "wg-quick@${SERVER_WG_NIC}"
		;;
	3)
		uninstallWg
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e $HOME/.wireguard/.installed ]]; then
    source $HOME/.wireguard/.installed
	manageMenu
else
	installWireGuard
fi
