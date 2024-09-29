#!/bin/bash
set -eu

# Temporary files folder
SCRIPT_TEMP_FOLDER="$HOME/.wireguard"

# Default WireGuard conf folder
WG_CONF_FOLDER="/etc/wireguard"

# Userspace WireGuard will check TUN device
TUN_DEV_PATH='/dev/net/tun'

# Go path (only used when userspace WG is needed)
GO_INSTALL_PATH='/usr/local/bin/go'
WG_GOROOT='/usr/local/bin/wireguard-go'

# Color for pretty stdout.
RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m'

# Get script root dir
SCRIPT_ROOT_DIR=$(
	cd "$(dirname "$0")"
	pwd
)

# Check whether userspace or kernel WireGuard
checkVirt() {
	OS_VIRT=$(systemd-detect-virt)
	USERSPACE_WG='false'

	if [ "$OS_VIRT" = 'openvz' ]; then
		echo -e "OpenVZ is detected, ${RED}wireguard-go${NC} will be installed, instead of the kernel wireguard."
		USERSPACE_WG="true"
	fi
	if [ "$OS_VIRT" = 'lxc' ]; then
		echo -e "LXC is detected, ${RED}wireguard-go${NC} will be installed, instead of the kernel wireguard."
		USERSPACE_WG='true'
	fi

	# Check if TUN/TAP device is enabled if userspace WG is used
	if [ $USERSPACE_WG = 'true' ]; then
		if ! sudo ls "$TUN_DEV_PATH"; then
			echo "$TUN_DEV_PATH not found, please enable TUN/TAP device driver for using userspace WireGuard."
			exit 1
		fi
	fi
}

# Check whether OS is supported
checkOS() {
	source '/etc/os-release'
	OS=$ID
	if [ "$OS" = 'debian' ] || [ "$OS" = 'raspbian' ]; then
		if [ "$VERSION_ID" -lt 11 ]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS='debian' # overwrite if raspbian
	elif [ "$OS" = 'ubuntu' ]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [ "$RELEASE_YEAR" -lt 20 ]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
	elif [ "$OS" = 'almalinux' ]; then
		:
	elif [ "$OS" = 'rocky' ]; then
		:
	elif [ "$OS" = 'arch' ]; then
		:
	elif [ "$OS" = 'fedora' ]; then
		:
	else
		echo "Your Linux distribution (${OS}) is not supported. Please use Ubuntu 20.04 or later"
		exit 1
	fi
}

################################################################################
######################## Step 1 : Prepare Folders ##############################
################################################################################

prepareFolders() {
	sudo mkdir -p "$WG_CONF_FOLDER"
	mkdir -p "$SCRIPT_TEMP_FOLDER"
}

deleteFolders() {
	sudo rm -rf "$WG_CONF_FOLDER" "$SCRIPT_TEMP_FOLDER"
}

################################################################################
########################## Step 2 : Install WG #################################
################################################################################

installonDebian() {
	sudo apt-get update
	sudo apt-get install -y wireguard nftables qrencode curl git make wget
}

uninstallonDebian() {
	sudo apt-get autoremove -y wireguard wireguard-tools qrencode
}

installAlmaLinux() {
	sudo rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux
	sudo dnf update -y
	sudo dnf install -y epel-release elrepo-release
	sudo dnf install -y kmod-wireguard wireguard-tools nftables qrencode curl git make wget
}

uninstallAlmaLinux() {
	sudo dnf autoremove -y kmod-wireguard wireguard-tools qrencode
	sudo dnf clean all -y
}

installRockyLinux() {
	sudo dnf update -y
	sudo dnf install -y epel-release elrepo-release
	sudo dnf install -y kmod-wireguard wireguard-tools nftables qrencode curl git make wget
}

uninstallRockyLinux() {
	sudo dnf autoremove -y kmod-wireguard wireguard-tools qrencode
	sudo dnf clean all -y
}

installArchLinux() {
	sudo pacman -Sy --noconfirm wireguard-tools nftables qrencode curl git make wget
}

uninstallArchLinux() {
	sudo pacman -R --noconfirm wireguard-tools qrencode
}

installFedora() {
	sudo dnf update -y
	sudo dnf install -y wireguard-tools nftables qrencode curl git make wget
}

uninstallFedora() {
	sudo dnf autoremove -y wireguard-tools qrencode
	sudo dnf clean all -y
}

installUserspaceWG() {
	bash <(curl -sL https://git.io/go-installer)
	sudo ln -s "$HOME/.go/bin/go" "$GO_INSTALL_PATH"
	git clone "https://git.zx2c4.com/wireguard-go" "${SCRIPT_ROOT_DIR}/wireguard-go"
	{
		cd "${SCRIPT_ROOT_DIR}/wireguard-go"
		make
		sudo ln -s "${SCRIPT_ROOT_DIR}/wireguard-go/wireguard-go" "$WG_GOROOT"
	}
}

uninstallUserspaceWG() {
	# If we have to use the userspace WireGuard
	if [ $USERSPACE_WG = 'true' ]; then
		sudo rm -rf "${SCRIPT_ROOT_DIR}/wireguard-go"
		sudo rm -rf "$HOME/.go"
		sudo unlink "$GO_INSTALL_PATH" || true
		sudo unlink "$WG_GOROOT" || true
	fi
}

installWireGuard() {
	# Install WireGuard tools and module
	if [ "$OS" = 'ubuntu' ] || [ "$OS" = 'debian' ]; then
		installonDebian
	elif [ "$OS" = 'almalinux' ]; then
		installAlmaLinux
	elif [ "$OS" = 'rocky' ]; then
		installRockyLinux
	elif [ "$OS" = 'arch' ]; then
		installArchLinux
	elif [ "$OS" = 'fedora' ]; then
		installFedora
	fi

	if [ $USERSPACE_WG = 'true' ]; then
		installUserspaceWG
	fi
}

cleanUpInstall() {
	if [ "${OS}" = 'ubuntu' ] || [ "${OS}" = 'debian' ]; then
		uninstallonDebian
	elif [ "$OS" = 'almalinux' ]; then
		uninstallAlmaLinux
	elif [ "$OS" = 'rocky' ]; then
		uninstallRockyLinux
	elif [ "$OS" = 'arch' ]; then
		uninstallArchLinux
	elif [ "$OS" = 'fedora' ]; then
		uninstallFedora
	fi

	if [ $USERSPACE_WG = 'true' ]; then
		uninstallUserspaceWG
	fi
}

################################################################################
####################### Step 3 : Configure WG Server ###########################
################################################################################

serverConfQuestions() {
	clear
	echo "I need to ask you a few questions to set up WireGuard server."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [ -z "$SERVER_PUB_IP" ]; then
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
	while ! echo "$SERVER_PUB_NIC" | grep -qE '^[a-zA-Z0-9_]+$'; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done
	while ! echo "$SERVER_WG_NIC" | grep -qE '^[a-zA-Z0-9_]+$' || [ ${#SERVER_WG_NIC} -gt 16 ]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done
	while ! echo "$SERVER_WG_IPV4" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; do
		read -rp "Server's WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done
	while [ -z "$SERVER_WG_IPV6" ]; do
		read -rp "Server's WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i65001-65535 -n1)
	SERVER_PORT=''
	while (! echo "$SERVER_PORT" | grep -qE '^[0-9]+$') || [ "$SERVER_PORT" -gt 65535 ] || [ "$SERVER_PORT" -lt 65000 ]; do
		read -rp "Server's WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Cloudflare DNS by default
	CLIENT_DNS_1=''
	CLIENT_DNS_2=''
	while ! echo "$CLIENT_DNS_1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	while ! echo "$CLIENT_DNS_2" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [ "$CLIENT_DNS_2" = "" ]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done
}

createServerNATscripts() {
	sudo cp "${SCRIPT_ROOT_DIR}/templates/add-fullcone-nat.sh" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
	sudo cp "${SCRIPT_ROOT_DIR}/templates/rm-fullcone-nat.sh" "${WG_CONF_FOLDER}/rm-fullcone-nat.sh"

	sudo sed -i "s/\$SERVER_PUB_NIC/${SERVER_PUB_NIC}/g" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"

	sudo chmod +x "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
	sudo chmod +x "${WG_CONF_FOLDER}/rm-fullcone-nat.sh"
	# Enable routing
	echo "net.ipv4.ip_forward = 1" | sudo tee "/etc/sysctl.d/wg.conf"
	echo "net.ipv6.conf.all.forwarding = 1" | sudo tee -a "/etc/sysctl.d/wg.conf"
	sudo sysctl --system
}

storeParams() {
	{
		echo "# Parameters used for WireGuard server configuration."
		echo "SERVER_PUB_IP=${SERVER_PUB_IP}"
		echo "SERVER_PUB_NIC=$SERVER_PUB_NIC"
		echo "SERVER_WG_NIC=$SERVER_WG_NIC"
		echo "SERVER_WG_IPV4=${SERVER_WG_IPV4}"
		echo "SERVER_WG_IPV6=${SERVER_WG_IPV6}"
		echo "SERVER_PORT=$SERVER_PORT"
		echo "CLIENT_DNS_1=${CLIENT_DNS_1}"
		echo "CLIENT_DNS_2=${CLIENT_DNS_2}"
		echo "SERVER_PUB_KEY=${SERVER_PUB_KEY}"
	} >"${SCRIPT_TEMP_FOLDER}/.params"
}

configureWGServer() {
	serverConfQuestions

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	{
		echo "[Interface]"
		echo "Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64"
		echo "ListenPort = $SERVER_PORT"
		echo "PrivateKey = ${SERVER_PRIV_KEY}"
		echo "PostUp = ${WG_CONF_FOLDER}/add-fullcone-nat.sh"
		echo "PostDown = ${WG_CONF_FOLDER}/rm-fullcone-nat.sh"
		echo "SaveConfig = false"
	} | sudo tee -a "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf"

	createServerNATscripts
	storeParams
}

newClientQuestions() {
	# If server public ip is ipv6, add [] when needed
	if echo "${SERVER_PUB_IP}" | grep -q ':'; then
		if (! echo "${SERVER_PUB_IP}" | grep -qE '^\[') && (! echo "${SERVER_PUB_IP}" | grep -qE '\]$'); then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi

	ENDPOINT="${SERVER_PUB_IP}:$SERVER_PORT"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	CLIENT_NAME=''
	while ! echo "$CLIENT_NAME" | grep -qE '^[a-zA-Z0-9_]+$' || [ ${#CLIENT_NAME} -gt 16 ] || grep -q "${CLIENT_NAME}" "${SCRIPT_TEMP_FOLDER}/.params"; do
		read -rp "Client name: " -e -i 'wg0client' CLIENT_NAME
	done

	for DOT_IP in {2..254}; do
		BASE_IPV4=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
		DOT_EXISTS=$(sudo grep -c "${BASE_IPV4}.${DOT_IP}" "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf" || true)
		if [ "$DOT_EXISTS" = '0' ]; then
			break
		fi
	done

	if [ "$DOT_EXISTS" = '1' ]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	IPV4_EXISTS='1'
	while [ "$IPV4_EXISTS" = '1' ]; do
		read -rp "Client WireGuard IPv4: ${BASE_IPV4}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IPV4}.${DOT_IP}"
		IPV4_EXISTS=$(sudo grep -c "$CLIENT_WG_IPV4/32" "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf" || true)

		if [ "$IPV4_EXISTS" != '0' ]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		BASE_IPV6=$(echo "${SERVER_WG_IPV6}" | awk -F '::' '{ print $1 }')
		DOT_EXISTS=$(sudo grep -c "${BASE_IPV6}::${DOT_IP}" "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf" || true)
		if [ "$DOT_EXISTS" = '0' ]; then
			break
		fi
	done

	if [ "$DOT_EXISTS" = '1' ]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	IPV6_EXISTS='1'
	while [ "$IPV6_EXISTS" = '1' ]; do
		read -rp "Client WireGuard IPv6: ${BASE_IPV6}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IPV6}::${DOT_IP}"
		IPV6_EXISTS=$(sudo grep -c "$CLIENT_WG_IPV6/128" "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf" || true)

		if [ "$IPV6_EXISTS" != 0 ]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	CLIENT_FORWARD_PORTS=''
	while [[ ! "$CLIENT_FORWARD_PORTS" =~ ^[0-9]+ ]] || [[ "$CLIENT_FORWARD_PORTS" =~ [[:space:]] ]]; do
		read -rp "The ports you want to forward for this client, (e.g. 80,443,100-200) NO space allowed: " -e CLIENT_FORWARD_PORTS
	done
}

addClientWGConfEntry() {
	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	{
		echo "[Interface]"
		echo "PrivateKey = ${CLIENT_PRIV_KEY}"
		echo "Address = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128"
		echo "DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}"
		echo ""
		echo "[Peer]"
		echo "PublicKey = ${SERVER_PUB_KEY}"
		echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY}"
		echo "Endpoint = ${ENDPOINT}"
		echo 'AllowedIPs = 0.0.0.0/0,::/0'
	} >"${SCRIPT_TEMP_FOLDER}/$SERVER_WG_NIC-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	{
		echo "# WG_CLIENT ${CLIENT_NAME}"
		echo "[Peer] # WG_CLIENT ${CLIENT_NAME}"
		echo "PublicKey = ${CLIENT_PUB_KEY} # WG_CLIENT ${CLIENT_NAME}"
		echo "PresharedKey = ${CLIENT_PRE_SHARED_KEY} # WG_CLIENT ${CLIENT_NAME}"
		echo "AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128 # WG_CLIENT ${CLIENT_NAME}"
	} | sudo tee -a "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf"
}

rmClientWGConfEntry() {
	local client_name="$1"
	sudo sed -i "/# WG_CLIENT ${client_name}/d" "${WG_CONF_FOLDER}/$SERVER_WG_NIC.conf"
	rm -f "${SCRIPT_TEMP_FOLDER}/$SERVER_WG_NIC-client-${CLIENT_NAME}.conf"
}

addClientNATEntry() {
	sudo sed -i "23i\        iifname \"$SERVER_PUB_NIC\" udp dport {$CLIENT_FORWARD_PORTS} dnat ip6 to $CLIENT_WG_IPV6 comment \"WireGuardGamingInstaller_Client_${CLIENT_NAME}\"" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
	sudo sed -i "23i\        iifname \"$SERVER_PUB_NIC\" tcp dport {$CLIENT_FORWARD_PORTS} dnat ip6 to $CLIENT_WG_IPV6 comment \"WireGuardGamingInstaller_Client_${CLIENT_NAME}\"" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
	sudo sed -i "23i\        iifname \"$SERVER_PUB_NIC\" udp dport {$CLIENT_FORWARD_PORTS} dnat ip to $CLIENT_WG_IPV4 comment \"WireGuardGamingInstaller_Client_${CLIENT_NAME}\"" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
	sudo sed -i "23i\        iifname \"$SERVER_PUB_NIC\" tcp dport {$CLIENT_FORWARD_PORTS} dnat ip to $CLIENT_WG_IPV4 comment \"WireGuardGamingInstaller_Client_${CLIENT_NAME}\"" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
}

rmClientNATEntry() {
	local client_name="$1"
	sudo sed -i "/Client_${client_name}/d" "${WG_CONF_FOLDER}/add-fullcone-nat.sh"
}

addClientParam() {
	echo "CLIENT_NAME=${CLIENT_NAME}" >>"${SCRIPT_TEMP_FOLDER}/.params"
}

rmClientParam() {
	local client_name="$1"
	sed -i "/CLIENT_NAME=${client_name}/d" "${SCRIPT_TEMP_FOLDER}/.params"
}

cleanWGClientConfiguration() {
	echo "There were errors adding this new WireGuard client, please try again."
	rmClientWGConfEntry "$CLIENT_NAME"
	rmClientNATEntry "$CLIENT_NAME"
	rmClientParam "$CLIENT_NAME"
	sudo systemctl restart "wg-quick@${SERVER_WG_NIC}"
}

rmWGClientConfiguration() {
	if [ -z "$CLIENT_NAME" ]; then
		echo "There is no client to remove!"
		exit 1
	fi
	read -rp "Type the client name you want to remove: " -e -i "$CLIENT_NAME" CLIENT_NAME
	while ! grep -q "CLIENT_NAME=$CLIENT_NAME" "${SCRIPT_TEMP_FOLDER}/.params"; do
		read -rp "The client is not found. Please retry: " -e -i "$CLIENT_NAME" CLIENT_NAME
	done
	while true; do
		echo -e "Do you really want to remove ${RED}${CLIENT_NAME}${NC}?"
		read -rp "[y/n]: " -e REMOVE
		case $REMOVE in
		[Yy]*)
			rmWGClientConfiguration
			break
			;;
		[Nn]*)
			echo "Aborted."
			break
			;;
		esac
	done
}

addWGClientConfiguration() {
	newClientQuestions
	addClientWGConfEntry
	addClientNATEntry
	addClientParam
}

cleanConfigureWGServer() {
	# Clean server conf
	sudo rm -f "${WG_CONF_FOLDER}"/*.conf
	sudo rm -f "/etc/sysctl.d/wg.conf"
	sudo sysctl --system
	# Clean client conf
	sudo rm -f "${WG_CONF_FOLDER}"/*.sh
	sudo rm -f "${SCRIPT_TEMP_FOLDER}"/*.conf
	# Clean params
	sudo rm -f "${SCRIPT_TEMP_FOLDER}/.params"
}

################################################################################
####################### Final Step : Start WG Server ###########################
################################################################################

showClientQRCode() {
	qrencode -t ansiutf8 -l L <"${SCRIPT_TEMP_FOLDER}/$SERVER_WG_NIC-client-${CLIENT_NAME}.conf"
	echo "It is also available in ${SCRIPT_TEMP_FOLDER}/$SERVER_WG_NIC-client-${CLIENT_NAME}.conf"
}

startWireGuardServer() {
	sudo systemctl start "wg-quick@${SERVER_WG_NIC}"
	sudo systemctl enable "wg-quick@${SERVER_WG_NIC}"

	if ! systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@$SERVER_WG_NIC${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device $SERVER_WG_NIC\", please reboot!${NC}"
	else
		echo -e "\nHere is your client config file as a QR Code:"
		showClientQRCode
	fi
}

cleanstartWireGuardServer() {
	sudo systemctl stop "wg-quick@${SERVER_WG_NIC}"
	sudo systemctl disable "wg-quick@${SERVER_WG_NIC}"
}

################################################################################
############################## Miscellaneous ###################################
################################################################################

restartWireGuardServer() {
	sudo systemctl restart "wg-quick@${SERVER_WG_NIC}"

	if ! systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"; then
		echo -e "${RED}WARNING: WireGuard does not seem to be running.${NC}"
	else
		echo "WireGuard Server restarted sucessfully."
	fi
}

uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [ "$REMOVE" = 'y' ]; then
		cleanstartWireGuardServer
		cleanConfigureWGServer
		cleanUpInstall
		deleteFolders

		# Check if WireGuard is running
		if systemctl is-active --quiet "wg-quick@$SERVER_WG_NIC"; then
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

manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo -e "   1) Stop WireGuard"
	echo -e "   2) Restart WireGuard"
	echo -e "   3) Uninstall WireGuard"
	echo -e "   4) ${RED}Add${NC} a WireGuard client"
	echo -e "   5) ${RED}Remove${NC} a WireGuard client"
	echo -e "   6) Exit"

	MENU_OPTION=''
	while ! echo "${MENU_OPTION}" | grep -qE '[1-6]'; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		sudo systemctl stop "wg-quick@$SERVER_WG_NIC"
		;;
	2)
		sudo systemctl restart "wg-quick@$SERVER_WG_NIC"
		;;
	3)
		uninstallWg
		;;
	4)
		addWGClientConfiguration
		trap cleanWGClientConfiguration EXIT
		restartWireGuardServer
		showClientQRCode
		trap - EXIT
		;;
	5)
		rmWGClientConfiguration
		restartWireGuardServer
		;;
	6)
		exit 0
		;;
	esac
}

################################################################################
############################# Script Beginning #################################
################################################################################

checkVirt
checkOS

# Check if WireGuard is already installed and load params
if cat "$SCRIPT_TEMP_FOLDER/.status" 2>/dev/null | grep -q 'Final Step Done'; then
	source "$SCRIPT_TEMP_FOLDER/.params"
	manageMenu
	exit 0
fi

if ! cat "$SCRIPT_TEMP_FOLDER/.status" 2>/dev/null | grep -q 'Step 1 Done: Created Folders'; then
	# 1st Step: Preparing folders
	trap deleteFolders EXIT
	prepareFolders
	echo 'Step 1 Done: Created Folders' >>"$SCRIPT_TEMP_FOLDER/.status"
	trap - EXIT
fi

if ! cat "$SCRIPT_TEMP_FOLDER/.status" 2>/dev/null | grep -q 'Step 2 Done: Installed WG binary'; then
	# 2nd Step: Install WireGuard binary to system
	trap cleanUpInstall EXIT
	installWireGuard
	echo 'Step 2 Done: Installed WG binary' >>"$SCRIPT_TEMP_FOLDER/.status"
	trap - EXIT
fi

if ! cat "$SCRIPT_TEMP_FOLDER/.status" 2>/dev/null | grep -q 'Step 3 Done: Configured WG server'; then
	# 3rd Step: Configure WireGuard server
	trap cleanConfigureWGServer EXIT
	configureWGServer
	addWGClientConfiguration
	echo 'Step 3 Done: Configured WG server' >>"$SCRIPT_TEMP_FOLDER/.status"
	trap - EXIT
else
	source "$SCRIPT_TEMP_FOLDER/.params"
fi

if ! cat "$SCRIPT_TEMP_FOLDER/.status" 2>/dev/null | grep -q 'Final Step Done'; then
	# 5th Step: Start WireGuard server
	trap cleanstartWireGuardServer EXIT
	startWireGuardServer
	echo 'Final Step Done' >>"$SCRIPT_TEMP_FOLDER/.status"
	trap - EXIT
fi
