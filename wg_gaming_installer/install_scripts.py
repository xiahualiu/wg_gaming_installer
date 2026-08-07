"""
Main installation logic for WireGuard gaming installer.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from prompt_toolkit import prompt

from wg_gaming_installer.exec_scripts import (
    create_nftables_config,
    create_start_script,
    create_stop_script,
    create_wg_config,
)
from wg_gaming_installer.prompt_scripts import (
    add_peer_prompt,
    print_peer_summary,
    reconfigure_wg_prompt,
    rm_peer_prompt,
    select_peer_config_prompt,
    server_if_prompt,
    server_wg_prompt,
    uninstall_wg_prompt,
)
from wg_gaming_installer.shell_scripts import (
    ServiceStatus,
    delete_folders,
    get_os_info,
    get_wg_service_status,
    install_wg_dependencies,
    install_wireguard_go,
    is_os_supported,
    need_userspace_wireguard,
    qrencode_text_to_terminal,
    start_wg_service,
    stop_wg_service,
    uninstall_wg_dependencies,
    uninstall_wireguard_go,
)
from wg_gaming_installer.sqlite_scripts import (
    InstallStatus,
    OSInfo,
    PeerConfig,
    ServerIFConfig,
    ServerWGConfig,
    add_peer_config,
    conf_db_connected,
    create_config_db,
    delete_peer_config,
    ensure_wg_mtu_column,
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


@dataclass(frozen=True)
class Paths:
    """
    Centralized, customizable paths used by the installer.
    """

    wg_conf_folder: Path = Path('/etc/wireguard')
    tun_dev_path: Path = Path('/dev/net/tun')
    shell_path: Path = Path('/bin/sh')

    @property
    def server_conf_db_path(self) -> Path:
        """
        Path to the server configuration database (inside wg_conf_folder).
        """
        return self.wg_conf_folder / 'server_conf.db'

    @property
    def start_script_path(self) -> Path:
        """
        Path to the nftables start script.
        """
        return self.wg_conf_folder / 'wg_start.sh'

    @property
    def stop_script_path(self) -> Path:
        """
        Path to the nftables stop script.
        """
        return self.wg_conf_folder / 'wg_stop.sh'

    @property
    def nftables_conf_path(self) -> Path:
        """
        Path to the nftables configuration file.
        """
        return self.wg_conf_folder / 'wg.nft'

    def server_wg_conf_path(self, wg_nic_name: str) -> Path:
        """
        Path to the WireGuard configuration file for the server.
        """
        return self.wg_conf_folder / f"{wg_nic_name}.conf"


_PATHS: Paths = Paths()


def _uninstall_delete_folders() -> None:
    """
    Delete folders created by the installer.
    """
    delete_folders([_PATHS.wg_conf_folder])


def _create_wg_peer_str(
    peer: PeerConfig, server_config: ServerIFConfig, wg_config: ServerWGConfig
) -> str:
    """
    Generate a WireGuard configuration str for a peer.
    """

    peer_wg_conf_str = "[Interface]\n"
    if peer.ipv6:
        peer_wg_conf_str += f"Address = {peer.ipv4.ip!s}/32, {peer.ipv6.ip!s}/128\n"
    else:
        peer_wg_conf_str += f"Address = {peer.ipv4.ip!s}/32\n"
    peer_wg_conf_str += f"DNS = {', '.join(str(dns) for dns in peer.dns)}\n"
    peer_wg_conf_str += f"MTU = {wg_config.mtu}\n"
    peer_wg_conf_str += f"PrivateKey = {peer.private_key}\n"
    peer_wg_conf_str += "\n"
    peer_wg_conf_str += "[Peer]\n"
    peer_wg_conf_str += f"PublicKey = {wg_config.public_key}\n"
    peer_wg_conf_str += f"PresharedKey = {peer.preshared_key}\n"
    if wg_config.ipv6:
        peer_wg_conf_str += "AllowedIPs = 0.0.0.0/0,::/0\n"
    else:
        peer_wg_conf_str += "AllowedIPs = 0.0.0.0/0\n"
    peer_wg_conf_str += f"Endpoint = {server_config.nic_ipv4!s}"
    peer_wg_conf_str += ":"
    peer_wg_conf_str += f"{wg_config.listen_port}\n"
    peer_wg_conf_str += "PersistentKeepalive = 25\n"
    peer_wg_conf_str += "\n"

    return peer_wg_conf_str


# InstallStatus -> starting index into _FULL_INSTALL_STEPS
_INSTALL_STEP_START: dict[InstallStatus, int] = {
    InstallStatus.NOT_STARTED: 0,
    InstallStatus.DB_CREATED: 1,
    InstallStatus.SW_INSTALLED: 2,
    InstallStatus.SERVER_IF_CONFIGURED: 3,
    InstallStatus.SERVER_WG_CONFIGURED: 4,
}


def _continue_install(state: InstallStatus) -> list[Callable[[], None]]:
    """
    Continue the installation process.
    Returns a list of functions to be executed in order.
    """
    start: int | None = _INSTALL_STEP_START.get(state)
    if start is None:
        raise RuntimeError("Unknown installation state.")
    return _FULL_INSTALL_STEPS[start:]


def _db_setup_step() -> None:
    """
    Pre-installation setup tasks.
    """
    print("Step 1: Setting up configuration database...")

    # Create db parent folder if it doesn't exist
    _PATHS.wg_conf_folder.mkdir(parents=True, exist_ok=True)

    # Create or reset the configuration database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        create_config_db(db_conn=conn)
        update_install_status(db_conn=conn, new_state=InstallStatus.DB_CREATED)


def _install_wg_package_step() -> None:
    """
    Main installation function for WireGuard server.
    """
    print("Step 2: Starting WireGuard server installation...")

    # Step 1: Get OS information
    os_id, os_version = get_os_info()
    if not is_os_supported(os_id, os_version):
        raise RuntimeError(f"Operating system {os_id} {os_version} is not supported.")

    print(f"Detected operating system: {os_id} {os_version}")

    # Step 2: Install WireGuard and dependencies
    print("Installing WireGuard and dependencies...")
    install_wg_dependencies(os_id=os_id, os_version=os_version)

    # Check if userspace WireGuard is needed
    print("Checking if userspace WireGuard is needed...")
    userspace_wg: bool = need_userspace_wireguard(tun_dev_path=_PATHS.tun_dev_path)
    if userspace_wg:
        print("OS virtualization type requires userspace WireGuard implementation.")
        prompt("Press Enter to continue with WireGuard-Go installation...")
        install_wireguard_go()
    else:
        print("In-kernel WireGuard implementation is supported.")

    # Step 3: update install status in database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        update_os_info(
            db_conn=conn,
            os_info=OSInfo(
                os_name=os_id,
                os_version=os_version,
                userspace_wg=userspace_wg,
            ),
        )
        update_install_status(db_conn=conn, new_state=InstallStatus.SW_INSTALLED)


def _uninstall_wg_package_step() -> None:
    """
    Uninstall WireGuard server software.
    """
    # Read OS info from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        os_info: OSInfo | None = read_os_info(db_conn=conn)
        if not os_info:
            print("OS information not found in database.", file=sys.stderr)
            return

    # Uninstall userspace WireGuard if installed
    if os_info.userspace_wg:
        print("Uninstalling userspace WireGuard (WireGuard-Go)...")
        uninstall_wireguard_go()

    # Uninstall WireGuard dependencies
    print("Uninstalling WireGuard dependencies...")
    uninstall_wg_dependencies(os_info.os_name, os_info.os_version)


def _server_if_setup_step() -> None:
    """
    Configure server network interface.
    """
    print("Step 3: Configuring server network interface...")

    # Prompt user for server NIC configuration
    server_if_config: ServerIFConfig = server_if_prompt()

    # Update install status in database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        update_server_config(
            db_conn=conn,
            server_config=server_if_config,
        )
        update_install_status(
            db_conn=conn, new_state=InstallStatus.SERVER_IF_CONFIGURED
        )


def _restart_wg_if_active() -> None:
    """
    Restart the WireGuard service if it is currently active.
    """
    if _server_get_wg_status_step() == ServiceStatus.ACTIVE:
        print("Restarting WireGuard service...")
        _server_stop_wg_service_step()
        _server_start_wg_service_step()


def _server_reconfigure_step() -> None:
    """
    Purge all server settings and peers, then re-run server configuration.
    """
    print("Re-configuring WireGuard server...")

    confirm: bool = reconfigure_wg_prompt()
    if not confirm:
        print("Re-configuration cancelled.")
        return

    # Stop the service first so the running config and generated files
    # do not conflict with the new configuration.
    if _server_get_wg_status_step() == ServiceStatus.ACTIVE:
        print("Stopping WireGuard service...")
        _server_stop_wg_service_step()

    # Purge settings and reset install status so the server configuration
    # steps (server NIC, then server WG) run again.
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        purge_server_config(db_conn=conn)
        update_install_status(db_conn=conn, new_state=InstallStatus.SW_INSTALLED)

    # Re-run configuration from the server step
    for step in _continue_install(state=InstallStatus.SW_INSTALLED):
        step()

    print("Server re-configured successfully.")

    # Show the main menu again so the user can re-add peers, etc.
    _main_menu()


def _server_add_wg_peer_step() -> None:
    """
    Add a new WireGuard peer.
    """
    print("Adding a new WireGuard peer...")

    # Read existing WG config and peers from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        server_config: ServerIFConfig | None = read_server_nic_config(db_conn=conn)
        assert (
            server_config
        ), "Server network interface configuration not found in database."
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        assert wg_config, "WireGuard configuration not found in database."
        existing_peers: list[PeerConfig] = read_all_peer_configs(db_conn=conn)

    # Prompt user for new peer configuration
    new_peer_config: PeerConfig = add_peer_prompt(
        wg_config=wg_config, existing_peers=existing_peers
    )

    # Update database with new peer
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        add_peer_config(db_conn=conn, peer_config=new_peer_config)

    # Generate WireGuard peer configuration string
    peer_wg_conf_str: str = _create_wg_peer_str(
        peer=new_peer_config,
        server_config=server_config,
        wg_config=wg_config,
    )

    # Print the new peer WireGuard configuration
    print("\nNew peer WireGuard configuration:\n")
    print(peer_wg_conf_str)

    # QR code generation
    qrencode_text_to_terminal(text=peer_wg_conf_str)

    _restart_wg_if_active()

    print(f"Peer '{new_peer_config.name}' added successfully.")


def _server_rm_wg_peer_step(selected_peer: PeerConfig) -> None:
    """
    Remove a WireGuard peer.
    """
    print(f"Removing WireGuard peer '{selected_peer.name}'...")

    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        delete_peer_config(db_conn=conn, peer_name=selected_peer.name)
    print(f"Peer '{selected_peer.name}' removed successfully.")

    _restart_wg_if_active()


def _server_edit_wg_peer_step(selected_peer: PeerConfig) -> None:
    """
    Edit a WireGuard peer.
    """
    print(f"Editing WireGuard peer '{selected_peer.name}'...")

    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        server_config: ServerIFConfig | None = read_server_nic_config(db_conn=conn)
        assert (
            server_config
        ), "Server network interface configuration not found in database."
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        assert wg_config, "WireGuard configuration not found in database."

        # First, delete the existing peer
        delete_peer_config(db_conn=conn, peer_name=selected_peer.name)

        existing_peers: list[PeerConfig] = read_all_peer_configs(db_conn=conn)
        modified_peer_config: PeerConfig = add_peer_prompt(
            wg_config=wg_config,
            existing_peers=existing_peers,
            base_peer=selected_peer,
        )

        # Add the modified peer back to the database
        add_peer_config(db_conn=conn, peer_config=modified_peer_config)

    _restart_wg_if_active()

    print(f"Peer '{selected_peer.name}' edited successfully.")


def _server_wg_setup_step() -> None:
    """
    Configure server WireGuard interface.
    """
    print("Step 4: Configuring server WireGuard interface...")

    # Check if server has IPv6 configured
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        server_conf: ServerIFConfig | None = read_server_nic_config(db_conn=conn)
        if not server_conf:
            raise RuntimeError("Server configuration not found in database.")
        has_ipv6: bool = server_conf.nic_ipv6 is not None

    # Prompt user for server WireGuard configuration
    server_wg_config: ServerWGConfig = server_wg_prompt(has_ipv6=has_ipv6)

    # Update install status in database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        update_wg_config(
            db_conn=conn,
            wg_config=server_wg_config,
        )
        update_install_status(
            db_conn=conn, new_state=InstallStatus.SERVER_WG_CONFIGURED
        )

    # Start WireGuard service
    _server_start_wg_service_step()


def _server_start_wg_service_step() -> None:
    """
    Start the WireGuard service on the server.
    """
    print("Starting WireGuard service...")

    # Read WG config from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        server_config: ServerIFConfig | None = read_server_nic_config(db_conn=conn)
        peer_configs: list[PeerConfig] = read_all_peer_configs(db_conn=conn)
        if not wg_config:
            raise RuntimeError("WireGuard configuration not found in database.")
        if not server_config:
            raise RuntimeError("Server configuration not found in database.")

    # Create WireGuard configuration file
    wg_conf_path: Path = _PATHS.server_wg_conf_path(wg_nic_name=wg_config.wg_name)

    # Generate WireGuard configuration file
    create_wg_config(
        wg_conf_path=wg_conf_path,
        wg_config=wg_config,
        peer_config=peer_configs,
        start_script_path=_PATHS.start_script_path,
        stop_script_path=_PATHS.stop_script_path,
    )

    # Generate start and stop scripts
    create_start_script(
        has_ipv6=bool(wg_config.ipv6),
        shell_path=_PATHS.shell_path,
        start_script_path=_PATHS.start_script_path,
        nftables_conf_path=_PATHS.nftables_conf_path,
    )
    create_stop_script(
        has_ipv6=bool(wg_config.ipv6),
        shell_path=_PATHS.shell_path,
        stop_script_path=_PATHS.stop_script_path,
    )

    # Generate nftables configuration file
    create_nftables_config(
        wg_config=wg_config,
        server_config=server_config,
        peer_configs=peer_configs,
        nftables_conf_path=_PATHS.nftables_conf_path,
    )

    # Start WireGuard service
    start_wg_service(wg_nic_name=wg_config.wg_name)
    print("WireGuard service started successfully.")


def _server_stop_wg_service_step() -> None:
    """
    Stop the WireGuard service on the server.
    """
    print("Stopping WireGuard service...")

    # Read WG config from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        if not wg_config:
            print("WireGuard configuration not found in database.", file=sys.stderr)
            return

    stop_wg_service(wg_nic_name=wg_config.wg_name)

    # Remove WireGuard configuration file
    wg_conf_path: Path = _PATHS.server_wg_conf_path(wg_nic_name=wg_config.wg_name)
    if wg_conf_path.exists():
        wg_conf_path.unlink()

    # Remove start and stop scripts
    if _PATHS.start_script_path.exists():
        _PATHS.start_script_path.unlink()
    if _PATHS.stop_script_path.exists():
        _PATHS.stop_script_path.unlink()

    # Remove nftables configuration file
    if _PATHS.nftables_conf_path.exists():
        _PATHS.nftables_conf_path.unlink()

    print("WireGuard service stopped successfully.")


def _server_get_wg_status_step() -> ServiceStatus:
    """
    Get the status of the WireGuard service on the server.
    """
    print("Getting WireGuard service status...")

    # Read WG config from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        if not wg_config:
            raise RuntimeError("WireGuard configuration not found in database.")

    return get_wg_service_status(wg_nic_name=wg_config.wg_name)


# Installation steps, indexed by the InstallStatus at which they are reached.
# Defined after the step functions so the module loads without forward refs.
_FULL_INSTALL_STEPS: list[Callable[[], None]] = [
    _db_setup_step,
    _install_wg_package_step,
    _server_if_setup_step,
    _server_wg_setup_step,
]


def _main_menu() -> None:
    """
    Show the main menu after installation.
    """

    # Load config from database
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        os_info: OSInfo | None = read_os_info(db_conn=conn)
        wg_config: ServerWGConfig | None = read_wg_config(db_conn=conn)
        server_config: ServerIFConfig | None = read_server_nic_config(db_conn=conn)
        peer_configs: list[PeerConfig] = read_all_peer_configs(db_conn=conn)

        if not os_info:
            print("OS information not found in database.", file=sys.stderr)
            return

        if not wg_config:
            print("WireGuard configuration not found in database.", file=sys.stderr)
            return

        if not server_config:
            print("Server configuration not found in database.", file=sys.stderr)
            return

    print("Welcome to the WireGuard Gaming Installer main menu!")
    print(" 1. Stop WireGuard service (and disable on OS start up).")
    print(" 2. Start WireGuard service (and enable on OS start up).")
    print(" 3. Uninstall WireGuard service.")
    print(" 4. List all peers.")
    print(" 5. Show QR code & config for a peer.")
    print(" 6. Add a new peer.")
    print(" 7. Remove a peer.")
    print(" 8. Edit peer.")
    print(" 9. Re-configure server.")
    print("10. Exit.")

    user_input: str
    while True:
        user_input = prompt("Please select an option from the menu [1-10] => ").strip()
        if user_input not in map(str, range(1, 11)):
            print("Invalid option, please try again.")
            continue
        break

    def uninstall_handler() -> None:
        confirm: bool = uninstall_wg_prompt()
        if confirm:
            stop_wg_service(wg_nic_name=wg_config.wg_name)
            _uninstall_wg_package_step()
            _uninstall_delete_folders()
            print("WireGuard service uninstalled successfully.")
        else:
            print("Uninstallation cancelled.")

    def list_peers_handler() -> None:
        print("Listing all peers...")
        for idx, peer in enumerate(peer_configs):
            print_peer_summary(
                index=idx,
                peer_name=peer.name,
                peer_ipv4=peer.ipv4,
                peer_ipv6=peer.ipv6,
                peer_dns=peer.dns,
                peer_forward_ports=peer.forward_ports,
            )
            print()

    def show_peer_qr_handler() -> None:
        selected_peer = select_peer_config_prompt(peers=peer_configs)
        if not selected_peer:
            return
        peer_wg_conf_str: str = _create_wg_peer_str(
            peer=selected_peer,
            server_config=server_config,
            wg_config=wg_config,
        )
        print("\nPeer WireGuard configuration:\n")
        print(peer_wg_conf_str)
        qrencode_text_to_terminal(text=peer_wg_conf_str)

    def remove_peer_handler() -> None:
        selected_peer = rm_peer_prompt(existing_peers=peer_configs)
        if not selected_peer:
            return
        _server_rm_wg_peer_step(selected_peer=selected_peer)

    def edit_peer_handler() -> None:
        selected_peer = select_peer_config_prompt(peers=peer_configs)
        if not selected_peer:
            return
        _server_edit_wg_peer_step(selected_peer=selected_peer)

    def exit_handler() -> None:
        print("Exiting main menu.")

    menu_actions: dict[str, Callable[[], None]] = {
        "1": _server_stop_wg_service_step,
        "2": _server_start_wg_service_step,
        "3": uninstall_handler,
        "4": list_peers_handler,
        "5": show_peer_qr_handler,
        "6": _server_add_wg_peer_step,
        "7": remove_peer_handler,
        "8": edit_peer_handler,
        "9": _server_reconfigure_step,
        "10": exit_handler,
    }

    menu_actions[user_input]()


def main() -> None:
    """
    Entry point for the WireGuard Gaming Installer CLI.
    """
    # Check if db exists
    print("Checking if configuration database exists...")
    if not _PATHS.server_conf_db_path.exists():
        _db_setup_step()

    # Migrate pre-existing databases (e.g. add the mtu column)
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        ensure_wg_mtu_column(db_conn=conn)

    # Continue installation from the beginning
    print("Reading installation status from database...")
    with conf_db_connected(db_path=_PATHS.server_conf_db_path) as conn:
        status: InstallStatus = read_install_status(db_conn=conn)
        steps: list[Callable[[], None]] = _continue_install(state=status)

    # Execute installation steps
    for step in steps:
        step()

    print("Installation completed successfully.")

    # Show main menu
    _main_menu()


if __name__ == "__main__":
    main()
