#!/usr/bin/env python3
"""
End-to-end test for wg_gaming_installer.

Drives the real `wg-gaming-installer` CLI inside a systemd-enabled Docker
container (as root) via a PTY, then asserts on the resulting system state:

   1. Full install flow:
        - creates /etc/wireguard/server_conf.db with the expected rows
        - generates wg0.conf, wg_start.sh, wg_stop.sh, wg.nft with correct modes
        - brings up `wg-quick@wg0` (systemd service active)
        - installs the nftables `ip wg_nat` table with the expected chains/rules
   2. Add-peer flow (menu option 6) with a forwarded port:
        - persists the peer in the database
        - rewrites wg0.conf with the peer
        - registers the peer on the live `wg0` interface
        - adds the DNAT rule to wg.nft and the live nftables ruleset

Every interactive step has an explicit timeout so a stuck prompt fails fast
instead of hanging the CI job. Exit code is non-zero on any failure.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pexpect

INSTALLER = "/venv/bin/wg-gaming-installer"
WG_CONF_DIR = Path("/etc/wireguard")
DB_PATH = WG_CONF_DIR / "server_conf.db"
WG_CONF_PATH = WG_CONF_DIR / "wg0.conf"
START_SCRIPT = WG_CONF_DIR / "wg_start.sh"
STOP_SCRIPT = WG_CONF_DIR / "wg_stop.sh"
NFT_CONF = WG_CONF_DIR / "wg.nft"

# Seconds to wait for a single prompt. Phase 1's first prompt also covers the
# `apt-get install` of WireGuard dependencies, so it gets a larger budget.
PROMPT_TIMEOUT = 120
FIRST_PROMPT_TIMEOUT = 600
EOF_TIMEOUT = 60

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    """Record a failure if condition is False, otherwise report success."""
    if condition:
        print(f"[PASS] {message}")
    else:
        print(f"[FAIL] {message}")
        FAILURES.append(message)


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def nft_wg_nat_rules() -> str:
    """Return the live ruleset of the `ip wg_nat` nftables table."""
    return run(["nft", "list", "table", "ip", "wg_nat"])


def spawn_installer() -> pexpect.spawn:
    child = pexpect.spawn(
        INSTALLER,
        timeout=PROMPT_TIMEOUT,
        encoding="utf-8",
        dimensions=(50, 160),
    )
    return child


def feed(
    child: pexpect.spawn,
    pattern: str,
    answer: str,
    timeout: int = PROMPT_TIMEOUT,
) -> None:
    """Wait for a prompt and reply, timing the step and failing on timeout."""
    start = time.monotonic()
    try:
        child.expect(pattern, timeout=timeout)
    except pexpect.exceptions.TIMEOUT:
        print(
            f"[TIMEOUT] waited {timeout}s for prompt {pattern!r} "
            f"(after {time.monotonic() - start:.1f}s)",
            file=sys.stderr,
        )
        child.close(force=True)
        raise
    if answer:
        # Clear any pre-filled default text (prompt_toolkit buffers it) so the
        # typed answer is not appended to it, then submit the answer.
        child.send("\x15")  # Ctrl-U: kill line / discard buffer
        child.sendline(answer)
    else:
        child.sendline("")  # accept the pre-filled default
    print(f"  [prompt] {pattern!r} answered in {time.monotonic() - start:.1f}s")


def wait_exit(child: pexpect.spawn, description: str) -> None:
    """Wait for the installer process to finish, timing the step."""
    start = time.monotonic()
    child.expect(pexpect.EOF, timeout=EOF_TIMEOUT)
    child.close()
    print(f"  [exit] {description} finished in {time.monotonic() - start:.1f}s")
    check(
        child.exitstatus == 0,
        f"{description} exited with status 0 (got {child.exitstatus})",
    )


def phase_full_install() -> None:
    """Drive a fresh full installation, then exit the main menu."""
    print("\n=== Phase 1: full install ===")
    start = time.monotonic()
    child = spawn_installer()
    child.logfile_read = sys.stdout

    # First prompt waits for apt-get to finish installing WireGuard deps.
    feed(
        child,
        "Input the public interface name:",
        "",  # accept default
        timeout=FIRST_PROMPT_TIMEOUT,
    )
    feed(child, "Input the public IPv4 address of the server:", "")  # default
    feed(child, "Does the server have a public IPv6 address?", "")  # default: no
    feed(child, "Is this information correct?", "yes")
    feed(child, "Input the WireGuard interface name:", "")  # default: wg0
    feed(child, "Input the WireGuard IPv4 interface of the server:", "")  # default
    feed(child, "Input the WireGuard listen port:", "")  # default: 51820
    feed(child, "Input the WireGuard MTU:", "")  # default: 1420
    feed(child, "Is this information correct?", "yes")
    feed(child, "Please select an option from the menu", "10")  # exit

    wait_exit(child, "full install")
    print(f"  [phase] Phase 1 total: {time.monotonic() - start:.1f}s")


def phase_add_peer() -> None:
    """Re-run the installer (already installed) and add a peer with port forwarding."""
    print("\n=== Phase 2: add peer with port forwarding ===")
    start = time.monotonic()
    child = spawn_installer()
    child.logfile_read = sys.stdout

    feed(child, "Please select an option from the menu", "6")  # add peer
    feed(child, "Input the name of the new peer:", "laptop")
    feed(child, "Input the WireGuard IPv4 interface of the new peer:", "")  # default
    feed(child, "Input the DNS servers for the peer", "")  # default DNS
    feed(child, "Enable port forwarding for this peer?", "yes")
    feed(child, "Input the ports to forward", "25565")
    feed(child, "Is this information correct?", "yes")

    try:
        child.expect("Peer 'laptop' added successfully.", timeout=PROMPT_TIMEOUT)
    except pexpect.exceptions.TIMEOUT:
        print(
            "[TIMEOUT] waiting for 'Peer laptop added successfully.'",
            file=sys.stderr,
        )
        child.close(force=True)
        raise

    wait_exit(child, "add peer")
    print(f"  [phase] Phase 2 total: {time.monotonic() - start:.1f}s")


def verify_install_state() -> None:
    print("\n=== Verify install state ===")
    check(DB_PATH.exists(), "server_conf.db exists")

    with sqlite3.connect(DB_PATH) as conn:
        status = conn.execute(
            "SELECT state FROM install_status WHERE id = 1"
        ).fetchone()
        check(status and status[0] == "server_wg_configured", "install_status is set")

        wg = conn.execute(
            "SELECT wg_name, listen_port FROM server_wg_config WHERE id = 1"
        ).fetchone()
        check(wg is not None, "server_wg_config row exists")
        if wg:
            check(wg[0] == "wg0", f"wg_name == 'wg0' (got {wg[0]!r})")
            check(wg[1] == 51820, f"listen_port == 51820 (got {wg[1]!r})")

    for path, mode in (
        (WG_CONF_PATH, 0o600),
        (START_SCRIPT, 0o700),
        (STOP_SCRIPT, 0o700),
        (NFT_CONF, 0o600),
    ):
        check(path.exists(), f"{path.name} exists")
        if path.exists():
            check(
                path.stat().st_mode & 0o777 == mode,
                f"{path.name} mode == {oct(mode)}",
            )

    wg_conf = WG_CONF_PATH.read_text()
    check("[Interface]" in wg_conf, "wg0.conf contains [Interface]")
    check("MTU = 1420" in wg_conf, "wg0.conf contains MTU = 1420")

    active = run(["systemctl", "is-active", "wg-quick@wg0"]).strip()
    check(active == "active", f"wg-quick@wg0 is active (got {active!r})")

    wg_show = run(["wg", "show", "wg0"])
    check("listening port: 51820" in wg_show, "wg show wg0 shows listen port 51820")

    tables = run(["nft", "list", "tables"])
    check("table ip wg_nat" in tables, "nft ruleset contains ip wg_nat")

    nft_nat = nft_wg_nat_rules()
    check("chain postrouting" in nft_nat, "nft wg_nat has postrouting chain")
    check("masquerade" in nft_nat, "nft wg_nat has masquerade (SNAT) rule")
    check('"wg0"' in nft_nat, 'nft wg_nat SNAT rule matches iifname "wg0"')
    check("chain prerouting" in nft_nat, "nft wg_nat has prerouting chain")


def verify_peer_state() -> None:
    print("\n=== Verify peer state ===")
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT name, forward_ports, public_key FROM peer_config "
            "WHERE name = 'laptop'"
        ).fetchone()
        check(row is not None, "peer 'laptop' persisted in database")
        if row:
            check(row[1] == "25565", f"peer forward_ports == '25565' (got {row[1]!r})")
            peer_public_key = row[2]

    wg_conf = WG_CONF_PATH.read_text()
    check("[Peer] # laptop" in wg_conf, "wg0.conf contains [Peer] # laptop")

    wg_show = run(["wg", "show", "wg0"])
    if row:
        check(
            peer_public_key in wg_show,
            "live wg0 interface has the new peer's public key",
        )

    nft_conf = NFT_CONF.read_text()
    check("dnat to 10.66.66.2;" in nft_conf, "wg.nft contains dnat to 10.66.66.2")

    nft_nat = nft_wg_nat_rules()
    check(
        "dnat to 10.66.66.2" in nft_nat,
        "live nft ruleset DNATs to the new peer (10.66.66.2)",
    )
    check("25565" in nft_nat, "live nft ruleset forwards port 25565")
    check("tcp dport" in nft_nat, "live nft ruleset has TCP DNAT rule")
    check("udp dport" in nft_nat, "live nft ruleset has UDP DNAT rule")


def main() -> int:
    if os.geteuid() != 0:
        print("E2E test must be run as root.", file=sys.stderr)
        return 1

    total_start = time.monotonic()
    phase_full_install()
    verify_install_state()
    phase_add_peer()
    verify_peer_state()
    print(f"\n=== Total e2e time: {time.monotonic() - total_start:.1f}s ===")

    if FAILURES:
        print(f"\n{len(FAILURES)} E2E assertion(s) failed:", file=sys.stderr)
        for failure in FAILURES:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nAll E2E checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
