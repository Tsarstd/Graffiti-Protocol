# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

"""
TsarChain — Full Node CLI Miner

Role
- Runs a full node with on-disk persistence.
- Receives/maintains mempool and includes transactions in mined blocks.

Intended environment
- VPS / always-on servers.

Key flags
--node-only     : Run as full node only (no mining) — still relays mempool & chain.
--no-bootstrap  : Skip snapshot fast-sync; use default block-by-block sync.

Safety & behavior
- Validates headers, difficulty, timestamps, and full block rules.
- Keeps local DB, mempool policies apply (size/fees/sanity checks).
- Reorg-safe: cancels current work and re-mines on new best tip.
"""

from __future__ import annotations

import sys
import argparse
import contextlib
import multiprocessing as mp

from rich.panel import Panel
from datetime import datetime
from rich.prompt import Prompt
from rich.console import Console

# ---------------- Local Project ----------------
from tsarchain.storage import kv
from tsarchain.utils import config as CFG
from tsarchain.utils.thread_check import get_thread_monitor
from tsarchain.miner.cosmetic import interface as COL
from tsarchain.miner.cosmetic.tui import MinerTUI, create_tui_logger, _enable_windows_vt100
from tsarchain.miner.orchestrator import NodeRunner, SimpleMiner

from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
log = get_ctx_logger("apps.cli_node_miner")



def main():
    _enable_windows_vt100()
    args = _parse_args()

    if args.thread_report:
        _show_thread_report()
        return

    is_interactive = sys.stdin.isatty() and not args.yes
    is_fully_configured = bool(args.address and args.cores)

    if args.init_genesis:
        _run_init_genesis(args, is_interactive)
        return

    if args.node_only:
        mode = 1
    elif is_interactive and not is_fully_configured:
        COL.print_banner()
        COL.print_system_snapshot(cores_hint=None)
        mode = _choose_mode()
    else:
        mode = 0  # Default to mining mode when non-interactive or fully configured via CLI

    if mode == 1:
        _run_node_only(args)
    else:
        _run_miner(args, is_interactive, is_fully_configured)


# =============================================================================
# INTERNAL METHODS
# =============================================================================


def _stamp() -> str:
    now = datetime.now()
    d = f"{now.strftime("%d %b %Y")}"
    t = f"{now.hour:02d}:{now.minute:02d}:{now.second:02d}"
    return f"{COL.BOLD}{COL.GREY}{d}{COL.RESET} {COL.ITALIC}{t}{COL.RESET}"


def _format_clog(message: str, color: str = COL.GREY) -> str:
    return f"{_stamp()} : {color}{message}{COL.RESET}"


def _clog(message: str, color: str = COL.GREY):
    print(_format_clog(message, color))


def _make_tui_log_fn(tui: MinerTUI):
    tui_log = create_tui_logger(tui)
    return lambda msg, color=COL.GREY: tui_log(_format_clog(msg, color))


def _safe_peer_counts(net) -> tuple[int, int]:
    if not net:
        return 0, 0
    inbound = len(net.inbound_peers) if net.inbound_peers else 0
    outbound = len(net.outbound_peers) if net.outbound_peers else 0
    return inbound, outbound


def _safe_mempool_count(runner) -> int:
    if not runner:
        return 0
    if runner.blockchain:
        return runner.blockchain.get_mempool_size()
    with contextlib.suppress(AttributeError):
        return len(runner.network.broadcast.mempool._pool)
    return 0


def _normalize_cores(cores: int | None) -> int | None:
    cpu_total = mp.cpu_count() or 1
    if cores is None:
        return cpu_total
    cores_int = int(cores)
    return min(cores_int, cpu_total) if cores_int > 0 else None


def _show_thread_report():
    monitor = get_thread_monitor()
    monitor.print_thread_report(detailed=True)


def _choose_mode() -> int:
    console = Console()
    console.print(Panel(
        "[bold yellow]Choose Execution Mode[/bold yellow]\n"
        "[bold green]0[/bold green] : Mining Mode (Full Node + Miner)\n"
        "[bold blue]1[/bold blue] : Node Only (Relay & Mempool)",
        border_style="cyan",
    ))

    try:
        sel = Prompt.ask("[bold cyan]Select Mode[/bold cyan]", choices=["0", "1"], default="0").strip()
    except (KeyboardInterrupt, EOFError):
        console.print("[yellow]Using default: Mining Mode (0)[/yellow]")
        return 0

    if sel == "1":
        console.print("[bold blue]✓ Selected Mode: Node Only (1)[/bold blue]\n")
        return 1
    console.print("[bold green]✓ Selected Mode: Mining Mode (0)[/bold green]\n")
    return 0


def _parse_args():
    parser = argparse.ArgumentParser(description="TsarChain CLI miner / node runner")
    parser.add_argument("--init-genesis", action="store_true", help="Mine and lock Genesis Block (Block 0) if database is empty")
    parser.add_argument("--address", help="Miner payout address (tsar1...)")
    parser.add_argument("--cores", type=int, help="CPU cores to use for mining")
    parser.add_argument("--node-only", action="store_true", help="Run node without mining")
    parser.add_argument("--timeout", type=int, default=560, help="Sync timeout in seconds (mining mode)")
    parser.add_argument("--no-bootstrap", action="store_true", help="Skip snapshot bootstrap download")
    parser.add_argument("--rx-full", action="store_true", help="Enable RandomX FULL MEMORY mode (+2.5GB dataset)")
    parser.add_argument("--rx-light", action="store_true", help="Force RandomX LIGHT mode (~<2.5GB, lower RAM)")
    parser.add_argument("--thread-report", action="store_true", help="Show thread report and exit")
    parser.add_argument("-y", "--yes", action="store_true", help="Non-interactive mode (auto-accept prompts and defaults)")
    return parser.parse_args()


def _run_init_genesis(args, is_interactive: bool) -> None:
    _clog("Checking Genesis status in LMDB database...", COL.CYAN)
    from tsarchain.consensus.blockchain import Blockchain
    bc = Blockchain()
    if len(bc.chain) > 0:
        g_hash = bc.chain[0].hash().hex()
        _clog(f"Genesis Block already exists in LMDB! Hash: {g_hash}", COL.GREEN)
        _clog("No need to run --init-genesis again.", COL.YELLOW)
        bc.shutdown()
        sys.exit(0)

    address = args.address
    cores = args.cores
    if not address or not cores:
        if not is_interactive:
            _clog("Error: --address and --cores are required for --init-genesis in non-interactive mode.", COL.RED)
            bc.shutdown()
            sys.exit(2)
        input_address, input_cores = COL.get_user_input()
        address = address or input_address
        cores = cores or input_cores

    cores = _normalize_cores(cores)
    _clog(f"Mining Genesis Block (Block 0) for address '{address}' with {cores} core(s)...", COL.CYAN)
    success = bc.ensure_genesis(address, use_cores=cores, init_genesis=True)
    if success and len(bc.chain) > 0:
        g = bc.chain[0]
        _clog("================================================================", COL.YELLOW)
        _clog("Genesis Block created & locked in LMDB successfully!", COL.GREEN)
        _clog(f"Hash      : {g.hash().hex()}", COL.GREEN)
        _clog(f"Height    : {g.height}", COL.GREEN)
        _clog(f"PrevHash  : {g.prev_block_hash.hex()}", COL.GREEN)
        _clog(f"Nonce     : {g.nonce}", COL.GREEN)
        _clog(f"Timestamp : {g.timestamp}", COL.GREEN)
        _clog("================================================================", COL.YELLOW)
        _clog("Environment ready! You can now start the node or miner in normal mode.", COL.CYAN)
        kv.sync(force=True)
        bc.shutdown()
        sys.exit(0)
    else:
        _clog("Failed to create Genesis Block!", COL.RED)
        bc.shutdown()
        sys.exit(1)


def _run_node_only(args) -> None:
    runner = None
    tui = MinerTUI(
        address="Node Only",
        cores=0,
        mode=" Node Only",
        randomx_mode=" Disabled",
        hashrate_queue=None,
        chain_height_fn=lambda: int(runner.blockchain.height) if runner and runner.blockchain else -1,
        peer_counts_fn=lambda: _safe_peer_counts(runner.network) if runner else (0, 0),
        mempool_count_fn=lambda: _safe_mempool_count(runner),
        node_only=True,
    )
    tui.start()
    log_fn = _make_tui_log_fn(tui)
    runner = NodeRunner(bootstrap_snapshot=not args.no_bootstrap, log_fn=log_fn)

    try:
        runner.start()
    except KeyboardInterrupt:
        log_fn("Interrupted by user")
    finally:
        tui.stop()


def _run_miner(args, is_interactive: bool, is_fully_configured: bool) -> None:
    address = args.address
    cores = args.cores

    if not address or not cores:
        if not is_interactive:
            _clog("Error: --address and --cores are required for mining in non-interactive mode.", COL.RED)
            sys.exit(2)
        input_address, input_cores = COL.get_user_input()
        address = input_address
        cores   = input_cores

    cores = _normalize_cores(cores)
    if cores is None:
        _clog("Invalid --cores value. Please provide a positive integer.")
        sys.exit(2)

    # Decide RandomX memory mode (mining mode only)
    if args.rx_full and args.rx_light:
        _clog("Cannot set both --rx-full and --rx-light. Choose one.")
        sys.exit(2)
    if args.rx_full:
        rx_full_mem = True
    elif args.rx_light:
        rx_full_mem = False
    elif not is_interactive or is_fully_configured:
        rx_full_mem = False  # Default to light mode in non-interactive / automated setups
    else:
        rx_full_mem = COL.prompt_rx_full_mem()
    CFG.RANDOMX_FULL_MEM = bool(rx_full_mem)
    mode_label = "FULL-MEM (+2.5GB)" if CFG.RANDOMX_FULL_MEM else "LIGHT"

    # --- TUI + progress queue ---
    progress_q: mp.Queue = mp.Queue()

    miner = None
    tui = MinerTUI(
        address=address,
        cores=cores,
        mode=" Mining...",
        randomx_mode=mode_label,
        hashrate_queue=progress_q,
        chain_height_fn=lambda: int(miner.blockchain.height) if miner and miner.blockchain else -1,
        peer_counts_fn=lambda: _safe_peer_counts(miner.network) if miner else (0, 0),
        mempool_count_fn=lambda: _safe_mempool_count(miner),
    )
    tui.start()
    log_fn = _make_tui_log_fn(tui)

    miner = SimpleMiner(
        address=address,
        cores=cores,
        bootstrap_snapshot=not args.no_bootstrap,
        progress_queue=progress_q,
        log_fn=log_fn,
    )
    miner.tui = tui

    try:
        miner.start_mining(timeout=args.timeout)
    except KeyboardInterrupt:
        log_fn("Interrupted by user")
    except Exception as exc:
        log_fn(f"Fatal error: {exc}")
    finally:
        miner.stop()
        tui.stop()


if __name__ == "__main__":
    mp.freeze_support()
    setup_logging("logging/node.log", force=True)
    main()