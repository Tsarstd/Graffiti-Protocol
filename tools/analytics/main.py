#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys

# Ensure UTF-8 output on Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Ensure src/ and repo root are in sys.path for direct execution
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SRC_DIR = os.path.join(_REPO_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import json
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from tsarchain.utils import config as CFG
from tsarchain.storage.utxo import UTXODB
from tsarchain.contracts.graffiti_registry import GraffitiRegistry
from tsarchain.mempool.pool import TxPool

from tools.analytics.helpers import (
    console,
    open_ro_db,
    format_tsar,
    format_bytes,
    pause,
)
from tools.analytics.chain_view import show_chain_analytics
from tools.analytics.utxo_view import show_utxo_analytics, inspect_address
from tools.analytics.graffiti_view import show_graffiti_analytics
from tools.analytics.mempool_view import show_mempool_analytics
from tools.analytics.audit_view import show_audit_analytics


def show_overview_dashboard() -> None:
    """Render combined executive summary across all blockchain domains."""
    console.print("\n[bold cyan]═══ TSARCHAIN GLOBAL EXECUTIVE OVERVIEW ═══[/bold cyan]\n")

    # 1. Chain stats
    tip_height = 0
    tip_hash = "N/A"
    diff = 0
    env_c, dbi_c = open_ro_db(CFG.LMDB_CHAIN_DIR, "chain")
    if env_c and dbi_c is not None:
        try:
            with env_c.begin(db=dbi_c, write=False) as txn:
                raw_m = txn.get(b"__meta__")
                if raw_m:
                    m = json.loads(raw_m.decode("utf-8"))
                    tip_height = m.get("tip_height", 0)
                    tip_hash = m.get("tip_hash", "N/A")
                last_raw = txn.get(f"h:{tip_height:012d}".encode("utf-8"))
                if last_raw:
                    from tsarchain.core.block import Block
                    blk = Block.from_storage_bytes(last_raw)
                    diff = blk.difficulty
        except Exception:
            pass
        env_c.close()

    # 2. Supply & UTXO stats
    utxo_count = 0
    total_supply_sats = 0
    active_addrs = 0
    try:
        db_utxo = UTXODB()
        with db_utxo._lock:
            db_utxo._ensure_index_locked()
            utxo_count = len(db_utxo.utxos)
            total_supply_sats = sum(db_utxo._addr_total_balance.values())
            active_addrs = len(db_utxo._addr_total_balance)
    except Exception:
        pass

    # 3. Graffiti stats
    graff_count = 0
    total_media_size = 0
    try:
        reg = GraffitiRegistry()
        posts = reg.data.get("posts", {})
        graff_count = len(posts)
        total_media_size = sum(int(p.get("size", 0)) for p in posts.values())
    except Exception:
        pass

    # 4. Mempool stats
    mem_txs = 0
    try:
        pool = TxPool()
        with pool._lock:
            mem_txs = len(pool._pool)
    except Exception:
        pass

    # Render Domain Cards in a styled grid table
    tbl = Table(title="Current TsarChain Multi-Domain Status", border_style="cyan", show_header=False)
    tbl.add_column("Domain", style="bold white", width=24)
    tbl.add_column("Primary Metrics", style="cyan")
    tbl.add_column("Status / Details", style="green")

    tbl.add_row(
        "Chain & Consensus",
        f"Tip: #{tip_height:,} ({tip_height + 1:,} blocks)",
        f"Difficulty: {diff:,} | Hash: {tip_hash[:20]}...",
    )
    tbl.add_row(
        "Supply & UTXO Ledger",
        f"Total Supply: {format_tsar(total_supply_sats)}",
        f"{utxo_count:,} active UTXOs | {active_addrs:,} funded addresses",
    )
    tbl.add_row(
        "Graffiti & Archive",
        f"{graff_count:,} permanent artworks",
        f"Media Size: {format_bytes(total_media_size)}",
    )
    tbl.add_row(
        "Mempool Queue",
        f"{mem_txs:,} pending transactions",
        "Clean queue (no congestion)" if mem_txs == 0 else f"{mem_txs} txs awaiting miners",
    )

    console.print(tbl)
    pause()


def main() -> None:
    """Main interactive menu loop for TsarChain Analytics."""
    while True:
        console.clear()

        # Header Banner
        banner = (
            "[bold cyan]  ████████ ███████  █████  ██████   ██████ ██   ██  █████  ██ ███    ██ [/bold cyan]\n"
            "[bold cyan]     ██    ██      ██   ██ ██   ██ ██      ██   ██ ██   ██ ██ ████   ██ [/bold cyan]\n"
            "[bold white]     ██    ███████ ███████ ██████  ██      ███████ ███████ ██ ██ ██  ██ [/bold white]\n"
            "[bold blue]     ██         ██ ██   ██ ██   ██ ██      ██   ██ ██   ██ ██ ██  ██ ██ [/bold blue]\n"
            "[bold blue]     ██    ███████ ██   ██ ██   ██  ██████ ██   ██ ██   ██ ██ ██   ████ [/bold blue]\n\n"
            "[bold yellow]          TSARCHAIN BLOCKCHAIN & DATABASE OFFLINE ANALYTICS          [/bold yellow]\n"
            "[dim cyan]                  Developer Offline Diagnostic Suite                 [/dim cyan]"
        )
        console.print(Panel(banner, border_style="cyan"))

        # Menu Panel
        menu_text = (
            "[bold white][1][/bold white] [cyan]Global Executive Overview Dashboard[/cyan]\n"
            "[bold white][2][/bold white] [cyan]Chain & Consensus Health (Tip, Difficulty, Top Miners, Halving)[/cyan]\n"
            "[bold white][3][/bold white] [cyan]UTXO Ledger & Monetary Audit (Inflation, Rich List, UTXO Health)[/cyan]\n"
            "[bold white][4][/bold white] [cyan]Address Deep Inspector (Balances, Role, & Unspent Outputs)[/cyan]\n"
            "[bold white][5][/bold white] [cyan]Graffiti Protocol & Archivist Economics (Media, Escrows, Proofs)[/cyan]\n"
            "[bold white][6][/bold white] [cyan]Mempool Diagnostics (Pending Queue, Fee Rates, Congestion)[/cyan]\n"
            "[bold white][7][/bold white] [cyan]Multi-DB Consistency & Chain Integrity Audit (Sync & Headers)[/cyan]\n"
            "[bold white][0][/bold white] [bold red]Exit[/bold red]"
        )
        console.print(Panel(menu_text, title="[bold]Interactive Navigation Menu[/bold]", border_style="blue"))

        choice = Prompt.ask("[bold yellow]Select menu [0-7][/bold yellow]", default="1").strip()

        if choice == "1":
            show_overview_dashboard()
        elif choice == "2":
            show_chain_analytics()
        elif choice == "3":
            show_utxo_analytics()
        elif choice == "4":
            inspect_address()
            pause()
        elif choice == "5":
            show_graffiti_analytics()
        elif choice == "6":
            show_mempool_analytics()
        elif choice == "7":
            show_audit_analytics()
        elif choice == "0":
            console.print("\n[bold green]Thank you. Analytics session closed.[/bold green]\n")
            break
        else:
            console.print("[red]Invalid selection. Please choose 0-7.[/red]")
            pause()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Exit.[/dim]")
        sys.exit(0)
