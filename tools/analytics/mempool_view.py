# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import time
from rich.table import Table
from rich.panel import Panel

from tsarchain.utils import config as CFG
from tsarchain.mempool.pool import TxPool
from .helpers import console, format_tsar, format_bytes, format_duration, pause


def show_mempool_analytics() -> None:
    """Render interactive Mempool Diagnostics view."""
    console.print("\n[bold cyan]═══ MEMPOOL DIAGNOSTICS ═══[/bold cyan]\n")

    pool = TxPool()
    with pool._lock:
        txs = list(pool._pool.values())
        size_map = dict(pool._size_map)

    total_count = len(txs)
    total_vbytes = sum(size_map.values())
    total_fees = sum(int(tx.fee or 0) for tx in txs)

    # Summary Panel
    if total_count == 0:
        summary_text = (
            "[bold green]Mempool is currently EMPTY (0 pending transactions).[/bold green]\n\n"
            f"[bold white]Maximum Capacity   :[/bold white] {CFG.MEMPOOL_MAX_SIZE} MB\n"
            f"[bold white]Min Relay Fee Rate :[/bold white] 1 sat/vB\n"
            f"[bold white]Max Tx Size        :[/bold white] {format_bytes(CFG.MAX_BLOCK_BYTES // 2)}\n"
            "[dim]All network transactions have been confirmed into blocks.[/dim]"
        )
        console.print(Panel(summary_text, title="[bold]Mempool Queue Status[/bold]", border_style="green"))
    else:
        now = time.time()
        fee_rates = []
        for tx in txs:
            vsz = max(1, size_map.get(tx.txid().hex(), 250))
            fee_rates.append((tx.fee or 0) / vsz)

        min_fr = min(fee_rates)
        max_fr = max(fee_rates)
        median_fr = sorted(fee_rates)[len(fee_rates) // 2]

        summary_text = (
            f"[bold white]Pending Txs        :[/bold white] [bold yellow]{total_count:,}[/bold yellow] txs\n"
            f"[bold white]Total Queue Size   :[/bold white] {format_bytes(total_vbytes)} ({total_vbytes:,} vB)\n"
            f"[bold white]Total Queued Fees  :[/bold white] [bold green]{format_tsar(total_fees)}[/bold green]\n"
            f"[bold white]Fee Rate Range     :[/bold white] Min: {min_fr:.1f} sat/vB | Median: {median_fr:.1f} sat/vB | Max: {max_fr:.1f} sat/vB"
        )
        console.print(Panel(summary_text, title="[bold]Mempool Queue Status[/bold]", border_style="yellow"))

        tbl = Table(title="Queued Mempool Transactions", border_style="blue")
        tbl.add_column("TxID", style="cyan")
        tbl.add_column("Fee", justify="right", style="green")
        tbl.add_column("Size (vB)", justify="right")
        tbl.add_column("Fee Rate", justify="right", style="yellow")
        tbl.add_column("Wait Time", justify="right", style="dim")

        for tx in txs[:20]:
            txid = tx.txid().hex()
            vsz = max(1, size_map.get(txid, 250))
            fr = (tx.fee or 0) / vsz
            age_sec = max(0, int(now - (tx.timestamp or now)))

            tbl.add_row(txid[:16] + "...", format_tsar(tx.fee or 0), f"{vsz:,} vB", f"{fr:.1f} sat/vB", format_duration(age_sec))

        if len(txs) > 20:
            tbl.add_row(f"... and {len(txs) - 20} other transactions", "", "", "", "")
        console.print(tbl)

    pause()
