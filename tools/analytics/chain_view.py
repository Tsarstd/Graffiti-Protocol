# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import json
from collections import Counter
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from tsarchain.utils import config as CFG
from tsarchain.core.block import Block
from tsarchain.mempool.scripts import script_to_address
from .helpers import console, open_ro_db, format_tsar, format_bytes, format_duration, pause


def show_chain_analytics() -> None:
    """Render interactive Chain & Consensus Health view."""
    console.print("\n[bold cyan]═══ CHAIN & CONSENSUS ANALYTICS ═══[/bold cyan]\n")

    env_chain, dbi_chain = open_ro_db(CFG.LMDB_CHAIN_DIR, "chain")
    if not env_chain or dbi_chain is None:
        console.print("[bold red]Failed to open chain database.[/bold red]")
        pause()
        return

    env_state, dbi_state = open_ro_db(CFG.LMDB_STATE_DIR, "state")
    snapshot = {}
    if env_state and dbi_state is not None:
        try:
            with env_state.begin(db=dbi_state, write=False) as txn:
                raw_snap = txn.get(b"k:snapshot")
                if raw_snap:
                    snapshot = json.loads(raw_snap.decode("utf-8"))
        except Exception:
            snapshot = {}
        env_state.close()

    try:
        with env_chain.begin(db=dbi_chain, write=False) as txn:
            meta_raw = txn.get(b"__meta__")
            meta = json.loads(meta_raw.decode("utf-8")) if meta_raw else {}

            tip_height = meta.get("tip_height")
            tip_hash = meta.get("tip_hash", "N/A")

            # Fallback if tip_height missing from meta: find last key
            if tip_height is None:
                cur = txn.cursor()
                if cur.last():
                    k_str = cur.key().decode("utf-8")
                    if k_str.startswith("h:"):
                        tip_height = int(k_str[2:])

            if tip_height is None or tip_height < 0:
                console.print("[yellow]Chain database is empty (no blocks found).[/yellow]")
                env_chain.close()
                pause()
                return

            # Read tip block
            tip_key = f"h:{tip_height:012d}".encode("utf-8")
            tip_raw = txn.get(tip_key)
            tip_block = Block.from_storage_bytes(tip_raw) if tip_raw else None

            # Read recent blocks for interval analysis (up to 100 blocks)
            recent_count = min(100, tip_height + 1)
            start_h = max(0, tip_height - recent_count + 1)
            recent_blocks = []
            for h in range(start_h, tip_height + 1):
                raw_b = txn.get(f"h:{h:012d}".encode("utf-8"))
                if raw_b:
                    recent_blocks.append(Block.from_storage_bytes(raw_b))

    except Exception as exc:
        console.print(f"[bold red]Error reading chain data: {exc}[/bold red]")
        env_chain.close()
        pause()
        return

    # Calculate chain file size on disk
    chain_disk_size = 0
    chain_data_file = os.path.join(CFG.LMDB_CHAIN_DIR, "data.mdb")
    if os.path.isfile(chain_data_file):
        chain_disk_size = os.path.getsize(chain_data_file)

    env_chain.close()

    # Tip Panel
    tip_ts = tip_block.timestamp if tip_block else 0
    age_sec = max(0, int(time.time() - tip_ts))
    summary_text = (
        f"[bold white]Tip Height   :[/bold white] [bold green]#{tip_height:,}[/bold green]\n"
        f"[bold white]Tip Hash     :[/bold white] [cyan]{tip_hash}[/cyan]\n"
        f"[bold white]Block Time   :[/bold white] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tip_ts))} "
        f"([dim]{format_duration(age_sec)} ago[/dim])\n"
        f"[bold white]Chain Disk   :[/bold white] {format_bytes(chain_disk_size)}"
    )
    console.print(Panel(summary_text, title="[bold]Chain Tip Status[/bold]", border_style="cyan"))

    # Consensus & Mining Details Table
    table_diff = Table(title="Consensus Parameters & Mining Difficulty", border_style="blue")
    table_diff.add_column("Parameter", style="cyan", no_wrap=True)
    table_diff.add_column("Current Value", style="green")
    table_diff.add_column("Notes / Target", style="dim")

    diff_val = tip_block.difficulty if tip_block else 0
    bits_val = tip_block.bits if tip_block else 0
    cw_val = tip_block.chainwork if tip_block else 0

    table_diff.add_row("Mining Difficulty", f"{diff_val:,}", "LWMA Dynamic Target")
    table_diff.add_row("Compact Bits", f"0x{bits_val:08x} ({bits_val})", "Initial: 0x1f0fffff")
    table_diff.add_row("Cumulative Chainwork", f"{cw_val:,}", "Total PoW Work")
    table_diff.add_row("Target Block Time", f"{CFG.TARGET_BLOCK_TIME}s", "Target interval per block")

    # Block interval statistics
    if len(recent_blocks) > 1:
        intervals = [
            recent_blocks[i].timestamp - recent_blocks[i - 1].timestamp
            for i in range(1, len(recent_blocks))
        ]
        avg_int = sum(intervals) / len(intervals)
        min_int = min(intervals)
        max_int = max(intervals)
        table_diff.add_row(
            f"Avg Interval ({len(intervals)} blocks)",
            f"{avg_int:.1f}s (Min: {min_int}s, Max: {max_int}s)",
            f"Deviation: {avg_int - CFG.TARGET_BLOCK_TIME:+.1f}s",
        )

    # Halving & Subsidy
    supply_snap = snapshot.get("supply", {})
    epoch = supply_snap.get("current_epoch", tip_height // int(CFG.BLOCKS_PER_HALVING or 105120))
    next_halving_h = supply_snap.get("next_halving_height", (epoch + 1) * int(CFG.BLOCKS_PER_HALVING or 105120))
    blocks_left = max(0, next_halving_h - tip_height)
    curr_subsidy = supply_snap.get("current_block_subsidy", int(CFG.INITIAL_REWARD or 250 * CFG.TSAR) >> epoch)

    table_diff.add_row("Halving Epoch", f"Epoch {epoch}", f"Halving every {CFG.BLOCKS_PER_HALVING:,} blocks")
    table_diff.add_row("Block Subsidy", format_tsar(curr_subsidy), "Base Coinbase")
    table_diff.add_row("Until Next Halving", f"{blocks_left:,} blocks left", f"Target at #{next_halving_h:,}")

    console.print(table_diff)

    # Top Miners Table
    table_miners = Table(title="Miner Distribution (Top Miners)", border_style="magenta")
    table_miners.add_column("Rank", justify="center", style="bold")
    table_miners.add_column("Miner Address", style="cyan")
    table_miners.add_column("Blocks Mined", justify="right", style="green")
    table_miners.add_column("Share", justify="right", style="yellow")

    top_miners_data = snapshot.get("miners_snapshot", {}).get("top_miners", [])
    if not top_miners_data:
        # Fallback: compute from recent blocks
        counter = Counter()
        for blk in recent_blocks:
            if blk.transactions:
                cb = blk.transactions[0]
                if cb.outputs:
                    spk = cb.outputs[0].script_pubkey
                    raw_spk = spk if type(spk) in (bytes, bytearray) else bytes.fromhex(str(spk))
                    addr = script_to_address(raw_spk) or "Unknown"
                    counter[addr] += 1
        top_miners_data = counter.most_common(10)

    total_blocks_analyzed = tip_height + 1
    for rank, item in enumerate(top_miners_data[:10], start=1):
        miner_addr = str(item[0])
        b_count = int(item[1])
        pct = (b_count / total_blocks_analyzed * 100) if total_blocks_analyzed > 0 else 0
        table_miners.add_row(str(rank), miner_addr, f"{b_count:,}", f"{pct:.2f}%")

    console.print(table_miners)

    # Interactive Sub-Prompt: Inspect specific block or Return
    sub = Prompt.ask(
        "\n[dim yellow]Enter block height ([bold]0-" + str(tip_height) + "[/bold]) for details, or press [bold]Enter[/bold] to return[/dim yellow]",
        default="",
    )
    if sub.strip().isdigit():
        target_h = int(sub.strip())
        if 0 <= target_h <= tip_height:
            _show_block_detail(target_h)
            pause()
        else:
            console.print("[red]Block height out of range.[/red]")
            pause()


def _show_block_detail(height: int) -> None:
    """Display in-depth information about a specific block."""
    env_chain, dbi_chain = open_ro_db(CFG.LMDB_CHAIN_DIR, "chain")
    if not env_chain or dbi_chain is None:
        console.print("[red]Failed to open chain database.[/red]")
        return

    try:
        with env_chain.begin(db=dbi_chain, write=False) as txn:
            raw_b = txn.get(f"h:{height:012d}".encode("utf-8"))
            if not raw_b:
                console.print(f"[red]Block #{height} not found.[/red]")
                return
            blk = Block.from_storage_bytes(raw_b)
    finally:
        env_chain.close()

    txs = blk.transactions or []
    coinbase_tx = txs[0] if txs else None
    miner_addr = "N/A"
    coinbase_amt = 0
    if coinbase_tx and coinbase_tx.outputs:
        coinbase_amt = coinbase_tx.outputs[0].amount or 0
        spk = coinbase_tx.outputs[0].script_pubkey
        raw_spk = spk if type(spk) in (bytes, bytearray) else bytes.fromhex(str(spk))
        miner_addr = script_to_address(raw_spk) or "N/A"

    details = (
        f"[bold white]Block Height     :[/bold white] #{blk.height:,}\n"
        f"[bold white]Timestamp        :[/bold white] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(blk.timestamp))}\n"
        f"[bold white]Prev Hash        :[/bold white] {blk.prev_block_hash.hex()}\n"
        f"[bold white]Merkle Root      :[/bold white] {blk.merkle_root.hex()}\n"
        f"[bold white]Nonce / Bits     :[/bold white] {blk.nonce:,} / 0x{blk.bits:08x}\n"
        f"[bold white]Difficulty       :[/bold white] {blk.difficulty:,}\n"
        f"[bold white]Transaction Count:[/bold white] {len(txs)} txs\n"
        f"[bold white]Miner            :[/bold white] [cyan]{miner_addr}[/cyan]\n"
        f"[bold white]Coinbase Subsidy :[/bold white] {format_tsar(coinbase_amt)}"
    )
    console.print(Panel(details, title=f"[bold]Block #{height} Details[/bold]", border_style="cyan"))

    if len(txs) > 1:
        tbl = Table(title=f"Non-Coinbase Transactions (#{height})", border_style="blue")
        tbl.add_column("TxID", style="cyan")
        tbl.add_column("Inputs", justify="right")
        tbl.add_column("Outputs", justify="right")
        tbl.add_column("Fee", justify="right", style="green")

        for tx in txs[1:11]:
            txid = tx.txid().hex()
            tbl.add_row(txid, str(len(tx.inputs)), str(len(tx.outputs)), format_tsar(tx.fee or 0))
        if len(txs) > 11:
            tbl.add_row(f"... and {len(txs) - 11} other transactions", "", "", "")
        console.print(tbl)
