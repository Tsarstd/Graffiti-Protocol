# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import json
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from tsarchain.utils import config as CFG
from tsarchain.core.block import Block
from tsarchain.consensus.genesis import GENESIS_HASH
from tsarchain.storage.utxo import UTXODB
from .helpers import console, open_ro_db, pause


def show_audit_analytics() -> None:
    """Render interactive Cross-DB Consistency & Chain Integrity Audit view."""
    console.print("\n[bold cyan]═══ MULTI-DATABASE CONSISTENCY & CHAIN INTEGRITY AUDIT ═══[/bold cyan]\n")

    choice = Prompt.ask(
        "[bold white]Select Audit Mode:[/bold white]\n"
        "  [bold cyan][1][/bold cyan] Quick Audit (Last 1,000 Blocks + Multi-DB Sync)\n"
        "  [bold cyan][2][/bold cyan] Full Audit (All Blocks from Genesis to Tip + Multi-DB Sync)\n"
        "  [bold dim][0][/bold dim] Cancel / Return\n"
        "[bold yellow]Your Choice[/bold yellow]",
        choices=["1", "2", "0"],
        default="1",
    )

    if choice == "0":
        return

    full_scan = (choice == "2")
    console.print(f"\n[cyan]Running {'Full' if full_scan else 'Quick'} Audit...[/cyan]\n")

    tbl = Table(title="Integrity & Consistency Audit Results", border_style="cyan")
    tbl.add_column("Audit Component", style="bold white")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Findings / Observations", style="dim")

    # 1. Multi-DB Sync Check
    chain_tip = None
    env_chain, dbi_chain = open_ro_db(CFG.LMDB_CHAIN_DIR, "chain")
    if env_chain and dbi_chain is not None:
        try:
            with env_chain.begin(db=dbi_chain, write=False) as txn:
                meta_raw = txn.get(b"__meta__")
                if meta_raw:
                    meta = json.loads(meta_raw.decode("utf-8"))
                    chain_tip = meta.get("tip_height")
        except Exception:
            pass

    utxo_tip_hint = None
    env_utxo, dbi_utxo = open_ro_db(CFG.LMDB_UTXO_DIR, "utxo")
    if env_utxo and dbi_utxo is not None:
        try:
            with env_utxo.begin(db=dbi_utxo, write=False) as txn:
                meta_raw = txn.get(b"__meta__")
                if meta_raw:
                    meta = json.loads(meta_raw.decode("utf-8"))
                    utxo_tip_hint = meta.get("tip_height_hint")
        except Exception:
            pass
        env_utxo.close()

    state_tip = None
    env_state, dbi_state = open_ro_db(CFG.LMDB_STATE_DIR, "state")
    if env_state and dbi_state is not None:
        try:
            with env_state.begin(db=dbi_state, write=False) as txn:
                raw_snap = txn.get(b"k:snapshot")
                if raw_snap:
                    snap = json.loads(raw_snap.decode("utf-8"))
                    state_tip = snap.get("chain", {}).get("tip_height")
        except Exception:
            pass
        env_state.close()

    # Evaluate Multi-DB sync
    sync_details = f"Chain: #{chain_tip} | UTXO Hint: #{utxo_tip_hint} | State: #{state_tip}"
    if chain_tip is not None and utxo_tip_hint is not None and state_tip is not None:
        diff = abs(chain_tip - utxo_tip_hint)
        if diff == 0 and chain_tip == state_tip:
            tbl.add_row("Multi-DB Tip Sync", "[bold green]PASS[/bold green]", f"All databases perfectly synchronized ({sync_details})")
        elif diff <= 5 and chain_tip == state_tip:
            tbl.add_row("Multi-DB Tip Sync", "[bold yellow]SYNC LAG[/bold yellow]", f"UTXO is {diff} blocks behind chain (normal during active node: {sync_details})")
        else:
            tbl.add_row("Multi-DB Tip Sync", "[bold red]DESYNC[/bold red]", f"Significant desync detected ({sync_details})")
    else:
        tbl.add_row("Multi-DB Tip Sync", "[bold yellow]WARN[/bold yellow]", f"Partial DB metadata missing ({sync_details})")

    # 2. Genesis Block Check
    if env_chain and dbi_chain is not None:
        try:
            with env_chain.begin(db=dbi_chain, write=False) as txn:
                raw_b0 = txn.get(b"h:000000000000")
                if raw_b0:
                    b0 = Block.from_storage_bytes(raw_b0)
                    gen_prev_ok = (b0.prev_block_hash == CFG.ZERO_HASH)
                    gen_hash_ok = (GENESIS_HASH is None or b0.hash() == GENESIS_HASH)
                    if gen_prev_ok and gen_hash_ok:
                        tbl.add_row("Genesis Block Header", "[bold green]PASS[/bold green]", f"Block 0 valid, hash: {b0.hash().hex()[:24]}...")
                    else:
                        tbl.add_row("Genesis Block Header", "[bold red]FAIL[/bold red]", "Genesis hash does not match network consensus!")
                else:
                    tbl.add_row("Genesis Block Header", "[bold red]FAIL[/bold red]", "Genesis block (h:000000000000) not found!")
        except Exception as exc:
            tbl.add_row("Genesis Block Header", "[bold red]ERROR[/bold red]", str(exc))

    # 3. Chain Continuity & Sequence Scan
    if env_chain and dbi_chain is not None and chain_tip is not None:
        start_h = 0 if full_scan else max(0, chain_tip - 999)
        blocks_checked = 0
        missing_heights = []
        time_warps = 0
        prev_ts = None

        try:
            with env_chain.begin(db=dbi_chain, write=False) as txn:
                for h in range(start_h, chain_tip + 1):
                    raw_b = txn.get(f"h:{h:012d}".encode("utf-8"))
                    if not raw_b:
                        missing_heights.append(h)
                        continue
                    blocks_checked += 1
                    # Extract timestamp (bytes 68:72)
                    ts = int.from_bytes(raw_b[68:72], "little")
                    if prev_ts is not None and ts < (prev_ts - CFG.FUTURE_DRIFT):
                        time_warps += 1
                    prev_ts = ts

            if not missing_heights and time_warps == 0:
                tbl.add_row(
                    f"Chain Continuity ({blocks_checked:,} blocks)",
                    "[bold green]PASS[/bold green]",
                    f"Sequential range #{start_h:,} to #{chain_tip:,} complete without gaps",
                )
            else:
                err_msg = []
                if missing_heights:
                    err_msg.append(f"{len(missing_heights)} missing blocks")
                if time_warps > 0:
                    err_msg.append(f"{time_warps} timestamp anomalies")
                tbl.add_row(f"Chain Continuity ({blocks_checked:,} blocks)", "[bold red]FAIL[/bold red]", ", ".join(err_msg))

        except Exception as exc:
            tbl.add_row("Chain Continuity", "[bold red]ERROR[/bold red]", str(exc))
        finally:
            env_chain.close()

    # 4. Orphan UTXO Check
    db_utxo = UTXODB()
    with db_utxo._lock:
        tip_limit = chain_tip if chain_tip is not None else 999999999
        orphan_utxos = []
        for key, entry in db_utxo.utxos.items():
            if entry:
                born = int(entry.get("block_height", 0))
                if born > tip_limit:
                    orphan_utxos.append((key, born))

    if not orphan_utxos:
        tbl.add_row("Orphan UTXO Check", "[bold green]PASS[/bold green]", f"All {len(db_utxo.utxos):,} UTXOs reference valid blocks (<= #{tip_limit})")
    else:
        tbl.add_row("Orphan UTXO Check", "[bold red]FAIL[/bold red]", f"Found {len(orphan_utxos)} orphan UTXOs referencing future blocks (> #{tip_limit})")

    console.print(tbl)
    pause()
