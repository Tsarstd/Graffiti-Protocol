# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import json
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from tsarchain.utils import config as CFG
from tsarchain.storage.utxo import UTXODB
from tsarchain.mempool.scripts import script_to_address
from .helpers import console, open_ro_db, format_tsar, pause


def show_utxo_analytics() -> None:
    """Render interactive UTXO Ledger & Monetary Supply Audit view."""
    console.print("\n[bold cyan]═══ UTXO LEDGER & MONETARY SUPPLY AUDIT ═══[/bold cyan]\n")

    db = UTXODB()
    with db._lock:
        db._ensure_index_locked()
        total_utxos = len(db.utxos)
        addr_balances = dict(db._addr_total_balance)
        key_amounts = dict(db._key_to_amount)
        coinbases = dict(db._coinbases_by_height)

    total_actual_sats = sum(addr_balances.values())
    total_addrs = len(addr_balances)

    # Fetch expected supply from state snapshot
    expected_sats = total_actual_sats
    env_state, dbi_state = open_ro_db(CFG.LMDB_STATE_DIR, "state")
    if env_state and dbi_state is not None:
        try:
            with env_state.begin(db=dbi_state, write=False) as txn:
                raw_snap = txn.get(b"k:snapshot")
                if raw_snap:
                    snap = json.loads(raw_snap.decode("utf-8"))
                    expected_sats = int(snap.get("supply", {}).get("emitted_subsidy", total_actual_sats))
        except Exception:
            pass
        env_state.close()

    inflation_delta = total_actual_sats - expected_sats

    # Summary Panel
    status_color = "green" if inflation_delta == 0 else "red"
    status_label = "BALANCED (0 Sat Delta - Perfect Integrity)" if inflation_delta == 0 else f"ANOMALY ({inflation_delta:+d} Sats)"

    summary_text = (
        f"[bold white]Total UTXO Supply :[/bold white] [bold green]{format_tsar(total_actual_sats)}[/bold green]\n"
        f"[bold white]Theoretical Supply:[/bold white] {format_tsar(expected_sats)}\n"
        f"[bold white]Inflation Status  :[/bold white] [{status_color}]{status_label}[/{status_color}]\n"
        f"[bold white]Total UTXO Entries:[/bold white] [cyan]{total_utxos:,}[/cyan] unspent outputs\n"
        f"[bold white]Funded Addresses  :[/bold white] [yellow]{total_addrs:,}[/yellow] active addresses"
    )
    console.print(Panel(summary_text, title="[bold]Monetary Audit & Ledger Condition[/bold]", border_style=status_color))

    # UTXO Health Table
    dust_threshold = 10_000  # 10,000 sats
    dust_count = sum(1 for amt in key_amounts.values() if amt < dust_threshold)
    avg_utxo_sats = (total_actual_sats // total_utxos) if total_utxos > 0 else 0

    immature_cb_sats = 0
    curr_h = db._get_tip_height_from_state() or 0
    min_immature_born = max(0, curr_h + 2 - int(CFG.COINBASE_MATURITY))
    for h in range(min_immature_born, curr_h + 1):
        entries = coinbases.get(h)
        if entries:
            for _, amt in entries.values():
                immature_cb_sats += amt

    table_health = Table(title="UTXO Set Health", border_style="blue")
    table_health.add_column("Metric", style="cyan")
    table_health.add_column("Value", style="green")
    table_health.add_column("Proportion / Description", style="dim")

    table_health.add_row("Average UTXO Value", format_tsar(avg_utxo_sats), "Average balance per output")
    table_health.add_row("Immature Coinbase", format_tsar(immature_cb_sats), f"< {CFG.COINBASE_MATURITY} confirmations maturity")
    table_health.add_row("Dust UTXOs (< 10,000 sat)", f"{dust_count:,}", f"{(dust_count / total_utxos * 100):.2f}% of total UTXOs")
    console.print(table_health)

    # Rich List Table
    sorted_holders = sorted(addr_balances.items(), key=lambda x: x[1], reverse=True)
    _render_rich_table(sorted_holders, total_actual_sats, limit=10)

    # Sub-Menu: View More Rich List, Deep Inspect Address, or Return
    while True:
        sub = Prompt.ask(
            "\n[dim yellow]Options: [bold][L][/bold] Show More Rich List | [bold][A][/bold] Inspect Address | [bold]Enter[/bold] Return[/dim yellow]",
            default="",
        ).strip().upper()

        if sub == "L":
            _render_rich_table(sorted_holders, total_actual_sats, limit=30)
        elif sub == "A":
            inspect_address(db)
        else:
            break


def _render_rich_table(sorted_holders: list, total_supply: int, limit: int = 10) -> None:
    """Render table of top wealthiest addresses."""
    table_rich = Table(title=f"Wealth Distribution — Rich List (Top {min(limit, len(sorted_holders))})", border_style="magenta")
    table_rich.add_column("Rank", justify="center", style="bold")
    table_rich.add_column("Bech32 Address", style="cyan")
    table_rich.add_column("Total Balance", justify="right", style="green")
    table_rich.add_column("Supply Share", justify="right", style="yellow")

    for rank, (spk_hex, sats) in enumerate(sorted_holders[:limit], start=1):
        raw_spk = bytes.fromhex(spk_hex)
        addr = script_to_address(raw_spk) or spk_hex
        pct = (sats / total_supply * 100) if total_supply > 0 else 0
        table_rich.add_row(str(rank), addr, format_tsar(sats), f"{pct:.2f}%")

    console.print(table_rich)


def inspect_address(db: UTXODB | None = None) -> None:
    """Interactively inspect a specific TsarChain address."""
    if db is None:
        db = UTXODB()

    target_addr = Prompt.ask("\n[bold cyan]Enter TsarChain Address (tsar1...)[/bold cyan]").strip()
    if not target_addr:
        console.print("[yellow]Address inspection cancelled.[/yellow]")
        return

    try:
        total_bal = db.get_balance(target_addr, mode="total")
        spendable_bal = db.get_balance(target_addr, mode="spendable")
        immature_bal = max(0, total_bal - spendable_bal)
        utxo_dict = db.get(target_addr)
    except Exception as exc:
        console.print(f"[bold red]Invalid address format or read failed: {exc}[/bold red]")
        return

    # Role classification
    role = "Standard Wallet (P2WPKH/P2WSH)"
    if target_addr.startswith("tsar1qe"):
        role = "Storage Escrow Pool (Graffiti Smart Pool)"
    elif target_addr.startswith("tsar1q"):
        if any(bool(u.get("is_coinbase")) for u in utxo_dict.values()):
            role = "Miner / Solo Node Wallet (Coinbase Recipient)"

    info_text = (
        f"[bold white]Address          :[/bold white] [cyan]{target_addr}[/cyan]\n"
        f"[bold white]Type / Role      :[/bold white] [yellow]{role}[/yellow]\n"
        f"[bold white]Total Balance    :[/bold white] [bold green]{format_tsar(total_bal)}[/bold green]\n"
        f"[bold white]Spendable Balance:[/bold white] {format_tsar(spendable_bal)}\n"
        f"[bold white]Immature Subsidy :[/bold white] {format_tsar(immature_bal)}\n"
        f"[bold white]Total Outputs    :[/bold white] {len(utxo_dict):,} unspent outputs"
    )
    console.print(Panel(info_text, title="[bold]Address Detailed Inspection[/bold]", border_style="cyan"))

    if utxo_dict:
        tbl = Table(title="Unspent UTXO Outputs List", border_style="blue")
        tbl.add_column("TxID:Vout", style="cyan")
        tbl.add_column("Amount", justify="right", style="green")
        tbl.add_column("Block Height", justify="right")
        tbl.add_column("Type", justify="center")

        items = list(utxo_dict.items())
        for key, item in items[:15]:
            is_cb = "[bold yellow]Coinbase[/bold yellow]" if item.get("is_coinbase") else "Transfer"
            tbl.add_row(key, format_tsar(item.get("amount", 0)), f"#{item.get('block_height', 0):,}", is_cb)
        if len(items) > 15:
            tbl.add_row(f"... and {len(items) - 15} other UTXOs", "", "", "")
        console.print(tbl)
