# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

from collections import Counter, defaultdict
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from tsarchain.contracts.graffiti_registry import GraffitiRegistry
from .helpers import console, format_tsar, format_bytes, pause


def show_graffiti_analytics() -> None:
    """Render interactive Graffiti Protocol & Archivist Economics view."""
    console.print("\n[bold cyan]═══ GRAFFITI PROTOCOL & ARCHIVIST ECONOMICS ═══[/bold cyan]\n")

    registry = GraffitiRegistry()
    posts = registry.data.get("posts", {})
    comments = registry.data.get("comments", {})
    payouts = registry.data.get("payouts", {})
    proofs = registry.data.get("proofs", {})

    total_posts = len(posts)
    total_comments = sum(len(c_list) for c_list in comments.values())
    total_payout_events = sum(len(p_list) for p_list in payouts.values())
    total_proof_events = sum(len(r_list) for r_list in proofs.values())

    total_media_bytes = sum(int(p.get("size", 0)) for p in posts.values())
    total_initial_escrow = sum(int(p.get("amount_paid", 0)) for p in posts.values())
    total_pool_balance = sum(int(p.get("stats", {}).get("pool_balance", 0)) for p in posts.values())
    total_creator_paid = sum(int(p.get("stats", {}).get("creator_paid", 0)) for p in posts.values())
    total_storage_paid = sum(int(p.get("stats", {}).get("storage_paid", 0)) for p in posts.values())

    # Summary Panel
    summary_text = (
        f"[bold white]Total Artworks   :[/bold white] [bold green]{total_posts:,}[/bold green] registered artworks\n"
        f"[bold white]Media Volume     :[/bold white] [cyan]{format_bytes(total_media_bytes)}[/cyan] permanently archived\n"
        f"[bold white]Initial Escrow   :[/bold white] {format_tsar(total_initial_escrow)}\n"
        f"[bold white]Remaining Escrow :[/bold white] [yellow]{format_tsar(total_pool_balance)}[/yellow]\n"
        f"[bold white]Creator Tips     :[/bold white] {format_tsar(total_creator_paid)}\n"
        f"[bold white]Storage Payouts  :[/bold white] {format_tsar(total_storage_paid)}\n"
        f"[bold white]Social Activity  :[/bold white] {total_comments:,} comments | {total_payout_events:,} payouts | {total_proof_events:,} retention proofs"
    )
    console.print(Panel(summary_text, title="[bold]Graffiti Ecosystem Summary[/bold]", border_style="cyan"))

    # MIME Type Distribution Table
    mime_counts = Counter()
    mime_bytes = defaultdict(int)
    for p in posts.values():
        m = p.get("mime", "unknown")
        mime_counts[m] += 1
        mime_bytes[m] += int(p.get("size", 0))

    tbl_mime = Table(title="Media Type Distribution", border_style="blue")
    tbl_mime.add_column("MIME Type", style="cyan")
    tbl_mime.add_column("File Count", justify="right", style="green")
    tbl_mime.add_column("Total Size", justify="right", style="yellow")
    tbl_mime.add_column("Volume Share", justify="right")

    for mime, count in mime_counts.most_common():
        b_size = mime_bytes[mime]
        pct = (b_size / total_media_bytes * 100) if total_media_bytes > 0 else 0
        tbl_mime.add_row(mime, f"{count:,}", format_bytes(b_size), f"{pct:.1f}%")
    console.print(tbl_mime)

    # Recent Artworks Table
    tbl_art = Table(title="Artworks Registry (Latest)", border_style="magenta")
    tbl_art.add_column("Art ID", style="cyan")
    tbl_art.add_column("Creator", style="dim")
    tbl_art.add_column("Size", justify="right")
    tbl_art.add_column("Height", justify="right")
    tbl_art.add_column("Comments", justify="right")
    tbl_art.add_column("Storer Node", style="dim")

    post_list = sorted(posts.values(), key=lambda x: int(x.get("block_height", 0)), reverse=True)
    for p in post_list[:10]:
        art_id = p.get("art_id", "")
        short_art = art_id[:16] + "..." if len(art_id) > 19 else art_id
        creator = p.get("creator", "N/A")
        short_creator = creator[:12] + "..." if len(creator) > 15 else creator
        storer = p.get("storer", "N/A")
        short_storer = storer[:12] + "..." if len(storer) > 15 else storer
        c_count = len(comments.get(art_id, []))

        tbl_art.add_row(
            short_art,
            short_creator,
            format_bytes(p.get("size", 0)),
            f"#{p.get('block_height', 0):,}",
            str(c_count),
            short_storer,
        )
    console.print(tbl_art)

    # Sub-prompt: Inspect specific Art ID
    sub = Prompt.ask(
        "\n[dim yellow]Enter [bold]Art ID[/bold] for details, or press [bold]Enter[/bold] to return[/dim yellow]",
        default="",
    ).strip()

    if sub:
        # Match exact or prefix
        match = None
        for k, v in posts.items():
            if k == sub or k.startswith(sub):
                match = v
                break
        if match:
            _show_art_detail(match, comments.get(match.get("art_id", ""), []))
            pause()
        else:
            console.print("[red]Art ID not found in registry.[/red]")
            pause()


def _show_art_detail(entry: dict, art_comments: list) -> None:
    """Display in-depth information about a specific artwork."""
    art_id = entry.get("art_id", "N/A")
    stats = entry.get("stats", {})
    details = (
        f"[bold white]Art ID           :[/bold white] [cyan]{art_id}[/cyan]\n"
        f"[bold white]SHA256           :[/bold white] {entry.get('sha256', 'N/A')}\n"
        f"[bold white]MIME Type        :[/bold white] {entry.get('mime', 'N/A')}\n"
        f"[bold white]File Size        :[/bold white] {format_bytes(entry.get('size', 0))} ({entry.get('mcount', 0)} chunks)\n"
        f"[bold white]Creator          :[/bold white] [green]{entry.get('creator', 'N/A')}[/green]\n"
        f"[bold white]Storer Node      :[/bold white] {entry.get('storer', 'N/A')}\n"
        f"[bold white]Pool Escrow      :[/bold white] {entry.get('pool_address', 'N/A')}\n"
        f"[bold white]Initial Stake    :[/bold white] {format_tsar(entry.get('amount_paid', 0))}\n"
        f"[bold white]Remaining Escrow :[/bold white] {format_tsar(stats.get('pool_balance', 0))}\n"
        f"[bold white]Creator Tips     :[/bold white] {format_tsar(stats.get('creator_paid', 0))}\n"
        f"[bold white]Storage Paid     :[/bold white] {format_tsar(stats.get('storage_paid', 0))}\n"
        f"[bold white]Confirmed In     :[/bold white] Block #{entry.get('block_height', 0):,} (Tx: {entry.get('txid', 'N/A')})"
    )
    console.print(Panel(details, title="[bold]Graffiti Artwork Details[/bold]", border_style="cyan"))

    if art_comments:
        tbl = Table(title=f"Comments & Associated Tips ({len(art_comments)} comments)", border_style="blue")
        tbl.add_column("Commenter", style="dim")
        tbl.add_column("Comment", style="cyan")
        tbl.add_column("Creator Tip", justify="right", style="green")
        tbl.add_column("Storage Fee", justify="right", style="yellow")
        tbl.add_column("Block", justify="right")

        for c in art_comments[:10]:
            comm_hex = c.get("comment", "")
            try:
                comm_text = bytes.fromhex(comm_hex).decode("utf-8")
            except Exception:
                comm_text = comm_hex[:20]
            tbl.add_row(
                c.get("commenter", "")[:12] + "...",
                comm_text,
                format_tsar(c.get("tip", 0)),
                format_tsar(c.get("storage_paid", 0)),
                f"#{c.get('block_height', 0):,}",
            )
        console.print(tbl)
