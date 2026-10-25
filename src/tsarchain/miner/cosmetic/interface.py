# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import sys
import psutil
import shutil
import platform
import contextlib

from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.prompt import Prompt
from rich.prompt import Confirm
from rich.console import Console

from ...utils import config as CFG
from .tui import _enable_windows_vt100

_enable_windows_vt100()


def print_banner():
    banner_text = (
        "[bold orange1]"
        "████████╗███████╗ █████╗ ██████╗    ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗\n"
        "╚══██╔══╝██╔════╝██╔══██╗██╔══██╗  ██╔════╝██║  ██║██╔══██╗██║████╗  ██║\n"
        "   ██║   ███████╗███████║██████╔╝  ██║     ███████║███████║██║██╔██╗ ██║\n"
        "   ██║   ╚════██║██╔══██║██╔══██╗  ██║     ██╔══██║██╔══██║██║██║╚██╗██║\n"
        "   ██║   ███████║██║  ██║██║  ██║  ╚██████╗██║  ██║██║  ██║██║██║ ╚████║\n"
        "   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝\n"
        "[/bold orange1]\n"
        "[bold yellow]TsarChain Mining CLI  •  Long Live The Voice Sovereignty[/bold yellow]"
    )
    console = Console()
    console.print(Panel(Align.center(banner_text), border_style="orange1", expand=False))


# RGB custom
def _rgb_color(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def _bg_rgb_color(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"


# Text
RED     = _rgb_color(235, 59, 59)
GREY    = _rgb_color(245, 246, 244)
CYAN    = _rgb_color(0, 215, 235)
GREEN   = _rgb_color(59, 196, 59)
YELLOW  = _rgb_color(232, 215, 59)
ORANGE  = _rgb_color(242, 132, 0)

# Background
BG_RED    = _bg_rgb_color(191, 34, 34)
BG_GREY   = _bg_rgb_color(100, 100, 100)
BG_BLUE   = _bg_rgb_color(32, 163, 223)
BG_GREEN  = _bg_rgb_color(59, 196, 59)
BG_WHITE  = _bg_rgb_color(240, 247, 249)
BG_ORANGE = _bg_rgb_color(242, 132, 0)
BG_YELLOW = _bg_rgb_color(232, 215, 59)
BG_CYAN   = _bg_rgb_color(0, 215, 235)

# Text styles
DIM       = "\033[2m"
BOLD      = "\033[1m"
RESET     = "\033[0m"
BLINK     = "\033[5m"
HIDDEN    = "\033[8m"
ITALIC    = "\033[3m"
REVERSE   = "\033[7m"
UNDERLINE = "\033[4m"



def print_system_snapshot(cores_hint: int | None = None):
    console = Console()
    try:
        uname = platform.uname()
        vm = psutil.virtual_memory()
        du = shutil.disk_usage(".")
        freq = None
        with contextlib.suppress(Exception):
            freq = psutil.cpu_freq()

        phys = psutil.cpu_count(logical=False) or 0
        logi = psutil.cpu_count(logical=True) or 0

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Key", style="bold cyan")
        table.add_column("Value", style="bold white")

        table.add_row("CPU Model", _cpu_brand())

        core_info = f"{phys} physical / {logi} logical"
        if cores_hint:
            core_info += f" (recommended: {cores_hint})"
        table.add_row("CPU Cores", core_info)

        if freq:
            base = f"{(freq.min or 0)/1000:.2f}"
            cur  = f"{(freq.current or 0)/1000:.2f}"
            mx   = f"{(freq.max or 0)/1000:.2f}"
            table.add_row("CPU Speed", f"{cur} GHz (base ~{base} / boost ~{mx})")

        table.add_row("RAM Memory", f"{_human_bytes(vm.total)} total, {_human_bytes(vm.available)} free")
        table.add_row("Disk Space", f"{_human_bytes(du.free)} free of {_human_bytes(du.total)}")
        table.add_row("OS System", f"{uname.system} {uname.release} ({uname.machine})")
        table.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

        console.print(Panel(table, title="[bold gold1]Hardware Specifications[/bold gold1]", border_style="cyan", expand=False))
    except Exception as e:
        console.print(f"[bold red][snapshot] failed: {e}[/bold red]")


def get_user_input():
    console = Console()
    console.print("\n[bold orange1]Miner Setup[/bold orange1]")

    # Input address
    while True:
        try:
            address = Prompt.ask("[bold cyan]Enter Miner Address[/bold cyan] ([dim]must start with tsar1...[/dim])").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Setup cancelled by user.[/yellow]")
            sys.exit(0)

        if address and address.lower().startswith("tsar1"):
            console.print(f"[bold green]✓ Wallet Address locked:[bold green] [white]{address}[/white]")
            break
        else:
            console.print("[bold red]Error: Address must start with 'tsar1...'[/bold red]")
            console.print("[dim]Example: tsar1qyourwalletaddresshere[/dim]")

    # Input CPU cores
    total_cores = psutil.cpu_count(logical=True) or 1
    console.print(f"\n[bold cyan]System detected [green]{total_cores}[/green] total CPU thread(s).[/bold cyan]")

    while True:
        try:
            cores_input = Prompt.ask(
                "[bold cyan]CPU cores to assign for mining[/bold cyan]",
                default=str(total_cores)
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Setup cancelled by user.[/yellow]")
            sys.exit(0)

        try:
            cores = int(cores_input)
            if cores <= 0:
                console.print("[bold red]Error: Cores must be a positive integer.[/bold red]")
                continue
            if cores > total_cores:
                console.print(f"[bold red]Warning: Selected {cores} exceeds total detected {total_cores} cores. Setting max to {total_cores}.[/bold red]")
                cores = total_cores
            console.print(f"[bold green]✓ Assigned Cores:[bold green] [bold white]{cores} core(s)[/bold white]")
            break
        except ValueError:
            console.print("[bold red]Error: Please enter a valid integer number.[/bold red]")

    return address, cores


def prompt_rx_full_mem() -> bool:
    console = Console()
    console.print("\n[bold orange1]RandomX Configuration[/bold orange1]")
    console.print("[bold green]FULL MEMORY Mode[/bold green] : Faster hashrate (+2.5GB RAM dataset)")
    console.print("[bold blue]LIGHT MODE[/bold blue]       : Stable RAM usage (~2.5GB RAM dataset)")

    vm = psutil.virtual_memory()
    total_ram_gb = vm.total / (1024 ** 3)
    avail_ram_gb = vm.available / (1024 ** 3)

    if total_ram_gb < 3.5 or avail_ram_gb < 2.5:
        console.print(f"[bold yellow]⚠️ System Memory Notice: {avail_ram_gb:.1f} GB available of {total_ram_gb:.1f} GB total.[/bold yellow]")
        console.print("[yellow]RandomX Full Memory Mode requires ~2.5 GB dedicated free RAM. Light Mode is recommended.[/yellow]")

    try:
        enabled = Confirm.ask("[bold cyan]Enable RandomX FULL MEMORY Mode?[/bold cyan]", default=False)
    except (KeyboardInterrupt, EOFError):
        console.print("[yellow]Using default LIGHT MODE.[/yellow]")
        return False

    if enabled:
        if avail_ram_gb < 2.5:
            console.print(f"[bold red]⚠️ Warning: Low available memory ({avail_ram_gb:.1f} GB). Full Memory mode may cause system swapping or OOM crash.[/bold red]")
        console.print("[bold green]✓ RandomX FULL MEMORY Enabled (+2.5GB RAM)[/bold green]\n")
    else:
        console.print("[bold blue]✓ RandomX LIGHT MODE Selected[/bold blue]\n")
    return enabled


# ----- CLI INTERFACE INFO ------


def snapshot_info(status: str = "backup", detail: str = ""):
    if status == "backup":
        return _badges(
            ("SNAPSHOTS", YELLOW),
            ("ENABLED", BG_GREEN, BOLD),
            (f"every {CFG.BLOCK_BACKUP_SNAPSHOT} blocks -> '{CFG.SNAPSHOT_BACKUP_DIR}'", ITALIC),
        )
    if status == "backup_disabled":
        return _badges(
            ("SNAPSHOTS", YELLOW),
            ("DISABLED", BG_RED, BOLD),
            ("Periodic backup snapshots disabled", ITALIC),
        )
    if status == "disabled":
        return _badges(
            ("BOOTSTRAP", YELLOW),
            ("DISABLED", BG_RED, BOLD),
            ("Fast sync disabled; proceeding with Seed RPC sync", ITALIC),
        )
    if status == "installed":
        return _badges(
            ("BOOTSTRAP", YELLOW),
            ("SUCCESS", BG_GREEN, BOLD),
            (f"Restored database to {detail}", ITALIC),
        )
    if status == "failed":
        return _badges(
            ("BOOTSTRAP", YELLOW),
            ("FAILED", BG_RED, BOLD),
            (f"{detail} (falling back to Seed RPC)", YELLOW),
        )
    if status == "skipped":
        return _badges(
            ("BOOTSTRAP", YELLOW),
            ("SKIPPED", BG_YELLOW, BOLD),
            (f"{detail} (using standard P2P sync)", ITALIC),
        )
    return _badges(
        ("BOOTSTRAP", YELLOW),
        ("SYNC", BG_CYAN, BOLD),
        (detail or status, ITALIC),
    )


def node_info(status: str, detail: str = ""):
    if status == "started":
        return _badges(("NODE", YELLOW), ("ONLINE", BG_CYAN, BOLD), (detail, ITALIC))
    if status == "starting":
        return _badges(("NODE", YELLOW), ("STARTING", BG_YELLOW, BOLD), (detail, ITALIC))
    if status == "stopping":
        return _badges(("NODE", YELLOW), ("STOPPING", BG_RED, BOLD), (detail, ITALIC))
    if status == "stopped":
        return _badges(("NODE", YELLOW), ("STOPPED", BG_RED, BOLD), (detail or "Node stopped", ITALIC))
    if status == "interrupted":
        return _badges(("SIGNAL", YELLOW), ("INTERRUPT", BG_RED, BOLD), (detail or "Mining interrupted by user", YELLOW))
    return _badges(("NODE", YELLOW), (detail or status, ITALIC))


def sync_info(status: str, detail: str = "", extra: str = ""):
    if status == "waiting":
        return _badges(("SYNC", YELLOW), ("WAITING", BG_YELLOW, BOLD), (detail or "Waiting for blockchain sync...", ITALIC))
    if status == "waiting_peers":
        return _badges(("SYNC", YELLOW), ("PEERS", BG_BLUE, BOLD), ("Waiting for peer connection...", ITALIC))
    if status == "waiting_trusted":
        return _badges(("SYNC", YELLOW), ("BOOTSTRAP", BG_BLUE, BOLD), ("Waiting for trusted bootstrap height...", ITALIC))
    if status == "paused_peers":
        return _badges(("MINING", YELLOW), ("PAUSED", BG_RED, BOLD), ("No active peers; waiting for peers...", ITALIC))
    if status == "synced":
        tip_str = f" (trusted tip {extra})" if extra else ""
        return _badges(("SYNC", YELLOW), ("READY", BG_GREEN, BOLD), (f"Chain synced to height {detail}{tip_str}", ITALIC))
    if status == "gap":
        return _badges(("SYNC", YELLOW), ("CATCHUP", BG_ORANGE, BOLD), (f"Local {detail} behind trusted tip {extra}; syncing...", ITALIC))
    if status == "progress":
        return _badges(("SYNC", YELLOW), ("PROGRESS", BG_CYAN, BOLD), (f"Local height {detail}, trusted best {extra}", ITALIC))
    if status == "mismatch":
        return _badges(("SYNC", YELLOW), ("RESYNC", BG_YELLOW, BOLD), ("Local tip hash differs from trusted; resyncing...", ITALIC))
    if status == "timeout":
        return _badges(("SYNC", YELLOW), ("TIMEOUT", BG_RED, BOLD), ("Sync timeout or interrupted", ITALIC))
    if status == "confirmed":
        return _badges(("CHAIN", YELLOW), ("CONFIRMED", BG_GREEN, BOLD), (detail or "Node is live (no mining)", ITALIC))
    if status == "height":
        return _badges(("CHAIN", YELLOW), ("HEIGHT", BG_BLUE, BOLD), (f"Local chain height: {detail}", ITALIC))
    return _badges(("SYNC", YELLOW), (detail or status, ITALIC))


def genesis_info(created: bool):
    if created:
        return _badges(("GENESIS", YELLOW), ("CREATED", BG_GREEN, BOLD), ("Genesis block created & locked in LMDB", ITALIC))
    return _badges(("GENESIS", YELLOW), ("FAILED", BG_RED, BOLD), ("Failed to create genesis block", YELLOW))


def tip_switch_info(height: int, tip_hash: str = ""):
    hx_str = f" [{tip_hash[:16]}...]" if tip_hash else ""
    return _badges(("MINING", YELLOW), ("NEW TIP", BG_CYAN, BOLD), (f"New block at height {height}{hx_str}; switching tip", ITALIC))


def error_info(tag: str, message: str):
    return _badges(("ERROR", RED), (tag, BG_GREY, RED), (message, YELLOW))


def warn_info(tag: str, message: str):
    return _badges(("WARN", YELLOW), (tag, BG_GREY, ORANGE), (message, GREY))


def mining_stop_info():
    return _badges(
        ("Press", BG_WHITE, ORANGE),
        ("Ctrl+C", BG_RED),
        ("to stop mining", BG_WHITE, ORANGE),
    )


def block_found_info(b_height, b_hash, tx_label):
    return _badges(
        ("Block Found!", YELLOW),
        (b_height, BG_GREEN),
        (b_hash, ITALIC),
        (tx_label, BG_RED),
    )


# ----- END OF CLI INTERFACE INFO ------


# =============================================================================
# INTERNAL METHODS
# =============================================================================


def _badges(*items: tuple[object, ...]) -> str:
    parts = []
    for item in items:
        text = item[0]
        bg = item[1] if len(item) > 1 else ""
        fg = item[2] if len(item) > 2 else ""
        bold = item[3] if len(item) > 3 else True
        parts.append(_joins(text, bg=bg, fg=fg, bold=bold))
    return "".join(parts)


def _joins(text: object, bg: str = "", fg: str = "", bold: bool = True) -> str:
    style = f"{BOLD if bold else ''}{bg}{fg}"
    return f"{style} {text} {RESET}"


def _human_bytes(n: int | float) -> str:
    try:
        n = float(n)
    except (ValueError, TypeError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EB"


def _cpu_brand() -> str:
    sysname = platform.system()
    if sysname == "Windows":
        with contextlib.suppress(Exception):
            import winreg  # type: ignore
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            ) as k:
                name, _ = winreg.QueryValueEx(k, "ProcessorNameString")
                clean = " ".join(str(name).split())
                if clean:
                    return clean
    elif sysname == "Linux":
        with contextlib.suppress(Exception):
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "model name" in line:
                        clean = " ".join(line.split(":", 1)[1].strip().split())
                        if clean:
                            return clean
    name = platform.processor() or ""
    clean = " ".join(str(name).split())
    return clean or "Unknown CPU"
