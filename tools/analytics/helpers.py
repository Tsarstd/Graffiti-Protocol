# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import sys

# Ensure UTF-8 output on Windows console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import math
import lmdb
from typing import Any
from rich.console import Console
from rich.prompt import Prompt

console = Console(legacy_windows=False)


def open_ro_db(path: str, db_name: str | None = None) -> tuple[lmdb.Environment | None, Any]:
    """Safely open an LMDB environment and named sub-database in read-only mode with zero locking."""
    try:
        env = lmdb.open(path, readonly=True, max_dbs=32, lock=False)
        target = db_name.encode("utf-8") if db_name else None
        try:
            dbi = env.open_db(target, create=False)
        except lmdb.Error:
            dbi = env.open_db(None, create=False)
        return env, dbi
    except Exception:
        return None, None


def format_tsar(amount: int | float, decimals: int = 7) -> str:
    """Format satoshis to TSAR string with 7 decimal precision."""
    amt = int(amount or 0)
    sign = "-" if amt < 0 else ""
    whole, frac = divmod(abs(amt), 10 ** decimals)
    formatted_whole = f"{whole:,}"
    return f"{sign}{formatted_whole}.{frac:0{decimals}d} TSAR"


def format_bytes(size_bytes: int | float) -> str:
    """Format bytes into human readable binary units."""
    size = float(size_bytes or 0)
    if size <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = min(int(math.floor(math.log(size, 1024))), len(units) - 1)
    p = math.pow(1024, i)
    return f"{round(size / p, 2)} {units[i]}"


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    sec = int(seconds or 0)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    hours = sec // 3600
    mins = (sec % 3600) // 60
    return f"{hours}h {mins}m {sec % 60}s"


def pause() -> None:
    """Wait for user to press Enter before returning to menu."""
    Prompt.ask("\n[dim yellow]Press [bold]Enter[/bold] to return to menu[/dim yellow]", default="")
