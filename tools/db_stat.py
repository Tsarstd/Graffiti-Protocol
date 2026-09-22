#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP173

import os
import sys

reconfig = getattr(sys.stdout, 'reconfigure', None)
if callable(reconfig):
    reconfig(encoding='utf-8', errors='replace')

import math
import lmdb
import struct
import shutil
import argparse
import colorama
import tempfile
from typing import Any
from datetime import datetime
from bech32 import bech32_encode, convertbits

# Add src to sys.path if not present
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_HERE, 'src')
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from tsarchain.utils import config as CFG
try:
    from tsarchain.core.block import Block
    from tsarchain.core.tx import Tx
    from tsarchain.mempool.scripts import script_to_address
    from tsarchain.contracts.graffiti_registry import (
        deserialize_post_binary,
        deserialize_comment_binary,
        deserialize_payout_binary,
        deserialize_proof_binary,
    )
    from tsarchain.network.rpc_helper.chat import decode_prekey_bundle
except ImportError:
    Block = None
    Tx = None
    script_to_address = None
    deserialize_post_binary = None
    deserialize_comment_binary = None
    deserialize_payout_binary = None
    deserialize_proof_binary = None
    decode_prekey_bundle = None


colorama.init()
RESET  = "\033[0m"
BLUE   = "\033[34m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

def clog(message: str, color: str | None = GREEN):
    if color:
        print(f"{color}{message}{RESET}")
    else:
        print(message)

def color_text(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


# ============================================================
# DATABASE PATHS & DOMAINS (Aligned with lmdb_to_json.py)
# ============================================================
DOMAINS = {
    'node': 'data/node',
    'keys': 'data/keys',
    'archivist': 'data/archivist/storage',
    'web': 'data/web',
}

NODE_SUBDBS = ['chain', 'state', 'utxo', 'mempool', 'graffiti', 'chat_prekeys']
NODE_SUBDB_PATHS = {
    'chain': 'data/node/chain',
    'state': 'data/node/state',
    'utxo': 'data/node/utxo',
    'mempool': 'data/node/mempool',
    'graffiti': 'data/node/graffiti',
    'chat_prekeys': 'data/node/chat_prekeys',
}

KEYS_SUBDBS = ['node_secrets', 'secure_wallet', 'wallet_peer_keys', 'stor_peer_keys']
KEYS_ENV_PATH = "data/keys"

ARCHIVIST_ENV_PATH = "data/archivist/storage"
ARCHIVIST_TARGETS = {
    'index_db': ('data/archivist/storage/index_db', 'idx'),
    'payout_guard': ('data/archivist/storage/payout_guard', 'guard'),
}

WEB_ENV_PATH = "data/web"
WEB_SUBDBS = ['web_cache', 'web_media', 'web_blocks']

LEGACY_NODE_PATH = "data/node"
SUBDBS = NODE_SUBDBS


def _default_db_dir() -> str:
    try:
        return CFG.NODE_DATA_DIR
    except Exception:
        return os.path.join('data', 'node')


def is_lmdb_dir(path: str) -> bool:
    """Check if path is directly an LMDB environment directory (contains data.mdb or lock.mdb)."""
    return os.path.isdir(path) and (
        os.path.exists(os.path.join(path, "data.mdb")) or os.path.exists(os.path.join(path, "lock.mdb"))
    )


def get_lmdb_envs(target_dir: str) -> dict[str, str]:
    """
    Returns mapping {name: env_path}.
    - If target_dir is directly an LMDB environment (e.g. data/node/chain, data/keys, data/web), returns {basename: target_dir}.
    - If target_dir is a container directory (e.g. data/node, data/archivist/storage), discovers all child LMDB environments.
    """
    if not os.path.isdir(target_dir):
        return {}

    if is_lmdb_dir(target_dir):
        return {os.path.basename(os.path.abspath(target_dir)): target_dir}

    envs = {}
    for entry in os.scandir(target_dir):
        if entry.is_dir() and is_lmdb_dir(entry.path):
            envs[entry.name] = entry.path

    # Fallback to known paths if relative from project root and matching NODE_DATA_DIR
    if not envs and os.path.abspath(target_dir) == os.path.abspath(_default_db_dir()):
        for name, p in NODE_SUBDB_PATHS.items():
            if is_lmdb_dir(p):
                envs[name] = p

    return envs


def get_env_subdbs_info(env_path: str) -> dict[str, int]:
    """
    Returns mapping of {subdb_name: entry_count} for an LMDB environment.
    If it has named sub-databases (like data/web or data/keys or index_db), inspects each.
    """
    res = {}
    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False)
        named = []
        try:
            root_dbi = env.open_db(None, create=False)
            with env.begin(db=root_dbi, write=False) as txn:
                with txn.cursor() as cur:
                    for k, _ in cur:
                        try:
                            named.append(k.decode('utf-8'))
                        except Exception:
                            pass
        except Exception:
            pass

        if named:
            for s in named:
                try:
                    dbi = env.open_db(s.encode('utf-8'), create=False)
                    with env.begin(db=dbi, write=False) as txn:
                        res[s] = txn.stat()['entries']
                except Exception:
                    pass
        else:
            try:
                root_dbi = env.open_db(None, create=False)
                with env.begin(db=root_dbi, write=False) as txn:
                    res[os.path.basename(env_path)] = txn.stat()['entries']
            except Exception:
                pass
        env.close()
    except Exception:
        pass
    return res


def peek_env_keys(env_path: str, limit: int = 3) -> dict[str, list[str]]:
    """
    Returns mapping of {subdb_name: [sample_keys]} for all sub-databases in an LMDB environment.
    """
    out = {}
    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False)
        named = []
        try:
            root_dbi = env.open_db(None, create=False)
            with env.begin(db=root_dbi, write=False) as txn:
                with txn.cursor() as cur:
                    for k, _ in cur:
                        try:
                            named.append(k.decode('utf-8'))
                        except Exception:
                            pass
        except Exception:
            pass

        targets = named if named else [None]
        for s in targets:
            label = s if s else os.path.basename(env_path)
            try:
                dbi = env.open_db(s.encode('utf-8') if s else None, create=False)
                keys = []
                with env.begin(db=dbi, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, _ in cur:
                            if k == b'__meta__':
                                continue
                            try:
                                keys.append(k.decode('utf-8'))
                            except Exception:
                                keys.append(str(k))
                            if len(keys) >= limit:
                                break
                if keys:
                    out[label] = keys
            except Exception:
                pass
        env.close()
    except Exception:
        pass
    return out


def _bytes_to_human(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"


def check_storage_health(env) -> dict:
    try:
        info = env.info()
        stats = env.stat()

        current_size = info.get('map_size', 0)
        max_size = CFG.LMDB_MAP_SIZE_MAX
        page_size = stats.get('psize', 4096)
        leaf_pages = stats.get('leaf_pages', 0)
        used_pages = page_size * leaf_pages

        usage_ratio = current_size / max_size if max_size > 0 else 0
        actual_usage_ratio = used_pages / current_size if current_size > 0 else 0

        health_status = "HEALTHY"
        warnings = []

        if usage_ratio > 0.9:
            health_status = "CRITICAL"
            warnings.append(f"Storage near maximum capacity: {usage_ratio:.1%}")
        elif usage_ratio > 0.8:
            health_status = "WARNING"
            warnings.append(f"Storage usage high: {usage_ratio:.1%}")
        elif usage_ratio > 0.7:
            health_status = "HEALTHY"
            warnings.append(f"Storage usage moderate: {usage_ratio:.1%}")

        # Check if auto-growth is still possible
        can_grow = current_size < max_size

        # Check transaction count (potential performance issue)
        txn_count = info.get('last_txnid', 0)
        if txn_count > 1000000:  # Arbitrary threshold
            warnings.append(f"High transaction count: {txn_count:,} - consider compaction")

        # Check for overflow pages (fragmentation indicator)
        overflow_pages = stats.get('overflow_pages', 0)
        if overflow_pages > 1000:
            warnings.append(f"High overflow pages: {overflow_pages:,} - database fragmentation detected")

        return {
            "status": health_status,
            "current_size_bytes": current_size,
            "current_size_human": _bytes_to_human(current_size),
            "max_size_bytes": max_size,
            "max_size_human": _bytes_to_human(max_size),
            "usage_percent": usage_ratio * 100,
            "actual_usage_percent": actual_usage_ratio * 100,
            "used_pages_bytes": used_pages,
            "used_pages_human": _bytes_to_human(used_pages),
            "can_grow": can_grow,
            "last_txn_id": txn_count,
            "page_size": page_size,
            "leaf_pages": leaf_pages,
            "branch_pages": stats.get('branch_pages', 0),
            "overflow_pages": overflow_pages,
            "warnings": warnings,
            "recommendations": _generate_recommendations(
                usage_ratio,
                can_grow,
                current_size,
                max_size,
                overflow_pages
            ),
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e),
            "warnings": ["Health check failed"],
            "recommendations": ["Check LMDB directory permissions and integrity"],
        }


def _generate_recommendations(
    usage_ratio: float,
    can_grow: bool,
    current: int,
    max_size: int,
    overflow_pages: int,
) -> list:
    
    recommendations = []
    if usage_ratio > 0.9:
        recommendations.extend([
            "🚨 IMMEDIATE ACTION REQUIRED: Storage near maximum",
            f"Current: {_bytes_to_human(current)}, Max: {_bytes_to_human(max_size)}",
            "Options:",
            "  1. Increase LMDB_MAP_SIZE_MAX in config.py",
            "  2. Run database compaction (--compact flag)",
            "  3. Prune old data if applicable",
        ])
    elif usage_ratio > 0.8:
        recommendations.extend([
            "⚠️  Storage usage high - monitor closely",
            f"Consider increasing LMDB_MAP_SIZE_MAX from {_bytes_to_human(max_size)}",
            "Run with --compact to reclaim space",
        ])
    elif not can_grow:
        recommendations.extend([
            "📏 Storage at maximum configured size",
            "Cannot auto-grow further without config change",
        ])

    if overflow_pages > 1000:
        recommendations.append("🔧 Run compaction to reduce fragmentation from overflow pages")

    if usage_ratio < 0.3:
        recommendations.append("💚 Storage utilization is healthy")

    # Always suggest monitoring
    recommendations.append("📈 Run regularly with --health to monitor storage trends")

    return recommendations


def _compact_single_env(env_path: str) -> tuple[int, int]:
    """
    Compact a single LMDB directory environment using native env.copy(..., compact=True).
    Returns (original_size_bytes, compacted_size_bytes).
    """
    orig_size = sum(f.stat().st_size for f in os.scandir(env_path) if f.is_file())
    temp_dir = tempfile.mkdtemp(prefix="lmdb_compact_")
    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=64, lock=False)
        env.copy(temp_dir, compact=True)
        env.close()

        new_size = sum(f.stat().st_size for f in os.scandir(temp_dir) if f.is_file())

        shutil.rmtree(env_path)
        shutil.move(temp_dir, env_path)
        return orig_size, new_size
    except PermissionError as pe:
        raise PermissionError(
            f"Database file is locked by another process. Stop TsarChain node/wallet first ({pe})"
        ) from pe
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def compact_database(db_dir: str, backup: bool = True) -> bool:
    try:
        clog(f"Starting database compaction for: {db_dir}")

        envs = get_lmdb_envs(db_dir)
        if not envs:
            clog(f"❌ No LMDB databases found in: {db_dir}")
            return False

        if backup:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = f"{db_dir.rstrip('/\\')}.backup.{ts}"
            clog(f"Creating backup: {backup_dir}")
            shutil.copytree(db_dir, backup_dir)

        total_orig = 0
        total_new = 0

        for name, env_path in envs.items():
            try:
                orig_sz, new_sz = _compact_single_env(env_path)
                total_orig += orig_sz
                total_new += new_sz
                pct = ((orig_sz - new_sz) / orig_sz * 100) if orig_sz > 0 else 0
                clog(f"  ✅ Compacted: {name} ({_bytes_to_human(orig_sz)} → {_bytes_to_human(new_sz)}, {pct:.1f}% reduction)")
            except Exception as e:
                clog(f"  ❌ Failed {name}: {e}")

        clog("✅ Database compaction completed successfully")
        if total_orig > 0:
            reduction = ((total_orig - total_new) / total_orig * 100)
            clog(
                f"📊 Size change: {_bytes_to_human(total_orig)} → "
                f"{_bytes_to_human(total_new)} "
                f"({reduction:.1f}% reduction)"
            )
        return True
    except Exception as e:
        clog(f"❌ Compaction error: {e}")
        return False


def open_subdb_env(base_dir: str, db_name: str | None = None) -> tuple[lmdb.Environment | None, Any]:
    if db_name:
        # Check archivist aliases
        if db_name in ('index_db', 'idx'):
            idx_p = os.path.join(base_dir, 'index_db') if os.path.isdir(os.path.join(base_dir, 'index_db')) else 'data/archivist/storage/index_db'
            if is_lmdb_dir(idx_p):
                try:
                    env = lmdb.open(idx_p, readonly=True, max_dbs=32, lock=False)
                    try:
                        dbi = env.open_db(b'idx', create=False)
                    except lmdb.Error:
                        dbi = env.open_db(None, create=False)
                    return env, dbi
                except Exception:
                    pass
        elif db_name in ('payout_guard', 'guard'):
            pg_p = os.path.join(base_dir, 'payout_guard') if os.path.isdir(os.path.join(base_dir, 'payout_guard')) else 'data/archivist/storage/payout_guard'
            if is_lmdb_dir(pg_p):
                try:
                    env = lmdb.open(pg_p, readonly=True, max_dbs=32, lock=False)
                    try:
                        dbi = env.open_db(b'guard', create=False)
                    except lmdb.Error:
                        dbi = env.open_db(None, create=False)
                    return env, dbi
                except Exception:
                    pass
        elif db_name in WEB_SUBDBS:
            web_p = base_dir if os.path.basename(os.path.abspath(base_dir)) == 'web' else 'data/web'
            if is_lmdb_dir(web_p):
                try:
                    env = lmdb.open(web_p, readonly=True, max_dbs=32, lock=False)
                    try:
                        dbi = env.open_db(db_name.encode('utf-8'), create=False)
                        return env, dbi
                    except lmdb.Error:
                        env.close()
                except Exception:
                    pass
        elif db_name in KEYS_SUBDBS:
            keys_p = base_dir if os.path.basename(os.path.abspath(base_dir)) == 'keys' else 'data/keys'
            if is_lmdb_dir(keys_p):
                try:
                    env = lmdb.open(keys_p, readonly=True, max_dbs=32, lock=False)
                    try:
                        dbi = env.open_db(db_name.encode('utf-8'), create=False)
                        return env, dbi
                    except lmdb.Error:
                        env.close()
                except Exception:
                    pass

        # 1. Dedicated subdirectory e.g. base_dir/chain or base_dir/utxo
        dedicated = os.path.join(base_dir, db_name)
        if is_lmdb_dir(dedicated):
            try:
                env = lmdb.open(dedicated, readonly=True, max_dbs=32, lock=False)
                try:
                    dbi = env.open_db(db_name.encode('utf-8'), create=False)
                except lmdb.Error:
                    dbi = env.open_db(None, create=False)
                return env, dbi
            except Exception:
                pass

        # 2. Check known NODE_SUBDB_PATHS if base_dir is default / node
        known_path = NODE_SUBDB_PATHS.get(db_name)
        if known_path and os.path.abspath(base_dir) == os.path.abspath(os.path.dirname(known_path)) and is_lmdb_dir(known_path):
            try:
                env = lmdb.open(known_path, readonly=True, max_dbs=32, lock=False)
                try:
                    dbi = env.open_db(db_name.encode('utf-8'), create=False)
                except lmdb.Error:
                    dbi = env.open_db(None, create=False)
                return env, dbi
            except Exception:
                pass

    # 3. Target directory itself is directly an LMDB environment
    if is_lmdb_dir(base_dir):
        try:
            env = lmdb.open(base_dir, readonly=True, max_dbs=32, lock=False)
            if db_name:
                if os.path.basename(os.path.abspath(base_dir)) == db_name:
                    try:
                        dbi = env.open_db(db_name.encode('utf-8'), create=False)
                    except lmdb.Error:
                        dbi = env.open_db(None, create=False)
                    return env, dbi
                try:
                    dbi = env.open_db(db_name.encode('utf-8'), create=False)
                    return env, dbi
                except lmdb.Error:
                    env.close()
                    return None, None
            else:
                dbi = env.open_db(None, create=False)
                return env, dbi
        except Exception:
            return None, None

    return None, None


def _count(base_dir: str, name: str) -> int:
    env, dbi = open_subdb_env(base_dir, name)
    if not env or dbi is None:
        return 0
    n = 0
    try:
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    if k != b'__meta__':
                        n += 1
    finally:
        env.close()
    return n


def _peek_keys(base_dir: str, name: str, limit: int = 5):
    out = []
    env, dbi = open_subdb_env(base_dir, name)
    if not env or dbi is None:
        return out
    try:
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    out.append(k)
                    if len(out) >= limit:
                        break
    finally:
        env.close()
    return out


def _graffiti_summary(base_dir: str) -> dict | None:
    env, dbi = open_subdb_env(base_dir, "graffiti")
    if not env or dbi is None:
        return None
    try:
        posts = 0
        comments = 0
        payouts = 0
        proofs = 0
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, _ in cur:
                    if k.startswith(b"p:"):
                        posts += 1
                    elif k.startswith(b"c:"):
                        comments += 1
                    elif k.startswith(b"y:"):
                        payouts += 1
                    elif k.startswith(b"r:"):
                        proofs += 1
        return {"posts": posts, "comments": comments, "payouts": payouts, "proofs": proofs}
    except Exception:
        return None
    finally:
        env.close()


def _load_graffiti_registry(base_dir: str) -> dict | None:
    env, dbi = open_subdb_env(base_dir, "graffiti")
    if not env or dbi is None:
        return None
    try:
        posts = {}
        comments = {}
        payouts = {}
        proofs = {}
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cur:
                for k, v in cur:
                    try:
                        if k.startswith(b"p:") and deserialize_post_binary:
                            art_id = k[2:].decode("utf-8", errors="replace")
                            posts[art_id] = deserialize_post_binary(v, art_id)
                        elif k.startswith(b"c:") and deserialize_comment_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                comments.setdefault(parts[0], []).append(deserialize_comment_binary(v))
                        elif k.startswith(b"y:") and deserialize_payout_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                payouts.setdefault(parts[0], []).append(deserialize_payout_binary(v))
                        elif k.startswith(b"r:") and deserialize_proof_binary:
                            parts = k[2:].decode("utf-8", errors="replace").split(":")
                            if len(parts) >= 2:
                                proofs.setdefault(parts[0], []).append(deserialize_proof_binary(v))
                    except Exception:
                        pass
        return {"posts": posts, "comments": comments, "payouts": payouts, "proofs": proofs}
    except Exception:
        return None
    finally:
        env.close()


def _render_payouts(reg: dict, limit: int = 10) -> None:
    payouts = reg.get("payouts") or {}
    total_entries = sum(len(v or []) for v in payouts.values())
    total_arts = len(payouts)
    total_amount = 0
    rows = []
    for art_id, items in payouts.items():
        for entry in items or []:
            try:
                amt = int(entry.get("amount", 0))
            except Exception:
                amt = 0
            total_amount += amt
            rows.append({
                "art_id": art_id,
                "txid": entry.get("txid"),
                "height": int(entry.get("block_height", 0) or 0),
                "amount": amt,
                "epoch": entry.get("epoch"),
            })
    rows.sort(key=lambda r: (r.get("height", 0), r.get("epoch") or -1), reverse=True)

    clog(f"payouts   : {total_entries}")
    clog(f"arts paid : {total_arts}")
    clog(f"amount sum: {total_amount}")
    if not rows:
        return
    show = rows[:max(1, limit)]
    clog("\nTop payouts (by height):")
    for r in show:
        art = (r.get("art_id") or "")[:16]
        amt = r.get("amount", 0)
        h = r.get("height", 0)
        ep = r.get("epoch")
        txid = (r.get("txid") or "")[:16]
        clog(f"- h={h} ep={ep} amt={amt} art={art} txid={txid}")


# ---- CLI core ----

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='LMDB quick stats, health check, and compaction for TsarChain (Node, Archivist, Web, Keys).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                             # Interactive menu
  %(prog)s --domain node               # Quick summary for node databases
  %(prog)s --domain archivist          # Quick summary for archivist databases
  %(prog)s --domain web                # Quick summary for web explorer cache
  %(prog)s --domain keys               # Quick summary for node secrets & wallets
  %(prog)s --domain all                # Complete summary across all domains
  %(prog)s --domain web --size-only    # Storage breakdown of web domain
  %(prog)s --domain archivist --compact# Compact archivist storage
  %(prog)s --detail idx --peek 5       # Show archivist index_db records
  %(prog)s --detail guard --peek 5     # Show archivist payout guard records
  %(prog)s --detail web_cache          # Show cached web responses
  %(prog)s --detail web_blocks         # Show cached explorer blocks
        """,
    )

    ap.add_argument(
        '--db',
        dest='db_dir',
        default=_default_db_dir(),
        help='LMDB directory (default: from config or data/node)',
    )
    ap.add_argument(
        '--domain',
        dest='domain',
        choices=['node', 'keys', 'archivist', 'web', 'all'],
        help='Target specific domain (node, keys, archivist, web, all)',
    )
    ap.add_argument(
        '--peek',
        dest='peek',
        type=int,
        default=3,
        help='Number of keys/items to peek per subdb (default: 3)',
    )
    ap.add_argument(
        '--detail',
        dest='detail',
        choices=[
            'utxo', 'mempool', 'chain', 'state', 'graffiti', 'payout', 'chat_prekeys', 'prekeys',
            'index_db', 'idx', 'payout_guard', 'guard',
            'web_cache', 'web_media', 'web_blocks',
            'node_secrets', 'secrets',
        ],
        help='Show detailed items for a subdb',
    )

    # Health and maintenance arguments
    health_group = ap.add_argument_group('Health & Maintenance')
    health_group.add_argument(
        '--health',
        dest='health',
        action='store_true',
        help='Run comprehensive health check across databases',
    )
    health_group.add_argument(
        '--compact',
        dest='compact',
        action='store_true',
        help='Compact database to reclaim space via native LMDB copy',
    )
    health_group.add_argument(
        '--no-backup',
        dest='no_backup',
        action='store_true',
        help='Skip backup during compaction (not recommended)',
    )
    health_group.add_argument(
        '--size-only',
        dest='size_only',
        action='store_true',
        help='Show storage breakdown and total size',
    )

    return ap


def _run_single_target(db_dir: str, args) -> int:
    if not os.path.isdir(db_dir):
        clog(f"DB dir not found: {db_dir}")
        return 1

    # 1. Compact database if requested
    if getattr(args, "compact", False):
        success = compact_database(db_dir, backup=not getattr(args, "no_backup", False))
        return 0 if success else 1

    # 2. Health check mode
    if getattr(args, "health", False):
        clog(f"🔍 LMDB Storage Health Check ({db_dir})")
        clog("=" * 50)
        envs = get_lmdb_envs(db_dir)
        if not envs:
            clog(f"❌ No LMDB databases found in: {db_dir}")
            return 1
        for name, env_path in envs.items():
            try:
                env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False)
                health = check_storage_health(env)
                status_icons = {"HEALTHY": "✅", "WARNING": "⚠️", "CRITICAL": "🚨", "ERROR": "❌"}
                icon = status_icons.get(health['status'], "🔍")
                clog(f"[{name.upper()}] {icon} Status: {health['status']} | Size: {health['current_size_human']} ({health['usage_percent']:.1f}%)")
                if health.get('warnings'):
                    for w in health['warnings']:
                        clog(f"   ⚠️  {w}", YELLOW)
                if health.get('recommendations') and health['status'] != 'HEALTHY':
                    for r in health['recommendations']:
                        clog(f"   👉 {r}", CYAN)
                env.close()
            except Exception as e:
                clog(f"[{name.upper()}] ❌ Error opening: {e}")
        return 0

    # 3. Size-only mode
    if getattr(args, "size_only", False):
        envs = get_lmdb_envs(db_dir)
        total_sz = 0
        if envs and len(envs) > 1:
            clog(f"📊 LMDB Storage Breakdown for: {db_dir}")
            for name, path in sorted(envs.items()):
                sz = sum(f.stat().st_size for f in os.scandir(path) if f.is_file())
                total_sz += sz
                clog(f"  - {name:<14}: {_bytes_to_human(sz)}")
            clog("-" * 35)
            clog(f"Total Storage: {_bytes_to_human(total_sz)}")
        else:
            scan_dirs = [envs[k] for k in envs] if envs else [db_dir]
            for p in scan_dirs:
                total_sz += sum(f.stat().st_size for f in os.scandir(p) if f.is_file())
            clog(f"Total Storage ({db_dir}): {_bytes_to_human(total_sz)}")
        return 0

    # 4. Detail dump mode
    detail_choice = getattr(args, "detail", None)
    if detail_choice:
        limit = max(1, int(getattr(args, "peek", 3) or 3))

        if detail_choice == 'utxo':
            env_utxo, dbi_utxo = open_subdb_env(db_dir, 'utxo')
            if not env_utxo or dbi_utxo is None:
                clog('No utxo subdb found')
                return 0
            clog(f"{color_text('\n[detail:utxo]', CYAN)}")
            cnt = 0
            try:
                with env_utxo.begin(db=dbi_utxo, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            if k == b'__meta__':
                                continue
                            try:
                                key = k.decode('utf-8', errors='replace')
                                if len(v) >= 19:
                                    amt, is_cb, height, spk_len = struct.unpack_from("<Q?qH", v, 0)
                                    spk = v[19:19 + spk_len]
                                    addr = script_to_address(spk) if script_to_address else None
                                    if not addr:
                                        try:
                                            if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
                                                prog = spk[2:22]
                                                data = [0] + list(convertbits(prog, 8, 5, True))
                                                addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                                            elif len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
                                                prog = spk[2:34]
                                                data = [0] + list(convertbits(prog, 8, 5, True))
                                                addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                                        except Exception:
                                            addr = None
                                    clog(f"- {key} | amount: {amt} | height: {height} | cb: {is_cb} | address: {addr or 'n/a'}")
                                else:
                                    clog(f"- {key} | raw size: {len(v)} bytes")
                            except Exception as e:
                                clog(f"- decode error for key {k!r}: {e}")
                            cnt += 1
                            if cnt >= limit:
                                break
            finally:
                env_utxo.close()
            return 0

        elif detail_choice == 'chain':
            env_chain, dbi_chain = open_subdb_env(db_dir, 'chain')
            if not env_chain or dbi_chain is None:
                clog('No chain subdb found')
                return 0
            clog(f"{color_text('\n[detail:chain]', CYAN)}")
            cnt = 0
            try:
                with env_chain.begin(db=dbi_chain, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            if k == b'__meta__':
                                clog(f"- meta: {v.decode('utf-8', errors='replace')}")
                                continue
                            if not k.startswith(b'h:'):
                                continue
                            key_str = k.decode('utf-8', errors='replace')
                            if Block:
                                try:
                                    blk = Block.from_storage_bytes(v)
                                    ts_str = datetime.fromtimestamp(blk.timestamp).strftime('%Y-%m-%d %H:%M:%S') if blk.timestamp else 'n/a'
                                    prev_h = blk.prev_block_hash.hex()[:16] if isinstance(blk.prev_block_hash, bytes) else str(blk.prev_block_hash)[:16]
                                    clog(f"- {key_str} | txs: {len(blk.transactions)} | prev: {prev_h}... | size: {len(v)} bytes | time: {ts_str}")
                                except Exception as e:
                                    clog(f"- {key_str} | size: {len(v)} bytes (decode err: {e})")
                            else:
                                clog(f"- {key_str} | size: {len(v)} bytes")
                            cnt += 1
                            if cnt >= limit:
                                break
            finally:
                env_chain.close()
            return 0

        elif detail_choice == 'mempool':
            env_mem, dbi_mem = open_subdb_env(db_dir, 'mempool')
            if not env_mem or dbi_mem is None:
                clog('No mempool subdb found')
                return 0
            clog(f"{color_text('\n[detail:mempool]', CYAN)}")
            cnt = 0
            try:
                with env_mem.begin(db=dbi_mem, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            if k == b'__meta__':
                                continue
                            key_str = k.decode('utf-8', errors='replace')
                            if len(v) >= 20:
                                try:
                                    _, fee, vsize, weight = struct.unpack_from("<dIII", v, 0)
                                    raw_tx = v[20:]
                                    txid = Tx.from_storage_bytes(raw_tx).txid if Tx else key_str
                                    clog(f"- tx: {txid[:16]}... | fee: {fee} | vbytes: {vsize} | weight: {weight}")
                                except Exception:
                                    clog(f"- {key_str} | size: {len(v)} bytes")
                            else:
                                clog(f"- {key_str} | size: {len(v)} bytes")
                            cnt += 1
                            if cnt >= limit:
                                break
                    if cnt == 0:
                        clog("Mempool is currently empty.")
            finally:
                env_mem.close()
            return 0

        elif detail_choice == 'state':
            env_st, dbi_st = open_subdb_env(db_dir, 'state')
            if not env_st or dbi_st is None:
                clog('No state subdb found')
                return 0
            clog(f"{color_text('\n[detail:state]', CYAN)}")
            try:
                with env_st.begin(db=dbi_st, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            try:
                                ks = k.decode('utf-8', errors='replace')
                                vs = v.decode('utf-8', errors='replace')
                                clog(f"- {color_text(ks, YELLOW)}: {vs}")
                            except Exception:
                                clog(f"- {k!r}: <{len(v)} bytes>")
            finally:
                env_st.close()
            return 0

        elif detail_choice == 'graffiti':
            reg = _load_graffiti_registry(db_dir)
            if not reg:
                clog('No graffiti records found')
                return 0
            clog(f"{color_text('\n[detail:graffiti]', CYAN)}")
            posts = reg.get("posts") or {}
            comments = reg.get("comments") or {}
            payouts = reg.get("payouts") or {}
            proofs = reg.get("proofs") or {}
            clog(f"posts   : {len(posts)}")
            clog(f"comments: {sum(len(v or []) for v in comments.values())}")
            clog(f"payouts : {sum(len(v or []) for v in payouts.values())}")
            clog(f"proofs  : {sum(len(v or []) for v in proofs.values())}")
            return 0

        elif detail_choice == 'payout':
            reg = _load_graffiti_registry(db_dir)
            if reg is None:
                clog("No graffiti registry found")
                return 0
            clog(f"{color_text('\n[detail:payout]', CYAN)}")
            _render_payouts(reg, limit=limit)
            return 0

        elif detail_choice in ('chat_prekeys', 'prekeys'):
            env_pk, dbi_pk = open_subdb_env(db_dir, 'chat_prekeys')
            if not env_pk or dbi_pk is None:
                clog('No chat_prekeys subdb found')
                return 0
            clog(f"{color_text('\n[detail:chat_prekeys]', CYAN)}")
            cnt = 0
            try:
                with env_pk.begin(db=dbi_pk, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            if k == b'__meta__':
                                continue
                            key_str = k.decode('utf-8', errors='replace')
                            if decode_prekey_bundle and len(v) >= 9:
                                try:
                                    bundle = decode_prekey_bundle(v)
                                    opk_count = len(bundle.get('opk_pool', []))
                                    clog(f"- peer: {key_str} | updated_at: {bundle.get('timestamp')} | opks: {opk_count}")
                                except Exception:
                                    clog(f"- peer: {key_str} | raw: {len(v)} bytes")
                            else:
                                clog(f"- peer: {key_str} | raw: {len(v)} bytes")
                            cnt += 1
                            if cnt >= limit:
                                break
            finally:
                env_pk.close()
            return 0

        elif detail_choice in ('index_db', 'idx'):
            env_idx, dbi_idx = open_subdb_env(db_dir, 'idx')
            if not env_idx or dbi_idx is None:
                clog('No index_db (idx) subdb found')
                return 0
            clog(f"{color_text('\n[detail:index_db (idx)]', CYAN)}")
            cnt = 0
            try:
                with env_idx.begin(db=dbi_idx, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            ks = k.decode('utf-8', errors='replace')
                            vs = v.decode('utf-8', errors='replace')
                            preview = vs[:64] + '...' if len(vs) > 64 else vs
                            clog(f"- {ks} -> {preview}")
                            cnt += 1
                            if cnt >= limit:
                                break
                    if cnt == 0:
                        clog("index_db (idx) is empty.")
            finally:
                env_idx.close()
            return 0

        elif detail_choice in ('payout_guard', 'guard'):
            env_g, dbi_g = open_subdb_env(db_dir, 'guard')
            if not env_g or dbi_g is None:
                clog('No payout_guard (guard) subdb found')
                return 0
            clog(f"{color_text('\n[detail:payout_guard]', CYAN)}")
            cnt = 0
            try:
                with env_g.begin(db=dbi_g, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            ks = k.decode('utf-8', errors='replace')
                            vs = v.decode('utf-8', errors='replace')
                            clog(f"- {ks} -> {vs}")
                            cnt += 1
                            if cnt >= limit:
                                break
                    if cnt == 0:
                        clog("payout_guard is empty.")
            finally:
                env_g.close()
            return 0

        elif detail_choice in ('web_cache', 'web_media', 'web_blocks'):
            env_w, dbi_w = open_subdb_env(db_dir, detail_choice)
            if not env_w or dbi_w is None:
                clog(f'No {detail_choice} subdb found')
                return 0
            clog(f"{color_text(f'\n[detail:{detail_choice}]', CYAN)}")
            cnt = 0
            try:
                with env_w.begin(db=dbi_w, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            ks = k.decode('utf-8', errors='replace')
                            vs = v.decode('utf-8', errors='replace')
                            preview = vs[:64] + '...' if len(vs) > 64 else vs
                            clog(f"- {ks} -> {preview}")
                            cnt += 1
                            if cnt >= limit:
                                break
                    if cnt == 0:
                        clog(f"{detail_choice} is empty.")
            finally:
                env_w.close()
            return 0

        elif detail_choice in ('node_secrets', 'secrets'):
            env_s, dbi_s = open_subdb_env(db_dir, 'node_secrets')
            if not env_s or dbi_s is None:
                clog('No node_secrets subdb found')
                return 0
            clog(f"{color_text('\n[detail:node_secrets]', CYAN)}")
            cnt = 0
            try:
                with env_s.begin(db=dbi_s, write=False) as txn:
                    with txn.cursor() as cur:
                        for k, v in cur:
                            ks = k.decode('utf-8', errors='replace')
                            clog(f"- secret: {ks} (len: {len(v)} bytes, [MASKED])")
                            cnt += 1
                            if cnt >= limit:
                                break
            finally:
                env_s.close()
            return 0

    # 5. Default summary mode
    clog(f"📁 DB: {db_dir}", GREEN)
    clog("\n---------------------", RED)

    envs = get_lmdb_envs(db_dir)
    base_name = os.path.basename(os.path.abspath(db_dir))
    norm_path = db_dir.replace('\\', '/')

    is_node = any(k in envs for k in ('chain', 'utxo', 'state', 'graffiti', 'mempool', 'chat_prekeys'))
    is_archivist = ('index_db' in envs or 'payout_guard' in envs) or base_name == 'storage' or 'archivist' in norm_path
    is_web = base_name == 'web' or 'data/web' in norm_path
    is_keys = base_name == 'keys' or 'data/keys' in norm_path

    if is_node and not (is_archivist or is_web or is_keys):
        n_chain = _count(db_dir, 'chain')
        clog(f"⛓️  {color_text('chain blocks : ', CYAN)}{n_chain}")

        env_state, dbi_state = open_subdb_env(db_dir, 'state')
        if env_state and dbi_state is not None:
            try:
                with env_state.begin(db=dbi_state, write=False) as txn:
                    tb = txn.get(b'k:total_blocks')
                    ts = txn.get(b'k:total_supply')
                    if tb or ts:
                        clog(f"📊 {color_text('total_blocks : ', CYAN)}{int(tb.decode('utf-8')) if tb else 0}")
                        clog(f"💰 {color_text('total_supply : ', CYAN)}{int(ts.decode('utf-8')) if ts else 0}")
            finally:
                env_state.close()

        n_utxo = _count(db_dir, 'utxo')
        n_mempool = _count(db_dir, 'mempool')
        clog(f"📦 {color_text('utxo entries : ', CYAN)}{n_utxo}")
        clog(f"📝 {color_text('mempool txs  : ', CYAN)}{n_mempool}")

        gstats = _graffiti_summary(db_dir)
        if gstats:
            clog(f"{color_text('graffiti     : ', CYAN)}{gstats.get('posts', 0)}")
            clog(f"{color_text('comments     : ', CYAN)}{gstats.get('comments', 0)}")
            clog(f"{color_text('payouts      : ', CYAN)}{gstats.get('payouts', 0)}")
            clog(f"{color_text('proofs       : ', CYAN)}{gstats.get('proofs', 0)}")

        n_prekeys = _count(db_dir, 'chat_prekeys')
        if n_prekeys > 0:
            clog(f"💬 {color_text('chat prekeys : ', CYAN)}{n_prekeys}")

    elif is_archivist:
        clog("📚 ARCHIVIST STORAGE", YELLOW)
        for env_name, env_p in sorted(envs.items()):
            sub_info = get_env_subdbs_info(env_p)
            for sname, scnt in sorted(sub_info.items()):
                if scnt > 0 or sname in ('idx', 'guard'):
                    clog(f"📦 {color_text(f'{env_name}/{sname:<10} : ', CYAN)}{scnt} entries")

    elif is_web:
        clog("🌐 WEB EXPLORER CACHE", YELLOW)
        sub_info = get_env_subdbs_info(db_dir if is_lmdb_dir(db_dir) else os.path.join(db_dir, 'web'))
        for sname, scnt in sorted(sub_info.items()):
            clog(f"🌐 {color_text(f'{sname:<14} : ', CYAN)}{scnt} entries")

    elif is_keys:
        clog("🔑 KEYS & WALLET SECRETS", YELLOW)
        sub_info = get_env_subdbs_info(db_dir if is_lmdb_dir(db_dir) else os.path.join(db_dir, 'keys'))
        for sname, scnt in sorted(sub_info.items()):
            clog(f"🔑 {color_text(f'{sname:<14} : ', CYAN)}{scnt} entries")

    else:
        for env_name, env_p in sorted(envs.items()):
            sub_info = get_env_subdbs_info(env_p)
            for sname, scnt in sorted(sub_info.items()):
                label = f"{env_name}/{sname}" if sname != env_name else env_name
                clog(f"📦 {color_text(f'{label:<16} : ', CYAN)}{scnt} entries")

    # Optional peeks across all discovered environments
    if getattr(args, "peek", 0) > 0:
        clog(f"\n🔍 Peeking {args.peek} keys per database:")
        for env_name, env_path in sorted(envs.items()):
            sub_keys = peek_env_keys(env_path, limit=args.peek)
            for sname, keys in sorted(sub_keys.items()):
                label = f"{env_name}/{sname}" if (sname != env_name and len(envs) > 1) else sname
                try:
                    show = [k if isinstance(k, str) else k.decode('utf-8', 'ignore') for k in keys]
                except Exception:
                    show = [str(k) for k in keys]
                clog(f"  {label}: {show}")

    return 0


def run_tool(args) -> int:
    domain = getattr(args, "domain", None)

    if domain == 'all':
        clog("🚀 TSARCHAIN MONOREPO MULTI-DOMAIN DATABASE INSPECTOR", YELLOW)
        clog("=" * 60)
        overall_exit = 0
        for dom_name in ['node', 'archivist', 'web', 'keys']:
            dom_path = DOMAINS.get(dom_name)
            if not os.path.exists(dom_path):
                continue
            clog(f"\n🏷️  DOMAIN: [{dom_name.upper()}] -> {dom_path}", CYAN)
            rc = _run_single_target(dom_path, args)
            if rc != 0:
                overall_exit = rc
        return overall_exit
    elif domain in DOMAINS:
        target_path = DOMAINS[domain]
        return _run_single_target(target_path, args)
    else:
        db_dir = args.db_dir
        return _run_single_target(db_dir, args)


def main(argv=None) -> int:
    """Entry point for non-interactive CLI."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_tool(args)


def cli_menu() -> None:
    """Interactive CLI menu."""
    default_db = _default_db_dir()
    db_dir = default_db

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        clog("==============================================", color=CYAN)
        clog("         TsarChain LMDB Dev Toolbox   ", color=YELLOW)
        clog("==============================================", color=CYAN)
        clog(f"Current DB dir: {db_dir}", color=BLUE)
        clog("----------------------------------------------", color=RED)
        clog("1) Quick summary (auto-detect domain metrics)")
        clog("2) Size-only (breakdown & total)")
        clog("3) Health check (detailed)")
        clog("4) Peek keys")
        clog("5) Detail dump (node, archivist, web, keys)")
        clog("6) Compact database")
        clog("7) Switch Domain / Directory")
        clog("0) Exit")
        clog("----------------------------------------------", color=RED)

        choice = input("Select option: ").strip()

        if choice == '0':
            clog("Bye.")
            return

        if choice == '7':
            clog("\nSelect Domain / Target:")
            clog("1) Node       (data/node)")
            clog("2) Archivist  (data/archivist/storage)")
            clog("3) Web        (data/web)")
            clog("4) Keys       (data/keys)")
            clog("5) Custom path")
            dom_ch = input("Choice [1-5]: ").strip()
            if dom_ch == '1':
                db_dir = 'data/node'
            elif dom_ch == '2':
                db_dir = 'data/archivist/storage'
            elif dom_ch == '3':
                db_dir = 'data/web'
            elif dom_ch == '4':
                db_dir = 'data/keys'
            elif dom_ch == '5':
                new_dir = input(f"New DB dir [{db_dir}]: ").strip()
                if new_dir:
                    db_dir = new_dir
            continue

        argv = None

        if choice == '1':
            argv = ['--db', db_dir]
        elif choice == '2':
            argv = ['--db', db_dir, '--size-only']
        elif choice == '3':
            argv = ['--db', db_dir, '--health']
        elif choice == '4':
            peek = input("Peek how many keys per DB? [3]: ").strip() or "3"
            argv = ['--db', db_dir, '--peek', peek]
        elif choice == '5':
            clog("\nAvailable details:")
            clog("  Node      : utxo, chain, mempool, state, graffiti, payout, chat_prekeys")
            clog("  Archivist : index_db (idx), payout_guard (guard)")
            clog("  Web       : web_cache, web_media, web_blocks")
            clog("  Keys      : node_secrets")
            which = input("Which detail?: ").strip().lower()
            if which:
                peek = input("How many items to show? [5]: ").strip() or "5"
                argv = ['--db', db_dir, '--detail', which, '--peek', peek]
        elif choice == '6':
            clog(f"\nWARNING: Compaction will rewrite the DB directory ({db_dir}).")
            yn = input("Proceed with backup before compaction? [Y/n]: ").strip().lower()
            if yn != 'n':
                argv = ['--db', db_dir, '--compact']
            else:
                yn2 = input("Compact WITHOUT backup (NOT recommended)? [y/N]: ").strip().lower()
                if yn2.startswith('y'):
                    argv = ['--db', db_dir, '--compact', '--no-backup']
                else:
                    clog("Compaction cancelled.")
        else:
            clog("Invalid choice.")
            input("\nPress Enter to continue...")
            continue

        if argv is not None:
            clog("\n--- Informations ---\n", color=YELLOW)
            try:
                exit_code = main(argv)
                if exit_code != 0:
                    clog(f"\nCommand finished with exit code {exit_code}")
            except KeyboardInterrupt:
                clog("\nInterrupted by user.")

        input("\nPress Enter to return to menu...")


if __name__ == '__main__':
    if len(sys.argv) == 1 or '--menu' in sys.argv:
        try:
            cli_menu()
        except KeyboardInterrupt:
            clog("\nExit.")
    else:
        raise SystemExit(main())
