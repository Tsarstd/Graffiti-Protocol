#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio

"""
Export LMDB sub-databases to JSON with FULL STREAMING (memory-safe).
Supports multi-domain exports with native binary decoding:
- Keys: node_secrets -> data/keys/json_output/node_secrets.json
- Node: chain, state, utxo, mempool, graffiti -> data/node/json_output/
- Archivist: index_db, payout_guard -> data/archivist/storage/json_output/
- Web: web_cache, web_media, web_blocks -> data/web/json_output/
"""

import os
import sys
import json
import lmdb
import base64
import struct
import argparse

reconfig = getattr(sys.stdout, 'reconfigure', None)
if callable(reconfig):
    reconfig(encoding='utf-8', errors='replace')

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable
from typing import Any, Dict, List, Union, Optional, Tuple

# Add src to sys.path for native models
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

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

# ============================
# USER SETTINGS
# ============================
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
LEGACY_NODE_PATH = "data/node"

KEYS_OUTPUT_DIR = "data/keys/json_output"
NODE_OUTPUT_DIR = "data/node/json_output"
ARCHIVIST_OUTPUT_DIR = "data/archivist/storage/json_output"
WEB_OUTPUT_DIR = "data/web/json_output"

INDENT = 2                        # 'None' for smaller size but less readable.
SORT_UTXO = False

# Registry of databases operating on Pure Binary storage
BINARY_STORAGE_REGISTRY = {
    'utxo': {
        'model': 'Compact Binary Header (<Q?qH) + Raw ScriptPubkey',
        'benefit': '~80% disk reduction, instant O(log N) prefix lookups',
    },
    'chain': {
        'model': 'Binary Block (80B Header + 24B Meta + Serialized Witness Txs)',
        'benefit': '~70% disk reduction, zero-copy native parsing for IBD',
    },
    'graffiti': {
        'model': 'Granular Binary Structs (p: Posts, c: Comments, y: Payouts, r: Proofs)',
        'benefit': 'O(1) isolated record updates, prevents monolithic rewrite lag',
    },
    'mempool': {
        'model': 'Compact Binary Header (<dIII) + Binary Tx Bytes',
        'benefit': 'Microsecond memory-mapped queue persistence',
    },
    'chat_prekeys': {
        'model': 'Binary Prekey Bundle (<QB Header + IK + SPK + Sig + OPK Pool)',
        'benefit': '~60% storage reduction, zero-deserialization overhead for offline bundles',
    },
}
# ============================


def decode_key(key_bytes: bytes) -> str:
    try:
        return key_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return key_bytes.hex()


def decode_value(value_bytes: bytes) -> Union[str, Dict, List, Any]:
    try:
        text = value_bytes.decode('utf-8')
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    except UnicodeDecodeError:
        return {
            "_binary": True,
            "hex": value_bytes.hex(),
            "base64": base64.b64encode(value_bytes).decode('ascii'),
            "size": len(value_bytes)
        }


def decode_db_value(db_name: str, key_bytes: bytes, value_bytes: bytes) -> Union[str, Dict, List, Any]:
    key_str = decode_key(key_bytes)
    if key_str == '__meta__':
        try:
            return json.loads(value_bytes.decode('utf-8'))
        except Exception:
            return value_bytes.decode('utf-8', errors='replace')

    # 1. UTXO binary decoding
    if db_name == 'utxo' and len(value_bytes) >= 19 and not value_bytes.startswith(b'{'):
        try:
            amt, is_cb, height, spk_len = struct.unpack_from("<Q?qH", value_bytes, 0)
            spk_bytes = value_bytes[19:19 + spk_len]
            spk_hex = spk_bytes.hex()
            addr = script_to_address(spk_bytes) if script_to_address else None
            return {
                "amount": amt,
                "is_coinbase": bool(is_cb),
                "block_height": height,
                "script_pubkey": spk_hex,
                "address": addr,
            }
        except Exception:
            pass

    # 2. Chain binary decoding
    if db_name == 'chain' and key_str.startswith('h:'):
        return decode_chain_block(value_bytes)

    # 3. Mempool binary decoding
    if db_name == 'mempool' and len(value_bytes) >= 20 and not value_bytes.startswith(b'{'):
        if Tx:
            try:
                recv_at, fee, vsize, weight = struct.unpack_from("<dIII", value_bytes, 0)
                raw_tx = value_bytes[20:]
                tx_obj = Tx.from_storage_bytes(raw_tx)
                tx_dict = tx_obj.to_dict(include_txid=True)
                tx_dict["_meta"] = {
                    "received_at": recv_at,
                    "fee": fee,
                    "vbytes": vsize,
                    "weight": weight,
                }
                return tx_dict
            except Exception:
                pass

    # 4. Chat Prekeys binary decoding
    if db_name == 'chat_prekeys' and len(value_bytes) >= 9 and not value_bytes.startswith(b'{'):
        try:
            if decode_prekey_bundle:
                return decode_prekey_bundle(value_bytes)
        except Exception:
            pass

    # Fallback to standard text / json decoding
    return decode_value(value_bytes)


def decode_chain_block(value_bytes: bytes, cached_hash_hex: Optional[str] = None) -> Any:
    if not Block:
        return decode_value(value_bytes)
    try:
        blk = Block.from_storage_bytes(value_bytes)
        if cached_hash_hex:
            blk._cached_hash = bytes.fromhex(cached_hash_hex)
            blk._cached_hash_nonce = blk.nonce
            blk._cached_hash_bits = blk.bits
            blk._cached_hash_mr = blk.merkle_root
            blk._cached_hash_prev = blk.prev_block_hash
        return blk.to_dict()
    except Exception:
        return decode_value(value_bytes)


def iter_chain_entries(cursor, tip_hash: Optional[str] = None):
    """
    Streaming lookahead generator for chain blocks.
    Propagates Block N hash from Block N+1 prev_block_hash (raw bytes 4..36)
    and uses tip_hash for the latest block to eliminate RandomX PoW overhead.
    """
    prev_entry = None
    for k_bytes, v_bytes in cursor:
        k_str = decode_key(k_bytes)
        if k_str == '__meta__':
            try:
                yield k_str, json.loads(v_bytes.decode('utf-8'))
            except Exception:
                yield k_str, v_bytes.decode('utf-8', errors='replace')
            continue

        if k_str.startswith('h:'):
            if prev_entry is not None:
                prev_k, prev_v = prev_entry
                next_prev_hash = v_bytes[4:36].hex() if len(v_bytes) >= 36 else None
                yield prev_k, decode_chain_block(prev_v, next_prev_hash)
            prev_entry = (k_str, v_bytes)
        else:
            yield k_str, decode_value(v_bytes)

    if prev_entry is not None:
        prev_k, prev_v = prev_entry
        yield prev_k, decode_chain_block(prev_v, tip_hash)


def stream_write_json(filepath: str, items, db_name: str = "") -> int:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    count = 0
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('{\n')
        first = True

        for item in tqdm(items, desc=f"Writing {os.path.basename(filepath)}", unit=" entries"):
            k, v = item
            key_str = decode_key(k) if type(k) is bytes else k
            if type(v) is bytes:
                val = decode_db_value(db_name, k if type(k) is bytes else k.encode('utf-8'), v)
            else:
                val = v

            if not first:
                f.write(',\n')
            first = False

            key_json = json.dumps(key_str, ensure_ascii=False)
            val_json = json.dumps(val, ensure_ascii=False, default=str, indent=INDENT)
            f.write(f'  {key_json}: {val_json}')
            count += 1

            if count % 1000 == 0:
                f.flush()

        f.write('\n}\n')

    return count


def open_lmdb_env_dbi(env_path: str, db_name: Optional[str] = None) -> Tuple[Optional[lmdb.Environment], Any]:
    if not os.path.exists(env_path):
        return None, None
    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False, subdir=os.path.isdir(env_path))
    except Exception as e:
        print(f"❌ Failed to open LMDB environment at {env_path}: {e}")
        return None, None

    dbi = None
    if db_name:
        try:
            dbi = env.open_db(db_name.encode('utf-8'), create=False)
        except lmdb.Error:
            try:
                dbi = env.open_db(None, create=False)
            except lmdb.Error:
                env.close()
                return None, None
    else:
        try:
            dbi = env.open_db(None, create=False)
        except lmdb.Error:
            env.close()
            return None, None

    return env, dbi


# ============================================================
# EXPORT MODULES
# ============================================================

def export_keys_data(target_dbs: Optional[set] = None) -> int:
    """Exports key sub-databases (node_secrets, secure_wallet, wallet_peer_keys, stor_peer_keys) from data/keys to data/keys/json_output/."""
    subdbs_to_export = [s for s in KEYS_SUBDBS if not target_dbs or s.lower() in target_dbs]
    if not subdbs_to_export:
        return 0

    print("\n🔑 --- Exporting Keys Data ---")
    os.makedirs(KEYS_OUTPUT_DIR, exist_ok=True)

    env_path = KEYS_ENV_PATH if os.path.exists(KEYS_ENV_PATH) else LEGACY_NODE_PATH
    if not os.path.exists(env_path):
        print(f"⚠️  Keys LMDB environment directory not found at '{env_path}', skipping...")
        return 0

    total_entries = 0
    for subdb in subdbs_to_export:
        env, dbi = open_lmdb_env_dbi(env_path, subdb)
        if not env or dbi is None:
            continue

        output_file = os.path.join(KEYS_OUTPUT_DIR, f"{subdb}.json")
        print(f"📁 Reading '{subdb}' from {env_path}")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=subdb)
                print(f"   ✅ {count} entries written to {output_file}")
                total_entries += count
        env.close()

    if total_entries == 0:
        print(f"ℹ️  No populated key sub-databases found in '{env_path}'.")

    return total_entries


def sort_utxo_items(items):
    """Sort UTXO items by block_height, with __meta__ placed first."""
    meta = None
    others = []
    for k, v in items:
        if k == '__meta__':
            meta = (k, v)
        else:
            others.append((k, v))
    others.sort(key=lambda x: (x[1].get('block_height', 0) if type(x[1]) is dict else 0))
    if meta:
        return [meta] + others
    return others


def export_node_data(target_dbs: Optional[set] = None) -> int:
    """Exports Node sub-databases (chain, state, utxo, mempool, graffiti) to data/node/json_output/."""
    subdbs_to_export = [s for s in NODE_SUBDBS if not target_dbs or s.lower() in target_dbs]
    if not subdbs_to_export:
        return 0

    print("\n📦 --- Exporting Node Data ---")
    os.makedirs(NODE_OUTPUT_DIR, exist_ok=True)
    total_entries = 0

    for db_name in subdbs_to_export:
        dedicated_path = NODE_SUBDB_PATHS.get(db_name)
        env_path = dedicated_path if (dedicated_path and os.path.exists(dedicated_path)) else LEGACY_NODE_PATH
        if not os.path.exists(env_path):
            print(f"⚠️  Environment directory for '{db_name}' not found at '{env_path}', skipping...")
            continue

        env, dbi = open_lmdb_env_dbi(env_path, db_name)
        if not env or dbi is None:
            print(f"⚠️  Sub-database '{db_name}' not found in {env_path}, skipping...")
            continue

        is_binary = db_name in BINARY_STORAGE_REGISTRY
        badge = " [BINARY ENGINE]" if is_binary else " [JSON/KV]"
        print(f"📁 Reading '{db_name}'{badge} from: {env_path}")

        # ---------- GRAFFITI (Granular Binary Engine) ----------
        if db_name == 'graffiti':
            posts = {}
            comments = {}
            payouts = {}
            proofs = {}
            count = 0

            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    for k_bytes, v_bytes in cursor:
                        count += 1
                        try:
                            if k_bytes.startswith(b"p:") and deserialize_post_binary:
                                art_id = k_bytes[2:].decode("utf-8", errors="replace")
                                posts[art_id] = deserialize_post_binary(v_bytes, art_id)
                            elif k_bytes.startswith(b"c:") and deserialize_comment_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    comments.setdefault(parts[0], []).append(deserialize_comment_binary(v_bytes))
                            elif k_bytes.startswith(b"y:") and deserialize_payout_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    payouts.setdefault(parts[0], []).append(deserialize_payout_binary(v_bytes))
                            elif k_bytes.startswith(b"r:") and deserialize_proof_binary:
                                parts = k_bytes[2:].decode("utf-8", errors="replace").split(":")
                                if len(parts) >= 2:
                                    proofs.setdefault(parts[0], []).append(deserialize_proof_binary(v_bytes))
                        except Exception as e:
                            print(f"   ⚠️  Error decoding graffiti key {k_bytes}: {e}")

            graffiti_dir = os.path.join(NODE_OUTPUT_DIR, 'graffiti')
            os.makedirs(graffiti_dir, exist_ok=True)

            for subkey, sdata in [('posts', posts), ('comments', comments), ('payouts', payouts), ('proofs', proofs)]:
                out_file = os.path.join(graffiti_dir, f"{subkey}.json")
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(sdata, f, indent=INDENT, ensure_ascii=False, default=str)
                print(f"   ✅ {subkey}.json written ({len(sdata)} entries)")

            total_entries += count
            env.close()
            continue

        # ---------- CHAIN (Fast Streaming with Hash Chaining) ----------
        if db_name == 'chain':
            output_file = os.path.join(NODE_OUTPUT_DIR, f"{db_name}.json")
            with env.begin(db=dbi, write=False) as txn:
                tip_hash = None
                meta_raw = txn.get(b'__meta__')
                if meta_raw:
                    try:
                        tip_hash = json.loads(meta_raw.decode('utf-8')).get('tip_hash')
                    except Exception:
                        pass
                with txn.cursor() as cursor:
                    count = stream_write_json(output_file, iter_chain_entries(cursor, tip_hash), db_name=db_name)
                    print(f"   ✅ {count} entries streamed to {output_file}")
                    total_entries += count
            env.close()
            continue

        # ---------- STREAMING ALL OTHER NODE DBS ----------
        output_file = os.path.join(NODE_OUTPUT_DIR, f"{db_name}.json")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=db_name)
                print(f"   ✅ {count} entries streamed to {output_file}")
                total_entries += count

        env.close()

    # POST-PROCESS: SORT UTXO (if enabled)
    if SORT_UTXO and (not target_dbs or 'utxo' in target_dbs):
        utxo_file = os.path.join(NODE_OUTPUT_DIR, "utxo.json")
        if os.path.exists(utxo_file):
            print("\n🔄 Post-processing UTXO: sorting by block_height...")
            try:
                with open(utxo_file, 'r', encoding='utf-8') as f:
                    utxo_data = json.load(f)

                if type(utxo_data) is dict:
                    items = list(utxo_data.items())
                    print(f"   📊 Sorting {len(items)} UTXO items...")
                    sorted_items = sort_utxo_items(items)
                    sorted_data = dict(sorted_items)
                    with open(utxo_file, 'w', encoding='utf-8') as f:
                        json.dump(sorted_data, f, indent=INDENT, ensure_ascii=False, default=str)
                    print(f"   ✅ UTXO sorted and saved back to {utxo_file}")
                    del utxo_data, items, sorted_data
                else:
                    print("   ⚠️  UTXO file is not a dict, skipping sort.")
            except Exception as e:
                print(f"   ❌ Error during UTXO sorting: {e}")

    return total_entries


def export_archivist_data(target_dbs: Optional[set] = None) -> int:
    """Exports Archivist sub-databases (index_db, payout_guard) to data/archivist/storage/json_output/."""
    targets = [
        ("index_db", "data/archivist/storage/index_db", "idx", "index.json"),
        ("payout_guard", "data/archivist/storage/payout_guard", "guard", "payout_guard.json"),
    ]

    if target_dbs:
        targets = [
            t for t in targets
            if t[0].lower() in target_dbs or t[2].lower() in target_dbs or os.path.splitext(t[3])[0].lower() in target_dbs
        ]

    if not targets:
        return 0

    print("\n📚 --- Exporting Archivist Storage Data ---")
    os.makedirs(ARCHIVIST_OUTPUT_DIR, exist_ok=True)
    total_entries = 0

    for label, env_path, db_name, out_filename in targets:
        if not os.path.exists(env_path):
            print(f"⚠️  Archivist '{label}' environment directory not found at '{env_path}', skipping...")
            continue

        env, dbi = open_lmdb_env_dbi(env_path, db_name)
        if not env or dbi is None:
            print(f"⚠️  Sub-database '{db_name}' not found in {env_path}, skipping...")
            continue

        output_file = os.path.join(ARCHIVIST_OUTPUT_DIR, out_filename)
        print(f"📁 Reading '{label}' ({db_name}) from {env_path}")
        with env.begin(db=dbi, write=False) as txn:
            with txn.cursor() as cursor:
                count = stream_write_json(output_file, cursor, db_name=db_name)
                print(f"   ✅ {count} entries written to {output_file}")
                total_entries += count

        env.close()

    return total_entries


def export_web_data(target_dbs: Optional[set] = None) -> int:
    """Exports Web LMDB data (web_cache, web_media, web_blocks) to data/web/json_output/."""
    web_subdbs = ['web_cache', 'web_media', 'web_blocks']
    if target_dbs:
        web_subdbs = [s for s in web_subdbs if s.lower() in target_dbs or 'web' in target_dbs]
        if not web_subdbs and 'web' not in target_dbs:
            return 0

    print("\n🌐 --- Exporting Web Data ---")
    os.makedirs(WEB_OUTPUT_DIR, exist_ok=True)

    env_path = "data/web"
    if not os.path.exists(env_path):
        print(f"⚠️  Web LMDB environment directory not found at '{env_path}', skipping...")
        return 0

    total_entries = 0

    try:
        env = lmdb.open(env_path, readonly=True, max_dbs=32, lock=False, subdir=os.path.isdir(env_path))
    except Exception as e:
        print(f"❌ Failed to open Web LMDB at {env_path}: {e}")
        return 0

    found_any = False
    for subdb in web_subdbs:
        try:
            dbi = env.open_db(subdb.encode('utf-8'), create=False)
            output_file = os.path.join(WEB_OUTPUT_DIR, f"{subdb}.json")
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    count = stream_write_json(output_file, cursor, db_name=subdb)
                    print(f"   ✅ {count} entries written to {output_file}")
                    total_entries += count
                    found_any = True
        except lmdb.Error:
            continue

    if not found_any and (not target_dbs or 'web' in target_dbs):
        try:
            dbi = env.open_db(None, create=False)
            output_file = os.path.join(WEB_OUTPUT_DIR, "web.json")
            with env.begin(db=dbi, write=False) as txn:
                with txn.cursor() as cursor:
                    count = stream_write_json(output_file, cursor, db_name="web")
                    print(f"   ✅ {count} entries written to {output_file} (fallback)")
                    total_entries += count
        except lmdb.Error:
            print(f"⚠️  No readable sub-databases found in {env_path}")
            env.close()
            return 0

    env.close()
    return total_entries


# ============================================================
# MAIN ORCHESTRATION
# ============================================================

def export_lmdb(target_dbs: Optional[set] = None, domain: str = 'all'):
    print("=" * 72)
    print("🚀 TSARCHAIN MULTI-DOMAIN LMDB EXPORTER & SMART BINARY DECODER")
    print("=" * 72)
    if target_dbs:
        print(f"🎯 Target Databases Filter : {', '.join(sorted(target_dbs))}")
    if domain != 'all':
        print(f"🌐 Target Domain Filter    : {domain}")
    print("🛡️  ACTIVE BINARY STORAGE ENGINE REGISTER:")
    for db_name, info in BINARY_STORAGE_REGISTRY.items():
        if target_dbs and db_name not in target_dbs and domain not in ('all', 'node'):
            continue
        print(f"   ⚡ [{db_name.upper():<8}] Model   : {info['model']}")
        print(f"                 Benefit : {info['benefit']}")
    print("=" * 72)

    keys_count = 0
    node_count = 0
    archivist_count = 0
    web_count = 0

    if domain in ('all', 'keys'):
        keys_count = export_keys_data(target_dbs=target_dbs)
    if domain in ('all', 'node'):
        node_count = export_node_data(target_dbs=target_dbs)
    if domain in ('all', 'archivist'):
        archivist_count = export_archivist_data(target_dbs=target_dbs)
    if domain in ('all', 'web'):
        web_count = export_web_data(target_dbs=target_dbs)

    total = keys_count + node_count + archivist_count + web_count
    print("\n" + "=" * 72)
    print("🔒 ALL LMDB EXPORTS & BINARY DECODING COMPLETED SUCCESSFULLY.")
    print("📊 SUMMARY OF EXPORTED ENTRIES:")
    if domain in ('all', 'keys'):
        print(f"   - Keys (secrets/wallets) : {keys_count}")
    if domain in ('all', 'node'):
        print(f"   - Node (chain,utxo,etc)  : {node_count}")
    if domain in ('all', 'archivist'):
        print(f"   - Archivist (storage)    : {archivist_count}")
    if domain in ('all', 'web'):
        print(f"   - Web (explorer cache)   : {web_count}")
    print(f"   - Total Decoded Entries  : {total}")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="Export LMDB sub-databases to JSON with full streaming and binary decoding.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh Penggunaan:
  python tools/lmdb_to_json.py                      # Ekspor semua database
  python tools/lmdb_to_json.py state                # Hanya ekspor database 'state'
  python tools/lmdb_to_json.py state utxo           # Ekspor 'state' dan 'utxo'
  python tools/lmdb_to_json.py --db state           # Menggunakan flag --db
  python tools/lmdb_to_json.py --domain node        # Hanya domain 'node'
  python tools/lmdb_to_json.py --list               # Lihat daftar database yang tersedia
"""
    )
    parser.add_argument(
        'databases',
        nargs='*',
        help="Nama database spesifik yang ingin diekstrak (contoh: state utxo mempool)"
    )
    parser.add_argument(
        '--db', '-d',
        nargs='+',
        dest='db_flag',
        help="Nama database spesifik (alternatif flag: --db state utxo)"
    )
    parser.add_argument(
        '--domain',
        choices=['all', 'node', 'keys', 'archivist', 'web'],
        default='all',
        help="Filter berdasarkan domain tertentu (default: all)"
    )
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help="Tampilkan daftar semua nama database dan domain yang tersedia"
    )

    args = parser.parse_args()

    if args.list:
        print("=" * 60)
        print("📋 DAFTAR SUB-DATABASE & DOMAIN YANG TERSEDIA")
        print("=" * 60)
        print("  Domain 'node':      ", ", ".join(NODE_SUBDBS))
        print("  Domain 'keys':      ", ", ".join(KEYS_SUBDBS))
        print("  Domain 'archivist': ", "index_db, payout_guard")
        print("  Domain 'web':       ", "web_cache, web_media, web_blocks")
        print("=" * 60)
        return

    raw_dbs = list(args.databases or []) + list(args.db_flag or [])
    selected_dbs = set()
    for item in raw_dbs:
        for part in item.split(','):
            part = part.strip().lower()
            if part:
                selected_dbs.add(part)

    known_dbs = (
        {s.lower() for s in KEYS_SUBDBS} |
        {s.lower() for s in NODE_SUBDBS} |
        {'index_db', 'idx', 'index', 'payout_guard', 'guard'} |
        {'web_cache', 'web_media', 'web_blocks', 'web'}
    )

    if selected_dbs:
        unknown = selected_dbs - known_dbs
        if unknown:
            print(f"⚠️  Peringatan: Database berikut mungkin tidak dikenal: {', '.join(unknown)}")
            print(f"ℹ️  Jalankan 'python tools/lmdb_to_json.py --list' untuk melihat daftar nama yang valid.\n")

    target_dbs = selected_dbs if selected_dbs else None
    export_lmdb(target_dbs=target_dbs, domain=args.domain)


if __name__ == '__main__':
    main()