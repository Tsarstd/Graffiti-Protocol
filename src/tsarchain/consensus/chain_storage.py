# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import time
import json
import shutil
import hashlib
import tarfile
import threading
import datetime as dt

from collections import Counter
from typing import Optional, TYPE_CHECKING

from ..core.block import Block
from .genesis import GENESIS_HASH
from ..storage.utxo import UTXODB
from ..utils import config as CFG
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from ..utils.bootstrap import annotate_local_snapshot_meta
from ..storage.kv import batch, iter_prefix, clear_db, delete, _ensure_env
from ..utils.helpers import bits_to_target, target_to_difficulty, estimate_block_size_bytes

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.chain_storage')


if TYPE_CHECKING:
    from .blockchain import Blockchain

class ChainStorage:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain
        self._backup_lock = threading.Lock()
        self._reset_cumulative_metrics()


    def save_chain(self, *, force_full: bool = False):
        backup_tip = None
        backup_ts = None
        with self.blockchain.lock:
            tip_height = len(self.blockchain.chain) - 1
            if tip_height < 0:
                self.blockchain._chain_dirty_from = None
                self.blockchain._persisted_height = -1
                return

            tip_hash = self.blockchain.chain[-1].hash().hex()
            chain_meta = self._build_chain_meta(tip_height, tip_hash)
            full_flush = force_full or self.blockchain._persisted_height < 0
            if force_full:
                self.blockchain._chain_dirty_from = 0
                self.blockchain._persisted_height = -1

            start_height = self._determine_save_start_height(tip_height, force_full, full_flush)
            if not self._should_flush_chain(tip_height, start_height, full_flush):
                return

            self._save_chain_kv(tip_height, start_height, full_flush, chain_meta)

            self.blockchain._chain_dirty_from = None
            backup_tip = tip_height
            backup_ts = int(self.blockchain.chain[-1].timestamp or 0)

        if backup_tip is not None:
            self._maybe_backup_snapshot(backup_tip, tip_timestamp=backup_ts)


    def load_chain(self):
        meta, chain = self._fetch_kv_chain_data()
        if not chain or not self._validate_loaded_chain(chain):
            return

        self.blockchain.chain = chain
        self.blockchain._chain_meta = meta or {}
        self.blockchain.total_blocks = len(self.blockchain.chain)
        self.blockchain.total_supply = self.blockchain.calculate_total_supply()
        self.blockchain.supply_in_tsar = self.blockchain.total_supply / CFG.TSAR if self.blockchain.total_supply else 0
        self.blockchain._persisted_height = len(self.blockchain.chain) - 1
        self.blockchain._chain_dirty_from = None
        
        interval = int(CFG.BLOCK_BACKUP_SNAPSHOT)
        if interval > 0 and self.blockchain._persisted_height >= 0:
            self.blockchain._snapshot_last_backup_height = (self.blockchain._persisted_height // interval) * interval
        else:
            self.blockchain._snapshot_last_backup_height = self.blockchain._persisted_height
            
        self.blockchain.ensure_utxodb()
        self.blockchain._utxo_last_flush_height = self.blockchain.height
        self.blockchain._utxo_dirty = False
        tip_ts = None
        if self.blockchain.chain:
            tip_ts = int(self.blockchain.chain[-1].timestamp or 0)
        annotate_local_snapshot_meta(height=self.blockchain.height, tip_timestamp=tip_ts)


    def save_state(self):
        blocks_count = len(self.blockchain.chain)
        self.blockchain.total_blocks = blocks_count
        self.blockchain.total_supply = self.blockchain.calculate_total_supply()
        self.blockchain.supply_in_tsar = self.blockchain.total_supply / CFG.TSAR if self.blockchain.total_supply else 0
        data = self._compute_state_snapshot()
        data["total_supply"] = int(self.blockchain.total_supply)
        data["total_blocks"] = int(self.blockchain.total_blocks)

        # Normalize schema version from config
        data["schema_version"] = int(CFG.DATA_SCHEMA_VERSION)

        ordered = {
            "schema_version": data.get("schema_version"),
            "last_updated": data.get("last_updated"),
            "total_blocks": data.get("total_blocks", self.blockchain.total_blocks),
            "total_supply": data.get("total_supply", self.blockchain.total_supply),
            "identity": data.get("identity", {}),
            "chain": data.get("chain", {}),
            "supply": data.get("supply", {}),
            "transactions": data.get("transactions", {}),
            "utxo": data.get("utxo", {}),
            "graffiti": data.get("graffiti", {}),
            "miners_snapshot": data.get("miners_snapshot", {}),
        }

        # Save to LMDB
        with batch('state') as b:
            b.put(b'k:total_supply', str(int(self.blockchain.total_supply)).encode('utf-8'))
            b.put(b'k:total_blocks', str(int(self.blockchain.total_blocks)).encode('utf-8'))
            b.put(b'k:snapshot', json.dumps(ordered, separators=CFG.CANONICAL_SEP).encode('utf-8'))


    def load_state(self):
        data = self._read_snapshot_state()
        self.blockchain.total_supply = int(data.get("total_supply", 0) or 0)
        self.blockchain.total_blocks = int(data.get("total_blocks", 0) or 0)
        self.blockchain.supply_in_tsar = self.blockchain.total_supply / CFG.TSAR if self.blockchain.total_supply else 0
        self._init_cumulative_metrics_from_snapshot(data)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _build_chain_meta(self, tip_height: int, tip_hash: str | None = None) -> dict:
        return {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "generated_at": int(time.time()),
            "tip_height": int(tip_height),
            "tip_hash": tip_hash,
            "network_id": CFG.DEFAULT_NET_ID,
            "pow_algo": CFG.POW_ALGO,
            "max_bits": int(CFG.MAX_BITS),
            "target_block_time_sec": int(CFG.TARGET_BLOCK_TIME),
            "blocks": int(tip_height + 1 if tip_height >= 0 else 0),
        }


    def _determine_save_start_height(self, tip_height: int, force_full: bool, full_flush: bool) -> Optional[int]:
        if full_flush:
            return 0
        if self.blockchain._chain_dirty_from is not None:
            return max(0, self.blockchain._chain_dirty_from)
        if tip_height > self.blockchain._persisted_height:
            return self.blockchain._persisted_height + 1
        if force_full or self.blockchain._persisted_height < 0:
            return 0
        return None


    def _should_flush_chain(self, tip_height: int, start_height: Optional[int], full_flush: bool) -> bool:
        flush_interval = max(1, int(CFG.CHAIN_FLUSH_INTERVAL))
        should_flush = (
            full_flush
            or tip_height < self.blockchain._persisted_height
            or flush_interval <= 1
        )
        if not should_flush and start_height is not None:
            pending = tip_height - self.blockchain._persisted_height if self.blockchain._persisted_height >= 0 else tip_height + 1
            if pending < flush_interval:
                if self.blockchain._chain_dirty_from is None:
                    self.blockchain._chain_dirty_from = start_height
                else:
                    self.blockchain._chain_dirty_from = min(self.blockchain._chain_dirty_from, start_height)
                return False
        return True


    def _save_chain_kv(self, tip_height: int, start_height: Optional[int], full_flush: bool, chain_meta: dict):
        if full_flush:
            clear_db('chain')
            self.blockchain._persisted_height = -1
                
        if tip_height < self.blockchain._persisted_height:
            self._prune_chain_store(tip_height + 1)
            self.blockchain._persisted_height = tip_height
            
        if start_height is not None and start_height <= tip_height:
            with batch('chain') as b:
                b.put(b'__meta__', json.dumps(chain_meta, separators=CFG.CANONICAL_SEP).encode('utf-8'))
                for height in range(start_height, tip_height + 1):
                    key = f"h:{height:012d}".encode('utf-8')
                    blk = self.blockchain.chain[height]
                    diff = blk.difficulty
                    if diff is None or diff == 0:
                        b_bits = blk.bits
                        blk.difficulty = int(target_to_difficulty(bits_to_target(b_bits)))

                    payload = blk.to_storage_bytes()
                    b.put(key, payload)
            self.blockchain._persisted_height = tip_height


    def _maybe_backup_snapshot(self, tip_height: int, *, tip_timestamp: int | None = None) -> None:
        if tip_height < 0:
            return
        if not self._backup_snapshot_enabled():
            return

        interval = int(CFG.BLOCK_BACKUP_SNAPSHOT or 0)
        if interval <= 0:
            return

        last = self.blockchain._snapshot_last_backup_height
        if last >= 0 and (tip_height - last) < interval:
            return

        target_dir = CFG.SNAPSHOT_BACKUP_DIR
        if not target_dir:
            return

        with self._backup_lock:
            if self.blockchain._snapshot_backup_active:
                return

            self.blockchain._snapshot_backup_active = True

        threading.Thread(
            target=self._run_backup,
            args=(target_dir, tip_height, tip_timestamp),
            name="tsarchain.snapshot_backup",
            daemon=True,
        ).start()


    def _mark_chain_dirty(self, height: int = 0) -> None:
        if height < 0:
            height = 0
        if self.blockchain._chain_dirty_from is None:
            self.blockchain._chain_dirty_from = height
        else:
            self.blockchain._chain_dirty_from = min(self.blockchain._chain_dirty_from, height)


    def _prune_chain_store(self, start_height: int) -> None:
        if start_height < 0:
            start_height = 0

        if self._metrics_synced_height >= start_height:
            self._reset_cumulative_metrics()
            
        keys_to_remove: list[bytes] = []
        for key, _ in iter_prefix('chain', b'h:'):
            h = int(key[2:].decode('utf-8'))
            if h >= start_height:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            delete('chain', key)


    def _reset_chain_store(self) -> None:
        clear_db('chain')
        meta_path = CFG.SNAPSHOT_META_PATH
        if meta_path and os.path.exists(meta_path):
            os.remove(meta_path)
        self.blockchain._persisted_height = -1
        self.blockchain._chain_dirty_from = None
        self.blockchain._snapshot_last_backup_height = -1
        self._reset_cumulative_metrics()


    def _backup_snapshot_enabled(self) -> bool:
        return bool(CFG.BACKUP_SNAPSHOT)


    def _write_snapshot_manifest(self, target_dir: str, meta: dict, height: int) -> None:
        archive_path = os.path.join(target_dir, "tsarchain.tar.gz")
        sha = meta.get("sha256")
        size = meta.get("size")
        if (not sha or not size) and os.path.exists(archive_path):
            size = size or os.path.getsize(archive_path)
            sha = sha or self._hash_file(archive_path)

        manifest = {
            "version": 1,
            "snapshot_url": meta.get("source") or CFG.SNAPSHOT_FILE_URL,
            "size": int(size or 0),
            "sha256": sha or "",
            "height": int(meta.get("height", height)),
            "generated_at": int(meta.get("generated_at") or int(time.time())),
        }

        manifest_path = os.path.join(target_dir, "snapshot.manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)


    def _run_backup(self, target_dir: str, height: int, ts_hint: int | None):
        target_dir = os.path.abspath(target_dir)
        os.makedirs(target_dir, exist_ok=True)
        staging_dir = f"{target_dir}.staging_{int(time.time())}"
        try:
            # 1) Copy all 5 active LMDB environments -> isolated staging directory
            self._copy_snapshot_env(staging_dir)

            # 2) Package sub-databases into tsarchain.tar.gz in staging
            staging_archive = os.path.join(staging_dir, "tsarchain.tar.gz")
            with tarfile.open(staging_archive, "w:gz") as tar:
                for db_name in ("chain", "utxo", "state", "graffiti", "mempool"):
                    db_path = os.path.join(staging_dir, db_name)
                    if os.path.exists(db_path):
                        tar.add(db_path, arcname=db_name)

            # 3) Clean up uncompressed raw staging folders to save disk space
            for db_name in ("chain", "utxo", "state", "graffiti", "mempool"):
                db_path = os.path.join(staging_dir, db_name)
                if os.path.exists(db_path):
                    shutil.rmtree(db_path, ignore_errors=True)

            archive_stat = os.stat(staging_archive)
            archive_size = int(archive_stat.st_size)
            archive_sha = self._hash_file(staging_archive)

            # 4) Tip timestamp
            tip_ts = ts_hint
            if tip_ts is None and self.blockchain.chain:
                tip_ts = int(self.blockchain.chain[-1].timestamp or 0)

            # 5) Write metadata and manifest into staging
            meta = {
                "height": int(height),
                "generated_at": int(tip_ts or time.time()),
                "size": archive_size,
                "sha256": archive_sha or "",
                "applied_at": int(time.time()),
                "source": CFG.SNAPSHOT_FILE_URL or "",
            }

            meta_name = os.path.basename(CFG.SNAPSHOT_META_PATH or "snapshot.meta.json")
            staging_meta_path = os.path.join(staging_dir, meta_name)
            with open(staging_meta_path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2, sort_keys=True)

            self._write_snapshot_manifest(staging_dir, meta, height)

            # 6) Atomically replace output files in target_dir (never delete or rename target_dir itself)
            target_archive = os.path.join(target_dir, "tsarchain.tar.gz")
            target_meta = os.path.join(target_dir, meta_name)
            target_manifest = os.path.join(target_dir, "snapshot.manifest.json")

            os.replace(staging_archive, target_archive)
            os.replace(staging_meta_path, target_meta)
            staging_manifest = os.path.join(staging_dir, "snapshot.manifest.json")
            if os.path.exists(staging_manifest):
                os.replace(staging_manifest, target_manifest)

            self.blockchain._snapshot_last_backup_height = height
            log.info("[backup_snapshot] Snapshot archive created at height %s in %s (%.2f MB)", height, target_archive, archive_size / (1024 * 1024))
        except Exception:
            log.exception("[backup_snapshot] Unexpected error during snapshot backup:")
        finally:
            if os.path.exists(staging_dir):
                shutil.rmtree(staging_dir, ignore_errors=True)
            with self._backup_lock:
                self.blockchain._snapshot_backup_active = False


    def _copy_snapshot_env(self, target_dir: str) -> None:
        target_dir = os.path.abspath(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        for db_name in ("chain", "utxo", "state", "graffiti", "mempool"):
            sub_dir = os.path.join(target_dir, db_name)
            try:
                env = _ensure_env(db_name)
                if env is not None:
                    os.makedirs(sub_dir, exist_ok=True)
                    env.copy(sub_dir, compact=True)
            except Exception as exc:
                log.warning("[_copy_snapshot_env] Failed to copy sub-DB %s: %s", db_name, exc)

    
    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()


    def _fetch_kv_chain_data(self) -> tuple[dict, list]:
        meta = {}
        items = list(iter_prefix('chain', b''))
        blocks: list[tuple[bytes, bytes]] = []
        for k, v in items:
            if k == b'__meta__':
                meta = json.loads(v.decode('utf-8')) or {}

            elif k.startswith(b'h:'):
                blocks.append((k, v))
        blocks.sort(key=lambda kv: kv[0])
        chain_objs = []
        for _, v in blocks:
            try:
                chain_objs.append(Block.from_storage_bytes(v))
            except Exception:
                log.exception("[_fetch_kv_chain_data] Failed to parse block binary from KV")

        if chain_objs:
            for i in range(len(chain_objs) - 1):
                next_prev = chain_objs[i + 1].prev_block_hash
                if type(next_prev) in (bytes, bytearray) and len(next_prev) == 32:
                    chain_objs[i]._cached_hash = bytes(next_prev)
                    chain_objs[i]._cached_hash_nonce = chain_objs[i].nonce
                    chain_objs[i]._cached_hash_bits = chain_objs[i].bits
                    chain_objs[i]._cached_hash_mr = chain_objs[i].merkle_root
                    chain_objs[i]._cached_hash_prev = chain_objs[i].prev_block_hash

            tip_hash_str = meta.get("tip_hash")
            if type(tip_hash_str) is str and len(tip_hash_str) >= 64:
                tip_h = bytes.fromhex(tip_hash_str)
                last_blk = chain_objs[-1]
                last_blk._cached_hash = tip_h
                last_blk._cached_hash_nonce = last_blk.nonce
                last_blk._cached_hash_bits = last_blk.bits
                last_blk._cached_hash_mr = last_blk.merkle_root
                last_blk._cached_hash_prev = last_blk.prev_block_hash

        return meta, chain_objs


    def _validate_loaded_chain(self, chain: list) -> bool:
        if chain[0].height != 0 or chain[0].prev_block_hash != CFG.ZERO_HASH:
            prev_hex = chain[0].prev_block_hash.hex()
            log.error(
                "[load_chain] Invalid on-disk genesis header fields (height=%s prev=%s); resetting chain store",
                chain[0].height,
                prev_hex,
            )
            self._reset_chain_store()
            return False
            
        if GENESIS_HASH is not None and chain[0].hash() != GENESIS_HASH:
            log.error(
                "[load_chain] Invalid genesis for this network. Expected %s, got %s; resetting chain store",
                GENESIS_HASH.hex(),
                chain[0].hash().hex(),
            )
            self._reset_chain_store()
            return False
            
        return True


    def _read_snapshot_state(self) -> dict:
        items = {
            k.decode("utf-8"): v.decode("utf-8")
            for k, v in iter_prefix("state", b"k:")
        }

        data: dict = {}
        snap_raw = items.get("k:snapshot")
        if snap_raw:
            data = json.loads(snap_raw)

        if (not data) and items:
            data["total_supply"] = int(items.get("k:total_supply", "0"))
            data["total_blocks"] = int(items.get("k:total_blocks", "0"))

        if type(data) is not dict:
            data = {}
        return data


    def _reset_cumulative_metrics(self) -> None:
        self._metrics_synced_height: int = -1
        self._cumulative_block_size_bytes: int = 0
        self._cumulative_total_txs: int = 0
        self._cumulative_non_coinbase_txs: int = 0
        self._cumulative_fees_paid: int = 0
        self._cumulative_miner_counter: Counter[str] = Counter()


    def _init_cumulative_metrics_from_snapshot(self, data: dict) -> None:
        if type(data) is not dict:
            return
        chain_info = data.get("chain")
        if type(chain_info) is not dict:
            chain_info = {}
        tx_info = data.get("transactions")
        if type(tx_info) is not dict:
            tx_info = {}
        miners_info = data.get("miners_snapshot")
        if type(miners_info) is not dict:
            miners_info = {}

        snap_height = chain_info.get("tip_height")
        if snap_height is not None and type(snap_height) is int and snap_height >= 0:
            self._metrics_synced_height = snap_height
            self._cumulative_block_size_bytes = int(chain_info.get("total_block_size_bytes", 0) or 0)
            self._cumulative_total_txs = int(tx_info.get("total_txs", 0) or 0)
            self._cumulative_non_coinbase_txs = int(tx_info.get("total_non_coinbase_txs", 0) or 0)
            self._cumulative_fees_paid = int(tx_info.get("total_fees_paid", 0) or 0)
            self._cumulative_miner_counter = Counter()
            for row in miners_info.get("top_miners") or []:
                if type(row) in (list, tuple) and len(row) >= 2:
                    self._cumulative_miner_counter[str(row[0])] = int(row[1])


    def _sync_cumulative_metrics(self, chain: list) -> None:
        chain_len = len(chain)
        tip_height = chain_len - 1
        if tip_height < 0:
            self._reset_cumulative_metrics()
            return

        if tip_height < self._metrics_synced_height:
            self._reset_cumulative_metrics()

        if self._metrics_synced_height >= tip_height:
            return

        start_h = self._metrics_synced_height + 1
        for h in range(start_h, chain_len):
            blk = chain[h]
            self._cumulative_block_size_bytes += estimate_block_size_bytes(blk)
            txs = blk.transactions or []
            tx_count = len(txs)
            self._cumulative_total_txs += tx_count
            self._cumulative_non_coinbase_txs += max(0, tx_count - 1)
            if txs:
                coinbase = txs[0]
                outputs = coinbase.outputs or []
                cb_amt = sum(int(out.amount or 0) for out in outputs)
                base = self.blockchain.scheduled_reward(int(blk.height or 0))
                fee = max(0, cb_amt - base)
                self._cumulative_fees_paid += fee

                miner_addr = coinbase.to_address
                if not miner_addr and outputs:
                    miner_addr = outputs[0].address
                if miner_addr:
                    self._cumulative_miner_counter[str(miner_addr)] += 1

        self._metrics_synced_height = tip_height


    def _compute_state_snapshot(self) -> dict:
        tip_height = self.blockchain.height
        utxo = self.blockchain.ensure_utxodb() or UTXODB()
        utxo_version = utxo.version
        cache = self.blockchain._state_snapshot_cache
        token = (tip_height, utxo_version)
        if cache and cache.get("token") == token and cache.get("data"):
            return dict(cache["data"])

        chain = self.blockchain.chain or []
        self._sync_cumulative_metrics(chain)
        chain_stats = self._compute_chain_stats(chain)
        tx_stats = self._compute_transaction_and_miner_stats(chain)
        mempool_stats = self._compute_mempool_stats()
        supply_stats = self._compute_utxo_supply_stats(utxo, tip_height, chain)
        graffiti_stats = self._compute_graffiti_stats()

        emitted_subsidy = self.blockchain.calculate_total_supply()
        cur_epoch = 0 if tip_height < 0 else int(tip_height // int(CFG.BLOCKS_PER_HALVING))
        next_halving_height = int((cur_epoch + 1) * int(CFG.BLOCKS_PER_HALVING))
        blocks_to_halving = None if tip_height < 0 else max(0, next_halving_height - (tip_height + 1))
        current_block_subsidy = self.blockchain.scheduled_reward(max(0, tip_height))

        genesis_block = chain[0] if chain else None
        tip_block = chain[-1] if chain else None
        tip_hash = tip_block.hash().hex() if tip_block else None
        tip_timestamp = int(tip_block.timestamp or 0) if tip_block else None
        genesis_dict = genesis_block.to_dict() if genesis_block else {}
        tip_dict = tip_block.to_dict() if tip_block else {}

        snapshot = {
            "schema_version": int(CFG.DATA_SCHEMA_VERSION),
            "last_updated": dt.datetime.now().astimezone().isoformat(),
            "identity": {
                "network_id": CFG.DEFAULT_NET_ID,
                "address_prefix": CFG.ADDRESS_PREFIX,
                "network_magic_hex": CFG.NETWORK_MAGIC.hex(),
                "pow_algo": CFG.POW_ALGO,
            },
            "chain": {
                "total_blocks": chain_stats["total_blocks"],
                "tip_height": tip_height,
                "genesis_hash": genesis_dict.get("hash"),
                "genesis_message": (((genesis_dict.get("transactions") or [{}])[0]) or {}).get("block_id"),
                "tip_hash": tip_hash or tip_dict.get("hash"),
                "tip_timestamp": tip_timestamp or tip_dict.get("timestamp"),
                "tip_bits": chain_stats["tip_bits"],
                "tip_target_hex": (None if chain_stats["tip_target"] is None else hex(chain_stats["tip_target"])),
                "tip_difficulty": chain_stats["tip_difficulty"],
                "tip_chainwork": chain_stats["tip_chainwork"],
                "median_time_past": chain_stats["median_time_past_val"],
                "max_bits": int(CFG.MAX_BITS),
                "target_block_time_sec": int(CFG.TARGET_BLOCK_TIME),
                "total_block_size_bytes": int(chain_stats["total_block_size_bytes"]),
                "avg_block_time_sec_window": None if chain_stats["avg_block_time_sec"] is None else round(float(chain_stats["avg_block_time_sec"]), 3),
                "est_network_hashrate_hps_window": chain_stats["est_hashrate_hps"],
            },
            "supply": {
                "max_supply": int(CFG.MAX_SUPPLY),
                "emitted_subsidy": int(emitted_subsidy),
                "circulating_estimate": int(supply_stats["circulating_estimate"]),
                "immature_coinbase": int(supply_stats["immature_coinbase"]),
                "utxo_total_value": int(supply_stats["utxo_total_value"]),
                "coinbase_maturity": int(CFG.COINBASE_MATURITY),
                "current_block_subsidy": int(current_block_subsidy),
                "current_epoch": int(cur_epoch),
                "next_halving_height": int(next_halving_height),
                "blocks_to_halving": None if blocks_to_halving is None else int(blocks_to_halving),
            },
            "transactions": {
                "total_txs": int(tx_stats["total_txs"]),
                "total_non_coinbase_txs": int(tx_stats["total_non_coinbase_txs"]),
                "total_fees_paid": int(tx_stats["total_fees_paid"]),
                "mempool_txs": int(mempool_stats["mempool_count"]),
                "mempool_vbytes_estimate": mempool_stats["mempool_vbytes_est"],
                "mempool_bytes_estimate": mempool_stats["mempool_bytes_est"],
                "mempool_max_bytes": int(CFG.MEMPOOL_MAX_SIZE),
            },
            "utxo": {
                "utxo_set_size": int(supply_stats["utxo_set_size"]),
            },
            "graffiti": graffiti_stats,
            "miners_snapshot": {
                "top_miners": [(miner, count) for miner, count in tx_stats["miner_counter"].most_common() if miner]
            },
        }

        self.blockchain._state_snapshot_cache = {"token": token, "data": dict(snapshot)}
        return snapshot


    def _compute_chain_stats(self, chain: list) -> dict:
        total_blocks = len(chain)
        tip_block = chain[-1] if chain else None
        total_block_size_bytes = int(self._cumulative_block_size_bytes)

        cw = tip_block.chainwork if tip_block else None
        if cw is None:
            cw = self.blockchain._compute_chainwork_for_chain(chain)
        tip_chainwork = int(cw)
        median_time_past_val = int(self.blockchain.median_time_past())

        tip_bits = int(tip_block.bits or 0) if tip_block else None
        tip_target = None
        tip_difficulty = None
        if tip_bits is not None:
            tgt = bits_to_target(tip_bits)
            tip_target = int(tgt)
            tip_difficulty = int(target_to_difficulty(tgt))

        AVG_WINDOW = 20
        avg_block_time_sec = None
        est_hashrate_hps = None
        if total_blocks >= 2:
            window = min(AVG_WINDOW, total_blocks - 1)
            timestamps = [int(chain[i].timestamp or 0) for i in range(total_blocks - window - 1, total_blocks)]
            intervals = []
            for i in range(1, len(timestamps)):
                delta = timestamps[i] - timestamps[i - 1]
                if type(delta) in (int, float) and delta > 0:
                    intervals.append(delta)
            if intervals:
                avg_block_time_sec = sum(intervals) / len(intervals)
                if tip_difficulty:
                    est_hashrate_hps = int(tip_difficulty / max(1, avg_block_time_sec))

        return {
            "total_blocks": total_blocks,
            "total_block_size_bytes": total_block_size_bytes,
            "tip_chainwork": tip_chainwork,
            "median_time_past_val": median_time_past_val,
            "tip_bits": tip_bits,
            "tip_target": tip_target,
            "tip_difficulty": tip_difficulty,
            "avg_block_time_sec": avg_block_time_sec,
            "est_hashrate_hps": est_hashrate_hps,
        }


    def _compute_transaction_and_miner_stats(self, chain: list) -> dict:
        return {
            "total_txs": int(self._cumulative_total_txs),
            "total_non_coinbase_txs": int(self._cumulative_non_coinbase_txs),
            "total_fees_paid": int(self._cumulative_fees_paid),
            "miner_counter": Counter(self._cumulative_miner_counter),
        }


    def _compute_mempool_stats(self) -> dict:
        mempool_count = 0
        mempool_vbytes_est = None
        mempool_bytes_est = None
        pool = self.blockchain.get_mempool()

        if pool:
            stats = pool.stats()
            mempool_count = int(stats.get("count", 0))
            mempool_vbytes_est = int(stats.get("virtual_size", 0))
            mempool_bytes_est = int(stats.get("virtual_size", 0))
        return {
            "mempool_count": mempool_count,
            "mempool_vbytes_est": mempool_vbytes_est,
            "mempool_bytes_est": mempool_bytes_est,
        }


    def _compute_utxo_supply_stats(self, utxo, tip_height: int, chain: list | None = None) -> dict:
        maturity = int(CFG.COINBASE_MATURITY)
        immature_coinbase = 0
        if chain is None:
            chain = self.blockchain.chain or []
        if chain and tip_height >= 0:
            start_immature_h = max(0, tip_height - maturity + 2)
            for h in range(start_immature_h, tip_height + 1):
                if h < len(chain):
                    blk = chain[h]
                    txs = blk.transactions or []
                    if txs:
                        cb = txs[0]
                        outs = cb.outputs or []
                        immature_coinbase += sum(int(out.amount or 0) for out in outs)

        with utxo._lock:  # type: ignore[attr-defined]
            utxos_dict = utxo.utxos
            utxo_set_size = len(utxos_dict)
            utxo_total_value = sum(int(e["tx_out"].amount or 0) for e in utxos_dict.values())

        circulating_estimate = max(0, utxo_total_value - immature_coinbase)
        return {
            "utxo_set_size": int(utxo_set_size),
            "circulating_estimate": int(circulating_estimate),
            "immature_coinbase": int(immature_coinbase),
            "utxo_total_value": int(utxo_total_value),
        }


    def _compute_graffiti_stats(self) -> dict:
        graffiti_posts = 0
        total_comments = 0
        total_graffiti_storage = 0
        graffiti_on_mempool = 0
        reg = GraffitiRegistry()
        data_g = reg.data or {}
        posts_data = data_g.get("posts") or {}
        graffiti_posts = len(posts_data)
        
        total_pool_balances = 0
        for post in posts_data.values():
            if type(post) is not dict:
                continue
            total_graffiti_storage += int(post.get("size") or 0)
            stats = post.get("stats") or {}
            total_pool_balances += int(stats.get("pool_balance", 0) or 0)
            
        total_comments = sum(len(v or []) for v in (data_g.get("comments") or {}).values())
        mem = self.blockchain.get_mempool()
        for tx in mem.get_all_txs():
            for tx_out in (tx.outputs or []):
                spk = tx_out.script_pubkey
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "POST":
                        graffiti_on_mempool += 1
                        
        total_payouts = sum(len(v or []) for v in (data_g.get("payouts") or {}).values())

        return {
            "posts": int(graffiti_posts),
            "comments": int(total_comments),
            "graffiti_on_mempool": int(graffiti_on_mempool),
            "payouts": int(total_payouts),
            "pool_balances": int(total_pool_balances),
            "total_graffiti_storage": int(total_graffiti_storage),
        }