# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import queue
import threading
import multiprocessing as mp

from typing import List, Optional
from collections import OrderedDict
from multiprocessing.synchronize import Event as MpEvent

# ---------------- MIXIN ----------------
from .mining import MiningManager
from .rewards import RewardCalculator
from .validation import BlockValidator
from .chain_ops import ChainOperations
from .chain_storage import ChainStorage
from .utxo_validate import UTXOValidator
from .difficulty import DifficultyManager
from .genesis import GenesisManager

from ..core.block import Block
from ..utils import config as CFG
from ..storage.utxo import UTXODB
from ..mempool.pool import TxPool

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.consensus.blockchain")

__all__ = ["Blockchain"]

class Blockchain():
    def __init__(self, miner_address: str | None = None, use_cores: int | None = None,):
        self.chain: List[Block] = []
        self.total_supply = 0
        self.total_blocks = 0
        self._hash_cache: OrderedDict[int, str] = OrderedDict()
        self.supply_in_tsar = 0
        self._chain_meta: dict | None = None
        
        self.genesis_manager = GenesisManager(self)
        self.reward_calculator = RewardCalculator(self)
        self.difficulty_manager = DifficultyManager(self)
        self.mining_manager = MiningManager(self)
        self.utxo_validator = UTXOValidator(self)
        self.chain_ops = ChainOperations(self)
        self.chain_storage = ChainStorage(self)
        self.validator = BlockValidator(self)
        
        self.miner_address = miner_address
        self.use_cores = use_cores
        self.lock = threading.RLock()
        
        self.pending_blocks: List[Block] = []
            
        self._persisted_height: int = -1
        self._chain_dirty_from: Optional[int] = None
        self._utxodb: Optional[UTXODB] = None
        self._utxo_dirty: bool = False
        self._utxo_last_flush_height: int = -1
        self._utxo_synced: bool = False
        
        self._snapshot_last_backup_height: int = -1
        self._snapshot_backup_active: bool = False
        self._state_snapshot_cache: dict | None = None
        self._last_block_validation_error: str | None = None
        self._mempool: TxPool = TxPool()
        self._mining_cooloff_until: float = 0.0
        
        self._persist_queue: queue.Queue[bool | None] | None = None
        self._persist_thread: threading.Thread | None = None
        self._persist_stop = threading.Event()
        self._persist_opts_lock = threading.Lock()
        self._persist_opts = {
            "force_full": False,
            "flush_force": False,
            "save_state": True,
        }
        self._persist_pending = False
        self._cold_reload_attempted: bool = False
        self._on_tip_changed_callbacks = []
        

        self._start_persist_worker()
        self.load_chain()
        self.load_state()
        if self.chain:
            self.genesis_manager._enforce_genesis_lock()
            self._rebuild_hash_cache()
            return
        log.info("[__init__] Chain empty; node will wait for peer sync or --init-genesis")
        self.chain = []
        self.total_blocks = 0
        self.total_supply = 0
        self.genesis_manager._persist_empty_state_if_needed()
            

    def _rebuild_hash_cache(self):
        try:
            cache: OrderedDict[int, str] = OrderedDict()
            for b in self.chain:
                h_val = b.hash() if callable(b.hash) else b.hash
                if type(h_val) in (bytes, bytearray):
                    cache[int(b.height or 0)] = h_val.hex()
                elif type(h_val) is str and len(h_val) >= 64:
                    cache[int(b.height or 0)] = h_val

            # trim to config bound
            max_entries = max(1, int(CFG.HASH_CACHE_MAX))
            while len(cache) > max_entries:
                cache.popitem(last=False)
            self._hash_cache = cache
        except Exception:
            log.exception("[_rebuild_hash_cache] failed")

    def get_block_hash(self, height: int):
        if height < 0:
            return None

        with self.lock:
            if height in self._hash_cache:
                return self._hash_cache[height]

            if 0 <= height < len(self.chain):
                block = self.chain[height]
                h = block.hash()
                h_hex = h.hex() if type(h) in (bytes, bytearray) else str(h)
                self._hash_cache[height] = h_hex
                max_entries = max(1, int(CFG.HASH_CACHE_MAX))
                while len(self._hash_cache) > max_entries:
                    self._hash_cache.popitem(last=False)
                return h_hex
        return None

    def _start_persist_worker(self) -> None:
        if self._persist_thread is not None:
            return
        self._persist_queue = queue.Queue()
        self._persist_stop.clear()
        with self._persist_opts_lock:
            self._persist_opts = {
                "force_full": False,
                "flush_force": False,
                "save_state": True,
            }
            self._persist_pending = False
        self._persist_thread = threading.Thread(
            target=self._persist_loop,
            name="tsarchain.persist",
            daemon=True,
        )
        self._persist_thread.start()

    def _reload_chain_from_kv(self) -> bool:
        try:
            self.load_chain()
            self.load_state()
            return bool(self.chain)
        except Exception:
            log.exception("[reload_chain] Failed to reload chain from LMDB")
            return False

    def _persist_loop(self) -> None:
        assert self._persist_queue is not None
        while not self._persist_stop.is_set():
            try:
                task = self._persist_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if task is None:
                self._persist_queue.task_done()
                break
            with self._persist_opts_lock:
                opts = self._persist_opts.copy()
                self._persist_opts = {
                    "force_full": False,
                    "flush_force": False,
                    "save_state": True,
                }
                self._persist_pending = False
            try:
                self.save_chain(force_full=opts["force_full"])
                self.maybe_flush_utxo(force=opts["flush_force"])
                if opts["save_state"]:
                    self.save_state()
            except Exception:
                log.exception("[persist_worker] Failed persisting chain/utxo snapshot")
            finally:
                self._persist_queue.task_done()
        log.info("[persist_worker] stopped")

    def _schedule_persist(self, *, force_full: bool = False, flush_force: bool = False, save_state: bool = True, wait: bool = False) -> None:
        if wait or self._persist_queue is None:
            self.save_chain(force_full=force_full)
            self.maybe_flush_utxo(force=flush_force)
            if save_state:
                self.save_state()
            return
        with self._persist_opts_lock:
            self._persist_opts["force_full"] = self._persist_opts["force_full"] or force_full
            self._persist_opts["flush_force"] = self._persist_opts["flush_force"] or flush_force
            self._persist_opts["save_state"] = self._persist_opts["save_state"] or save_state
            if not self._persist_pending:
                self._persist_pending = True
                self._persist_queue.put(True)

    def _stop_persist_worker(self) -> None:
        if self._persist_thread is None or self._persist_queue is None:
            return
        self._persist_stop.set()
        worker = self._persist_thread
        self._persist_queue.put(None, timeout=1.0)

        if worker is not None:
            worker.join(timeout=5.0)
            still_alive = worker.is_alive()
        else:
            still_alive = False

        if still_alive:
            log.warning("[persist_worker] did not stop gracefully within timeout")
        self._persist_thread = None
        self._persist_queue = None
        if not self.chain:
            log.info("[_stop_persist_worker] Skip final persistence (chain empty)")
            return
        # Final synchronous persistence to ensure no data loss
        self.save_chain(force_full=True)
        self.maybe_flush_utxo(force=True)
        self.save_state()

    def attach_mempool(self, pool: TxPool) -> None:
        self._mempool = pool

    def get_mempool(self) -> TxPool:
        return self._mempool

    def get_mempool_size(self) -> int:
        return len(self._mempool._pool)

    @property
    def height(self) -> int:
        return len(self.chain) - 1

    def get_last_block(self) -> Optional[Block]:
        return self.chain[-1] if self.chain else None

    def to_dict(self) -> List[dict]:
        return [block.to_dict() for block in self.chain]

    @classmethod
    def from_dict(cls, data_list: List[dict]):
        bc = cls()
        bc.chain = [Block.from_dict(b) for b in data_list]
        bc.total_blocks = len(bc.chain)
        bc.total_supply = 0
        bc.supply_in_tsar = 0
        return bc

    def shutdown(self) -> None:
        self._stop_persist_worker()


    # ---------------- Proxy Methods for Genesis ----------------
    def ensure_genesis(self, miner_address: str, use_cores: int | None = None, init_genesis: bool = False) -> bool:
        return self.genesis_manager.ensure_genesis(miner_address, use_cores=use_cores, init_genesis=init_genesis)

    # ---------------- Proxy Methods for Rewards ----------------
    def scheduled_reward(self, height: int) -> int:
        return self.reward_calculator.scheduled_reward(height)

    def cumulative_supply_until(self, height: int) -> int:
        return self.reward_calculator.cumulative_supply_until(height)

    def get_block_reward(self, height: int) -> int:
        return self.reward_calculator.get_block_reward(height)

    def calculate_total_supply(self) -> int:
        return self.reward_calculator.calculate_total_supply()


    # ---------------- Proxy Methods for Difficulty ----------------
    def calculate_expected_bits(self, next_height: int) -> int:
        return self.difficulty_manager.calculate_expected_bits(next_height)

    def _validate_difficulty(self, block: Block) -> bool:
        return self.difficulty_manager._validate_difficulty(block)

    def _work_from_bits(self, bits: int) -> int:
        return self.difficulty_manager._work_from_bits(bits)

    def _compute_chainwork_for_chain(self, chain: List[Block]) -> int:
        return self.difficulty_manager._compute_chainwork_for_chain(chain)

    def _common_ancestor_height(self, other_chain_blocks: List[Block]) -> int:
        return self.difficulty_manager._common_ancestor_height(other_chain_blocks)

    def median_time_past(self, k: int = CFG.MTP_WINDOWS) -> int:
        return self.difficulty_manager.median_time_past(k)

    def _expected_bits_on_prefix(self, prefix: List[Block], next_height: int) -> int:
        return self.difficulty_manager._expected_bits_on_prefix(prefix, next_height)

    # ---------------- Tip Notification Callbacks ----------------
    def register_tip_changed_callback(self, cb):
        if callable(cb) and cb not in self._on_tip_changed_callbacks:
            self._on_tip_changed_callbacks.append(cb)

    def notify_tip_changed(self, new_height: int, new_hash: str):
        for cb in self._on_tip_changed_callbacks:
            try:
                cb(new_height, new_hash)
            except Exception:
                log.exception("[notify_tip_changed] callback error")


    # ---------------- Proxy Methods for Mining ----------------
    def mine_block(
        self,
        miner_address: str,
        use_cores: int | None = None,
        cancel_event: MpEvent | None = None,
        progress_queue: mp.Queue | None = None,
    ) -> Block | None:
        return self.mining_manager.mine_block(
            miner_address,
            use_cores=use_cores,
            cancel_event=cancel_event,
            progress_queue=progress_queue,
        )


    # ---------------- Proxy Methods for UTXO ----------------
    def ensure_utxodb(self) -> Optional[UTXODB]:
        return self.utxo_validator.ensure_utxodb()

    def mark_utxo_dirty(self) -> None:
        return self.utxo_validator.mark_utxo_dirty()

    def maybe_flush_utxo(self, *, force: bool = False) -> None:
        return self.utxo_validator.maybe_flush_utxo(force=force)


    # ---------------- Proxy Methods for Chain Ops ----------------
    def replace_with(self, other_chain: "Blockchain"):
        return self.chain_ops.replace_with(other_chain)

    def add_block(self, block: Block):
        return self.chain_ops.add_block(block)

    def swap_tip_if_better(self, block: Block):
        return self.chain_ops.swap_tip_if_better(block)

    def _has_pending_blocks(self) -> bool:
        return self.chain_ops._has_pending_blocks()

    def _is_chain_consistent(self) -> bool:
        return self.chain_ops._is_chain_consistent()

    def _validate_complete_chain(self, chain: List[Block]) -> bool:
        return self.chain_ops._validate_complete_chain(chain)


    # ---------------- Proxy Methods for Chain Storage ----------------
    def load_chain(self):
        return self.chain_storage.load_chain()

    def save_chain(self, *, force_full: bool = False):
        return self.chain_storage.save_chain(force_full=force_full)

    def load_state(self):
        return self.chain_storage.load_state()

    def save_state(self):
        return self.chain_storage.save_state()

    def _mark_chain_dirty(self, height: int = 0):
        return self.chain_storage._mark_chain_dirty(height)


    # ---------------- Proxy Methods for Block Validation ----------------
    def validate_block(self, block: "Block") -> bool:
        return self.validator.validate_block(block)

    def compute_txids_for_block(self, block: "Block") -> bool:
        return self.validator.compute_txids_for_block(block)
