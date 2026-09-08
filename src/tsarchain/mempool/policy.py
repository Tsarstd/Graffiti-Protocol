# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE.

from __future__ import annotations

import time
import heapq
from typing import Iterable

from ..core.tx import Tx
from ..utils import config as CFG
from ..utils.helpers import _estimate_tx_size_bytes
from .types import PrevoutRef, normalize_prevout_set

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.policy")

__all__ = ["MempoolPolicyMixin"]


class MempoolPolicyMixin:
    def _prevout_key(self, txid, vout) -> PrevoutRef | None:
        return PrevoutRef.from_values(txid, vout)

    def is_prevout_spent(self, txid, vout) -> bool:
        key = self._prevout_key(txid, vout)
        return bool(key and key in self._prevout_index)

    def _index_tx_prevouts(self, tx_obj: Tx) -> None:
        if tx_obj.is_coinbase:
            return
        owner_txid = self._normalize_txid(tx_obj.txid)
        if not owner_txid:
            return
        prevouts: set[PrevoutRef] = set()
        inputs = tx_obj.inputs or []
        for txin in inputs:
            prev = txin.txid
            vout = txin.vout
            key = self._prevout_key(prev, vout)
            if key:
                self._prevout_index[key] = owner_txid
                prevouts.add(key)
        if prevouts:
            tx_prevouts = self._tx_prevouts
            if tx_prevouts is None:
                self._tx_prevouts = {}
                tx_prevouts = self._tx_prevouts
            tx_prevouts[owner_txid] = prevouts

    def _drop_tx_prevouts(self, tx_obj: Tx | None) -> None:
        if not tx_obj:
            return
        if tx_obj.is_coinbase:
            return
        txid_val = tx_obj.txid
        if not txid_val:
            return
        owner_txid = self._normalize_txid(txid_val)
        if not owner_txid or not self._prevout_index:
            return
        
        tx_prevouts_map = self._tx_prevouts
        prevouts = tx_prevouts_map.pop(owner_txid, None) if tx_prevouts_map else None
        if prevouts:
            for key in prevouts:
                self._prevout_index.pop(key, None)
        else:
            to_delete = [k for k, owner in self._prevout_index.items() if owner == owner_txid]
            for key in to_delete:
                self._prevout_index.pop(key, None)

    def _ensure_space(self, needed_space: int) -> None:
        if needed_space <= 0:
            return
        with self._lock:
            if self.current_size + needed_space <= CFG.MEMPOOL_MAX_SIZE:
                return
            target = (self.current_size + needed_space) - CFG.MEMPOOL_MAX_SIZE
            freed = 0
            while freed < target and self._fee_heap:
                rate, txid = heapq.heappop(self._fee_heap)
                entry_rate = self._heap_entries.get(txid)
                if entry_rate is None or entry_rate != rate:
                    continue
                tx_obj = self._pool.pop(txid, None)
                self._heap_entries.pop(txid, None)
                if tx_obj is None:
                    continue
                self._drop_tx_prevouts(tx_obj)
                size = self._size_map.pop(txid, _estimate_tx_size_bytes(tx_obj))
                self.current_size -= size
                freed += size
            if freed > 0:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()

    def drop_conflicts(self, spent_prevouts: Iterable[tuple[str, int]]) -> int:
        normalized_spent = normalize_prevout_set(spent_prevouts)
        if not normalized_spent:
            return 0
        removed = 0
        with self._lock:
            to_remove = set()
            prevout_idx = self._prevout_index
            if prevout_idx:
                for prev in normalized_spent:
                    cid = prevout_idx.get(prev)
                    if cid and cid in self._pool:
                        to_remove.add(cid)

            if not to_remove:
                for txid, tx in self._pool.items():
                    conflict = False
                    inputs = tx.inputs or []
                    for txin in inputs:
                        prev_id = txin.txid
                        v_val = txin.vout
                        prev = self._prevout_key(prev_id, v_val)
                        if prev and prev in normalized_spent:
                            conflict = True
                            break
                    if conflict:
                        to_remove.add(txid)

            for txid in to_remove:
                tx_obj = self._pool.pop(txid, None)
                if tx_obj:
                    self._drop_tx_prevouts(tx_obj)
                self._remove_fee_record(txid)
                self.current_size -= self._size_map.pop(txid, 0)
                removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        if removed:
            self._maybe_flush_after_mutation()
        return removed

    def prune_stale_entries(self) -> int:
        current_version = self.utxo.version() if callable(self.utxo.version) else self.utxo.version
        if current_version is not None and current_version == self._last_prune_version:
            return 0
        now = time.time()
        if now - self._last_prune_reload_ts > max(float(CFG.MEMPOOL_FLUSH_INTERVAL), 5.0):
            self.utxo._load()
            self._last_prune_reload_ts = now

        utxo_set = self.utxo.utxos
        tip = self.utxo._get_tip_height_from_state()
        removed = 0
        with self._lock:
            to_remove = []
            for txid, tx in self._pool.items():
                if not self.validate_transaction(tx, utxo_set, spend_at_height=tip + 1):
                    to_remove.append(txid)
            for txid in to_remove:
                tx_obj = self._pool.pop(txid, None)
                if tx_obj:
                    self._drop_tx_prevouts(tx_obj)
                self._remove_fee_record(txid)
                self.current_size -= self._size_map.pop(txid, 0)
                removed += 1
            if removed:
                if self.current_size < 0:
                    self.current_size = 0
                self._mark_dirty()
        self._last_prune_version = current_version
        return removed

    def add_valid_tx(self, tx_data) -> bool:
        self.last_error_reason = None
        transaction_obj = Tx.from_dict(tx_data) if type(tx_data) is dict else tx_data

        txid_hex = transaction_obj.txid.hex() if transaction_obj.txid else None
        if txid_hex and self.has_tx(txid_hex):
            self.last_error_reason = "tx_already_in_pool"
            return False

        utxo_set = self.utxo.utxos
        tip = self.utxo._get_tip_height_from_state()
        if not self.validate_transaction(transaction_obj, utxo_set, spend_at_height=tip + 1):
            if not self.last_error_reason:
                self.last_error_reason = "tx_validation_failed"
            else:
                reason = str(self.last_error_reason)
                if reason.startswith("prevout_missing "):
                    missing = reason.split(" ", 1)[1].strip()
                    self._queue_orphan(transaction_obj, missing)
                    self.last_error_reason = f"orphan_waiting {missing}"
            return False

        new_prevouts = set()
        inputs = transaction_obj.inputs or []
        for txin in inputs:
            prev_id = txin.txid
            v_val = txin.vout
            key = self._prevout_key(prev_id, v_val)
            if key:
                new_prevouts.add(key)

        conflict_ids = {
            self._prevout_index.get(key) for key in new_prevouts if self._prevout_index.get(key)
        }
        conflicts: list[Tx] = [self._pool[cid] for cid in conflict_ids if cid and cid in self._pool]

        if conflicts:
            new_fee = int(transaction_obj.fee or 0)
            new_size = max(1, _estimate_tx_size_bytes(transaction_obj))
            new_rate = new_fee / new_size
            worst_old_rate = 0.0
            worst_old_fee = 0
            conflict_txids: list[str] = []
            for old in conflicts:
                old_fee = int(old.fee or 0)
                old_rate = old_fee / max(1, _estimate_tx_size_bytes(old))
                worst_old_rate = max(worst_old_rate, old_rate)
                worst_old_fee = max(worst_old_fee, old_fee)
                old_txid = old.txid
                conflict_txids.append(
                    old_txid.hex() if type(old_txid) in (bytes, bytearray) else str(old_txid or "")
                )

            if (new_rate > worst_old_rate) or (new_fee > worst_old_fee):
                for ctid in conflict_txids:
                    if ctid:
                        self.remove_tx(ctid)
            else:
                any_prev = next(iter(new_prevouts))
                prev_str = f"{any_prev.txid}:{any_prev.vout}"
                self.last_error_reason = (
                    f"double_spend_conflict prev={prev_str} with={','.join(conflict_txids)}"
                )
                log.warning(
                    "[add_valid_tx] Rejecting tx due to double-spend conflict: %s",
                    self.last_error_reason,
                )
                return False

        self.add_tx(transaction_obj)
        return True

