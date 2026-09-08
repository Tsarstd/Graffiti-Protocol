# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
import base64
from typing import Any, Dict, Set, Tuple

from ...core.tx import Tx
from ...core.block import Block
from ...utils import config as CFG
from .base import BroadcastHandlerProxy
from ...utils.benchmarks import benchmark
from ...utils.helpers import native_validate_block_txs, native_validate_block_txs_compact, extract_script_bytes

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.receive")


class ReceiveHandler(BroadcastHandlerProxy):

    @benchmark(label="receive_block", threshold_ms=500.0)
    def receive_block(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]) -> bool: #NOSONAR
        block_id = None
        inflight = False
        accepted = False
        try:
            msg_hash = message.get("hash")
            if type(msg_hash) is str and len(msg_hash) == 64:
                with self.lock:
                    if msg_hash in self.seen_blocks or msg_hash in self._processing_blocks:
                        return True

            block_data = message.get("data") or message.get("block")
            if not block_data:
                return False

            if type(block_data) is Block:
                block = block_data
            elif type(block_data) is str:
                raw_bytes = base64.b64decode(block_data)
                block = Block.from_storage_bytes(raw_bytes)
            elif type(block_data) is bytes:
                block = Block.from_storage_bytes(block_data)
            else:
                log.warning("[receive_block] Unsupported block data format: %s (legacy JSON rejected)", type(block_data))
                return False

            block_id = block.hash().hex()

            origin_port = message.get("port")
            origin = (addr[0], origin_port) if origin_port else None

            with self.lock:
                if block_id in self.seen_blocks or block_id in self._processing_blocks:
                    return True
                self._processing_blocks.add(block_id)
                inflight = True

            last = self.blockchain.get_last_block()
            potential_fork = False
            if last:
                tip_h = last.hash()
                if block.height > last.height + 1:
                    if self.network:
                        self.network.handle_block_gap(block, origin)
                    return False
                if block.prev_block_hash != tip_h:
                    potential_fork = True

            if not self._validate_block_before_add(block, block_id, potential_fork, addr, origin_port):
                return False

            old_tip = None
            try:
                ok = self.blockchain.add_block(block)
            except Exception as exc:
                ok = False
                b_h = block.height
                self._log_block_reject(
                    stage="add_block",
                    block_id=block_id,
                    height=b_h,
                    peer=f"{addr[0]}:{origin_port or 0}" if addr else None,
                    reason=str(exc),
                )
            
            if not ok:
                ok, old_tip = self._resolve_add_block_failure(block, block_id, potential_fork, addr, origin_port)

            if not ok:
                return False
            
            self._post_add_block_success(block, old_tip)

            with self.lock:
                self.seen_blocks.add(block_id)

            self.broadcast_block(block, peers, exclude=origin, force=True)

            # set mining cool-off to reduce stale mining after new tip
            cooloff = float(CFG.MINING_COOLDOWN_AFTER_BLOCK)
            if cooloff > 0:
                self.blockchain._mining_cooloff_until = time.time() + cooloff

            accepted = True
        except Exception:
            log.exception("[receive_block] Error processing incoming block")
            
        finally:
            if inflight and block_id:
                with self.lock:
                    self._processing_blocks.discard(block_id)
                    if not accepted:
                        self.seen_blocks.discard(block_id)
        return accepted


    def receive_tx(self, message: Dict[str, Any], addr, peers: Set[Tuple[str, int]]) -> bool:
        try:
            tx_data = message["data"]
            tx = Tx.from_dict(tx_data) if type(tx_data) is dict else tx_data
            tx_id = tx.txid.hex()
            phase = str(message.get("phase") or "fluff").strip().lower()

            use_dandelion = False
            dpp = self.dandelion
            use_dandelion = bool(dpp and dpp.enabled(len(peers)))
            is_stem = use_dandelion and phase == "stem"
            if not is_stem:
                with self.lock:
                    if tx_id in self.seen_txs:
                        return False
                    self.seen_txs.add(tx_id)

            is_valid = self.mempool.add_valid_tx(tx)

            if is_valid:
                if is_stem:
                    handled = self.dandelion.handle_inbound_stem(tx, tx_id, peers, origin=addr)
                    if not handled:
                        # fallback to fluff if handler declines
                        self.broadcast_tx_fluff(tx, tx_id, peers)
                else:
                    self.broadcast_tx_fluff(tx, tx_id, peers)
                return True
            else:
                return False
        except Exception:
            log.exception("[receive_tx] Error processing incoming TX")
            return False


    def receive_mempool(self, message: Dict[str, Any]):
        try:
            is_caught = self.network.is_caught_up if self.network else None
            if callable(is_caught):
                if not is_caught(freshness=20.0, height_slack=0):
                    if self.network:
                        self.network._pending_mempool_pull = True
                        self.network.request_sync(fast=True)
                    return

            bc_height = int(self.blockchain.height)
            if bc_height < 0:
                if self.network:
                    self.network._pending_mempool_pull = True
                    self.network.request_sync(fast=True)
                return

            txs_data = message.get("data") or message.get("txs") or []
            if type(txs_data) is not list:
                return
            txs_data = txs_data[:CFG.MEMPOOL_INLINE_MAX_TX]

            added_count = 0
            for tx_data in txs_data:
                tx = Tx.from_dict(tx_data) if type(tx_data) is dict else tx_data
                if self.mempool.add_valid_tx(tx):
                    added_count += 1

            recheck_fn = self.mempool.recheck_orphans
            rechecked = recheck_fn() if callable(recheck_fn) else 0
            if rechecked:
                added_count += rechecked
                log.debug("[receive_mempool] Revalidated %s orphan transactions", rechecked)
            if added_count:
                log.info("[receive_mempool] Mempool updated: %s new transactions", added_count)
                self.mempool.flush()
        except Exception:
            log.exception("[receive_mempool] Error updating mempool")


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _validate_block_before_add(self, block: Block, block_id: str, potential_fork: bool, addr, origin_port) -> bool:
        # Defer full validation to the fork resolution path; downstream logic (swap_tip_if_better/add_block)
        # enforces all consensus rules (PoW, UTXO, sigops, etc.) against the correct parent state.
        if potential_fork:
            return True

        b_h = block.height
        if not self._native_precheck_block(block):
            self._log_block_reject(
                stage="precheck",
                block_id=block_id,
                height=b_h,
                peer=f"{addr[0]}:{origin_port or 0}" if addr else None,
                reason="native_precheck_failed",
            )
            return False
        if not self.blockchain.validate_block(block):
            reason = self.blockchain._last_block_validation_error
            self._log_block_reject(
                stage="validate",
                block_id=block_id,
                height=b_h,
                peer=f"{addr[0]}:{origin_port or 0}" if addr else None,
                reason=reason,
            )
            if reason and type(reason) is str and reason.startswith("prevout_missing"):
                if self.network:
                    self.network.request_sync(fast=True)
            return False
        return True


    def _native_precheck_block(self, block: Block) -> bool:
        snapshot = self._build_native_prevout_snapshot(block)
        if snapshot is None:
            return True
        if type(snapshot) is tuple and len(snapshot) == 2:
            snapshot_dict, utxo_items = snapshot
        else:
            snapshot_dict, utxo_items = snapshot, None

        opts = {
            "coinbase_maturity": int(CFG.COINBASE_MATURITY),
            "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
            "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
            "max_tx_vsize": int(CFG.MAX_TX_VSIZE),
            "min_tx_vsize": int(CFG.MIN_TX_VSIZE),
            "max_tx_weight": int(CFG.MAX_TX_WEIGHT),
            "min_tx_weight": int(CFG.MIN_TX_WEIGHT),
            "max_tx_inputs": int(CFG.MAX_TX_INPUTS),
            "max_tx_outputs": int(CFG.MAX_TX_OUTPUTS),
            "enforce_low_s": True,
        }

        b_h = int(block.height or 0)
        try:
            if utxo_items is not None:
                tx_payloads = self._parse_block_txs_compact(block)
                ok, reason, fees = native_validate_block_txs_compact(
                    tx_payloads,
                    utxo_items,
                    b_h,
                    opts,
                )
            else:
                ok, reason, fees = native_validate_block_txs(
                    block.to_dict(),
                    snapshot_dict,
                    b_h,
                    opts,
                )
        except Exception:
            log.error("[_native_precheck_block] validator failed; falling back")
            return False

        if not ok:
            blk_label = block.hash().hex()[:12]
            log.warning("[_native_precheck_block] block %s rejected (%s)", blk_label, reason or "unknown")
            return False

        if type(fees) in (list, tuple):
            block._native_fee_hint = [int(f) for f in fees]  # type: ignore[attr-defined]
        return True
    

    def _build_native_prevout_snapshot(self, block: Block):
        lookup = self.utxodb.lookup_entry
        if not callable(lookup):
            return None

        txs = block.transactions or []
        if not txs:
            return {}

        snapshot: dict[str, dict] = {}
        utxo_items: list[tuple] = []
        processed_txids: set[str] = set()

        def _txid_lower(value) -> str | None:
            if value is None:
                return None
            if type(value) in (bytes, bytearray):
                return bytes(value).hex().lower()
            return str(value).lower()

        for tx in txs:
            tx_txid = tx.txid
            txid_lower = _txid_lower(tx_txid)
            is_cb = bool(tx.is_coinbase)
            if is_cb:
                if txid_lower:
                    processed_txids.add(txid_lower)
                continue

            if not self._process_tx_inputs_for_snapshot(tx, lookup, snapshot, utxo_items, processed_txids, _txid_lower):
                return None

            if txid_lower:
                processed_txids.add(txid_lower)

        return snapshot, utxo_items


    def _process_tx_inputs_for_snapshot(self, tx, lookup, snapshot, utxo_items, processed_txids, _txid_lower):
        inputs = tx.inputs or []
        for tx_input in inputs:
            prev_txid = tx_input.txid
            prev_txid_lower = _txid_lower(prev_txid)
            if prev_txid_lower is None:
                return False

            prev_index = int(tx_input.vout)
            if prev_txid_lower in processed_txids:
                continue
            snap_key = f"{prev_txid_lower}:{prev_index}"
            if snap_key in snapshot:
                continue
            entry = lookup(prev_txid_lower, prev_index)
            if entry is None:
                return False
            normalized = self._normalize_native_prevout(entry)
            if normalized is None:
                return False
            amount_int, script_bytes, is_cb, born = normalized
            snapshot[snap_key] = {
                "amount": amount_int,
                "script_pubkey": script_bytes,
                "is_coinbase": is_cb,
                "block_height": born,
            }
            txid_b = bytes.fromhex(prev_txid_lower)
            utxo_items.append((txid_b, int(prev_index), amount_int, script_bytes, is_cb, born))
        return True


    def _normalize_native_prevout(self, entry):
        candidate = entry
        if type(candidate) is dict:
            tx_out = candidate.get("tx_out") or candidate
        else:
            tx_out = candidate.tx_out or candidate

        script_bytes = self._native_script_bytes(tx_out)
        if script_bytes is None and type(candidate) is dict:
            script_bytes = self._native_script_bytes(candidate.get("script_pubkey"))
        if script_bytes is None:
            return None

        if type(tx_out) is dict:
            amount_val = tx_out.get("amount")
        else:
            amount_val = tx_out.amount
        amount_int = int(amount_val if amount_val is not None else 0)

        if type(candidate) is dict:
            is_cb = bool(candidate.get("is_coinbase", False))
            born = int(candidate.get("block_height", candidate.get("height", 0)) or 0)
        else:
            is_cb = bool(candidate.is_coinbase)
            born = int(candidate.block_height or 0)

        return amount_int, script_bytes, is_cb, born


    def _parse_block_txs_compact(self, block: Block): #NOSONAR
        tx_payloads = []

        txs = block.transactions or []
        for tx in txs:
            version = int(tx.version)
            locktime = int(tx.locktime)
            inputs_payload = []
            inputs = tx.inputs or []
            for tx_input in inputs:
                prev_txid_b = tx_input.txid
                if type(prev_txid_b) is str:
                    prev_txid_b = bytes.fromhex(prev_txid_b)
                if type(prev_txid_b) not in (bytes, bytearray) or len(prev_txid_b) != 32:
                    raise ValueError("txid_missing")

                prev_index = int(tx_input.vout)
                seq = int(tx_input.sequence)
                wit_vec = []
                witness = tx_input.witness or []
                for w in witness:
                    if type(w) in (bytes, bytearray):
                        wit_vec.append(bytes(w))
                    elif type(w) is str:
                        wit_vec.append(bytes.fromhex(w))
                    else:
                        raise ValueError("witness_invalid")
                inputs_payload.append((bytes(prev_txid_b), prev_index, seq, wit_vec))

            outputs_payload = []
            outputs = tx.outputs or []
            for tx_out in outputs:
                if type(tx_out) is dict:
                    amt = int(tx_out.get("amount", 0) or 0)
                    spk_obj = tx_out.get("script_pubkey")
                else:
                    amt = int(tx_out.amount or 0)
                    spk_obj = tx_out.script_pubkey
                spk_bytes = self._native_script_bytes(spk_obj)
                if spk_bytes is None:
                    raise ValueError("spk_missing")
                outputs_payload.append((amt, spk_bytes))

            txid_b = tx.txid
            if type(txid_b) is str:
                txid_b = bytes.fromhex(txid_b)

            if type(txid_b) not in (bytes, bytearray) or len(txid_b) != 32:
                raise ValueError("txid_missing")

            is_cb = bool(tx.is_coinbase)

            tx_payloads.append((version, locktime, inputs_payload, outputs_payload, bytes(txid_b), is_cb))

        return tx_payloads


    @staticmethod
    def _native_script_bytes(candidate) -> bytes | None:
        return extract_script_bytes(candidate)


    def _resolve_add_block_failure( #NOSONAR
        self,
        block: Block,
        block_id: str,
        potential_fork: bool,
        addr,
        origin_port
    ) -> Tuple[bool, Block | None]:
        
        old_tip = None
        ok = False
        try:
            # Fast-path fork resolution: if this block attaches to tip-1, try swap_tip_if_better
            if len(self.blockchain.chain) >= 2:
                parent = self.blockchain.chain[-2]
                p_h = parent.height
                expected_h = p_h + 1
                parent_hash_fn = parent.hash
                parent_hash = parent_hash_fn() if callable(parent_hash_fn) else parent_hash_fn
                b_h = block.height
                b_prev = block.prev_block_hash
                if b_h == expected_h and b_prev == parent_hash:
                    alt = self.blockchain.swap_tip_if_better(block)
                    if alt is not None:
                        old_tip = alt
                        ok = True
        except Exception:
            log.warning("[_resolve_add_block_failure] swap_tip_if_better failed", exc_info=True)

        if not ok:
            reason_str = self.blockchain._last_block_validation_error
            if self.network and type(reason_str) is str and (
                "Height mismatch" in reason_str or "prev_block_hash" in reason_str
            ):
                self.network.request_sync(fast=True)

            b_h = block.height
            self._log_block_reject(
                stage="add_block",
                block_id=block_id,
                height=b_h,
                peer=f"{addr[0]}:{origin_port or 0}" if addr else None,
                reason=reason_str,
                extra={"potential_fork": potential_fork},
            )
            if potential_fork and self.network:
                self.network.request_sync(fast=True)
        return ok, old_tip


    def _log_block_reject(self, *, stage: str, block_id: str | None, height: int | None, peer: str | None = None, reason: str | None = None, extra: dict | None = None) -> None:
        rid = (block_id or "unknown")[:16]
        src = peer or "-"
        msg = {
            "stage": stage,
            "height": int(height or -1),
            "hash": rid,
            "peer": src,
            "reason": reason or "unknown",
        }
        if extra:
            msg.update(extra)
        log.warning(
            "[_log_block_reject] stage=%s height=%s hash=%s peer=%s reason=%s extra=%s",
            msg["stage"],
            msg["height"],
            msg["hash"],
            msg["peer"],
            msg["reason"],
            {k: v for k, v in msg.items() if k not in ("stage", "height", "hash", "peer", "reason")},
        )


    def _post_add_block_success(self, block: Block, old_tip: Block | None):
        self.mempool.flush()

        if old_tip:
            for tx in (old_tip.transactions[1:] or []):
                self.mempool.add_valid_tx(tx)
        self.mempool.flush()

        if not self._utxo_shared:
            blk_hash = block.hash().hex()
            self.utxodb.update(block.transactions, block.height, block_hash=blk_hash)
            self.maybe_flush_local_utxo(block.height)

        recheck_fn = self.mempool.recheck_orphans
        recovered = recheck_fn() if callable(recheck_fn) else 0
        if recovered:
            log.info("[_post_add_block_success] Revalidated %s orphan mempool txs", recovered)


__all__ = ["ReceiveHandler"]