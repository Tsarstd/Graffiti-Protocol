# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: Merkle

from __future__ import annotations

import time
import threading
from typing import TYPE_CHECKING
from bech32 import bech32_encode, convertbits

# ---------------- Local Project ----------------
from ..core.block import Block
from ..utils import helpers as H
from ..storage.utxo import UTXODB
from .genesis import GENESIS_HASH
from ..utils import config as CFG
from ..utils.benchmarks import benchmark
from ..contracts import graffiti as GRAFFITI
from ..utils.helpers import bits_to_target, merkle_root, extract_script_bytes
from ..contracts.graffiti_registry import GraffitiRegistry

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.consensus.validation")

if TYPE_CHECKING:
    from .blockchain import Blockchain


class BlockValidator:
    _pow_light_warmed = False
    _pow_warm_next_epoch: int | None = None
    _pow_warm_lock = threading.Lock()
    _pow_epoch_warmed: set[int] = set()

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain

    # =============================================================================
    # 1. VALIDATION PROCESSING
    # =============================================================================

    @benchmark(label="validate_block", threshold_ms=2500.0)
    def validate_block(self, block: Block) -> bool:
        try:
            # 1. Check Field Completeness
            if block.height is None or not block.prev_block_hash or not block.transactions:
                self.blockchain._last_block_validation_error = "block_missing_fields"
                return False

            # 2. Warm-up POW
            b_height = int(block.height or 0)
            self._warm_pow_context(b_height)
            self._ensure_warm(b_height)

            if not self.__class__._pow_light_warmed and CFG.POW_ALGO == "randomx":
                H.pow_hash_verify_light(block.header(), height=block.height)
                self.__class__._pow_light_warmed = True

            # 3. Main Block Validation Steps
            steps = (
                (self._validate_pow, "pow_invalid"),
                (self.compute_txids_for_block, None),
                (self._validate_merkle, "merkle_mismatch"),
                (self._ensure_unique_txids, "duplicate_or_missing_txid"),
                (self._check_block_limits, "block_limits_exceeded"),
            )
            for validate_func, err_msg in steps:
                if not validate_func(block):
                    self.blockchain._last_block_validation_error = err_msg or self.blockchain._last_block_validation_error
                    return False

            # 4. State & Chain Context Validation
            with self.blockchain.lock:
                if not self._validate_chain_context_locked(block):
                    self.blockchain._last_block_validation_error = "chain_context_invalid"
                    return False
                store = self.blockchain.ensure_utxodb() or UTXODB()
                state_token = self._chain_state_token_locked()

            # 5. Store / UTXO Validation
            if not self._check_sigops_budget(block, store):
                self.blockchain._last_block_validation_error = "sigops_limit_exceeded"
                return False

            if block.height > 0 and not self._validate_transactions(block, store):
                return False

            # 6. Finalization
            with self.blockchain.lock:
                if state_token != self._chain_state_token_locked():
                    self.blockchain._last_block_validation_error = "chain_state_changed_during_validation"
                    return False
                self.blockchain._last_block_validation_error = None
            return True

        except Exception:
            self.blockchain._last_block_validation_error = "unexpected_validation_error"
            log.exception("[validate_block] Unexpected error during block validation")
            return False


    def compute_txids_for_block(self, block: Block) -> bool:
        for tx in (block.transactions or []):
            raw_no_witness = self._serialize_tx_cached(tx, include_witness=False)
            if raw_no_witness is None:
                self.blockchain._last_block_validation_error = "tx_serialize_failed"
                return False
            
            txid_bytes = H.hash256(raw_no_witness)
            if tx.txid != txid_bytes:
                self.blockchain._last_block_validation_error = "txid_mismatch"
                return False

            tx._cached_txid_bytes = txid_bytes
            tx._cached_raw_tx_nowit = raw_no_witness
            tx.txid = txid_bytes
            tx.txid_hex = txid_bytes.hex()
        return True


    # =============================================================================
    # INTERNAL METHODS
    # =============================================================================

    def _warm_pow_context(self, height: int):
        if CFG.POW_ALGO != "randomx":
            return
        epoch_blocks = max(1, int(CFG.RANDOMX_KEY_EPOCH_BLOCKS))
        next_epoch = (height // epoch_blocks) + 1
        with self._pow_warm_lock:
            if self.__class__._pow_warm_next_epoch == next_epoch:
                return
            self.__class__._pow_warm_next_epoch = next_epoch

        def _worker():
            key = H.pow_key_for_height(next_epoch * epoch_blocks)
            H.pow_hash_verify_light(b"\x00" * 80, key_hint=key)
            log.info("[pow_warm] warmed epoch=%s", next_epoch)

        threading.Thread(target=_worker, name="pow-warm", daemon=True).start()


    def _ensure_warm(self, height: int):
        if CFG.POW_ALGO != "randomx":
            return
        epoch_blocks = max(1, int(CFG.RANDOMX_KEY_EPOCH_BLOCKS))
        epoch = max(0, int(height) // epoch_blocks)
        with self._pow_warm_lock:
            if epoch in self.__class__._pow_epoch_warmed:
                return
            self.__class__._pow_epoch_warmed.add(epoch)

        key = H.pow_key_for_height(epoch * epoch_blocks)
        H.pow_hash_verify_light(b"\x00" * 80, key_hint=key)
        log.info("[pow_warm] ensured epoch=%s ready", epoch)


    def _validate_pow(self, block: Block) -> bool:
        return int.from_bytes(block.hash(), "big") <= int(bits_to_target(block.bits))


    def _validate_merkle(self, block: Block) -> bool:
        header_mr = block.merkle_root
        if type(header_mr) is str:
            header_mr = bytes.fromhex(header_mr)
        return merkle_root(block.transactions or []) == header_mr


    def _validate_transactions(self, block: Block, utxo_store: UTXODB | None = None) -> bool:
        store = utxo_store or self.blockchain.ensure_utxodb() or UTXODB()
        self.blockchain._last_block_validation_error = "validation_failed"
        txs = block.transactions or []
        if not txs:
            self.blockchain._last_block_validation_error = "empty_block_transactions"
            return False

        if not txs[0].is_coinbase:
            self.blockchain._last_block_validation_error = "missing_coinbase"
            return False
        if any(t.is_coinbase for t in txs[1:]):
            self.blockchain._last_block_validation_error = "duplicate_coinbase"
            return False

        spend_height = int(block.height or 0)
        return (
            self._validate_tx_guardrails(txs, spend_height)
            and self._validate_graffiti_rules(txs, txs[0], store)
            and self._validate_transactions_payload(block, txs, spend_height, txs[0], store)
        )


    def _validate_tx_guardrails(self, txs, block_height: int) -> bool:
        for tx in txs:
            raw_full = self._serialize_tx_cached(tx, include_witness=True)
            if raw_full is None:
                self.blockchain._last_block_validation_error = "tx_serialize_failed"
                return False
            if len(raw_full) > int(CFG.MAX_BLOCK_BYTES):
                self.blockchain._last_block_validation_error = "tx_too_large"
                return False
            try:
                weight, vsize, _base_size, _total_size = H.compute_tx_weight_vsize(tx)
            except Exception:
                log.exception("[_validate_tx_guardrails] weight_calc_failed txid=%s height=%s", tx.txid, block_height)
                self.blockchain._last_block_validation_error = "tx_weight_calc_failed"
                return False

            vin = len(tx.inputs or [])
            vout = len(tx.outputs or [])

            if not (int(CFG.MIN_TX_VSIZE) <= vsize <= int(CFG.MAX_TX_VSIZE)):
                self.blockchain._last_block_validation_error = "tx_vsize_below_min" if vsize < int(CFG.MIN_TX_VSIZE) else "tx_vsize_exceeds_limit"
                return False
            if not (int(CFG.MIN_TX_WEIGHT) <= weight <= int(CFG.MAX_TX_WEIGHT)):
                self.blockchain._last_block_validation_error = "tx_weight_below_min" if weight < int(CFG.MIN_TX_WEIGHT) else "tx_weight_exceeds_limit"
                return False
            if vin > int(CFG.MAX_TX_INPUTS):
                self.blockchain._last_block_validation_error = "tx_inputs_exceed_limit"
                return False
            if vout > int(CFG.MAX_TX_OUTPUTS):
                self.blockchain._last_block_validation_error = "tx_outputs_exceed_limit"
                return False

            for tx_out in (tx.outputs or []):
                if not self._validate_graffiti_output(tx_out.script_pubkey):
                    return False
        return True


    def _validate_graffiti_rules(self, txs, cb, store) -> bool:
        reg = store._graffiti_registry or GraffitiRegistry()
        return self._validate_graffiti_posts(txs, cb) and self._validate_graffiti_payouts(txs, reg)


    def _validate_graffiti_posts(self, txs, cb) -> bool:
        graffiti_posts = 0
        first_art_id = None
        for tx in txs[1:]:
            outputs = tx.outputs or []
            for tx_out in outputs:
                spk = tx_out.script_pubkey
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if not meta or str(meta.get("event", "")).upper() != "POST":
                    continue

                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    sha_hex = str(meta.get("sha256") or "").strip().lower()
                    creator = str(meta.get("creator") or "").strip().lower()
                    art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
                if not art_id:
                    continue

                pool_addr = GRAFFITI.derive_pool_address(art_id)
                min_fee = int(GRAFFITI.calc_upload_fee_sats(int(meta.get("size") or 0)))
                paid = sum(int(out.amount or 0) for out in outputs if self._spk_to_address(out.script_pubkey) == pool_addr)

                if paid < min_fee:
                    continue

                graffiti_posts += 1
                if not first_art_id:
                    first_art_id = art_id

        if graffiti_posts > 1:
            self.blockchain._last_block_validation_error = "too_many_graffiti_posts"
            return False

        cb_block_id = cb.block_id
        if type(cb_block_id) is str:
            cb_block_id = cb_block_id.strip().lower()
        if graffiti_posts == 1 and first_art_id and cb_block_id != first_art_id:
            self.blockchain._last_block_validation_error = "block_id_mismatch_graffiti"
            return False
        return True


    def _validate_graffiti_payouts(self, txs, reg) -> bool:
        for tx in txs[1:]:
            paymap: dict[str, int] = {}
            outputs = tx.outputs or []
            for out in outputs:
                addr = self._spk_to_address(out.script_pubkey)
                if not addr:
                    continue
                amt = int(out.amount or 0)
                if amt > 0:
                    key = addr.strip().lower()
                    paymap[key] = paymap.get(key, 0) + amt

            for out in outputs:
                meta = GRAFFITI.parse_from_script(out.script_pubkey) if out.script_pubkey is not None else None
                if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                    if not self._validate_single_payout(meta, paymap, reg):
                        return False
        return True


    def _validate_single_payout(self, meta: dict, paymap: dict[str, int], reg) -> bool:
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id:
            self.blockchain._last_block_validation_error = "payout_bad_art_id"
            return False
        post = reg.get_post(art_id) if reg else None
        if not post:
            self.blockchain._last_block_validation_error = "payout_unknown_art"
            return False
        
        stats = post.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))
        last_epoch = int(stats.get("last_paid_epoch", -1))
        epoch = int(meta.get("epoch", -1))

        if 0 <= epoch <= last_epoch:
            self.blockchain._last_block_validation_error = "payout_epoch_rewind"
            return False

        if epoch >= 0 and not self._validate_payout_proof(meta, epoch, art_id, reg):
            return False

        recs = meta.get("recipients")
        if type(recs) is not list or not recs:
            self.blockchain._last_block_validation_error = "payout_no_recipients"
            return False
            
        total_req = 0
        for rec in recs:
            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                self.blockchain._last_block_validation_error = "payout_bad_recipient"
                return False
            total_req += amt_req
            if paymap.get(addr, 0) < amt_req:
                self.blockchain._last_block_validation_error = "payout_shortfall"
                return False
                
        if total_req > pool_balance:
            self.blockchain._last_block_validation_error = "payout_exceeds_pool"
            return False
            
        return True


    def _validate_payout_proof(self, meta: dict, epoch: int, art_id: str, reg) -> bool:
        if reg.get_latest_proof_epoch(art_id) < epoch:
            proof_epoch = int(meta.get("proof_epoch", -1))
            if proof_epoch < 0:
                proof_height = int(meta.get("proof_height", meta.get("height", -1)))
                if proof_height >= 0:
                    proof_epoch = GRAFFITI.compute_proof_epoch(proof_height)
            if proof_epoch < epoch:
                self.blockchain._last_block_validation_error = "payout_missing_proof"
                return False
        return True


    def _validate_transactions_payload(self, block: Block, txs, spend_height: int, cb, store: UTXODB) -> bool:
        snapshot = self._prepare_tx_snapshot(txs, store)
        if snapshot is None:
            return False

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

        payload_txs, payload_utxo = self._build_block_payload_compact(txs, snapshot) or (None, None)
        if payload_txs is not None and payload_utxo is not None:
            ok, reason, fees = H.native_validate_block_txs_compact(
                payload_txs, payload_utxo, spend_height, opts
            )
        else:
            ok, reason, fees = H.native_validate_block_txs(
                block.to_dict(), snapshot, spend_height, opts
            )

        if not ok:
            self.blockchain._last_block_validation_error = reason or "native_validation_failed"
            return False

        return self._verify_block_fees_and_rewards(block, txs, cb, fees)


    def _prepare_tx_snapshot(self, txs, store: UTXODB) -> dict | None:
        store_lookup = store.lookup_entry
        processed_txids = set()
        snapshot: dict[str, dict] = {}
        for tx in txs:
            txid_hex = self._txid_hex(tx.txid)
            if txid_hex is None:
                tx.compute_txid()
                txid_hex = self._txid_hex(tx.txid)

            txid_lower = txid_hex.lower() if txid_hex else None
            if tx.is_coinbase:
                if txid_lower:
                    processed_txids.add(txid_lower)
                continue

            for tx_input in (tx.inputs or []):
                prev_txid_hex = self._txid_hex(tx_input.txid)
                if prev_txid_hex is None:
                    self.blockchain._last_block_validation_error = "tx_input_missing_prev_txid"
                    return None

                prev_index = int(tx_input.vout)
                if prev_txid_hex.lower() in processed_txids:
                    continue
                snap_key = f"{prev_txid_hex.lower()}:{prev_index}"
                if snap_key in snapshot:
                    continue

                entry = store_lookup(prev_txid_hex.lower(), prev_index)
                if entry is None:
                    self.blockchain._last_block_validation_error = f"prevout_missing {prev_txid_hex}:{prev_index}"
                    return None

                normalized = self._normalize_snapshot_entry(entry, snap_key)
                if normalized is None:
                    self.blockchain._last_block_validation_error = "native_snapshot_invalid_entry"
                    return None
                snapshot[snap_key] = normalized

            if txid_lower:
                processed_txids.add(txid_lower)
        return snapshot


    def _verify_block_fees_and_rewards(self, block: Block, txs, cb, fees) -> bool:
        if type(fees) in (list, tuple):
            if len(fees) != max(len(txs) - 1, 0):
                self.blockchain._last_block_validation_error = "fee_mismatch"
                return False
            fees_list = [int(f) for f in fees]
            for tx_obj, fee_val in zip(txs[1:], fees_list):
                tx_obj.fee = fee_val
        else:
            fees_list = [int(t.fee or 0) for t in txs[1:]]

        minted_before = int(self.blockchain.cumulative_supply_until(block.height) or 0)
        base = int(self.blockchain.scheduled_reward(block.height) or 0)
        reward = min(max(0, base), max(0, CFG.MAX_SUPPLY - minted_before))
        expected_cb = reward + sum(fees_list)
        actual_cb = sum(int(o.amount or 0) for o in (cb.outputs or []))
        if actual_cb != expected_cb:
            self.blockchain._last_block_validation_error = f"coinbase_amount_mismatch expected={expected_cb} actual={actual_cb}"
            return False

        return True


    def _serialize_tx_cached(self, tx, *, include_witness: bool) -> bytes | None:
        buf = tx._cached_raw_tx_w if include_witness else tx._cached_raw_tx_nowit
        if type(buf) in (bytes, bytearray):
            return bytes(buf)
        raw = H.serialize_tx(tx, include_witness=include_witness)
        if include_witness:
            tx._cached_raw_tx_w = raw
        else:
            tx._cached_raw_tx_nowit = raw
        return raw


    def _estimate_block_size(self, block: Block) -> int:
        return 80 + sum(len(tx.serialize()) for tx in (block.transactions or []))


    def _chain_state_token_locked(self):
        tip_hash = self.blockchain.chain[-1].hash() if self.blockchain.chain else None
        return (self.blockchain.height, tip_hash)


    def _validate_chain_context_locked(self, block: Block) -> bool:
        expected_height = self.blockchain.height + 1 if self.blockchain.chain else 0
        if block.height != expected_height:
            self.blockchain._last_block_validation_error = "height_mismatch"
            return False
        if self.blockchain.chain and block.prev_block_hash != self.blockchain.chain[-1].hash():
            self.blockchain._last_block_validation_error = "prev_hash_mismatch"
            return False
        if not self.blockchain.chain and (block.height != 0 or block.prev_block_hash != CFG.ZERO_HASH):
            self.blockchain._last_block_validation_error = "bad_genesis_prevhash"
            return False
        if not self.blockchain.chain and block.height == 0 and GENESIS_HASH is not None:
            if block.hash() != GENESIS_HASH:
                self.blockchain._last_block_validation_error = "genesis_hash_mismatch"
                return False
        mtp = self.blockchain.median_time_past(CFG.MTP_WINDOWS)
        if block.timestamp < mtp:
            self.blockchain._last_block_validation_error = "timestamp_too_old"
            return False
        if block.timestamp > int(time.time()) + CFG.FUTURE_DRIFT:
            self.blockchain._last_block_validation_error = "timestamp_in_future"
            return False
        if self.blockchain.chain:
            parent_ts = int(self.blockchain.chain[-1].timestamp or 0)
            if block.timestamp + int(CFG.TARGET_BLOCK_TIME) < parent_ts:
                self.blockchain._last_block_validation_error = "timestamp_backwards"
                return False
        if not self.blockchain._validate_difficulty(block):
            self.blockchain._last_block_validation_error = "difficulty_invalid"
            return False
        return True


    def _ensure_unique_txids(self, block: Block) -> bool:
        seen_txids = set()
        for tx in (block.transactions or []):
            txid_val = tx.txid
            if txid_val is None:
                tx.compute_txid()
                txid_val = tx.txid
            txid_b = bytes.fromhex(txid_val) if type(txid_val) is str else txid_val
            if not txid_b:
                self.blockchain._last_block_validation_error = "txid_missing"
                return False
            if txid_b in seen_txids:
                self.blockchain._last_block_validation_error = "txid_duplicate"
                return False
            seen_txids.add(txid_b)
        return True


    def _check_block_limits(self, block: Block) -> bool:
        if max(0, len(block.transactions or []) - 1) > CFG.MAX_TXS_PER_BLOCK:
            self.blockchain._last_block_validation_error = "too_many_txs"
            return False
        if self._estimate_block_size(block) > CFG.MAX_BLOCK_BYTES:
            self.blockchain._last_block_validation_error = "block_size_exceeded"
            return False
        return True


    def _validate_graffiti_output(self, spk_obj) -> bool:
        raw = extract_script_bytes(spk_obj)
        if not raw:
            return True
        data = H.last_pushdata(raw)
        if not data or not data.startswith(CFG.GRAFFITI_MAGIC):
            return True
        if len(data) > int(CFG.MAX_GRAFFITI_OPRET):
            self.blockchain._last_block_validation_error = "graffiti_opreturn_too_large"
            return False
        meta = GRAFFITI.parse_payload(data)
        if not meta:
            self.blockchain._last_block_validation_error = "graffiti_payload_invalid"
            return False
            
        event = str(meta.get("event", "")).upper()
        if event == "POST":
            return self._validate_graffiti_post_event(meta)
        if event == "COMMENT":
            return self._validate_graffiti_comment_event(meta)
        return True


    def _validate_graffiti_post_event(self, meta: dict) -> bool:
        size_val = int(meta.get("size", 0))
        if not (0 < size_val <= int(CFG.GRAFFITI_MAX_SIZE_BYTES)):
            self.blockchain._last_block_validation_error = "graffiti_size_invalid" if size_val <= 0 else "graffiti_size_exceeds_limit"
            return False
        return True


    def _validate_graffiti_comment_event(self, meta: dict) -> bool:
        comment_len = int(meta.get("comment_len", 0))
        if not (0 < comment_len <= int(CFG.GRAFFITI_COMMENT_MAX_BYTES)):
            self.blockchain._last_block_validation_error = "graffiti_comment_empty" if comment_len <= 0 else "graffiti_comment_too_large"
            return False
        if int(meta.get("amount", 0)) < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            self.blockchain._last_block_validation_error = "graffiti_comment_fee_too_low"
            return False
        if int(meta.get("tip", 0)) < 0:
            self.blockchain._last_block_validation_error = "graffiti_comment_tip_negative"
            return False
        return True


    def _spk_to_address(self, spk_obj) -> str | None:
        spk_bytes = extract_script_bytes(spk_obj)
        if spk_bytes and ((len(spk_bytes) == 22 and spk_bytes[:2] == b"\x00\x14") or (len(spk_bytes) == 34 and spk_bytes[:2] == b"\x00\x20")):
            data = [0] + list(convertbits(spk_bytes[2:], 8, 5, True))
            return bech32_encode(CFG.ADDRESS_PREFIX, data)
        return None


    def _txid_hex(self, value) -> str | None:
        if value is None:
            return None
        return value.hex() if type(value) in (bytes, bytearray) else str(value)


    def _normalize_snapshot_entry(self, entry: dict, key_desc: str) -> dict | None:
        tx_out = entry.get("tx_out", entry)
        script_bytes = extract_script_bytes(tx_out)
        if script_bytes is None:
            log.warning("[native_snapshot] entry %s missing script", key_desc)
            return None

        return {
            "amount": int(tx_out.amount or 0),
            "script_pubkey": script_bytes,
            "is_coinbase": bool(entry.get("is_coinbase", False)),
            "block_height": int(entry.get("block_height", 0)),
        }


    def _build_block_payload_compact(self, tx_list, snapshot_dict: dict):
        tx_payloads = [H.tx_to_compact_tuple(tx) for tx in tx_list]
        utxo_items = []
        for key, entry in snapshot_dict.items():
            if type(key) in (bytes, bytearray):
                key = key.decode("utf-8")
            if ":" not in key:
                continue
            txid_hex, vout_str = key.split(":", 1)
            utxo_items.append(
                (
                    bytes.fromhex(txid_hex),
                    int(vout_str),
                    int(entry.get("amount", 0)),
                    bytes(entry.get("script_pubkey", b"")),
                    bool(entry.get("is_coinbase", False)),
                    int(entry.get("block_height", 0)),
                )
            )
        return tx_payloads, utxo_items


    def _check_sigops_budget(self, block: Block, store: UTXODB) -> bool:
        lookup = store.lookup_entry
        total_sigops = 0
        for tx in (block.transactions or []):
            if tx.is_coinbase:
                continue

            so = int(
                tx.sigops_count(
                    lambda txid, vout: extract_script_bytes(
                        lookup(txid.hex() if type(txid) in (bytes, bytearray) else txid, int(vout))
                    )
                )
            )

            if so > int(CFG.MAX_SIGOPS_PER_TX):
                self.blockchain._last_block_validation_error = "sigops_per_tx_exceeded"
                return False
            total_sigops += so

        if total_sigops > int(CFG.MAX_SIGOPS_PER_BLOCK):
            self.blockchain._last_block_validation_error = "sigops_per_block_exceeded"
            return False
        return True