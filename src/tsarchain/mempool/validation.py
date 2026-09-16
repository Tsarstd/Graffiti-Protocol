# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP143; BIP141

from __future__ import annotations

from typing import Any

from ..core.tx import Tx
from ..utils import config as CFG
from ..storage.utxo import UTXODB
from ..utils.benchmarks import benchmark
from .scripts import get_utxo_script_bytes, script_to_address
from ..contracts import graffiti as GRAFFITI
from ..contracts.graffiti_registry import GraffitiRegistry
from ..utils.helpers import (
    is_p2wpkh,
    is_p2wsh,
    last_pushdata,
    tx_to_compact_tuple,
    native_validate_tx_p2wpkh_compact,
    compute_tx_weight_vsize,
)

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.mempool.validation")

_PAYOUT_REJECT_MSG = "[mempool] payout reject art=%s reason=%s"

__all__ = ["TxMempoolValidator"]


class TxMempoolValidator:
    utxo: UTXODB
    last_error_reason: str | None

    @benchmark(label="validate_transaction_mempool", threshold_ms=15.0)
    def validate_transaction(self, tx: Tx, utxo_set: dict[str, Any], spend_at_height: int | None = None) -> bool:
        if not self._validate_tx_basic_guards(tx):
            return False

        current_height = spend_at_height if spend_at_height is not None else self.utxo._get_tip_height_from_state()
        try:
            # ---- Special handling for Graffiti PAYOUT (P2WSH pool) ----
            payout_meta = self._find_payout_meta(tx)
            if payout_meta:
                return self._validate_payout_tx(tx, payout_meta, utxo_set)

            compact_tx = tx_to_compact_tuple(tx)
            target_keys = {
                k for k in (self._txin_prevkey(tin) for tin in (tx.inputs or [])) if k
            }
            utxo_items = self._utxo_snapshot_to_items(utxo_set, target_keys=target_keys)
            opts = {
                "coinbase_maturity": CFG.COINBASE_MATURITY,
                "max_sigops_per_tx": CFG.MAX_SIGOPS_PER_TX,
                "max_sigops_per_block": CFG.MAX_SIGOPS_PER_BLOCK,
                "max_tx_vsize": CFG.MAX_TX_VSIZE,
                "min_tx_vsize": CFG.MIN_TX_VSIZE,
                "max_tx_weight": CFG.MAX_TX_WEIGHT,
                "min_tx_weight": CFG.MIN_TX_WEIGHT,
                "max_tx_inputs": CFG.MAX_TX_INPUTS,
                "max_tx_outputs": CFG.MAX_TX_OUTPUTS,
                "enforce_low_s": True,
            }
            ok, reason, fee = native_validate_tx_p2wpkh_compact(
                compact_tx,
                utxo_items,
                int(current_height),
                opts,
            )
            if not ok:
                self.last_error_reason = reason or "native_mempool_reject"
                log.warning(
                    "[validate_transaction] Native reject txid=%s reason=%s",
                    tx.txid,
                    self.last_error_reason,
                )
                return False

            tx.fee = int(fee or 0)
            if spend_at_height is None:
                if not self._enforce_mempool_post_limit(tx) or not self._check_mempool_payout_sanity(tx):
                    return False

            return True
        except Exception:
            log.exception("[validate_transaction] Native validation error for tx %s", tx.txid)
            self.last_error_reason = "native_mempool_failed"
            return False

# =============================================================================
# INTERNAL METHOD
# =============================================================================

    def _script_to_address(self, script) -> str | None:
        """Convert P2WPKH/P2WSH scriptPubKey to bech32 address."""
        return script_to_address(script)

    def _check_mempool_payout_sanity(self, tx: Tx) -> bool:
        reg = self.utxo._graffiti_registry or GraffitiRegistry()
        paymap: dict[str, int] = {}
        for out in tx.outputs or []:
            addr = self._script_to_address(out.script_pubkey)
            amt = int(out.amount or 0)
            if addr and amt > 0:
                addr_clean = addr.strip().lower()
                paymap[addr_clean] = paymap.get(addr_clean, 0) + amt

        return self._validate_payout_sanity(tx, paymap, reg)

    def _validate_payout_art_and_epoch(self, payout_meta: dict[str, Any], reg: GraffitiRegistry) -> bool:
        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        post = reg.get_post(art_id)
        if not post:
            self.last_error_reason = "payout_unknown_art"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False

        stats = post.get("stats") or {}
        last_epoch = int(stats.get("last_paid_epoch", -1))
        epoch = int(payout_meta.get("epoch", -1))
        if 0 <= epoch <= last_epoch:
            self.last_error_reason = "payout_epoch_rewind"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False

        if epoch >= 0:
            latest_proof = reg.get_latest_proof_epoch(art_id)
            if latest_proof is None or latest_proof < epoch:
                self.last_error_reason = "payout_missing_proof"
                log.warning(
                    "[mempool] payout reject art=%s reason=%s last_proof=%s epoch=%s",
                    art_id[:16],
                    self.last_error_reason,
                    latest_proof,
                    epoch,
                )
                return False
        return True

    def _validate_payout_recipients_and_balance(self, tx: Tx, payout_meta: dict[str, Any], post: dict[str, Any]) -> bool:
        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        stats = post.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))

        recs = payout_meta.get("recipients")
        if not recs or type(recs) is not list:
            self.last_error_reason = "payout_no_recipients"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False

        epoch = int(payout_meta.get("epoch", -1))
        reg = self.utxo._graffiti_registry or GraffitiRegistry()
        proof_entry = reg.get_proof(art_id, "", epoch)
        valid_storer = ""
        if type(proof_entry) is dict:
            storer_val = proof_entry.get("storer")
            if type(storer_val) is str:
                valid_storer = storer_val.strip().lower()

        paymap: dict[str, int] = {}
        for out in tx.outputs or []:
            amt = int(out.amount or 0)
            if amt <= 0:
                continue

            spk = out.script_pubkey
            spk_bytes = get_utxo_script_bytes({"tx_out": {"script_pubkey": spk}})
            if is_p2wpkh(spk_bytes) or is_p2wsh(spk_bytes):
                addr = self._script_to_address(spk)
                if addr:
                    paymap[addr.strip().lower()] = paymap.get(addr.strip().lower(), 0) + amt

        total_req = 0
        for rec in recs:
            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                self.last_error_reason = "payout_bad_recipient"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False
            if valid_storer and addr != valid_storer:
                self.last_error_reason = "payout_recipient_mismatch"
                log.warning(
                    "[mempool] payout reject art=%s reason=%s rec=%s storer=%s",
                    art_id[:16],
                    self.last_error_reason,
                    addr,
                    valid_storer,
                )
                return False

            total_req += amt_req
            if paymap.get(addr, 0) < amt_req:
                self.last_error_reason = "payout_shortfall"
                log.warning(
                    "[mempool] payout reject art=%s reason=%s paid=%s req=%s",
                    art_id[:16],
                    self.last_error_reason,
                    paymap.get(addr, 0),
                    amt_req,
                )
                return False

        if total_req > pool_balance:
            self.last_error_reason = "payout_exceeds_pool"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False
        return True

    def _validate_payout_inputs(self, tx: Tx, art_id: str, utxo_set: dict[str, Any]) -> bool:
        total_in = 0
        pool_script_hash = GRAFFITI.hash_pool_redeem_script(art_id)
        for txin in tx.inputs or []:
            prev_txid_hex = self._txin_prev_txid(txin)
            vout = int(txin.vout or 0)
            utxo_entry = self._lookup_utxo_entry(utxo_set, prev_txid_hex, vout)
            if not utxo_entry:
                self.last_error_reason = "missing_prevout"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False

            spk_bytes = get_utxo_script_bytes(utxo_entry)
            total_in += self._get_utxo_amount(utxo_entry)
            if not (is_p2wsh(spk_bytes) and len(spk_bytes) == 34):
                self.last_error_reason = "payout_prev_not_pool"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False

            if spk_bytes[2:].hex() != pool_script_hash:
                self.last_error_reason = "payout_wrong_pool"
                log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
                return False

        total_out = sum(int(o.amount or 0) for o in (tx.outputs or []))
        if total_out > total_in:
            self.last_error_reason = "payout_fee_negative"
            log.warning(_PAYOUT_REJECT_MSG, art_id[:16], self.last_error_reason)
            return False

        tx.fee = int(total_in - total_out)
        return True

    def _has_exceeded_mempool_post_limit(self, max_limit: int) -> bool:
        current_posts = 0
        for existing in self._pool.values():
            for out in existing.outputs or []:
                if out.script_pubkey is not None:
                    meta = GRAFFITI.parse_from_script(out.script_pubkey)
                    if meta and str(meta.get("event", "")).upper() == "POST":
                        current_posts += 1
                        if current_posts >= max_limit:
                            return True
        return False

    def _validate_single_payout_sanity(self, meta: dict[str, Any], paymap: dict[str, int], reg: GraffitiRegistry) -> bool:
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id:
            self.last_error_reason = "payout_bad_art_id"
            return False

        post = reg.get_post(art_id)
        if not post:
            self.last_error_reason = "payout_unknown_art"
            return False

        stats = post.get("stats") or {}
        pool_balance = int(stats.get("pool_balance", 0))
        last_epoch = int(stats.get("last_paid_epoch", -1))
        epoch = int(meta.get("epoch", -1))
        if 0 <= epoch <= last_epoch:
            self.last_error_reason = "payout_epoch_rewind"
            return False

        if epoch >= 0 and reg.get_latest_proof_epoch(art_id) < epoch:
            self.last_error_reason = "payout_missing_proof"
            return False

        recs = meta.get("recipients")
        if not recs or type(recs) is not list:
            self.last_error_reason = "payout_no_recipients"
            return False

        total_req = 0
        for rec in recs:
            addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                self.last_error_reason = "payout_bad_recipient"
                return False

            total_req += amt_req
            if paymap.get(addr, 0) < amt_req:
                self.last_error_reason = "payout_shortfall"
                return False

        if total_req > pool_balance:
            self.last_error_reason = "payout_exceeds_pool"
            return False
        return True

    def _validate_tx_basic_guards(self, tx: Tx) -> bool:
        if tx.is_coinbase:
            return False

        try:
            weight, vsize, _base_size, _total_size = compute_tx_weight_vsize(tx)
        except Exception:
            log.exception("[validate_transaction] weight_calc_failed txid=%s", tx.txid)
            self.last_error_reason = "tx_weight_calc_failed"
            return False

        inputs = tx.inputs or []
        outputs = tx.outputs or []
        if vsize > CFG.MAX_TX_VSIZE:
            self.last_error_reason = "tx_vsize_exceeds_limit"
            return False
        if vsize < CFG.MIN_TX_VSIZE:
            self.last_error_reason = "tx_vsize_below_min"
            return False
        if weight > CFG.MAX_TX_WEIGHT:
            self.last_error_reason = "tx_weight_exceeds_limit"
            return False
        if weight < CFG.MIN_TX_WEIGHT:
            self.last_error_reason = "tx_weight_below_min"
            return False
        if len(inputs) > CFG.MAX_TX_INPUTS:
            self.last_error_reason = "tx_inputs_exceed_limit"
            return False
        if len(outputs) > CFG.MAX_TX_OUTPUTS:
            self.last_error_reason = "tx_outputs_exceed_limit"
            return False

        for tx_out in outputs:
            if not self._validate_graffiti_output(tx_out.script_pubkey):
                return False
        return True

    def _find_payout_meta(self, tx: Tx) -> dict[str, Any] | None:
        for tx_out in tx.outputs or []:
            spk = tx_out.script_pubkey
            if spk is not None:
                meta = GRAFFITI.parse_from_script(spk)
                if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                    return meta
        return None

    def _validate_payout_tx(self, tx: Tx, payout_meta: dict[str, Any], utxo_set: dict[str, Any]) -> bool:
        reg = self.utxo._graffiti_registry or GraffitiRegistry()
        if not self._validate_payout_art_and_epoch(payout_meta, reg):
            return False

        art_id = str(payout_meta.get("art_id") or "").strip().lower()
        post = reg.get_post(art_id)
        if not self._validate_payout_recipients_and_balance(tx, payout_meta, post):
            return False

        return self._validate_payout_inputs(tx, art_id, utxo_set)

    def _enforce_mempool_post_limit(self, tx: Tx) -> bool:
        is_post = False
        outputs = tx.outputs or []
        for tx_out in outputs:
            spk = tx_out.script_pubkey
            if spk is None:
                continue
            meta = GRAFFITI.parse_from_script(spk)
            if meta and str(meta.get("event", "")).upper() == "POST":
                is_post = True
                art_id = str(meta.get("art_id") or "").strip().lower()
                if not art_id:
                    sha_hex = str(meta.get("sha256") or "").strip().lower()
                    creator = str(meta.get("creator") or "").strip().lower()
                    art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
                if art_id:
                    cur_sha = str(meta.get("sha256") or "").strip().lower()
                    cur_mroot = str(meta.get("mroot") or meta.get("merkle_root") or "").strip().lower()

                    # 1. Fast O(1) direct key lookup against permanent posts in GraffitiRegistry
                    reg = None
                    try:
                        reg = self.utxo._graffiti_registry
                    except AttributeError:
                        pass
                    if not reg:
                        reg = GraffitiRegistry()
                    try:
                        existing_post = reg.get_post(art_id)
                    except (AttributeError, TypeError):
                        existing_post = None
                    if type(existing_post) is dict:
                        ex_sha = str(existing_post.get("sha256") or "").strip().lower()
                        ex_mroot = str(existing_post.get("mroot") or existing_post.get("merkle_root") or "").strip().lower()
                        if cur_sha and cur_mroot and ex_sha == cur_sha and ex_mroot == cur_mroot:
                            self.last_error_reason = "graffiti_duplicate_post"
                            log.warning("[_enforce_mempool_post_limit] POST rejected as on-chain duplicate: art_id=%s", art_id[:16])
                            return False

                    # 2. Fast check against unconfirmed posts in mempool
                    pool = None
                    try:
                        pool = self._pool
                    except AttributeError:
                        pass
                    if type(pool) is dict:
                        for existing_tx in pool.values():
                            if existing_tx.txid == tx.txid:
                                continue
                            for out in (existing_tx.outputs or []):
                                if out.script_pubkey is not None:
                                    p_meta = GRAFFITI.parse_from_script(out.script_pubkey)
                                    if p_meta and str(p_meta.get("event", "")).upper() == "POST":
                                        p_art_id = str(p_meta.get("art_id") or "").strip().lower()
                                        if not p_art_id:
                                            p_sha = str(p_meta.get("sha256") or "").strip().lower()
                                            p_creator = str(p_meta.get("creator") or "").strip().lower()
                                            p_art_id = GRAFFITI.compute_art_id(p_sha, p_creator) if p_sha and p_creator else ""
                                        if p_art_id and p_art_id == art_id:
                                            p_ex_sha = str(p_meta.get("sha256") or "").strip().lower()
                                            p_ex_mroot = str(p_meta.get("mroot") or p_meta.get("merkle_root") or "").strip().lower()
                                            if cur_sha and cur_mroot and p_ex_sha == cur_sha and p_ex_mroot == cur_mroot:
                                                self.last_error_reason = "graffiti_duplicate_post"
                                                log.warning("[_enforce_mempool_post_limit] POST rejected as mempool duplicate: art_id=%s", art_id[:16])
                                                return False

                    try:
                        pool_addr = GRAFFITI.derive_pool_address(art_id)
                        min_fee = GRAFFITI.calc_upload_fee_sats(int(meta.get("size") or 0))
                        paid = sum(int(out.amount or 0) for out in outputs if out.address == pool_addr)
                        if paid < min_fee:
                            self.last_error_reason = "graffiti_post_fee_insufficient"
                            log.warning(
                                "[_enforce_mempool_post_limit] POST rejected due to insufficient pool fee: paid=%s required=%s art_id=%s",
                                paid,
                                min_fee,
                                art_id[:16],
                            )
                            return False
                    except Exception:
                        pass
                break

        if is_post and CFG.MAX_GRAFFITI_ON_MEMPOOL > 0:
            if self._has_exceeded_mempool_post_limit(CFG.MAX_GRAFFITI_ON_MEMPOOL):
                self.last_error_reason = "mempool_graffiti_full"
                return False
        return True

    def _validate_payout_sanity(self, tx: Tx, paymap: dict[str, int], reg: GraffitiRegistry) -> bool:
        for out in tx.outputs or []:
            spk = out.script_pubkey
            if spk is not None:
                meta = GRAFFITI.parse_from_script(spk)
                if meta and str(meta.get("event", "")).upper() == "PAYOUT":
                    if not self._validate_single_payout_sanity(meta, paymap, reg):
                        return False
        return True

    def _lookup_in_snapshot_dict(self, snapshot: dict, txid: str, txid_raw: str, idx: int):
        for k in (f"{txid}:{idx}", f"{txid_raw}:{idx}", (txid, idx), (txid_raw, idx), f"{txid}:{idx}".encode("utf-8")):
            if k in snapshot:
                return snapshot[k]

        bucket = snapshot.get(txid) or snapshot.get(txid_raw)
        if type(bucket) is dict:
            return bucket.get(idx)

        try:
            txid_bytes = bytes.fromhex(txid)
            if (txid_bytes, idx) in snapshot:
                return snapshot[(txid_bytes, idx)]
        except ValueError:
            pass
        return None

    def _get_utxo_amount(self, utxo_data) -> int:
        if type(utxo_data) is dict:
            if "tx_out" in utxo_data:
                txo = utxo_data["tx_out"]
                return int(txo.get("amount", 0)) if type(txo) is dict else int(txo.amount or 0)
            if "amount" in utxo_data:
                return int(utxo_data["amount"])
        else:
            try:
                amt = utxo_data.amount
                if amt is not None:
                    return int(amt)
            except AttributeError:
                pass
        raise ValueError(f"Unknown UTXO format: {utxo_data}")

    def _txin_prev_txid(self, tx_in) -> str | None:
        if type(tx_in) is dict:
            txid_val = tx_in.get("txid") if tx_in.get("txid") is not None else tx_in.get("prev_tx")
        else:
            txid_val = tx_in.txid if tx_in.txid is not None else tx_in.prev_tx
        if txid_val is None:
            return None
        if type(txid_val) in (bytes, bytearray):
            return txid_val.hex().lower()
        return str(txid_val).lower()

    def _txin_prevkey(self, tx_in) -> str | None:
        txid_hex = self._txin_prev_txid(tx_in)
        if not txid_hex:
            return None
        vout = tx_in.get("vout", 0) if type(tx_in) is dict else tx_in.vout
        return f"{txid_hex}:{int(vout or 0)}"

    def _lookup_utxo_entry(self, snapshot, prev_txid_hex: str, prev_index: int):
        if prev_txid_hex is None:
            return None
        idx = int(prev_index)
        txid_raw = str(prev_txid_hex)
        txid = txid_raw.lower()

        if type(snapshot) is dict:
            res = self._lookup_in_snapshot_dict(snapshot, txid, txid_raw, idx)
            if res is not None:
                return res

        lookup_method = self.utxo.lookup_entry
        if callable(lookup_method):
            return lookup_method(txid, idx)
        return None

    def _utxo_snapshot_to_items(self, snapshot, target_keys=None) -> list[tuple]:
        if type(snapshot) is not dict:
            return []
        items = []
        if target_keys is not None:
            for key in target_keys:
                entry = snapshot.get(key)
                if entry is None and type(key) is str:
                    entry = snapshot.get(key.encode("utf-8"))
                if entry is None:
                    continue
                key_str = key.decode("utf-8") if type(key) in (bytes, bytearray) else str(key)
                if ":" not in key_str:
                    continue
                txid_hex, vout_str = key_str.split(":", 1)
                txid_b = bytes.fromhex(txid_hex)
                vout_i = int(vout_str)
                amt = self._get_utxo_amount(entry)
                spk_bytes = get_utxo_script_bytes(entry)
                is_cb, born = self.utxo._get_utxo_meta(entry)
                items.append((txid_b, vout_i, int(amt), spk_bytes, bool(is_cb), int(born)))
            return items

        for key, entry in snapshot.items():
            key_str = key.decode("utf-8") if type(key) in (bytes, bytearray) else str(key)
            if ":" not in key_str:
                continue
            txid_hex, vout_str = key_str.split(":", 1)
            txid_b = bytes.fromhex(txid_hex)
            vout_i = int(vout_str)
            amt = self._get_utxo_amount(entry)
            spk_bytes = get_utxo_script_bytes(entry)
            is_cb, born = self.utxo._get_utxo_meta(entry)
            items.append((txid_b, vout_i, int(amt), spk_bytes, bool(is_cb), int(born)))
        return items

    # Graffiti OP_RETURN guard (size/comment/min fee)
    def _validate_graffiti_output(self, spk_obj) -> bool:
        raw = spk_obj.serialize()
        if not raw:
            return True
        data = last_pushdata(raw)
        if not data or not data.startswith(CFG.GRAFFITI_MAGIC):
            return True
        if len(data) > CFG.MAX_GRAFFITI_OPRET:
            self.last_error_reason = "graffiti_opreturn_too_large"
            return False
        meta = GRAFFITI.parse_payload(data)
        if not meta:
            self.last_error_reason = "graffiti_payload_invalid"
            return False
        event = str(meta.get("event", "")).upper()
        if event == "POST":
            size_val = int(meta.get("size", 0))
            if size_val <= 0:
                self.last_error_reason = "graffiti_size_invalid"
                return False
            if size_val > CFG.GRAFFITI_MAX_SIZE_BYTES:
                self.last_error_reason = "graffiti_size_exceeds_limit"
                return False
            art_id = str(meta.get("art_id") or "").strip().lower()
            if not art_id:
                sha_hex = str(meta.get("sha256") or "").strip().lower()
                creator = str(meta.get("creator") or "").strip().lower()
                art_id = GRAFFITI.compute_art_id(sha_hex, creator) if sha_hex and creator else ""
            if art_id:
                cur_sha = str(meta.get("sha256") or "").strip().lower()
                cur_mroot = str(meta.get("mroot") or meta.get("merkle_root") or "").strip().lower()
                reg = None
                try:
                    reg = self.utxo._graffiti_registry
                except AttributeError:
                    pass
                if reg:
                    try:
                        existing_post = reg.get_post(art_id)
                    except (AttributeError, TypeError):
                        existing_post = None
                    if type(existing_post) is dict:
                        ex_sha = str(existing_post.get("sha256") or "").strip().lower()
                        ex_mroot = str(existing_post.get("mroot") or existing_post.get("merkle_root") or "").strip().lower()
                        if cur_sha and cur_mroot and ex_sha == cur_sha and ex_mroot == cur_mroot:
                            self.last_error_reason = "graffiti_duplicate_post"
                            return False
        elif event == "COMMENT":
            comment_len = int(meta.get("comment_len", 0))
            if comment_len <= 0:
                self.last_error_reason = "graffiti_comment_empty"
                return False
            if comment_len > CFG.GRAFFITI_COMMENT_MAX_BYTES:
                self.last_error_reason = "graffiti_comment_too_large"
                return False
            if int(meta.get("amount", 0)) < CFG.GRAFFITI_COMMENT_MIN_FEE:
                self.last_error_reason = "graffiti_comment_fee_too_low"
                return False
            if int(meta.get("tip", 0)) < 0:
                self.last_error_reason = "graffiti_comment_tip_negative"
                return False
        return True