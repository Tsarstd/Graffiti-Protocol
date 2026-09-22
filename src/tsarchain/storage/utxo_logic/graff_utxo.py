# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: BIP141; BIP173

from typing import Any
from ...mempool.scripts import script_to_address, extract_script_bytes
from ...contracts import graffiti as GRAFFITI
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.storage.utxo_logic.graff_utxo")


class UTXOGraffitiMixin:
    @staticmethod
    def _script_bytes(spk) -> bytes:
        res = extract_script_bytes(spk)
        return res if res is not None else b""


    def script_to_address(self, script) -> str | None:
        """
        Attempt to turn common script types (P2WPKH) into a bech32 address.
        Needed for Graffiti payout validation.
        """
        return script_to_address(script)


    def _record_graffiti_event(self, tx, outputs_info: list[dict[str, Any]], block_height: int | None, block_hash: str | None = None) -> None:
        if block_height is None:
            return

        tx_txid = tx.txid
        txid_hex = self._txid_hex(tx_txid)
        meta = None
        for info in outputs_info:
            script_bytes = info.get("script_bytes") or b""
            if script_bytes and script_bytes[0] == 0x6a:
                payload = self._read_opreturn_payload(script_bytes)
                if payload:
                    candidate = GRAFFITI.parse_payload(payload)
                    if candidate:
                        meta = candidate
                        break
        if not meta:
            return
        
        event = str(meta.get("event", "POST")).upper()
        if event == "POST":
            self._handle_graffiti_post(meta, outputs_info, txid_hex, block_height, block_hash)
        elif event == "COMMENT":
            self._handle_graffiti_comment(meta, outputs_info, txid_hex, block_height)
        elif event == "PAYOUT":
            self._handle_graffiti_payout(meta, outputs_info, txid_hex, block_height)


    def _handle_graffiti_post(
        self,
        meta: dict[str, Any],
        outputs_info: list[dict[str, Any]],
        txid_hex: str,
        block_height: int,
        block_hash: str | None = None
    ) -> None:
        
        sha_hex = str(meta.get("sha256") or "")
        creator = (meta.get("creator") or "").strip().lower()
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id and sha_hex and creator:
            art_id = GRAFFITI.compute_art_id(sha_hex, creator)
        if not art_id:
            log.warning("[_handle_graffiti_post] POST missing art_id/creator sha=%s tx=%s", sha_hex[:16], txid_hex)
            return
        pool_addr = GRAFFITI.derive_pool_address(art_id)
        min_fee = int(GRAFFITI.calc_upload_fee_sats(int(meta.get("size", 0))))
        
        paid = sum(int(info.get("amount", 0)) for info in outputs_info if info.get("address") == pool_addr)
        if paid < min_fee:
            log.warning("[_handle_graffiti_post] POST fee too low: paid=%s required=%s tx=%s", paid, min_fee, txid_hex)
            return
        
        entry = {
            "sha256": sha_hex,
            "size": int(meta.get("size", 0)),
            "mime": meta.get("mime"),
            "storer": meta.get("storer"),
            "receipt": meta.get("receipt"),
            "creator": creator,
            "block_hash": block_hash,
            "mroot": meta.get("mroot"),
            "mchunk": meta.get("mchunk"),
            "mcount": meta.get("mcount"),
        }
        self._graffiti_registry.record_post(art_id, entry, txid_hex, block_height, pool_addr, paid, block_hash=block_hash)
        current_pool_balance = self.get_balance(pool_addr, mode="total")
        self._graffiti_registry.set_pool_balance(art_id, current_pool_balance)


    def _handle_graffiti_comment(
        self,
        meta: dict[str, Any],
        outputs_info: list[dict[str, Any]],
        txid_hex: str,
        block_height: int
    ) -> None:
        
        art_id = str(meta.get("art_id") or "").lower()
        if not art_id:
            return

        post_entry = self._graffiti_registry.get_post(art_id)
        if not post_entry:
            log.warning("[_handle_graffiti_comment] COMMENT references unknown art_id=%s tx=%s", art_id, txid_hex)
            return

        pool_addr = post_entry.get("pool_address", GRAFFITI.derive_pool_address(art_id))
        creator_addr = post_entry.get("creator", meta.get("creator"))
        if not creator_addr:
            log.warning("[_handle_graffiti_comment] COMMENT missing creator for art_id=%s", art_id)
            return

        base_amount = int(meta.get("amount", 0))
        tip = int(meta.get("tip", 0))
        if base_amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
            log.warning("[_handle_graffiti_comment] COMMENT amount %s below minimum for art_id=%s", base_amount, art_id)
            return

        split = GRAFFITI.calc_comment_split(base_amount, tip)
        paid_creator = sum(int(info.get("amount", 0)) for info in outputs_info if info.get("address") == creator_addr)
        paid_pool = sum(int(info.get("amount", 0)) for info in outputs_info if info.get("address") == pool_addr)

        if paid_creator < split["creator_total"]:
            log.warning("[_handle_graffiti_comment] COMMENT royalty shortfall for art_id=%s paid=%s req=%s", art_id, paid_creator, split["creator_total"])
        if paid_pool < split["storage"]:
            log.warning("[_handle_graffiti_comment] COMMENT storage share shortfall for art_id=%s paid=%s req=%s", art_id, paid_pool, split["storage"])
            
        self._graffiti_registry.record_comment(
            art_id=art_id,
            meta=meta,
            txid=txid_hex,
            block_height=block_height,
            creator_paid=paid_creator,
            storage_paid=paid_pool,
        )
        current_pool_balance = self.get_balance(pool_addr, mode="total")
        self._graffiti_registry.set_pool_balance(art_id, current_pool_balance)


    def _handle_graffiti_payout(
        self,
        meta: dict[str, Any],
        outputs_info: list[dict[str, Any]],
        txid_hex: str,
        block_height: int
    ) -> None:

        art_id = str(meta.get("art_id") or "").lower()
        if not art_id:
            return

        pool_addr = GRAFFITI.derive_pool_address(art_id)
        post_entry = self._graffiti_registry.get_post(art_id)
        if not post_entry:
            log.warning("[_handle_graffiti_payout] PAYOUT references unknown art_id=%s tx=%s", art_id, txid_hex)
            return

        stats = post_entry.setdefault("stats", {})
        pool_balance = int(stats.get("pool_balance", 0))
        last_epoch = int(stats.get("last_paid_epoch", -1))
        recs = meta.get("recipients") or []
        if type(recs) is not list or not recs:
            log.warning("[_handle_graffiti_payout] PAYOUT missing recipients art_id=%s tx=%s", art_id, txid_hex)
            return

        epoch = int(meta.get("epoch", -1))
        # Idempotent replay: allow same-epoch payout if txid already recorded; otherwise reject rewind.
        if epoch >= 0 and last_epoch >= 0 and epoch <= last_epoch:
            already = False
            payouts = self._graffiti_registry.data.get("payouts", {}).get(art_id, [])
            already = any(p.get("txid") == txid_hex for p in payouts)
            if already:
                # Ensure pool balance stays in sync with UTXO set even when we skip re-recording.
                current_pool_balance = self.get_balance(pool_addr, mode="total")
                self._graffiti_registry.set_pool_balance(art_id, current_pool_balance)
                return

            log.warning("[_handle_graffiti_payout] PAYOUT epoch rewind art_id=%s epoch=%s last=%s tx=%s", art_id, epoch, last_epoch, txid_hex)
            return

        # Aggregate payments to recipients observed on-chain
        paid_map: dict[str, int] = {}
        for rec in recs:
            addr = str(rec.get("addr", rec.get("address", ""))).strip().lower()
            amt_req = int(rec.get("amount", 0))
            if not addr or amt_req <= 0:
                continue
    
            paid_actual = sum(int(info.get("amount", 0)) for info in outputs_info if (info.get("address") or "").strip().lower() == addr)
            if paid_actual < amt_req:
                log.warning("[_handle_graffiti_payout] PAYOUT shortfall to %s for art_id=%s paid=%s req=%s", addr, art_id, paid_actual, amt_req)
            paid_map[addr] = max(paid_actual, amt_req)

        if not paid_map:
            log.warning("[_handle_graffiti_payout] PAYOUT no valid recipients art_id=%s tx=%s", art_id, txid_hex)
            return

        total_paid = sum(paid_map.values())
        if total_paid > pool_balance:
            log.warning("[_handle_graffiti_payout] PAYOUT exceeds pool balance art_id=%s total=%s pool=%s tx=%s", art_id, total_paid, pool_balance, txid_hex)
            return

        # Optional: record proof metadata embedded in payout so new nodes can replay state from chain data.
        proof_epoch = meta.get("proof_epoch")
        proof_height = meta.get("proof_height", meta.get("height"))
        proof_offset = meta.get("proof_offset")
        proof_length = meta.get("proof_length")
        proof_hash = meta.get("proof_hash")
        proof_seed = meta.get("proof_seed", "")
        proof_storer = meta.get("proof_storer")
        # Derive epoch from height when explicit epoch is missing
        if proof_epoch is None and proof_height is not None:
            proof_epoch = GRAFFITI.compute_proof_epoch(int(proof_height))
        if proof_epoch is not None:
            pe = int(proof_epoch)
            poff = int(proof_offset) if proof_offset is not None else None
            plen = int(proof_length) if proof_length is not None else None
            ph = str(proof_hash).strip().lower() if proof_hash else None
            pstorer = str(proof_storer).strip().lower() if proof_storer else ""
            if (
                pstorer
                and poff is not None
                and plen is not None
                and ph
                and len(ph) == 64
            ):
                self._graffiti_registry.record_proof(
                    art_id=art_id,
                    storer=pstorer,
                    epoch=pe,
                    offset=poff,
                    length=plen,
                    proof_hash=ph,
                    height=int(proof_height) if proof_height is not None else block_height or 0,
                    seed=str(proof_seed or ""),
                )

        # Recalculate pool balance from UTXO set (total, not just mature)
        current_pool_balance = self.get_balance(pool_addr, mode="total")
        self._graffiti_registry.record_payout(
            art_id,
            paid_map,
            txid_hex,
            block_height,
            epoch=epoch if epoch >= 0 else None,
            pool_balance=current_pool_balance,
        )


    @staticmethod
    def _read_opreturn_payload(script_bytes: bytes) -> bytes | None:
        if not script_bytes or script_bytes[0] != 0x6a:
            return None
        i = 1
        if i >= len(script_bytes):
            return None
        first = script_bytes[i]
        i += 1
        if 1 <= first <= 75:
            n = first
            end = i + n
        elif first == 0x4c:
            if i >= len(script_bytes):
                return None
            n = script_bytes[i]
            i += 1
            end = i + n
        elif first == 0x4d:
            if i + 1 >= len(script_bytes):
                return None
            n = int.from_bytes(script_bytes[i:i+2], "little")
            i += 2
            end = i + n
        else:
            return None
        if end > len(script_bytes):
            return None
        return script_bytes[i:end]