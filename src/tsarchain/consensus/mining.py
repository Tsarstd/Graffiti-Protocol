# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: LWMA-Zawy

from __future__ import annotations

import time
import multiprocessing as mp
from multiprocessing.synchronize import Event as MpEvent

# ---------------- Local Project ----------------
from ..core.block import Block
from ..utils import config as CFG
from ..storage.utxo import UTXODB
from ..mempool.pool import TxPool
from ..core.coinbase import CoinbaseTx
from ..contracts import graffiti as GRAFFITI

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.consensus.mining')

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .blockchain import Blockchain

class MiningManager:
    def __init__(self, blockchain: "Blockchain"):
        self.blockchain = blockchain


    def mine_block(
        self,
        miner_address: str,
        use_cores: int | None = None,
        cancel_event: MpEvent | None = None,
        progress_queue: mp.Queue | None = None,
    ) -> Block | None:

        if not self._validate_chain_state():
            return None

        height = len(self.blockchain.chain)
        last_block = self.blockchain.chain[-1] if self.blockchain.chain else None
        reward = self._calculate_reward(height)
        pool = self._ensure_mempool()

        txs_from_mempool = self._fetch_sorted_mempool_txs(pool)
        new_block = self._build_candidate_block(
            miner_address=miner_address,
            height=height,
            reward=reward,
            last_block=last_block,
            pool=pool,
            txs_from_mempool=txs_from_mempool
        )

        found = new_block.mine(
            use_cores=use_cores,
            stop_event=cancel_event,
            progress_queue=progress_queue,
        )
        if not found:
            return None
        
        if self._is_stale_block(new_block):
            return None
            
        self._apply_mining_cooloff()
                
        if not self._validate_and_add_block(new_block):
            return None
        
        return new_block


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _validate_chain_state(self) -> bool:
        if self.blockchain._reload_chain_from_kv() and not self.blockchain.chain:
            log.warning("[_validate_chain_state] chain reloaded from LMDB; continuing mining")
                
        if not self.blockchain.chain:
            log.warning("[_validate_chain_state] refusing to mine on empty chain; run --init-genesis or sync from peers first.")
            return False

        if self.blockchain._has_pending_blocks():
            log.warning("[_validate_chain_state] pending blocks detected; skipping mining")
            return False

        if not self.blockchain._is_chain_consistent():
            log.warning("[_validate_chain_state] chain inconsistency detected; syncing first")
            return False

        return True


    def _calculate_reward(self, height: int) -> int:
        reward = self.blockchain.get_block_reward(height)
        if self.blockchain.total_supply + reward > CFG.MAX_SUPPLY:
            return max(0, CFG.MAX_SUPPLY - self.blockchain.total_supply)
        return reward


    def _ensure_mempool(self) -> TxPool:
        pool = self.blockchain.get_mempool()
        if pool is None:
            pool = TxPool(utxo_store=self.blockchain.ensure_utxodb())
            self.blockchain.attach_mempool(pool)
        return pool


    def _fetch_sorted_mempool_txs(self, pool: TxPool) -> list:
        txs_raw = pool.get_all_txs()
        graff_posts = [tx for tx in txs_raw if self._is_graffiti_post(tx)]
        other_txs = [tx for tx in txs_raw if not self._is_graffiti_post(tx)]
        graff_posts.sort(key=self._received_at)
        other_txs.sort(key=lambda t: (-self._fee(t), self._received_at(t)))
        return graff_posts + other_txs


    def _build_candidate_block(self, miner_address: str, height: int, reward: int, last_block: Block | None, pool: TxPool, txs_from_mempool: list) -> Block:
        store = self.blockchain.ensure_utxodb() or UTXODB()
        current_utxos = store.utxos
        temp_utxos = current_utxos.copy() if type(current_utxos) is dict else dict(current_utxos)

        valid_txs = []
        used_utxos_in_block = set()
        graffiti_post_seen = False

        for tx in txs_from_mempool:
            if any((txin.txid, txin.vout) in used_utxos_in_block for txin in tx.inputs):
                continue

            if not pool.validate_transaction(tx, temp_utxos, spend_at_height=height):
                reason = pool.last_error_reason
                if reason:
                    txid = tx.txid or b""
                    txid_hex = txid.hex() if type(txid) in (bytes, bytearray) else str(txid or "")
                    log.warning("[_build_candidate_block] tx %s rejected: %s", txid_hex[:12], reason)
                continue

            is_graff_post = self._is_graffiti_post(tx)
            if is_graff_post and graffiti_post_seen:
                txid = tx.txid or b""
                txid_hex = txid.hex() if type(txid) in (bytes, bytearray) else str(txid or "")
                log.info("[_build_candidate_block] skip extra Graffiti POST tx=%s (quota per block = 1)", txid_hex[:12])
                continue

            for txin in tx.inputs:
                used_utxos_in_block.add((txin.txid, txin.vout))
            
            valid_txs.append(tx)
            if is_graff_post:
                graffiti_post_seen = True
            
            self.blockchain._utxodb.apply_tx_to_utxoset(tx, temp_utxos)

        total_fee = sum(self._fee(tx) for tx in valid_txs)
        coinbase_value = reward + total_fee

        graffiti_art_id = self._select_graffiti_art_id(valid_txs)
        coinbase_kwargs = {"to_address": miner_address, "reward": coinbase_value, "height": height}
        if graffiti_art_id:
            coinbase_kwargs["block_id"] = graffiti_art_id
            log.info("[_build_candidate_block] Anchoring block_id to graffiti art_id %s", graffiti_art_id[:32])

        coinbase = CoinbaseTx(**coinbase_kwargs)
        coinbase.compute_txid()

        prev_hash = last_block.hash() if last_block else CFG.ZERO_HASH
        new_block = Block(height, prev_hash, [coinbase] + valid_txs)

        if height > 0:
            new_block.bits = self.blockchain.calculate_expected_bits(height)
            
        return new_block


    def _is_stale_block(self, new_block: Block) -> bool:
        latest = self.blockchain.get_last_block()
        if not latest:
            return False
            
        latest_hash = latest.hash()
        new_prev_hash = new_block.prev_block_hash
        new_height = int(new_block.height or 0)
        latest_height = int(latest.height if latest.height is not None else -1)
        is_stale = latest_hash != new_prev_hash or new_height != latest_height + 1
        
        if is_stale:
            new_prev_hex = new_prev_hash.hex() if type(new_prev_hash) in (bytes, bytearray) else str(new_prev_hash or "")
            latest_hex = latest_hash.hex() if type(latest_hash) in (bytes, bytearray) else str(latest_hash or "")
            log.warning(
                "[_is_stale_block] discard stale candidate height=%s prev=%s latest=%s",
                new_height,
                new_prev_hex,
                latest_hex,
            )
        return is_stale


    def _apply_mining_cooloff(self):
        cooloff = float(CFG.MINING_COOLDOWN_AFTER_BLOCK)
        if cooloff > 0:
            cooloff_until = float(self.blockchain._mining_cooloff_until or 0.0)
            remain = cooloff_until - time.time()
            if remain > 0:
                time.sleep(min(remain, cooloff))


    def _validate_and_add_block(self, new_block: Block) -> bool:
        height = int(new_block.height or 0)
        blk_hash = new_block.hash()
        blk_hex = blk_hash.hex() if type(blk_hash) in (bytes, bytearray) else str(blk_hash or "")
        
        if not self.blockchain.validate_block(new_block):
            reason = self.blockchain._last_block_validation_error or "unknown"
            prev_hash = new_block.prev_block_hash
            prev_hex = prev_hash.hex() if type(prev_hash) in (bytes, bytearray) else str(prev_hash or "")
            
            log.warning(
                "[block_reject] stage=validate source=local_miner height=%s hash=%s prev=%s reason=%s",
                height,
                blk_hex[:16] if blk_hex else None,
                prev_hex,
                reason,
            )
            return False
        
        if not self.blockchain.add_block(new_block):
            reason = self.blockchain._last_block_validation_error or "unknown"
            log.warning(
                "[block_reject] stage=add_block source=local_miner height=%s hash=%s reason=%s",
                height,
                blk_hex[:16] if blk_hex else None,
                reason,
            )
            return False
            
        return True


    def _select_graffiti_art_id(self, txs) -> str | None: #NOSONAR
        """
        Inspect candidate transactions for a valid Graffiti POST event and return its art_id.
        Only the first valid POST per block is used to anchor the block_id.
        A valid POST must pay >= min_upload_fee to the art's pool address.
        """
        for tx in txs:
            outputs = tx.outputs or []
            for tx_out in outputs:
                spk = tx_out.script_pubkey
                if spk is None:
                    continue
                meta = GRAFFITI.parse_from_script(spk)
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

                paid = 0
                for out in outputs:
                    if out.address == pool_addr:
                        paid += int(out.amount or 0)

                if paid < min_fee:
                    log.warning("[_select_graffiti_art_id] Rejecting candidate POST with insufficient pool fee: paid=%s required=%s art_id=%s", paid, min_fee, art_id[:16])
                    continue
                
                txid = tx.txid
                txid_hex = txid.hex() if type(txid) in (bytes, bytearray) else str(txid or "")
                log.info("[_select_graffiti_art_id] Graffiti POST found tx=%s art_id=%s", (txid_hex or "")[:12], art_id[:24])
                return art_id
        return None
    
    
    def _is_graffiti_post(self, tx_obj) -> bool:
        outputs = tx_obj.outputs or []
        for tx_out in outputs:
            spk = tx_out.script_pubkey
            if spk is None:
                continue
            meta = GRAFFITI.parse_from_script(spk)
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
            
            paid = 0
            for out in outputs:
                if out.address == pool_addr:
                    paid += int(out.amount or 0)
            
            if paid >= min_fee:
                return True
        return False


    def _received_at(self, tx_obj) -> float:
        return float(tx_obj._received_at or 0)


    def _fee(self, tx_obj) -> int:
        return int(tx_obj.fee or 0)