# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md
"""
A limited RPC bridge between nodes and graffiti modules.
Focus: payout & proof (no storage/archivist flow).
"""

import time
import base64
from typing import TYPE_CHECKING, Any, Optional

from ...utils import config as CFG
from ...utils.benchmarks import benchmark
from ...contracts import graffiti as GRAFFITI

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.storage_rpc")

if TYPE_CHECKING:
    from ..node import Network

__all__ = ["handle_storage_rpc"]


def handle_storage_rpc(
    self: "Network",
    message: dict[str, Any],
    addr,
    mtype: str,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:
    
    ip = str(addr[0]) if addr else "0.0.0.0"
    err = _check_storage_rate_limit(self, ip)
    if err: return err

    if not src_node_id:
        peer_meta = None
    else:
        peer_port = int(message.get("port", 0))
        with self.lock:
            peers = dict(self.storage_peers or {})
        peer_meta = _resolve_storage_sender_meta(self, peers, ip, peer_port, src_node_id, src_pubkey)

    if not peer_meta:
        log.warning("[storage_auth] forbidden storage RPC %s from %s", mtype, addr)
        return {"error": "forbidden: storage-only endpoint"}

    storer_addr = str(peer_meta.get("addr") or peer_meta.get("address") or "").strip().lower()
    if not storer_addr or not GRAFFITI._is_valid_tsar_address(storer_addr):
        log.warning("[storage_auth] invalid storer addr nid=%s ip=%s", src_node_id or "-", ip)
        return {"error": "storer_unregistered"}

    if mtype == "GRAFFITI_PROOF_SUBMIT":
        return _handle_storage_proof_submit(self, message, storer_addr, ip, src_node_id)
    elif mtype == "GRAFFITI_BUILD_PAYOUT":
        return _handle_storage_build_payout(self, message, storer_addr, ip, src_node_id)

    return None


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _check_storage_rate_limit(self, ip):
    rl_key = f"storage_rpc:{ip}"
    if not self.tb_node_allow(self.rl_ip, rl_key, CFG.STORAGE_RPC_RL_IP_BURST, CFG.STORAGE_RPC_RL_WINDOW_S, CFG.STORAGE_RPC_RL_IP_BURST, backoff_key=rl_key):
        self.backoff_node(rl_key, CFG.STORAGE_RPC_RL_BACKOFF_S)
        return {"error": "rate_limited"}
    return None


def _resolve_storage_sender_meta(_, peers, ip, peer_port, src_node_id, src_pubkey):
    best_meta = None
    best_score = -1
    for (peer_ip, peer_port_known), meta in peers.items():
        pinned_nid = (meta or {}).get("node_id")
        pinned_pk = (meta or {}).get("pubkey")
        if pinned_nid and pinned_nid != src_node_id:
            continue

        if pinned_pk and not src_pubkey:
            continue

        if pinned_pk and src_pubkey and pinned_pk != src_pubkey:
            log.warning("[storage_auth] pubkey mismatch nid=%s ip=%s", pinned_nid or "-", ip)
            continue

        if peer_ip != ip:
            continue

        score = -1
        if peer_port_known > 0 and peer_port > 0:
            if peer_port_known != peer_port:
                continue
            score = 2

        elif peer_port_known == 0 or peer_port == 0:
            score = 1

        if score > best_score:
            best_meta = meta
            best_score = score

    return best_meta


@benchmark(label="GRAFFITI_PROOF_SUBMIT", threshold_ms=100.0)
def _handle_storage_proof_submit(self, message, storer_addr, ip, src_node_id):
    ts_val = int(message.get("ts", 0))
    nonce_val = str(message.get("nonce") or "")
    sender_key = src_node_id or ip
    if not (ts_val and nonce_val and self.nonce_guard("storage_proof", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
        return {"error": "replay_guard"}

    err, basic_fields = _validate_proof_basic_fields(message, storer_addr)
    if err: return err
    art_id, epoch, offset, length, proof_hash, storer, height, seed = basic_fields

    try:
        reg = self.broadcast.utxodb._graffiti_registry
    except AttributeError:
        reg = None
    if not reg:
        return {"error": "registry_unavailable"}
    post = reg.get_post(art_id)
    if not post:
        return {"error": "unknown_art_id"}
    size = int(post.get("size") or 0)
    if size <= 0 or (offset + length) > size:
        return {"error": "out_of_range", "size": size}

    err, merkle_meta = _validate_merkle_meta(post)
    if err: return err
    mroot, mchunk, mcount = merkle_meta

    challenge = _validate_proof_challenge(self, epoch, height, art_id, size, mroot, mchunk, offset, length, seed)
    if "error" in challenge:
        return challenge

    err = _verify_proof_merkle_chunk(message, length, proof_hash, mroot, mchunk, mcount, offset)
    if err: return err

    existing = reg.get_proof(art_id, storer, epoch)
    if existing:
        existing_hash = str(existing.get("hash") or "").strip().lower()
        if existing_hash and existing_hash != proof_hash:
            log.error("[GRAFFITI_PROOF_SUBMIT] proof conflict: proof_hash=%s existing_hash=%s", proof_hash, existing_hash)
            return {"error": "proof_conflict"}
    
    reg.record_proof(
        art_id=art_id,
        storer=storer,
        epoch=epoch,
        offset=offset,
        length=length,
        proof_hash=proof_hash,
        height=height,
        seed=str(challenge.get("seed", "")),
    )
    return {"status": "ok", "art_id": art_id, "epoch": epoch}


@benchmark(label="GRAFFITI_BUILD_PAYOUT", threshold_ms=750.0)
def _handle_storage_build_payout(self, message, storer_addr, ip, src_node_id):
    ts_val = int(message.get("ts", 0))
    nonce_val = str(message.get("nonce") or "")
    sender_key = src_node_id or ip
    if not (ts_val and nonce_val and self.nonce_guard("storage_payout", sender_key, nonce_val, ts_val, CFG.REPLAY_WINDOW_SEC)):
        return {"error": "replay_guard"}
        
    art_id_raw = str(message.get("art_id") or "").strip()
    art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
    
    err, recipients = _parse_payout_recipients(message, storer_addr)
    if err: return err

    fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
    epoch_req = int(message.get("epoch", -1))
    try:
        utxo = self.broadcast.utxodb
    except AttributeError:
        utxo = None
    
    if utxo is None:
        return {"error": "utxo_unavailable"}
    
    try:
        reg = utxo._graffiti_registry
    except AttributeError:
        reg = None
    proof_entry = reg.get_latest_proof(art_id, storer_addr) if reg else None
    proof_meta = None
    if proof_entry:
        proof_meta = {
            "offset": proof_entry.get("offset"),
            "length": proof_entry.get("length"),
            "hash": proof_entry.get("hash"),
            "seed": proof_entry.get("seed"),
            "height": proof_entry.get("height"),
            "epoch": proof_entry.get("epoch"),
            "storer": proof_entry.get("storer"),
        }

    tip_height = int(self.broadcast.blockchain.height or 0)
    tip_epoch = GRAFFITI.compute_proof_epoch(tip_height)
    
    err, epoch = _validate_payout_epoch(epoch_req, tip_epoch, proof_entry)
    if err: return err

    err = _check_payout_cooldown(self, art_id, storer_addr)
    if err: return err

    tx_obj = GRAFFITI.build_payout_tx(
        utxo_db=utxo,
        art_id=art_id,
        recipients=recipients,
        fee_rate=fee_rate,
        epoch=epoch if epoch >= 0 else None,
        proof=proof_meta,
    )

    broadcast_flag = bool(message.get("broadcast"))
    if broadcast_flag:
        tx_msg = {"type": "NEW_TX", "data": tx_obj.to_dict(include_txid=True)}
        if CFG.ENABLE_DANDELION_PP:
            tx_msg["phase"] = "stem"
        ok = self.broadcast.receive_tx(tx_msg, None, self.peers)
        if not ok:
            log.warning("[payout] broadcast failed art=%s", art_id[:16])
            return {"error": "broadcast_failed"}
        
    return {"status": "ok", "tx": tx_obj.to_dict(include_txid=True)}


def _proof_epoch_window(self) -> tuple[int, int, int]:
    tip_height = int(self.broadcast.blockchain.height or 0)
    tip_epoch = GRAFFITI.compute_proof_epoch(tip_height)
    drift = int(CFG.GRAFFITI_PROOF_EPOCH_DRIFT)
    return tip_epoch, max(0, tip_epoch - drift), tip_epoch + drift


def _validate_proof_basic_fields(message, storer_addr):
    art_id_raw = str(message.get("art_id") or "").strip()
    art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
    epoch = int(message.get("epoch", -1))
    offset = int(message.get("offset", -1))
    length = int(message.get("length", -1))
    proof_hash = str(message.get("hash") or "").strip().lower()
    storer = str(message.get("storer") or "").strip().lower()
    height = int(message.get("height", 0) or 0)
    seed = str(message.get("seed") or "").strip().lower()
    
    if epoch < 0 or offset < 0 or length <= 0 or not GRAFFITI._is_valid_sha256_hex(proof_hash):
        return {"error": "bad_fields"}, None
    if not storer:
        return {"error": "missing_storer"}, None
    if storer != storer_addr:
        log.error("[GRAFFITI_PROOF_SUBMIT] missmatch storer: storer=%s storer_addr=%s", storer, storer_addr)
        return {"error": "storer_mismatch"}, None
        
    return None, (art_id, epoch, offset, length, proof_hash, storer, height, seed)


def _validate_merkle_meta(post):
    mroot = post.get("mroot") or post.get("merkle_root")
    mchunk = post.get("mchunk") or post.get("merkle_chunk")
    mcount = post.get("mcount") or post.get("merkle_count")
    if mroot or mchunk or mcount:
        if not (mroot and mchunk and mcount):
            return {"error": "merkle_meta_incomplete"}, None
        try:
            mchunk = int(mchunk)
            mcount = int(mcount)
        except Exception:
            return {"error": "merkle_meta_invalid"}, None
        if mchunk <= 0 or mcount <= 0:
            return {"error": "merkle_meta_invalid"}, None
        if not GRAFFITI._is_valid_sha256_hex(str(mroot)):
            return {"error": "merkle_root_invalid"}, None
    return None, (mroot, mchunk, mcount)


def _validate_proof_challenge(self, epoch, height, art_id, size, mroot, mchunk, offset, length, seed):
    if height < 0:
        height = 0
    if GRAFFITI.compute_proof_epoch(height) != epoch:
        return {"error": "epoch_mismatch"}
    tip_epoch, min_epoch, max_epoch = _proof_epoch_window(self)
    if epoch < min_epoch or epoch > max_epoch:
        log.error("[GRAFFITI_PROOF_SUBMIT] epoch out of range: epoch=%s tip_epoch=%s min_epoch=%s max_epoch=%s", epoch, tip_epoch, min_epoch, max_epoch)
        return {"error": "epoch_out_of_range", "tip_epoch": tip_epoch}
    challenge = GRAFFITI.calc_proof_challenge(
        art_id,
        size,
        height,
        chunk_bytes=int(mchunk) if mroot else None,
    )
    if int(challenge.get("offset", -1)) != offset or int(challenge.get("length", -1)) != length:
        return {"error": "challenge_mismatch"}
    if seed and seed != challenge.get("seed"):
        return {"error": "seed_mismatch"}
    return challenge


def _verify_proof_merkle_chunk(message, length, proof_hash, mroot, mchunk, mcount, offset):
    if not mroot:
        return None
    chunk_b64 = message.get("chunk")
    path = message.get("path")
    if type(chunk_b64) is not str or not chunk_b64:
        return {"error": "merkle_chunk_required"}
    if type(path) is not list:
        return {"error": "merkle_path_required"}
    try:
        chunk_bytes = base64.b64decode(chunk_b64.encode("ascii"), validate=True)
    except Exception:
        return {"error": "merkle_chunk_invalid"}
    if len(chunk_bytes) != int(length):
        return {"error": "merkle_chunk_length"}
    computed_hash = GRAFFITI.hash_proof_chunk(chunk_bytes)
    if computed_hash != proof_hash:
        return {"error": "merkle_chunk_hash_mismatch"}
    if mchunk and offset % int(mchunk) != 0:
        return {"error": "merkle_offset_mismatch"}
    if mchunk:
        idx = offset // int(mchunk)
        if idx < 0 or (mcount is not None and idx >= int(mcount)):
            return {"error": "merkle_index_out_of_range"}
    if not GRAFFITI.verify_merkle_path(str(mroot), proof_hash, path):
        return {"error": "merkle_path_invalid"}
    return None


def _parse_payout_recipients(message, storer_addr):
    recipients = message.get("recipients") or []
    if type(recipients) is dict:
        recipients = [{"addr": a, "amount": v} for a, v in recipients.items()]
    if not recipients and message.get("recipient") and message.get("amount"):
        amt = int(message.get("amount", 0))
        recipients = [{"addr": str(message.get("recipient")).strip(), "amount": amt}]
    if type(recipients) is not list or not recipients:
        return {"error": "bad_recipients"}, None
    if len(recipients) != 1:
        return {"error": "payout_requires_single_recipient"}, None
    
    rec = recipients[0] if type(recipients[0]) is dict else {}
    rec_addr = str(rec.get("addr") or rec.get("address") or "").strip().lower()
    rec_amt = int(rec.get("amount", 0) or 0)
    
    if not rec_addr or not GRAFFITI._is_valid_tsar_address(rec_addr) or rec_amt <= 0:
        return {"error": "bad_recipients"}, None
    if rec_addr != storer_addr:
        return {"error": "payout_recipient_mismatch"}, None
        
    return None, [{"addr": rec_addr, "amount": rec_amt}]


def _validate_payout_epoch(epoch, tip_epoch, proof_entry):
    if epoch >= 0:
        if epoch > tip_epoch:
            return {"error": "epoch_in_future", "tip_epoch": tip_epoch}, None
        if not proof_entry:
            return {"error": "missing_proof", "requested_epoch": epoch}, None
        proof_epoch = int(proof_entry.get("epoch", -1))
        if proof_epoch != epoch:
            return {"error": "proof_epoch_mismatch", "requested_epoch": epoch, "have": proof_epoch}, None
    else:
        if proof_entry:
            epoch = int(proof_entry.get("epoch", -1))
        if epoch > tip_epoch:
            return {"error": "epoch_in_future", "tip_epoch": tip_epoch}, None
        if not proof_entry:
            return {"error": "missing_proof"}, None
    return None, epoch


def _check_payout_cooldown(self, art_id, storer_addr):
    cooldown = int(CFG.ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC)
    if cooldown > 0:
        now = int(time.time())
        guard_key = f"{art_id}:{storer_addr}"
        with self.lock:
            try:
                guard = self._payout_guard
            except AttributeError:
                self._payout_guard = {}
                guard = self._payout_guard
            if guard is None:
                self._payout_guard = {}
                guard = self._payout_guard
            last_ts = int(guard.get(guard_key, 0) or 0)
            if last_ts and (now - last_ts) < cooldown:
                return {
                    "error": "payout_cooldown",
                    "retry_after": int(cooldown - (now - last_ts)),
                }
            guard[guard_key] = now
    return None