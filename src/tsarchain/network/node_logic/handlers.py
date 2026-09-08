# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import base64
import struct
import time
from typing import List

from ...utils import config as CFG
from ...utils.benchmarks import benchmark
from ...utils.helpers import decode_address
from ...utils.tsar_logging import get_ctx_logger
from .storage_registry import register_storage_peer

log = get_ctx_logger("tsarchain.network.node_logic.handlers")


def handle_hello(self, message, addr, *, src_node_id: str | None = None, src_pubkey: str | None = None):
    try:
        peer_ip = addr[0] if (addr and len(addr) > 0) else str(message.get("ip", "")).strip()
    except (TypeError, IndexError):
        peer_ip = str(message.get("ip", "")).strip()
    peer_port = int(message.get("port", 0))
    peer_tuple = (peer_ip, peer_port) if peer_ip and type(peer_port) is int and peer_port > 0 else None

    role = str(message.get("role", "")).strip().upper()
    advertised_height = int(message.get("height", -1))
    is_storage = role == "NODE_STORAGE"

    if is_storage:
        err = _process_storage_hello(self, message, peer_ip, peer_port, src_node_id, src_pubkey)
        if err:
            return err

    incoming_peers = message.get("peers") or []
    normalized_incoming = _process_incoming_peers(self, incoming_peers)

    with self.lock:
        if not is_storage:
            _update_peers_from_hello(self, peer_tuple, advertised_height, normalized_incoming)

        sane_peers = [{"ip": ip, "port": port} for ip, port in self.peers if type(port) is int and port > 0]
        height = int(self.broadcast.blockchain.height)
        peer_port_msg = int(message.get("port", -1))
        
        if (not is_storage) and type(addr) is tuple and peer_port_msg > 0:
            dst = (addr[0], peer_port_msg)
            self.broadcast.send_mempool_to_peer(dst)

    if (not is_storage) and peer_tuple:
        self.reward_peer(peer_tuple)
        
    return {
        "type": "HELLO_RESPONSE",
        "port": self.port,
        "height": height,
        "peers": sane_peers,
    }


@benchmark(label="handle_get_headers", threshold_ms=50.0)
def handle_get_headers(self, message, _):
    
    locator = message.get("locator") or []
    limit = int(message.get("limit", CFG.HEADERS_BATCH_MAX))
    limit = max(1, min(limit, CFG.HEADERS_BATCH_MAX))
    with self.broadcast.lock:
        chain = self.broadcast.blockchain.chain
        chain_len = len(chain)
        start_idx = 0
        if locator:
            locator_set = {str(cand).strip().lower() for cand in locator if cand}
            for idx in range(chain_len - 1, -1, -1):
                b_hash = self.bhash_hex(chain[idx]).lower()
                if b_hash in locator_set:
                    start_idx = idx + 1
                    break
        blks = list(chain[start_idx : start_idx + limit])

    headers = []
    for blk in blks:
        prev_hash = (
            blk.prev_block_hash.hex()
            if type(blk.prev_block_hash) in (bytes, bytearray)
            else str(blk.prev_block_hash)
        )

        blk_hash = blk.hash().hex() if callable(blk.hash) else (blk.hash.hex() if type(blk.hash) in (bytes, bytearray) else str(blk.hash or ""))

        b_height = blk.height
        b_ts = blk.timestamp
        b_bits = blk.bits

        headers.append(
            {
                "height": b_height,
                "hash": blk_hash,
                "prev_hash": prev_hash,
                "timestamp": b_ts,
                "bits": b_bits,
            }
        )
    more = (start_idx + limit) < chain_len

    return {
        "type": "HEADERS",
        "headers": headers,
        "more": more,
        "best_height": max(-1, chain_len - 1),
    }


@benchmark(label="handle_get_blocks", threshold_ms=30.0)
def handle_get_blocks(self, message, _):
        
    heights = message.get("heights") or []
    if type(heights) is not list:
        return {"type": "BLOCKS", "blocks": []}

    limit = min(len(heights), CFG.BLOCK_DOWNLOAD_BATCH_MAX)
    chunks: List[bytes] = []
    with self.broadcast.lock:
        chain = self.broadcast.blockchain.chain
        for raw_h in heights[:limit]:
            h = int(raw_h)
            if 0 <= h < len(chain):
                raw = chain[h].to_storage_bytes()
                chunks.append(struct.pack("<I", len(raw)) + raw)
    
    payload_bytes = b"".join(chunks)
    return {
        "type": "BLOCKS_BIN",
        "count": len(chunks),
        "data": base64.b64encode(payload_bytes).decode("ascii"),
    }


@benchmark(label="handle_get_block_at", threshold_ms=10.0)
def handle_get_block_at(self, height: int, src_tag: str | None = None) -> dict: #get block by heigt
        
    with self.broadcast.lock:
        chain = self.broadcast.blockchain.chain
        if height < 0 or height >= len(chain):
            return {"type": "BLOCK", "error": "height_out_of_range"}
        b = chain[height]

    d = self.serialize_block(b)
    d["type"] = "BLOCK"
    return d


@benchmark(label="handle_get_block_by_hash", threshold_ms=10.0)
def handle_get_block_by_hash(self, hx: str, src_tag: str | None = None) -> dict:
        
    hx = (hx or "").strip().lower()
    if hx.startswith("0x"):
        hx = hx[2:]
    target_b = None
    with self.broadcast.lock:
        chain = self.broadcast.blockchain.chain
        for b in reversed(chain):
            if self.bhash_hex(b).lower() == hx:
                target_b = b
                break

    if target_b is not None:
        d = self.serialize_block(target_b)
        d["type"] = "BLOCK"
        return d

    return {"type": "BLOCK", "error": "not_found"}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _process_storage_hello(self, message, peer_ip, peer_port, src_node_id, src_pubkey):
    if not (src_node_id and src_pubkey):
        return {"error": "storage_auth_required"}
    
    payout_addr = (message.get("address") or "").strip().lower()
    if not payout_addr:
        return {"error": "storage_address_required"}
    
    try:
        decode_address(payout_addr)
    except Exception:
        return {"error": "storage_address_invalid"}
    
    # enforce pin consistency
    with self.lock:
        storage_peers_dict = self.storage_peers or {}
        for _peer, meta in storage_peers_dict.items():
            if (meta or {}).get("node_id") == src_node_id:
                pinned_pk = (meta or {}).get("pubkey")
                if pinned_pk and pinned_pk != src_pubkey:
                    log.warning("[_process_storage_hello] storage pubkey change rejected nid=%s", src_node_id[:12])
                    return {"error": "storage_pubkey_pinned"}
    msg_port = int(message.get("port") or 0)
    storer_port = msg_port if msg_port > 0 else int(peer_port or 0)
    meta = {
        "addr": (message.get("address") or "").strip().lower(),
        "url": (message.get("url") or "").strip(),
        "ip": peer_ip,
        "port": storer_port,
        "last_seen": int(time.time()),
        "alive": True,
        "trusted": bool(message.get("trusted", False)),
        "node_id": src_node_id,
        "pubkey": src_pubkey,
    }
    register_storage_peer(self, peer_ip, meta)
    return None


def _process_incoming_peers(self, incoming_peers):
    normalized_incoming = []
    for entry in incoming_peers:
        if type(entry) is dict:
            ip = str(entry.get("ip") or entry.get("host") or "").strip()
            port = int(entry.get("port", 0))
            if not ip or port <= 0:
                continue
            if self._is_local_address(ip) and port == self.port:
                continue
            normalized_incoming.append((ip, port))
    return normalized_incoming


def _update_peers_from_hello(self, peer_tuple, advertised_height, normalized_incoming):
    if peer_tuple and not (self._is_local_address(peer_tuple[0]) and peer_tuple[1] == self.port):
        self.peers.add(peer_tuple)
        self.peer_scores.setdefault(peer_tuple, CFG.PEER_SCORE_START)
        if advertised_height >= 0:
            self._peer_best_height[peer_tuple] = advertised_height

    for cand in normalized_incoming:
        if cand == peer_tuple:
            continue
        self.peers.add(cand)
        self.peer_scores.setdefault(cand, CFG.PEER_SCORE_START // 2)
