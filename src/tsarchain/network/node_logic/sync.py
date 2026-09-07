# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import base64
import struct
import time
import random
from typing import Any, List, Optional, Tuple

from ...core.block import Block
from ...utils import config as CFG

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.sync")

_secure_random = random.SystemRandom()


def sync_loop(self):
    while not self._stop.is_set():
        try:
            window = CFG.FAST_SYNC_INTERVAL if time.time() < self._sync_fast_until else CFG.SYNC_INTERVAL
            self._sync_event.wait(timeout=max(1.0, float(window)))
            self._sync_event.clear()
            self.sync_with_peers()
        except Exception:
            log.exception("[sync_loop] Error during sync")


def request_sync(self, fast: bool = False) -> None:
    if fast:
        self._sync_fast_until = max(self._sync_fast_until, time.time() + CFG.FAST_SYNC_INTERVAL)
    self._sync_event.set()


def sync_with_peers(self):
    """
    Run a single round of sync: select outbound peers (plus high-ranking candidates),
    call sync_peer for headers/blocks, then pull an inline/snapshot or full sync mempool if needed.
    """
    selected = _select_sync_peers(self)
    if not selected:
        return

    now = time.time()
    last_count = self._last_sync_count
    last_log = self._last_sync_log
    if (len(selected) != last_count) or (now - last_log > float(CFG.SYNC_INFO_MIN_INTERVAL)):
        self._last_sync_count = len(selected)
        self._last_sync_log = now

    _secure_random.shuffle(selected)
    for peer in selected:
        norm = self.normalize_peer(peer)
        if not norm:
            continue
        try:
            synced = _sync_peer(self, norm)
            allow_mempool = self.is_caught_up(freshness=20.0, height_slack=0)
            inline_status = _process_mempool_sync(self, norm, allow_mempool)
            _handle_sync_fallback(self, norm, synced, allow_mempool, inline_status)
        except Exception:
            log.exception("[sync_with_peers] Error syncing with peer %s", norm)
            self.penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY * 2)


def handle_block_gap(self, block, origin: Optional[Tuple[str, int]]) -> None:
    peer = self.normalize_peer(origin)
    self.request_sync(fast=True)
    if not peer:
        return

    now = time.time()
    last = self._recent_gap_requests.get(peer, 0.0)
    if now - last < float(CFG.HEADERS_SYNC_MIN_INTERVAL):
        return

    self._recent_gap_requests[peer] = now
    height = int(block.height or 0)
    # Enlarge the download window when it's far behind to avoid bouncing back and forth between small spans.
    # Use the HEADERS_FANOUT factor and limit it with BLOCK_DOWNLOAD_BATCH_MAX.
    span = max(32, int(CFG.HEADERS_FANOUT) * 2)
    span = min(span, int(CFG.BLOCK_DOWNLOAD_BATCH_MAX))
    start_h = max(0, height - span)
    missing = list(range(start_h, height + 1))
    _download_blocks(self, peer, missing)


def is_caught_up(self, freshness: float = 10.0, height_slack: int = 0) -> bool:
    """
    Check if the node is sufficiently synchronized: it needs a recent peer sync (freshness)
    and the local block height difference to the best peer <= slack.
    """
    now = time.time()
    freshness = max(0.0, float(freshness))
    slack = max(0, int(height_slack))
    with self.lock:
        if not self._peer_last_sync:
            return False
        recent = any(now - ts <= freshness for ts in self._peer_last_sync.values())
        if not recent:
            return False
        candidates = [h for h in self._peer_best_height.values() if type(h) is int and h >= 0]
        if not candidates:
            return True
        best_remote = max(candidates)
    local_height = int(self.broadcast.blockchain.height)
    return (best_remote - local_height) <= slack


def get_best_peer_height(self) -> int:
    with self.lock:
        candidates = [h for h in self._peer_best_height.values() if type(h) is int and h >= 0]
    return max(candidates) if candidates else -1


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _select_sync_peers(self):
    with self.lock:
        selected = [p for p in self.outbound_peers if p in self.peers]
        if len(selected) < CFG.MAX_OUTBOUND_PEERS:
            extras = sorted(
                (p for p in self.peers if p not in selected),
                key=lambda p: self.peer_scores.get(p, 0),
                reverse=True,
            )
            for peer in extras:
                if len(selected) >= CFG.MAX_OUTBOUND_PEERS:
                    break
                selected.append(peer)
    return selected


def _process_mempool_sync(self, norm, allow_mempool):
    if not allow_mempool:
        return None

    pending_mempool_pull = bool(self._pending_mempool_pull)
    if pending_mempool_pull:
        pulled = self.request_mempool_inline(norm, force=True)
        if pulled is False or pulled is None:
            pulled = self.request_mempool_snapshot(norm, force=True)
        if pulled:
            self._pending_mempool_pull = False
            
    inline_status = self.request_mempool_inline(norm)
    if inline_status is False:
        retry_inline = self.request_mempool_inline(norm, force=True)
        if retry_inline is True:
            inline_status = True
        elif retry_inline is not None:
            inline_status = retry_inline
    return inline_status


def _handle_sync_fallback(self, norm, synced, allow_mempool, inline_status):
    if allow_mempool and inline_status is False:
        if norm not in self._snapshot_unreachable:
            self.request_mempool_snapshot(norm)


def _sync_peer(self, peer: Tuple[str, int]) -> bool:
    """
    Single-peer sync: respect intervals, request headers, calculate lost/reorg blocks,
    download and apply blocks, set backoff on rejection, and reward/penalty for peers.
    Returns True if up-to-date or a new block is applied.
    """
    now = time.time()
    fast_until = self._sync_fast_until
    min_iv = 0.0 if now < fast_until else float(CFG.HEADERS_SYNC_MIN_INTERVAL)
    if now - self._peer_last_sync.get(peer, 0.0) < min_iv:
        return False

    locator = _build_locator(self)
    headers_resp = _request_headers(self, peer, locator)
    if not headers_resp:
        self.penalize_peer(peer, CFG.PEER_SCORE_FAILURE_PENALTY)
        return False

    if headers_resp.get("type") == "SYNC_REJECT":
        retry = float(headers_resp.get("retry_after", 30.0))
        log.info("[_sync_peer] %s rejected header request (retry in %.1fs)", peer, retry)
        return False

    headers = headers_resp.get("headers") or []
    if not headers:
        self._peer_last_sync[peer] = now
        with self.lock:
            local_height = int(self.broadcast.blockchain.height)
            self._peer_best_height[peer] = max(self._peer_best_height.get(peer, -1), local_height)
        self.reward_peer(peer)
        return True

    with self.lock:
        max_h = max((int(h.get("height", -1)) for h in headers if type(h) is dict), default=-1)
        if max_h >= 0:
            self._peer_best_height[peer] = max(self._peer_best_height.get(peer, -1), max_h)

    missing = _determine_missing_blocks(self, headers)
    if not missing:
        self._peer_last_sync[peer] = now
        self.reward_peer(peer)
        return True

    _download_blocks(self, peer, missing)
    if headers_resp.get("more"):
        self.request_sync(fast=True)
        return True
    
    return False


def _build_locator(self) -> List[str]:
    """
    Build a block locator for request headers: take the block hash from the end of the chain in exponential steps (up to the depth),
    then ensure ZERO_HASH is also listed as the lowest anchor.
    """
    locator: List[str] = []
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    if not chain:
        locator.append(CFG.ZERO_HASH.hex())
        return locator
    idx = len(chain) - 1
    step = 1
    while idx >= 0 and len(locator) < CFG.HEADERS_LOCATOR_DEPTH:
        locator.append(chain[idx].hash().hex())
        if len(locator) >= 10:
            step *= 2
        idx -= step
    zero_hex = CFG.ZERO_HASH.hex()
    if zero_hex not in locator:
        locator.append(zero_hex)
    return locator


def _request_headers(self, peer: Tuple[str, int], locator: List[str]) -> Optional[dict]:
    payload = {
        "type": "GET_HEADERS",
        "locator": locator[: CFG.HEADERS_LOCATOR_DEPTH],
        "limit": int(CFG.HEADERS_BATCH_MAX),
        "port": self.port,
    }
    return self.rpc_request(peer, payload, timeout=max(10.0, CFG.SYNC_TIMEOUT))


def _determine_missing_blocks(self, headers: List[dict]) -> List[int]:
    """
    Calculate the height of missing blocks or reorgs: compare the remote header
    with the local chain, record mismatches as reorg points,
    and return a unique list of heights to be downloaded (sorted).
    """
    missing: List[int] = []
    reorg_point: Optional[int] = None
    max_remote_height = -1
    with self.broadcast.lock:
        chain = list(self.broadcast.blockchain.chain)
    for header in headers:
        height = int(header.get("height", -1))
        blk_hash = header.get("hash")
        if height < 0 or type(blk_hash) is not str:
            continue
        max_remote_height = max(max_remote_height, height)
        if height < len(chain):
            local_hash = chain[height].hash().hex()
            if local_hash != blk_hash:
                reorg_point = height if reorg_point is None else min(reorg_point, height)
        else:
            missing.append(height)
    if reorg_point is not None:
        start = max(0, reorg_point)
        end = max(max_remote_height, len(chain) - 1)
        missing.extend(range(start, end + 1))
    return sorted(set(missing))


def _download_blocks(self, peer: Tuple[str, int], heights: List[int]) -> Tuple[int, float]:
    start_time = time.time()
    if not heights:
        return 0, 0.0

    unique_heights = sorted({int(h) for h in heights if type(h) is int})
    if not unique_heights:
        return 0, 0.0

    batch_size = max(1, int(CFG.BLOCK_DOWNLOAD_BATCH_MAX))
    total_applied = 0
    total_attempted = len(unique_heights)
    total_chunks = (total_attempted + batch_size - 1) // batch_size
    for idx in range(0, len(unique_heights), batch_size):
        chunk = unique_heights[idx : idx + batch_size]
        payload = {"type": "GET_BLOCKS", "heights": chunk, "port": self.port}
        resp = self.rpc_request(peer, payload, timeout=max(15.0, CFG.SYNC_TIMEOUT))
        if not resp:
            log.info(
                "[_download_blocks] %s no response for chunk %d/%d (heights %s-%s)",
                peer,
                (idx // batch_size) + 1,
                total_chunks,
                chunk[0],
                chunk[-1],
            )
            break

        resp_type = resp.get("type")
        if resp_type == "BLOCKS_BIN":
            raw_b64 = resp.get("data") or ""
            raw = base64.b64decode(raw_b64)
            offset = 0
            blocks = []
            while offset < len(raw):
                (blen,) = struct.unpack_from("<I", raw, offset)
                offset += 4
                blk = Block.from_storage_bytes(raw[offset : offset + blen])
                offset += blen
                blocks.append(blk)
            total_applied, elapsed, stop = _process_downloaded_blocks(
                self, peer, blocks, start_time, total_applied
            )
            if stop:
                return total_applied, elapsed

        elif resp_type == "SYNC_REJECT":
            retry = float(resp.get("retry_after", 30.0))
            log.info(
                "[_download_blocks] %s asked to retry later (retry %.1fs)",
                peer,
                retry,
            )
            break
        else:
            log.info("[_download_blocks] %s returned unexpected type=%s", peer, resp_type)
            break

    elapsed = time.time() - start_time
    return total_applied, elapsed


def _process_downloaded_blocks(self, peer, blocks: List[Block], start_time, total_applied):
    for block_obj in blocks:
        h = int(block_obj.height or 0)
        bh = block_obj.hash().hex()
        local_chain = self.broadcast.blockchain.chain
        if 0 <= h < len(local_chain):
            local_hash = local_chain[h].hash().hex()
            if local_hash == bh:
                continue
            # already have a different block at this height -> re-request headers sync to evaluate reorg
            self.request_sync(fast=True)
            return total_applied, time.time() - start_time, True
            
        applied = _apply_block_from_sync(self, block_obj, peer)
        if applied:
            total_applied += 1
        else:
            label = str(bh or "unknown")
            log.warning("[_process_downloaded_blocks] Block %s rejected during sync from %s", label[:12], peer)
            self.request_sync(fast=True)
            return total_applied, time.time() - start_time, True
    return total_applied, 0.0, False


def _apply_block_from_sync(self, block_obj: Any, peer: Tuple[str, int]) -> bool:
    message = {
        "type": "NEW_BLOCK",
        "data": block_obj,
        "port": peer[1],
    }
    return bool(self.broadcast.receive_block(message, peer, self.peers))
