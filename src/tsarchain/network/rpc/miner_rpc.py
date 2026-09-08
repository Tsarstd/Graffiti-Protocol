# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE
# Refs: see REFERENCES.md

from typing import TYPE_CHECKING, Any, Optional

from ..node_logic import handlers
from ...utils import config as CFG

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.miner_rpc")

if TYPE_CHECKING:
    from ..node import Network


def _check_miner_rl(network: "Network", ip: str, endpoint: str, burst: int, window: int, backoff: int) -> dict | None:
    rl_key = f"miner:{endpoint}:{ip}"
    if not network.tb_node_allow(network.rl_ip, rl_key, burst, window, burst, backoff_key=rl_key):
        network.backoff_node(rl_key, backoff)
        return {
            "type": "SYNC_REJECT",
            "error": "rate_limited",
            "retry_after": float(backoff),
        }
    return None


def handle_miner_rpc(
    self: "Network",
    message: dict[str, Any],
    addr: Optional[tuple],
    mtype: str,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:

    ip = str(addr[0]) if addr else "0.0.0.0"
    if mtype == "HELLO":
        if err := _check_miner_rl(self, ip, "hello", CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_BACKOFF_S):
            return err
        return handlers.handle_hello(self, message, addr, src_node_id=src_node_id, src_pubkey=src_pubkey)


    if mtype == "NEW_BLOCK":
        if err := _check_miner_rl(self, ip, "new_block", CFG.MINER_NEWBLOCK_RL_IP_BURST, CFG.MINER_NEWBLOCK_RL_WINDOW_S, CFG.MINER_NEWBLOCK_RL_BACKOFF_S):
            return err
        with self.lock:
            peers_snapshot = set(self.peers)
        self.broadcast.receive_block(message, addr, peers_snapshot)
        return {"status": "ok"}


    if mtype == "GET_BLOCK_HASH":
        if err := _check_miner_rl(self, ip, "get_block_hash", CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_BACKOFF_S):
            return err
        raw_h = message.get("height")
        if raw_h is None:
            return {"type": "BLOCK_HASH", "error": "missing_height"}
        try:
            h = int(raw_h)
        except (ValueError, TypeError):
            return {"type": "BLOCK_HASH", "error": "invalid_height"}
        return self.handle_get_block_hash(h)


    if mtype == "GET_INFO":
        if err := _check_miner_rl(self, ip, "get_info", CFG.MINER_INFO_RL_IP_BURST, CFG.MINER_INFO_RL_WINDOW_S, CFG.MINER_INFO_RL_BACKOFF_S):
            return err
        with self.broadcast.lock:
            b_height = self.broadcast.blockchain.height
            b_blocks = len(self.broadcast.blockchain.chain)

        mempool_obj = self.broadcast.mempool
        mp_count = len(mempool_obj._pool)
        utxodb_obj = self.broadcast.utxodb
        utxo_count = len(utxodb_obj.utxos)

        with self.lock:
            peers_count = sum(1 for _, p in self.peers if type(p) is int and p > 0)

        return {
            "type": "INFO",
            "height": b_height,
            "blocks": b_blocks,
            "mempool": mp_count,
            "utxos": utxo_count,
            "peers": peers_count,
        }


    if mtype == "GET_HEADERS":
        if err := _check_miner_rl(self, ip, "get_headers", CFG.MINER_HEADERS_RL_IP_BURST, CFG.MINER_HEADERS_RL_WINDOW_S, CFG.MINER_HEADERS_RL_BACKOFF_S):
            return err
        return handlers.handle_get_headers(self, message, addr)


    if mtype == "GET_BLOCKS":
        if err := _check_miner_rl(self, ip, "get_blocks", CFG.MINER_BLOCKS_RL_IP_BURST, CFG.MINER_BLOCKS_RL_WINDOW_S, CFG.MINER_BLOCKS_RL_BACKOFF_S):
            return err
        return handlers.handle_get_blocks(self, message, addr)


    if mtype == "MEMPOOL":
        if err := _check_miner_rl(self, ip, "mempool", CFG.MINER_MEMPOOL_RL_IP_BURST, CFG.MINER_MEMPOOL_RL_WINDOW_S, CFG.MINER_MEMPOOL_RL_BACKOFF_S):
            return err
        self.broadcast.receive_mempool(message)
        return {"status": "mempool received"}


    return None