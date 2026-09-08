# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
"""
Outbound RPC interface from Archivist (Storage Node) to TsarChain Blockchain Node.
Allowed RPC types: HELLO, PING, GET_NETWORK_INFO, GRAFFITI_GET_POSTS, GRAFFITI_PROOF_SUBMIT, GRAFFITI_BUILD_PAYOUT.
"""

import time
import secrets
from typing import Any, Dict, List, Optional

from tsarchain.utils.benchmarks import benchmark
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.node_route")


@benchmark(label="RPC_HELLO", threshold_ms=100.0)
def rpc_hello(rpc, my_listen_port: int = 0, trusted: bool = False, timeout: float = 3.0) -> bool:
    """Send HELLO handshake to register storage role on the Node."""
    hello_msg = {
        "type": "HELLO",
        "role": "NODE_STORAGE",
        "pubkey": rpc.pub,
        "address": rpc.address,
        "url": "",
        "port": int(my_listen_port) if my_listen_port else 0,
        "trusted": bool(trusted),
    }
    _ = rpc.call(hello_msg, timeout=timeout)
    pong = rpc.call({"type": "PING"}, timeout=timeout)
    return pong.get("type") == "PONG"


@benchmark(label="RPC_PING", threshold_ms=300.0)
def rpc_ping(rpc, timeout: float = 2.0) -> bool:
    """Heartbeat check with the Node."""
    pong = rpc.call({"type": "PING"}, timeout=timeout)
    return pong.get("type") == "PONG"


@benchmark(label="RPC_GET_NETWORK_INFO", threshold_ms=250.0)
def rpc_get_network_info(rpc, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    """Fetch network status, tip height, and peers count from the Node."""
    raw = rpc.call({"type": "GET_NETWORK_INFO"}, timeout=timeout)
    if not raw.get("error"):
        return raw
    return None


@benchmark(label="RPC_GET_GRAFFITI_POSTS", threshold_ms=250.0)
def rpc_get_graffiti_posts(rpc, limit: int = 500, timeout: float = 6.0) -> List[Dict[str, Any]]:
    """Query confirmed on-chain graffiti posts from the Node."""
    resp = rpc.call({"type": "GRAFFITI_GET_POSTS", "limit": int(limit)}, timeout=timeout)
    posts = resp.get("posts")
    if type(posts) is list:
        return posts
    return []


@benchmark(label="RPC_SUBMIT_PROOF", threshold_ms=150.0)
def rpc_submit_proof(
    rpc,
    *,
    art_id: str,
    epoch: int,
    offset: int,
    length: int,
    proof_hash: str,
    height: int,
    seed: str,
    chunk: Optional[str] = None,
    path: Optional[list] = None,
    timeout: float = 8.0,
) -> Optional[Dict[str, Any]]:
    """Submit cryptographic Proof of Retention (PoR) for an artifact chunk to the Node."""

    rpc_addr = rpc.address
    payload: Dict[str, Any] = {
        "type": "GRAFFITI_PROOF_SUBMIT",
        "art_id": str(art_id).strip().lower(),
        "epoch": int(epoch),
        "offset": int(offset),
        "length": int(length),
        "hash": str(proof_hash),
        "height": int(height),
        "seed": str(seed),
        "storer": str(rpc_addr or "").strip().lower(),
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    if chunk:
        payload["chunk"] = chunk
    if path:
        payload["path"] = path

    return rpc.call(payload, timeout=timeout)


@benchmark(label="RPC_BUILD_PAYOUT", threshold_ms=750.0)
def rpc_build_payout(
    rpc,
    *,
    art_id: str,
    recipient: str,
    amount: int,
    epoch: int,
    broadcast: bool = True,
    timeout: float = 8.0,
) -> Optional[Dict[str, Any]]:
    """Request Node to construct and broadcast payout transaction for storage compensation."""
    payload: Dict[str, Any] = {
        "type": "GRAFFITI_BUILD_PAYOUT",
        "art_id": str(art_id).strip().lower(),
        "recipients": [{"addr": str(recipient).strip().lower(), "amount": int(amount)}],
        "epoch": int(epoch),
        "broadcast": bool(broadcast),
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    return rpc.call(payload, timeout=timeout)


__all__ = [
    "rpc_hello",
    "rpc_ping",
    "rpc_get_network_info",
    "rpc_get_graffiti_posts",
    "rpc_submit_proof",
    "rpc_build_payout",
]

