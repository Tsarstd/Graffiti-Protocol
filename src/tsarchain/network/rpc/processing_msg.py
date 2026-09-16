# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: Signal-X3DH; RFC7748-X25519

import random
from typing import TYPE_CHECKING, Any, Optional

# ---------------- Local Project ----------------
from ...utils import config as CFG
from ..node_logic.ratelimit import ban_ip
from ...contracts import graffiti as GRAFFITI

from .miner_rpc import handle_miner_rpc
from .storage_rpc import handle_storage_rpc
from .user_rpc.dispatcher import handle_user_rpc

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.processing_msg")

_secure_random = random.SystemRandom()

if TYPE_CHECKING:
    from ..node import Network

__all__ = ["process_message"]

# --------------------------------------------------------------------------
# RPC REGISTRY (role → allowed message types)
# --------------------------------------------------------------------------
MINER_RPC_TYPES = {
        "HELLO", "GET_INFO", "NEW_BLOCK",
        "MEMPOOL", "GET_HEADERS", "GET_BLOCKS", "GET_BLOCK_HASH"
}


STORAGE_RPC_TYPES = {
    "GRAFFITI_PROOF_SUBMIT", "GRAFFITI_BUILD_PAYOUT"
}


USER_RPC_TYPES = {
        "PING", "GET_BALANCES", "CREATE_TX", "GET_TX_HISTORY", "GET_TX_DETAIL", "NEW_TX", 
        "GET_TOTAL_UTXO", "GET_PEERS", "GET_NETWORK_INFO", "GET_BLOCK", "GET_BLOCK_RANGE", "STOR_LIST",
        # Graffiti
        "CREATE_TX_MULTI", "GRAFFITI_GET_POSTS","GRAFFITI_GET_COMMENTS", "GRAFFITI_GET_ART",
        "GRAFFITI_GET_PAYOUTS",
        # Chat & storage listing
        "CHAT_REGISTER", "CHAT_LOOKUP_PUB", "CHAT_CHECK_PREKEYS", "DEACTIVATE_CHAT", "CHAT_PRESENCE", "CHAT_SEND", "CHAT_PULL", "CHAT_RELAY",
        "CHAT_READ", "CHAT_GET_PREKEY", "CHAT_PUBLISH_PREKEYS",
        # Mempool utilities
        "GET_MEMPOOL"
}


ROLE_RPC_MAP = {
    "MINER": MINER_RPC_TYPES,
    "STORAGE": STORAGE_RPC_TYPES,
    "USER": USER_RPC_TYPES
}


BOOTSTRAP_MINER_ALLOW = {
    "HELLO", "GET_HEADERS"
}


def process_message(
    network: "Network",
    message: dict[str, Any],
    addr: tuple | None = None,
    *,
    src_node_id: Optional[str] = None,
    src_pubkey: Optional[str] = None,
) -> dict | None:
    
    if type(message) is not dict:
        return {"error": "invalid message: expected JSON object"}

    mtype = message.get("type")
    if type(mtype) is not str:
        return {"error": "missing or invalid 'type'"}
    
    mtype = mtype.strip().upper()
    is_miner = _is_miner_sender(network, src_node_id, src_pubkey, addr)
    role, category = _identify_rpc_role(mtype, network, src_node_id, src_pubkey, addr, is_miner=is_miner)
    raw_source = message.get("rpc_source") or message.get("source") or message.get("client")
    rpc_source = _sanitize_rpc_source(raw_source)
    if not rpc_source and _is_storage_node_id(network, src_node_id):
        rpc_source = "storage_node"

    if not rpc_source:
        if role == "MINER":
            rpc_source = "miner"
        elif role == "STORAGE":
            rpc_source = "storage"
        else:
            rpc_source = "user"

    message["rpc_source"] = rpc_source
    if role == "UNKNOWN":
        log.warning("[process_message] unknown RPC %s from %s", mtype, addr)
        return {"error": "unknown type", "drop": True}

    if (role == "MINER") and (mtype not in BOOTSTRAP_MINER_ALLOW) and not is_miner:
        ip = _client_ip(addr)
        ban_ip(ip, CFG.BAN_MALICIOUS_RPC)
        log.warning("[process_message] rejecting unauthorized miner: RPC %s from %s category %s (temp-ban)", mtype, addr, category)
        return {"error": "forbidden: miners-only endpoint", "drop": True}

    if role == "MINER":
        return handle_miner_rpc(network, message, addr, mtype, src_node_id=src_node_id, src_pubkey=src_pubkey)
    
    if role == "STORAGE":
        return handle_storage_rpc(network, message, addr, mtype, src_node_id=src_node_id, src_pubkey=src_pubkey)

    try:
        dispatch_result = handle_user_rpc(
            network,
            message,
            addr,
            mtype,
            client_ip=lambda: _client_ip(addr),
            is_miner_sender=lambda: is_miner,
            overlay_realtime_mempool_stats=_overlay_realtime_mempool_stats,
            choose_relay_route=_choose_relay_route,
            relay_chain=_relay_chain,
            send_chat_relay=_send_chat_relay,
        )

        if dispatch_result is not None:
            return dispatch_result
    except Exception as e:
        log.exception("[process_message] Error handling user RPC %s from %s: %s", mtype, addr, e)
        return {"error": str(e)}
    
    return {"error": "Unknown message type"}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _sanitize_rpc_source(val: Any) -> str | None:
    if val is None:
        return None
    txt = str(val)[:100].strip().lower()
    if not txt:
        return None
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    cleaned = "".join([c for c in txt if c in allowed])
    if not cleaned:
        return None
    return cleaned[:32]


def _is_storage_node_id(network, node_id: str | None) -> bool:
    if not node_id:
        return False
    peers = network.storage_peers or {}
    for meta in peers.values():
        if meta.get("node_id") == node_id:
            return True
    return False


def _is_miner_sender(network, src_node_id: str | None, src_pubkey: str | None, addr: Any) -> bool:
    if not src_node_id:
        return False

    peer_pubkeys = network.peer_pubkeys or {}
    pinned = peer_pubkeys.get(src_node_id)
    if not pinned:
        return False
    if src_pubkey and pinned != src_pubkey:
        log.warning("[miner_auth] pinned mismatch for %s from %s", src_node_id[:12], addr)
        return False
    return True


def _identify_rpc_role(mtype: str, network, src_node_id, src_pubkey, addr, *, is_miner: bool | None = None) -> tuple[str, str]:
    if is_miner is None:
        is_miner = _is_miner_sender(network, src_node_id, src_pubkey, addr)
    for role, allowed in ROLE_RPC_MAP.items():
        if mtype in allowed:
            category = f"{role}-AUTHORIZED" if (role == "MINER" and is_miner) else role
            return role, category
    return "UNKNOWN", "UNKNOWN"


def _client_ip(addr) -> str:
    if addr:
        return addr[0]
    return "0.0.0.0"


def _inject_mempool_basic_stats(tx_section: dict, pool) -> None:
    store = pool._pool
    tx_count = len(store)
    tx_section["mempool_txs"] = int(tx_count)
    size_est = pool.current_size
    if size_est is not None:
        tx_section["mempool_vbytes_estimate"] = int(size_est)


def _inject_mempool_graffiti_stats(snapshot: dict, pool) -> None:
    try:
        graff_section = snapshot.setdefault("graffiti", {})
        on_mem = 0
        all_txs_fn = pool.get_all_txs
        all_txs = all_txs_fn() if callable(all_txs_fn) else []
        for tx in all_txs or []:
            outputs = tx.outputs or []
            for tx_out in outputs:
                spk = tx_out.script_pubkey
                meta = GRAFFITI.parse_from_script(spk) if spk is not None else None
                if meta and str(meta.get("event", "")).upper() == "POST":
                    on_mem += 1
        graff_section["graffiti_on_mempool"] = int(on_mem)
    except (AttributeError, TypeError):
        pass


def _overlay_realtime_mempool_stats(snapshot: dict, network: "Network") -> None:
    """Inject live mempool stats into the snapshot returned to clients."""
    if type(snapshot) is not dict:
        return

    tx_section = snapshot.setdefault("transactions", {})
    if type(tx_section) is not dict:
        return

    broadcast = network.broadcast
    pool = broadcast.mempool if broadcast else None
    if pool is None:
        return

    _inject_mempool_basic_stats(tx_section, pool)
    _inject_mempool_graffiti_stats(snapshot, pool)


def _choose_relay_route(network, hops: int = 2) -> list[tuple]:
    with network.lock:
        pool = list(network.peers)
    _secure_random.shuffle(pool)
    return pool[:max(1, hops)]


def _relay_chain(network, route: list[tuple], inner: dict, src_addr=None):
    if not route:
        return
    first = route[0]
    payload = {"type": "CHAT_RELAY", "route": route[1:], "inner": inner}
    send_fn = network._send_chat_relay
    if callable(send_fn):
        send_fn(first, payload)
    else:
        _send_chat_relay(network, first, payload)


def _send_chat_relay(network, peer: tuple, payload: dict):
    try:
        network.send_to_peer(peer, payload)
        return {"status": "ok"}
    except Exception:
        log.exception("[_send_chat_relay] send error to %s", peer)
        return {"status": "error"}