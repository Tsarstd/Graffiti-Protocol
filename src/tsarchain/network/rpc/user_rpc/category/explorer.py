# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import json

from ....node_logic import handlers
from .....utils import config as CFG
from ...user_rpc import common as CM
from .....utils.benchmarks import benchmark
from .....utils.helpers import spkhex_to_address

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.explorer")

@benchmark(label="GET_BALANCES", threshold_ms=60.0)
def get_balances(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    
    addrs_raw = message.get("addresses") or []
    if not addrs_raw and message.get("address"):
        addrs_raw = [message["address"]]
    
    addrs, err = _validate_balances_request(addrs_raw)
    if err:
        return err

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:balance",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="bal",
        burst=CFG.BALANCE_RL_IP_BURST,
        window_s=CFG.BALANCE_RL_IP_WINDOW_S,
        backoff_s=CFG.BALANCE_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    with self.broadcast.lock:
        tip_height = int(self.broadcast.blockchain.height)
        mem = self.broadcast.mempool.get_all_txs() if self.broadcast.mempool else []

    if mem:
        opmap_chain, opmap_mem = self.build_outpoint_map([], mem)
        pending_out_map, incoming_map = _calculate_mempool_balances(self, mem, opmap_mem, opmap_chain)
    else:
        pending_out_map, incoming_map = {}, {}

    items = {}
    for addr_str in addrs:
        b = self.broadcast.utxodb.get_balance(addr_str, mode="breakdown", current_height=tip_height)
        if type(b) is not dict:
            b = {"total": int(b or 0), "mature": int(b or 0), "immature": 0}
        pending_out = int(pending_out_map.get(addr_str, 0))
        pending_in = int(incoming_map.get(addr_str, 0))

        spendable = max(0, int(b.get("mature", 0)) - int(pending_out or 0))
        items[addr_str] = {
            "balance": int(b.get("total", 0)),
            "spendable": spendable,
            "immature": int(b.get("immature", 0)),
            "pending_outgoing": int(pending_out or 0),
            "pending_incoming": int(pending_in or 0),
            "maturity": int(CFG.COINBASE_MATURITY),
        }
    
    response_dict = {"type": "BALANCES", "height": tip_height, "items": items}
    return response_dict


@benchmark(label="GET_NETWORK_INFO", threshold_ms=10.0)
def get_network_info(self, message, pow_obj, base_identity, *,
                     client_ip, overlay_realtime_mempool_stats, **kwargs):

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:info",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="info",
        burst=CFG.INFO_RL_IP_BURST,
        window_s=CFG.INFO_RL_IP_WINDOW_S,
        backoff_s=CFG.INFO_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    snap = self.broadcast.blockchain.chain_storage._read_snapshot_state()
    overlay_realtime_mempool_stats(snap, self)
    with self.lock:
        peers_sane = [(ip,p) for (ip,p) in self.peers if type(p) is int and p>0]
        
    snap.setdefault("peers", {})
    if type(snap["peers"]) is dict:
        snap["peers"]["count"] = len(peers_sane)
    else:
        snap["peers"] = {"count": len(peers_sane)}
        
    response_dict = {"type": "NETWORK_INFO", "data": snap}   
    return response_dict


@benchmark(label="GET_BLOCK", threshold_ms=15.0)
def get_block(self, message, pow_obj, base_identity,*,
                     client_ip, **kwargs):
    
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:block_fetch",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="blk",
        burst=CFG.BLOCK_FETCH_RL_IP_BURST,
        window_s=CFG.BLOCK_FETCH_RL_WINDOW_S,
        backoff_s=CFG.BLOCK_FETCH_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp
    src_tag = message.get("rpc_source")
    raw_h = message.get("height")
    if raw_h is not None and str(raw_h).strip() != "":
        try:
            return handlers.handle_get_block_at(self, int(raw_h), src_tag=src_tag)
        except (ValueError, TypeError):
            return {"type": "BLOCK", "error": "invalid_height"}
    hx = str(message.get("hash") or "").strip()
    if not hx:
        return {"type": "BLOCK", "error": "missing_height_or_hash"}
    return handlers.handle_get_block_by_hash(self, hx, src_tag=src_tag)


@benchmark(label="GET_BLOCK_RANGE", threshold_ms=25.0)
def get_block_range(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:block_range",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="blk_range",
        burst=CFG.BLOCK_RANGE_RL_IP_BURST,
        window_s=CFG.BLOCK_RANGE_RL_WINDOW_S,
        backoff_s=CFG.BLOCK_RANGE_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        log.warning("GET_BLOCK_RANGE pow required")
        return pow_resp

    raw_start = message.get("start_height", message.get("start"))
    raw_limit = message.get("limit", 200)
    limit = int(raw_limit)
    limit = max(1, min(limit, 500))

    with self.broadcast.lock:
        chain = self.broadcast.blockchain.chain
        tip_height = int(self.broadcast.blockchain.height)

    if not chain:
        return {
            "type": "BLOCK_RANGE",
            "items": [],
            "limit": limit,
            "start_height": -1,
            "tip_height": tip_height,
            "has_more": False,
            "next_height": -1,
        }

    if raw_start is None or raw_start == "":
        start_height = tip_height
    else:
        start_height = int(raw_start)

    if start_height > tip_height:
        start_height = tip_height
    if start_height < 0:
        return {
            "type": "BLOCK_RANGE",
            "items": [],
            "limit": limit,
            "start_height": start_height,
            "tip_height": tip_height,
            "has_more": False,
            "next_height": -1,
        }

    items = []
    h = start_height
    while h >= 0 and len(items) < limit:
        try:
            b = chain[h]
        except Exception:
            break
        items.append(CM.summarize_block(self, b))
        h -= 1

    has_more = h >= 0
    
    response_dict = {
        "type": "BLOCK_RANGE",
        "start_height": start_height,
        "limit": limit,
        "items": items,
        "tip_height": tip_height,
        "next_height": h,
        "has_more": has_more,
    }

    return response_dict


@benchmark(label="GET_MEMPOOL", threshold_ms=2050.0)
def get_mempool(self, message, pow_obj, base_identity, addr, *,
                     client_ip, is_miner_sender, **kwargs):
    
    mode = str(message.get("mode", "")).strip().lower()
    if mode not in ("inline", "inline_full"):
        ok, pow_resp = CM.allow_rpc_with_pow(
            self,
            scope="rpc:mempool",
            table=self.rl_ip,
            ip=client_ip,
            identity=base_identity,
            key_label="mempool",
            burst=CFG.MEMPOOL_INLINE_RL_BURST,
            window_s=CFG.MEMPOOL_INLINE_RL_WINDOW_S,
            backoff_s=CFG.MEMPOOL_INLINE_RL_BACKOFF,
            pow_obj=pow_obj,
            difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
        )
        if not ok:
            return pow_resp
        
    if mode == "snapshot":
        return _get_mempool_snapshot(self, message, addr, is_miner_sender)

    if mode in ("inline", "inline_full"):
        ok, pow_resp = CM.allow_rpc_with_pow(
            self,
            scope="rpc:mempool",
            table=self.rl_ip,
            ip=client_ip,
            identity=base_identity,
            key_label="mempool",
            burst=CFG.MEMPOOL_INLINE_RL_BURST,
            window_s=CFG.MEMPOOL_INLINE_RL_WINDOW_S,
            backoff_s=CFG.MEMPOOL_INLINE_RL_BACKOFF,
            pow_obj=pow_obj,
            difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
        )
        if not ok:
            return pow_resp
        all_txs = self.broadcast.mempool.get_all_txs() or []
        return _get_mempool_inline(all_txs)

    # --- fallback: mode txids (default) ---
    txs = self.broadcast.mempool.get_all_txs()
    hexes = []
    for t in txs:
        txid = t.txid
        if type(txid) in (bytes, bytearray):
            hexes.append(txid.hex())
        elif txid:
            hexes.append(str(txid))
        
    return {"type": "MEMPOOL", "mode": "txids", "txs": hexes}


@benchmark(label="GET_TX_HISTORY", threshold_ms=40.0)
def get_tx_history(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    
    addr_str = (message.get("address") or "").strip().lower()
    if not addr_str:
        return {"error": "missing address"}
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:history",
        table=self.rl_ip,
        ip=client_ip,
        identity=addr_str or base_identity,
        key_label="hist",
        burst=CFG.HISTORY_RL_IP_BURST,
        window_s=CFG.HISTORY_RL_IP_WINDOW_S,
        backoff_s=CFG.HISTORY_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp
    limit = int(message.get("limit", 50))
    offset = int(message.get("offset", 0))
    raw_since = message.get("since_height")
    since_height = None
    if raw_since is not None and str(raw_since).strip() != "":
        try:
            since_height = int(raw_since)
        except (ValueError, TypeError):
            since_height = None
    if limit > CFG.MAX_HISTORY_LIMIT:
        limit = CFG.MAX_HISTORY_LIMIT
    with self.broadcast.lock:
        tip_height = int(self.broadcast.blockchain.height)
    if since_height is not None:
        history = self.process_history_lookup(addr_str, limit=limit, offset=offset,
                                    direction=message.get("direction"),
                                    status=message.get("status"),
                                    since_height=since_height)
    else:
        history = self.process_history_lookup(addr_str, limit=limit, offset=offset,
                                    direction=message.get("direction"),
                                    status=message.get("status"))
    history["height"] = tip_height
            
    response_dict = {"type": "TX_HISTORY", "address": addr_str, **history}
    return response_dict


@benchmark(label="GET_TX_DETAIL", threshold_ms=50.0)
def get_tx_detail(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs): 
    
    txid_hex = message.get("txid")
    if not txid_hex:
        return {"error": "missing txid"}
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:txdetails",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="hist",
        burst=CFG.HISTORY_RL_IP_BURST,
        window_s=CFG.HISTORY_RL_IP_WINDOW_S,
        backoff_s=CFG.HISTORY_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp
        
    return self.process_tx_lookup(txid_hex, message.get("rpc_source"))


@benchmark(label="GET_TOTAL_UTXO", threshold_ms=10.0)
def get_total_utxo(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):

    address = (message.get("address") or "").strip().lower()
    if not address:
        return {"error": "missing address"}

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:history",
        table=self.rl_ip,
        ip=client_ip,
        identity=address or base_identity,
        key_label="hist",
        burst=CFG.HISTORY_RL_IP_BURST,
        window_s=CFG.HISTORY_RL_IP_WINDOW_S,
        backoff_s=CFG.HISTORY_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )
    if not ok:
        return pow_resp

    if len(address) > CFG.MAX_UTXO_ADDR_LEN:
        return {"error": "address too long"}
    
    count = self.broadcast.utxodb.count_utxos(address)
    return {"type": "UTXOS_COUNT", "count": count}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _validate_balances_request(addrs_raw) -> tuple[list[str], dict | None]:
    if type(addrs_raw) is not list or not addrs_raw:
        return [], {"error": "missing addresses"}
    if len(addrs_raw) > CFG.MAX_ADDRS_PER_REQ:
        return [], {"error": "too many addresses (max %d)" % CFG.MAX_ADDRS_PER_REQ}
    norm = []
    for a in addrs_raw:
        if not a:
            continue
        a = str(a).strip()
        if a.lower().startswith(CFG.ADDRESS_PREFIX):
            a = a.lower()
        if len(a) > CFG.MAX_UTXO_ADDR_LEN:
            return [], {"error": "address too long"}
        norm.append(a)
    return list(dict.fromkeys(norm)), None


def _calculate_mempool_balances(self, mem, opmap_mem, opmap_chain) -> tuple[dict[str, int], dict[str, int]]:
    pending_out_map: dict[str, int] = {}
    incoming_map: dict[str, int] = {}
    utxodb = self.broadcast.utxodb if self.broadcast else None
    for tx in mem or []:
        spent_local: dict[str, int] = {}
        recv_local: dict[str, int] = {}

        inputs = tx.inputs or []
        for tin in inputs:
            key = self.txin_prevkey(tin)
            amt_spk = opmap_mem.get(key) or opmap_chain.get(key)
            if not amt_spk and utxodb and type(utxodb.utxos) is dict:
                with utxodb._lock:
                    entry = utxodb.utxos.get(key)
                if type(entry) is dict:
                    tx_out = entry.get("tx_out")
                    amt = utxodb._amount_from_tx_out(tx_out)
                    spk_hex = utxodb._script_hex_from_tx_out(tx_out) or ""
                    amt_spk = (amt, spk_hex)
            if not amt_spk:
                continue
            amt, spk_hex = amt_spk
            owner = spkhex_to_address(spk_hex) if spk_hex else None
            if owner and amt:
                spent_local[owner] = spent_local.get(owner, 0) + int(amt)

        outputs = tx.outputs or []
        for o in outputs:
            amt = int(o.amount or 0)
            if amt <= 0:
                continue
            addr_o = self.txout_to_address(o)
            if addr_o:
                recv_local[addr_o] = recv_local.get(addr_o, 0) + amt

        # Treat change outputs (addr appears on both sides) as neutral.
        for addr, spent_amt in list(spent_local.items()):
            change_amt = min(spent_amt, recv_local.get(addr, 0))
            if change_amt > 0:
                spent_local[addr] = spent_amt - change_amt
                recv_local[addr] = recv_local.get(addr, 0) - change_amt

        for addr, spent_amt in spent_local.items():
            if spent_amt > 0:
                pending_out_map[addr] = pending_out_map.get(addr, 0) + spent_amt
        for addr, recv_amt in recv_local.items():
            if recv_amt > 0:
                incoming_map[addr] = incoming_map.get(addr, 0) + recv_amt
    return pending_out_map, incoming_map


def _get_mempool_snapshot(self, message, addr, is_miner_sender) -> dict:
    if not is_miner_sender():
        return {"error": "forbidden: miners-only endpoint"}
    peer_port = int(message.get("port", 0))
    target = None
    if type(addr) is tuple:
        if peer_port > 0:
            target = self.normalize_peer((addr[0], peer_port))
        if not target:
            # fall back to known peers with same IP
            with self.lock:
                for candidate in self.peers:
                    if candidate[0] == addr[0]:
                        target = candidate
                        break
    if not target:
        return {"error": "missing_peer_port"}
    min_iv = message.get("min_interval")
    force = bool(message.get("force"))
    pushed = self.broadcast.send_mempool_to_peer(target, min_interval_s=min_iv, force=force)
        
    return {"type": "MEMPOOL_SYNC", "count": int(pushed)}


def _get_mempool_inline(all_txs) -> dict:
    total = len(all_txs)
    inline = []
    hard_cap = max(1024, CFG.MAX_MSG) - len(CFG.NETWORK_MAGIC)
    limit = CFG.MEMPOOL_INLINE_MAX_TX
    base = {"type": "MEMPOOL", "mode": "inline_full", "total": total, "txs": []}

    for tx in all_txs:
        if len(inline) >= limit:
            break

        to_dict = tx.to_dict
        if callable(to_dict):
            tx_dict = to_dict(include_txid=True)
        elif type(tx) is dict:
            tx_dict = dict(tx)
        else:
            continue

        if not tx_dict.get("txid"):
            txid_attr = tx.txid
            if txid_attr:
                tx_dict["txid"] = txid_attr.hex() if type(txid_attr) in (bytes, bytearray) else str(txid_attr)

        candidate = dict(base)
        candidate["txs"] = inline + [tx_dict]
        enc = json.dumps(candidate, separators=CFG.CANONICAL_SEP).encode("utf-8")

        if hard_cap > 0 and enc and len(enc) > hard_cap:
            if inline:
                break
            # Single tx too large, skip it
            continue

        inline.append(tx_dict)

    return {
        "type": "MEMPOOL",
        "mode": "inline_full",
        "total": total,
        "count": len(inline),
        "txs": inline,
    }