# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import clean_remove_file
from tsarchain.utils.benchmarks import benchmark

from web.Backend.src.core import build_receipt, build_history_book
from web.Backend.src.core.logic_web import db_cache, db_blocks, db_media, db_files, rpc_client

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.src.core.logic_web.rpc_handlers")

RECEIPT_TTL = 30
_EXECUTOR = ThreadPoolExecutor(max_workers=8)


@benchmark(label="rpc_receipt", threshold_ms=15.0)
def rpc_receipt(client, txid: str):
    txid_norm = str(txid or "").strip().lower()
    if not txid_norm:
        return {"status": "error", "message": "Missing txid"}
    file_path = db_files.get_receipt_file_path(txid_norm)
    cache_key = rpc_client.cache_key("receipt", txid_norm)
    cached = rpc_client.cache_get(cache_key, refresh_ttl=True)

    if cached is not None:
        if db_files.is_receipt_fresh(file_path, max_age_seconds=RECEIPT_TTL):
            try:
                result = db_files.read_receipt_file_as_dict(file_path, txid_norm)
                if result is not None:
                    return result
            except FileNotFoundError:
                pass
        clean_remove_file(file_path)

    tx_data = rpc_tx(client, txid_norm)
    if tx_data and tx_data.get("error"):
        return {"status": "error", "message": f"Failed to fetch transaction: {tx_data.get('error')}"}
    
    output_dir = CFG.WEB_RECEIPTS_DIR
    receipt_gen = build_receipt.PaymentReceiptGenerator(output_dir)
    result = receipt_gen.generate_receipt_base64(tx_data)
    if result and result.get("status") == "success" and txid_norm:
        cache_info = {
            "txid": txid_norm,
            "file_path": file_path,
            "generated_at": int(time.time()),
            "scheduled_deletion": int(time.time()) + RECEIPT_TTL
        }
        rpc_client.cache_set(cache_key, cache_info, ttl_sec=RECEIPT_TTL)
        db_files.schedule_receipt_deletion(txid_norm, delay_seconds=RECEIPT_TTL)
        
    return result


@benchmark(label="rpc_history_book", threshold_ms=15.0)
def rpc_history_book(client, address: str):
    addr_norm = str(address or "").strip().lower()
    if not addr_norm:
        return {"status": "error", "message": "Missing address"}
    
    file_path = db_files.get_history_book_file_path(addr_norm)
    cache_key = rpc_client.cache_key("history_book", addr_norm)
    cached = rpc_client.cache_get(cache_key, refresh_ttl=True)

    if cached is not None:
        if db_files.is_history_book_fresh(file_path, max_age_seconds=RECEIPT_TTL):
            try:
                result = db_files.read_history_book_file_as_dict(file_path, addr_norm)
                if result is not None:
                    return result
            except FileNotFoundError:
                pass
        clean_remove_file(file_path)

    tx_data = rpc_address(client, addr_norm)
    if tx_data and tx_data.get("error"):
        return {"status": "error", "message": f"Failed to fetch address: {tx_data.get('error')}"}
    
    total_txs = 0
    if tx_data:
        raw_total = tx_data.get("total_txs")
        if raw_total is not None:
            total_txs = int(raw_total)
        elif "history" in tx_data and tx_data["history"]:
            total_txs = len(tx_data["history"])

    if total_txs < 20:
        return {
            "status": "error",
            "message": f"History Book requires at least 20 transactions (found {total_txs})."
        }
    
    output_dir = CFG.WEB_HISTORY_BOOKS_DIR
    hb_gen = build_history_book.HistoryBookGenerator(output_dir)
    result = hb_gen.generate_history_book_base64(tx_data)
    if result and result.get("status") == "success" and addr_norm:
        cache_info = {
            "address": addr_norm,
            "file_path": file_path,
            "generated_at": int(time.time()),
            "scheduled_deletion": int(time.time()) + RECEIPT_TTL
        }
        rpc_client.cache_set(cache_key, cache_info, ttl_sec=RECEIPT_TTL)
        db_files.schedule_history_book_deletion(addr_norm, delay_seconds=RECEIPT_TTL)
        
    return result


@benchmark(label="rpc_network", threshold_ms=15.0)
def rpc_network(client):
    key = rpc_client.cache_key("network")
    def _fetch():
        info = rpc_client.rpc_send(client, {"type": "GET_NETWORK_INFO"}) or {}
        peers = rpc_client.rpc_send(client, {"type": "GET_PEERS"}) or {}
        if peers and "peers" in peers:
            info["peers"] = peers.get("peers")
        if info and info.get("type") == "NETWORK_INFO":
            return info.get("data") or info
        return info
    return rpc_client.get_or_fetch_cached(key, _fetch)


@benchmark(label="rpc_block", threshold_ms=15.0)
def rpc_block(client, val: str):
    if str(val).isdigit():
        key = rpc_client.cache_key("block", "h", str(val))
        payload = {"type": "GET_BLOCK", "height": int(val)}
    else:
        key = rpc_client.cache_key("block", "hash", str(val).lower())
        payload = {"type": "GET_BLOCK", "hash": str(val)}
    cached = rpc_client.cache_get(key)
    if cached is not None:
        return cached
    resp = rpc_client.rpc_send(client, payload)
    if rpc_client.payload_has_error(resp):
        err_val = resp.get("error") if resp else None
        ttl_err = db_cache.get_error_cache_ttl(err_val)
        if ttl_err is not None:
            rpc_client.cache_set(key, resp, ttl_err)
        return resp
    db_cache.cache_set(key, resp, ttl_sec=0)
    return resp


def rpc_block_range(client, opts: dict):
    start_height = None
    if opts:
        start_height = opts.get("start_height") or opts.get("start") or opts.get("height")
        try:
            limit = int(opts.get("limit", 200) or 200)
        except (ValueError, TypeError):
            limit = 200
    else:
        limit = 200

    if start_height is None or start_height == "latest":
        key = rpc_client.cache_key("block_range", "latest", limit)
        cached = rpc_client.cache_get(key)
        if cached is not None:
            return cached
    
    if start_height is not None and start_height != "latest":
        try:
            start_height_int = int(start_height)
            storage_result = db_blocks.get_block_range_from_storage(start_height_int, limit)
            
            if len(storage_result["items"]) >= limit:
                log.debug("[rpc_block_range] Using %d blocks from permanent storage", 
                          len(storage_result["items"]))
                return storage_result
            
            missing_count = limit - len(storage_result["items"])
            if missing_count > 0:
                next_start = start_height_int - len(storage_result["items"])
                if next_start >= 0:
                    rpc_resp = rpc_client.rpc_send(client, {
                        "type": "GET_BLOCK_RANGE", 
                        "start_height": next_start, 
                        "limit": missing_count
                    })
                    
                    if rpc_resp and "items" in rpc_resp:
                        new_items = rpc_resp.get("items", [])
                        db_blocks.save_blocks_to_storage(new_items)
                        storage_result["items"].extend(new_items)
                        storage_result["has_more"] = rpc_resp.get("has_more", False)
                        storage_result["next_height"] = rpc_resp.get("next_height", -1)
                        if rpc_resp.get("tip_height") is not None:
                            storage_result["tip_height"] = rpc_resp.get("tip_height")
                else:
                    storage_result["has_more"] = False
                    storage_result["next_height"] = -1
                return storage_result   
            
        except (ValueError, TypeError):
            pass
    
    resp = rpc_client.rpc_send(client, {
        "type": "GET_BLOCK_RANGE", 
        "limit": limit, 
        "start_height": start_height
    })
    
    if resp and not rpc_client.payload_has_error(resp) and "items" in resp:
        db_blocks.save_blocks_to_storage(resp["items"])
        if start_height is None or start_height == "latest":
            cache_key = rpc_client.cache_key("block_range", "latest", limit)
            rpc_client.cache_set(cache_key, resp, ttl_sec=30)
    
    return resp


@benchmark(label="rpc_tx", threshold_ms=15.0)
def rpc_tx(client, txid: str):
    txid_norm = str(txid).lower()
    key = rpc_client.cache_key("tx", txid_norm)
    return rpc_client.get_or_fetch_cached(key, lambda: rpc_client.rpc_send(client, {"type": "GET_TX_DETAIL", "txid": txid_norm}))


@benchmark(label="rpc_address", threshold_ms=15.0)
def rpc_address(client, addr: str):
    addr_norm = str(addr or "").strip()
    addr_key = addr_norm.lower()
    
    hist_key = rpc_client.cache_key("addr_hist", addr_key)
    vol_key = rpc_client.cache_key("addr_vol", addr_key)
    legacy_key = rpc_client.cache_key("address", addr_key)
    
    cached_hist = rpc_client.cache_get(hist_key)
    cached_vol = rpc_client.cache_get(vol_key)
    
    # Check legacy cache for migration if new keys not populated
    if cached_hist is None and cached_vol is None:
        cached_legacy = rpc_client.cache_get(legacy_key)
        if cached_legacy is not None and type(cached_legacy) is dict:
            leg_hist = cached_legacy.get("history") or []
            leg_conf = [it for it in leg_hist if it.get("status") == "confirmed"]
            leg_unconf = [it for it in leg_hist if it.get("status") == "unconfirmed"]
            leg_h = cached_legacy.get("height")
            cached_hist = {
                "last_synced_height": leg_h,
                "items": leg_conf,
                "total": int(cached_legacy.get("total_txs", len(leg_conf)))
            }
            cached_vol = {
                "spendable": cached_legacy.get("spendable", 0),
                "immature": cached_legacy.get("immature", 0),
                "outgoing": cached_legacy.get("outgoing", 0),
                "incoming": cached_legacy.get("incoming", 0),
                "balance": cached_legacy.get("balance", 0),
                "utxo_count": cached_legacy.get("utxo_count", 0),
                "unconfirmed_items": leg_unconf,
                "height": leg_h
            }
            rpc_client.cache_set(hist_key, cached_hist, ttl_sec=0)
            rpc_client.cache_set(vol_key, cached_vol, ttl_sec=15)
            return _assemble_address_response(addr_norm, cached_vol, cached_hist, leg_h)

    # 1. Fast path: volatile cache is fresh (< 15s) and confirmed cache exists
    if cached_vol is not None and type(cached_vol) is dict and cached_hist is not None and type(cached_hist) is dict:
        tip_h = cached_vol.get("height")
        return _assemble_address_response(addr_norm, cached_vol, cached_hist, tip_h)
    
    # 2. Volatile cache expired or missing: fetch fresh balances & total UTXO
    fut_balances = _EXECUTOR.submit(rpc_client.rpc_send, client, {"type": "GET_BALANCES", "addresses": [addr_norm]})
    fut_utxos = _EXECUTOR.submit(rpc_client.rpc_send, client, {"type": "GET_TOTAL_UTXO", "address": addr_norm})
    
    synced_h = cached_hist.get("last_synced_height") if (cached_hist and type(cached_hist) is dict) else None
    
    if synced_h is None:
        # First time fetch: query full history (limit 200)
        fut_history = _EXECUTOR.submit(rpc_client.rpc_send, client, {"type": "GET_TX_HISTORY", "address": addr_norm, "limit": 200})
        balances = fut_balances.result() or {}
        utxos = fut_utxos.result() or {}
        history = fut_history.result() or {}
    else:
        # Confirmed history exists: wait for balances to detect current tip_height
        balances = fut_balances.result() or {}
        utxos = fut_utxos.result() or {}
        tip_h = balances.get("height")
        if tip_h is None:
            tip_h = db_blocks.get_last_stored_height()
            
        if tip_h is not None and tip_h == synced_h:
            # ponytail: height has not changed, confirmed txs are identical. Query unconfirmed mempool only.
            history = rpc_client.rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr_norm, "status": "unconfirmed", "limit": 50}) or {}
        elif tip_h is not None and tip_h > synced_h:
            # ponytail: height advanced, fetch only delta txs since synced_h
            history = rpc_client.rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr_norm, "since_height": synced_h, "limit": 200}) or {}
        else:
            # Reorg or height reset: full re-fetch
            history = rpc_client.rpc_send(client, {"type": "GET_TX_HISTORY", "address": addr_norm, "limit": 200}) or {}
            
    balance_info = balances.get("items", {}).get(addr_norm, {}) if balances else {}
    tip_height = history.get("height") or balances.get("height")
    if tip_height is None and cached_hist and type(cached_hist) is dict:
        tip_height = cached_hist.get("last_synced_height")

    had_error = rpc_client.payload_has_error(balances) or rpc_client.payload_has_error(utxos) or rpc_client.payload_has_error(history)
    if had_error:
        error_ttl = None
        for resp in (balances, utxos, history):
            if rpc_client.payload_has_error(resp):
                ttl = db_cache.get_error_cache_ttl(resp.get("error"))
                if ttl and (error_ttl is None or ttl > error_ttl):
                    error_ttl = ttl
        if cached_hist and cached_vol:
            return _assemble_address_response(addr_norm, cached_vol, cached_hist, tip_height)
            
        err_msg = (history.get("error") if history else None) or (balances.get("error") if balances else None) or (utxos.get("error") if utxos else None) or "rpc_error"
        out = {
            "address": addr_norm,
            "spendable": 0, "immature": 0, "outgoing": 0, "incoming": 0, "balance": 0,
            "utxo_count": 0, "history": [], "height": tip_height, "total_txs": 0,
            "error": err_msg
        }
        if error_ttl:
            rpc_client.cache_set(vol_key, out, error_ttl)
        return out

    items_from_rpc = history.get("items") or []
    new_unconfirmed = [it for it in items_from_rpc if it.get("status") == "unconfirmed"]
    new_confirmed = [it for it in items_from_rpc if it.get("status") == "confirmed"]

    if cached_hist is None or (synced_h is not None and tip_height is not None and tip_height < synced_h):
        # Initial population or reorg reset
        total_confirmed = int(history.get("total_confirmed") or history.get("total") or len(new_confirmed))
        cached_hist = {
            "last_synced_height": tip_height,
            "items": new_confirmed,
            "total": total_confirmed
        }
        rpc_client.cache_set(hist_key, cached_hist, ttl_sec=0)
    elif new_confirmed:
        # Delta merge: prepend new confirmed items and deduplicate
        existing_items = cached_hist.get("items") or []
        seen_txids = set()
        merged_confirmed = []
        for it in (new_confirmed + existing_items):
            tid = it.get("txid")
            if tid and tid not in seen_txids:
                seen_txids.add(tid)
                merged_confirmed.append(it)
        max_cap = int(CFG.MAX_HISTORY_LIMIT or 500)
        if len(merged_confirmed) > max_cap:
            merged_confirmed = merged_confirmed[:max_cap]
            
        total_confirmed = int(history.get("total_confirmed") or (int(cached_hist.get("total", len(existing_items))) + len(new_confirmed)))
        cached_hist = {
            "last_synced_height": tip_height,
            "items": merged_confirmed,
            "total": total_confirmed
        }
        rpc_client.cache_set(hist_key, cached_hist, ttl_sec=0)
    elif tip_height is not None and tip_height > int(cached_hist.get("last_synced_height") or 0):
        cached_hist["last_synced_height"] = tip_height
        rpc_client.cache_set(hist_key, cached_hist, ttl_sec=0)

    cached_vol = {
        "spendable": balance_info.get("spendable", 0),
        "immature": balance_info.get("immature", 0),
        "outgoing": balance_info.get("pending_outgoing", 0),
        "incoming": balance_info.get("pending_incoming", 0),
        "balance": balance_info.get("balance", 0),
        "utxo_count": utxos.get("count", 0),
        "unconfirmed_items": new_unconfirmed,
        "height": tip_height
    }
    rpc_client.cache_set(vol_key, cached_vol, ttl_sec=15)
    
    out = _assemble_address_response(addr_norm, cached_vol, cached_hist, tip_height)
    rpc_client.cache_set(legacy_key, out, ttl_sec=15)
    return out


def _assemble_address_response(addr_norm: str, vol: dict, hist: dict, tip_height: int | None) -> dict:
    confirmed_items = (hist.get("items") or []) if hist else []
    unconfirmed_items = (vol.get("unconfirmed_items") or []) if vol else []
    
    merged_history = []
    for it in unconfirmed_items:
        it_copy = dict(it)
        it_copy["confirmations"] = 0
        merged_history.append(it_copy)
    
    for it in confirmed_items:
        it_copy = dict(it)
        h = it_copy.get("height")
        if h is not None and tip_height is not None:
            it_copy["confirmations"] = max(0, int(tip_height) - int(h) + 1)
        else:
            it_copy["confirmations"] = 0
        merged_history.append(it_copy)
        
    if len(merged_history) > 200:
        merged_history = merged_history[:200]
        
    total_txs = len(unconfirmed_items) + int(hist.get("total", len(confirmed_items)) if hist else 0)
    
    return {
        "address": addr_norm,
        "spendable": vol.get("spendable", 0),
        "immature": vol.get("immature", 0),
        "outgoing": vol.get("pending_outgoing", 0),
        "incoming": vol.get("pending_incoming", 0),
        "balance": vol.get("balance", 0),
        "utxo_count": vol.get("utxo_count", 0),
        "history": merged_history,
        "height": tip_height,
        "total_txs": total_txs
    }


@benchmark(label="rpc_graffiti", threshold_ms=15.0)
def rpc_graffiti(client, art_id: str):
    art_norm = str(art_id or "").strip()
    key = rpc_client.cache_key("graffiti", art_norm.lower()) if art_norm else None
    if key:
        cached = rpc_client.cache_get(key)
        if cached is not None:
            return cached

    fut_post = _EXECUTOR.submit(rpc_client.rpc_send, client, {"type": "GRAFFITI_GET_ART", "art_id": art_norm})
    fut_comments = _EXECUTOR.submit(rpc_client.rpc_send, client, {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_norm})
    
    post_resp = fut_post.result() or {}
    comments_resp = fut_comments.result() or {}
        
    cache_ok = True
    error_ttl = None
    for resp in (post_resp, comments_resp):
        if not rpc_client.payload_has_error(resp):
            continue
        err_val = resp.get("error") if resp else None
        ttl = db_cache.get_error_cache_ttl(err_val)
        if ttl is None:
            cache_ok = False
            break
        if error_ttl is None or ttl > error_ttl:
            error_ttl = ttl
    post = (post_resp.get("post") or post_resp) if post_resp else None
    comments = comments_resp.get("comments") if comments_resp else None
    out = {"post": post, "comments": comments}
    if key and cache_ok:
        rpc_client.cache_set(key, out, error_ttl)
    return out


@benchmark(label="rpc_graffiti_posts", threshold_ms=15.0)
def rpc_graffiti_posts(client, opts: dict):
    limit = int(opts.get("limit", 50) or 50) if opts else 50
    offset = int(opts.get("offset", 0) or 0) if opts else 0
    key = rpc_client.cache_key("graffiti_posts", limit, offset)
    cached = rpc_client.cache_get(key)
    if cached is not None:
        return cached
    payload = {"type": "GRAFFITI_GET_POSTS", "limit": limit, "offset": offset}
    resp = rpc_client.rpc_send(client, payload)
    cache_ok = True
    error_ttl = None
    if rpc_client.payload_has_error(resp):
        err_val = resp.get("error") if resp else None
        error_ttl = db_cache.get_error_cache_ttl(err_val)
        cache_ok = error_ttl is not None
    if resp and resp.get("type") == "GRAFFITI_GET_POSTS":
        out = {"posts": resp.get("posts") or [], "limit": limit, "offset": offset, "total": resp.get("total", 0)}
    else:
        out = {"posts": [], "limit": limit, "offset": offset, "total": 0}
    if cache_ok:
        rpc_client.cache_set(key, out, error_ttl)
    return out


def rpc_graffiti_file(client, opts: dict, fallback_art_id: str | None):
    art_id = (opts.get("art_id") or fallback_art_id or "").strip() if opts else str(fallback_art_id or "").strip()
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip() if opts else ""
    cache_dir = (opts.get("cache_dir") or opts.get("cache") or "").strip() or None if opts else None
    try:
        max_bytes = int(opts.get("max_bytes") or CFG.GRAFFITI_MAX_SIZE_BYTES) if opts else CFG.GRAFFITI_MAX_SIZE_BYTES
    except (TypeError, ValueError):
        max_bytes = CFG.GRAFFITI_MAX_SIZE_BYTES
    try:
        timeout = float(opts.get("timeout") or 10.0) if opts else 10.0
    except (TypeError, ValueError):
        timeout = 10.0
    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}
    resp = db_media.fetch_graffiti_file(
        lambda payload: rpc_client.rpc_send(client, payload),
        art_id,
        storer_addr=storer,
        cache_dir=cache_dir,
        cache_scope=rpc_client.get_cache_scope(),
        max_bytes=max_bytes,
        timeout=timeout,
    )
    if resp:
        return {
            "status": resp.get("status") or "error",
            "reason": resp.get("reason"),
            "meta": resp.get("meta") or {},
            "cache_path": resp.get("cache_path"),
        }
    return {"status": "error", "reason": "bad_response"}


def rpc_graffiti_media_meta(client, opts: dict, fallback_art_id: str | None = None):
    art_id = (opts.get("art_id") or fallback_art_id or "").strip() if opts else str(fallback_art_id or "").strip()
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip() if opts else ""
    cache_dir = (opts.get("cache_dir") or opts.get("cache") or "").strip() or None if opts else None
    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}
    return db_media.get_graffiti_media_meta(
        lambda payload: rpc_client.rpc_send(client, payload),
        art_id,
        storer_addr=storer,
        cache_dir=cache_dir,
        cache_scope=rpc_client.get_cache_scope(),
    )


def rpc_graffiti_chunk(client, opts: dict):
    art_id = str(opts.get("art_id") or "").strip() if opts else ""
    storer = (opts.get("storer_addr") or opts.get("storer") or "").strip() if opts else ""
    try:
        offset = int(opts.get("offset") or 0) if opts else 0
    except Exception:
        offset = 0
    try:
        length = int(opts.get("length") or db_media.GRAFFITI_CHUNK_BYTES) if opts else db_media.GRAFFITI_CHUNK_BYTES
    except Exception:
        length = db_media.GRAFFITI_CHUNK_BYTES
    if not art_id:
        return {"status": "error", "reason": "missing_art_id"}
    return db_media.fetch_graffiti_chunk(
        lambda payload: rpc_client.rpc_send(client, payload),
        art_id,
        offset=offset,
        length=length,
        storer_addr=storer,
        cache_scope=rpc_client.get_cache_scope(),
    )
