# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from __future__ import annotations

import os
import time
import base64
from typing import Any, Callable, Dict, Optional, Tuple, List

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import clean_remove_file
from tsarchain.utils.benchmarks import benchmark
from kremlin.services.graffiti_service import _pick_endpoint, _send_storage_request

from web.Backend.src.core.logic_web import db_cache

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.src.core.logic_web.db_media")


def get_graffiti_media_meta(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    cache_scope: Optional[str] = None,
    stor_list_ttl_sec: Optional[int] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    art_norm = _sanitize_art_id(art_id)
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    cached = _get_cached_graffiti_file(art_norm, cache_dir)
    if cached is not None and cached.get("status") == "ok":
        cache_path = cached.get("cache_path")
        size_bytes = os.path.getsize(cache_path) if cache_path and os.path.isfile(cache_path) else 0
        meta = cached.get("meta") or {}
        if size_bytes > 0 and "size_bytes" not in meta:
            meta["size_bytes"] = size_bytes
        return {
            "status": "ok",
            "cached": True,
            "meta": meta,
            "cache_path": cache_path,
            "size_bytes": size_bytes,
        }

    candidates = _get_ordered_storers(
        rpc_call, storer_addr=storer_addr, cache_scope=cache_scope, stor_list_ttl_sec=stor_list_ttl_sec
    )
    if not candidates:
        return {"status": "error", "reason": "no_storers"}

    last_error = None
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint

        try:
            meta_payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": False}
            meta_resp = _send_storage_request(host, port, meta_payload, timeout=max(float(timeout), 8.0), max_len=msg_cap)

            is_ok, err_reason = _check_storage_response(meta_resp)
            if not is_ok:
                last_error = err_reason
                continue

            gid = str(meta_resp.get("graffiti_id") or "").strip()
            meta_info = meta_resp.get("meta") or {}
            total_size = _extract_total_size(meta_info)

            return {
                "status": "ok",
                "cached": False,
                "graffiti_id": gid,
                "meta": meta_info,
                "size_bytes": total_size,
            }
        except Exception:
            last_error = "io_error"
            continue

    return {"status": "error", "reason": last_error or "unavailable"}


def fetch_graffiti_chunk(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    offset: int = 0,
    length: int = CFG.GRAFFITI_CHUNK_BYTES,
    *,
    storer_addr: Optional[str] = None,
    cache_scope: Optional[str] = None,
    stor_list_ttl_sec: Optional[int] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    art_norm = _sanitize_art_id(art_id)
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    offset = max(0, int(offset or 0))
    length = max(1024, min(int(length or CFG.GRAFFITI_CHUNK_BYTES), CFG.GRAFFITI_CHUNK_BYTES))

    candidates = _get_ordered_storers(
        rpc_call, storer_addr=storer_addr, cache_scope=cache_scope, stor_list_ttl_sec=stor_list_ttl_sec
    )
    if not candidates:
        return {"status": "error", "reason": "no_storers"}

    last_error = None
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint

        try:
            chunk_payload = {
                "type": "STOR_GET_BY_ART",
                "art_id": art_norm,
                "include_data": True,
                "offset": offset,
                "length": length,
                "max_bytes": length,
            }
            resp = _send_storage_request(host, port, chunk_payload, timeout=max(float(timeout), 10.0), max_len=msg_cap)

            is_ok, err_reason = _check_storage_response(resp)
            if not is_ok:
                last_error = err_reason
                continue

            data_b64 = resp.get("data_b64") or ""
            if not data_b64 and not resp.get("eof"):
                last_error = "no_data"
                continue

            total_size = int(resp.get("total_size") or 0)
            eof = bool(resp.get("eof", False))
            resp_offset = int(resp.get("offset") if resp.get("offset") is not None else offset)
            resp_length = int(resp.get("length") if resp.get("length") is not None else 0)

            return {
                "status": "ok",
                "data_b64": data_b64,
                "offset": resp_offset,
                "length": resp_length,
                "total_size": total_size,
                "eof": eof,
                "meta": resp.get("meta") or {},
            }
        except Exception:
            last_error = "io_error"
            continue

    return {"status": "error", "reason": last_error or "unavailable"}


@benchmark(label="fetch_graffiti_file", threshold_ms=1000.0)
def fetch_graffiti_file(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    cache_scope: Optional[str] = None,
    stor_list_ttl_sec: Optional[int] = None,
    max_bytes: int = CFG.GRAFFITI_MAX_SIZE_BYTES,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    art_norm = _sanitize_art_id(art_id)
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    cached = _get_cached_graffiti_file(art_norm, cache_dir)
    if cached is not None:
        return cached

    max_bytes = max(32 * 1024, min(int(max_bytes), int(CFG.GRAFFITI_MAX_SIZE_BYTES)))
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = msg_cap * 3 // 4

    candidates = _get_ordered_storers(
        rpc_call, storer_addr=storer_addr, cache_scope=cache_scope, stor_list_ttl_sec=stor_list_ttl_sec
    )
    if not candidates:
        return {"status": "error", "reason": "no_storers"}

    cache_root = cache_dir or CFG.WEB_MEDIA_CACHE_DIR
    os.makedirs(cache_root, exist_ok=True)

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint
        tmp_path: Optional[str] = None

        try:
            meta_payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": False}
            meta_resp = _send_storage_request(host, port, meta_payload, timeout=max(float(timeout), 8.0), max_len=msg_cap)

            is_ok, err_reason = _check_storage_response(meta_resp)
            if not is_ok:
                last_error = err_reason
                continue

            gid = str(meta_resp.get("graffiti_id") or "").strip()
            meta_info = meta_resp.get("meta") or {}
            total_size = _extract_total_size(meta_info)

            if total_size <= 0:
                payload = {
                    "type": "STOR_GET_BY_ART",
                    "art_id": art_norm,
                    "include_data": True,
                    "max_bytes": min(max_bytes, data_cap),
                }
                res = _do_oneshot_fetch(
                    host=host, port=port, payload=payload, timeout=timeout, msg_cap=msg_cap,
                    art_norm=art_norm, meta_info=meta_info, cache_root=cache_root, log_tag="oneshot_unknown"
                )
                if type(res) is str:
                    last_error = res
                    continue
                return res

            if total_size > max_bytes:
                last_error = "file_too_large"
                continue

            ext = _guess_media_ext(meta_info, art_norm)
            cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
            tmp_path = cache_path + ".part"

            if os.path.isfile(cache_path) and os.path.getsize(cache_path) == total_size:
                _cache_media_success(art_norm, meta_info, cache_path, total_size, ttl_sec=0)
                log.info("[webdb] ok(disk_hit) art=%s host=%s size=%s cache=%s", art_norm[:16], host, total_size, True)
                return {"status": "ok", "meta": meta_info, "cache_path": cache_path}

            one_shot_limit = min(data_cap, 8 * 1024 * 1024)
            if total_size <= one_shot_limit:
                payload = {
                    "type": "STOR_GET_BY_ART",
                    "art_id": art_norm,
                    "include_data": True,
                    "max_bytes": min(total_size, data_cap),
                }
                res = _do_oneshot_fetch(
                    host=host, port=port, payload=payload, timeout=timeout, msg_cap=msg_cap,
                    art_norm=art_norm, meta_info=meta_info, cache_root=cache_root, log_tag="oneshot"
                )
                if type(res) is str:
                    last_error = res
                    continue
                return res

            burst = int(CFG.STOR_GET_RL_IP_BURST)
            target_calls = max(2, min(8, burst - 2))
            chunk_raw = (total_size + target_calls - 1) // target_calls
            chunk_raw = max(1024 * 1024, chunk_raw)
            chunk_raw = min(chunk_raw, min(data_cap, 64 * 1024 * 1024))

            dl_timeout = max(float(timeout), 20.0)

            offset = 0
            calls = 0
            start_ts = time.time()
            ok = True

            with open(tmp_path, "wb") as out:
                while offset < total_size:
                    want = min(chunk_raw, total_size - offset)
                    chunk_payload = {
                        "type": "STOR_GET_BY_ART",
                        "art_id": art_norm,
                        "include_data": True,
                        "offset": offset,
                        "length": want,
                        "max_bytes": want,
                    }
                    if gid:
                        chunk_payload["graffiti_id"] = gid

                    resp = _send_storage_request(host, port, chunk_payload, timeout=dl_timeout, max_len=msg_cap)
                    calls += 1

                    chk_ok, chk_err = _check_storage_response(resp)
                    if not chk_ok:
                        last_error = chk_err
                        ok = False
                        break

                    data_b64 = resp.get("data_b64") or ""
                    if not data_b64:
                        last_error = "no_data"
                        ok = False
                        break

                    try:
                        chunk = base64.b64decode(data_b64)
                    except Exception:
                        last_error = "bad_response"
                        ok = False
                        break

                    if not chunk:
                        last_error = "no_data"
                        ok = False
                        break

                    out.write(chunk)
                    offset += len(chunk)

            if not ok:
                if tmp_path:
                    clean_remove_file(tmp_path)
                continue

            os.replace(tmp_path, cache_path)

        except Exception:
            last_error = "io_error"
            if tmp_path:
                clean_remove_file(tmp_path)
            continue

        elapsed = max(0.001, time.time() - start_ts)
        mbps = (float(total_size) / (1024 * 1024)) / elapsed
        _cache_media_success(art_norm, meta_info, cache_path, total_size, ttl_sec=0)
        log.info(
            "[webdb] ok(chunked) art=%s host=%s size=%s chunk=%s calls~%s speed=%.2fMB/s cache=%s",
            art_norm[:16],
            host,
            total_size,
            chunk_raw,
            calls,
            mbps,
            True,
        )
        return {"status": "ok", "meta": meta_info, "cache_path": cache_path}

    reason = last_error or "unavailable"
    ttl_err = db_cache.get_error_cache_ttl(reason)
    if ttl_err is not None:
        _cache_media_error(art_norm, reason, ttl_sec=ttl_err)
    return {"status": "error", "reason": reason}


def fetch_storers(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    limit: Optional[int] = None,
    *,
    cache_scope: Optional[str] = None,
    ttl_sec: Optional[int] = None,
) -> list[Dict[str, Any]]:
    ttl_sec = int(ttl_sec or db_cache.WEB_STOR_LIST_TTL_SEC)
    cache_key = db_cache.make_cache_key("web", cache_scope, "stor_list")
    cached = db_cache.cache_get(cache_key)
    if cached and type(cached) is list:
        return cached[:limit] if limit is not None and limit > 0 else cached

    resp = rpc_call({"type": "STOR_LIST"}) or {}
    if resp.get("error"):
        ttl_err = db_cache.get_error_cache_ttl(resp.get("error"))
        if ttl_err is not None:
            db_cache.cache_set(cache_key, [], ttl_sec=ttl_err)
        return []

    storers = resp.get("storers") or resp.get("items") or []
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port") or 0)
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if ttl_sec > 0:
        db_cache.cache_set(cache_key, valid, ttl_sec=ttl_sec)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


# =============================================================================
# INTERNAL METHOD
# =============================================================================

def _media_meta_key(art_id: str) -> bytes:
    return f"meta:{art_id}".encode("utf-8")


def _media_data_key(art_id: str) -> bytes:
    return f"data:{art_id}".encode("utf-8")


def _cache_media_error(art_id: str, reason: str, ttl_sec: int = db_cache.WEB_CACHE_TTL_SEC) -> None:
    store = db_cache.open_web_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "status": "error",
        "reason": str(reason or "error"),
    }
    try:
        store.put_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id), db_cache._serialize_payload(entry))
        store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_error cache failed art=%s", art_id[:16])


def _cache_media_success(art_id: str, meta: dict, cache_path: str, size: int, ttl_sec: int = 0) -> None:
    store = db_cache.open_web_store()
    if store is None:
        return
    entry = {
        "ts": int(time.time()),
        "ttl": int(ttl_sec),
        "status": "ok",
        "meta": meta or {},
        "size": int(size or 0),
        "cache_path": str(cache_path or ""),
    }
    try:
        store.put_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id), db_cache._serialize_payload(entry))
        store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    except Exception:
        log.warning("[webdb] media_ok_path cache failed art=%s", art_id[:16])


def _load_media_entry(art_id: str) -> Optional[dict]:
    store = db_cache.open_web_store()
    if store is None:
        return None
    raw = store.get_bytes(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id))
    if raw is None:
        return None
    entry = db_cache._deserialize_payload(bytes(raw))
    if not entry or db_cache._is_expired(entry):
        try:
            store.delete(db_cache.WEB_MEDIA_DB, _media_meta_key(art_id))
            store.delete(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
        except Exception:
            pass
        return None
    return entry


def _sanitize_art_id(art_id: str) -> Optional[str]:
    art_norm = str(art_id or "").strip().lower()
    art_norm = os.path.basename(art_norm).replace("..", "").replace("/", "").replace("\\", "")
    return art_norm if art_norm else None


def _guess_media_ext(meta: dict, art_id: str) -> str:
    fname = str(meta.get("filename") or f"{art_id}.bin")
    ext = os.path.splitext(fname)[1] or ""
    mime = str(meta.get("mime") or "").lower()
    if "pdf" in mime or ext.lower() == ".pdf":
        return ".pdf"
    if mime.startswith("image/"):
        return ext if ext.lower() in (".jpg", ".jpeg") else ".jpg"
    if mime.startswith("video/"):
        return ".mkv" if ("matroska" in mime or "mkv" in mime) else (".mp4" if ext.lower() != ".mp4" else ext)
    return ext or ".bin"


def _write_cache_file(cache_root: str, art_id: str, meta: dict, data: bytes) -> str:
    ext = _guess_media_ext(meta, art_id)
    cache_path = os.path.join(cache_root, f"{art_id}{ext}")
    try:
        os.makedirs(cache_root, exist_ok=True)
        if not os.path.exists(cache_path) or os.path.getsize(cache_path) != len(data):
            with open(cache_path, "wb") as fh:
                fh.write(data)
    except Exception:
        log.warning("[webdb] cache write failed art=%s", art_id[:16])
    return cache_path


def _extract_total_size(meta: dict) -> int:
    try:
        return int(meta.get("size_bytes") or meta.get("size") or meta.get("bytes") or 0)
    except Exception:
        return 0


def _check_storage_response(resp: Any) -> Tuple[bool, str]:
    if not resp:
        return False, "bad_response"
    if not resp.get("found"):
        return False, str(resp.get("reason") or "not_found")
    if resp.get("status") == "error":
        return False, str(resp.get("reason") or "error")
    return True, ""


def _get_cached_graffiti_file(art_id: str, cache_dir: Optional[str]) -> Optional[dict]:
    store = db_cache.open_web_store()
    if store is None:
        return None
    entry = _load_media_entry(art_id)
    if not entry:
        return None
    if entry.get("status") != "ok":
        return {"status": "error", "reason": entry.get("reason") or "not_found"}

    cache_path = entry.get("cache_path")
    expected_size = entry.get("size")
    if cache_path and expected_size is not None:
        if os.path.isfile(cache_path) and os.path.getsize(cache_path) == expected_size:
            log.debug("[webdb] ok(cache_disk_hit) art=%s path=%s", art_id[:16], cache_path)
            return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}

    data_raw = store.get_bytes(db_cache.WEB_MEDIA_DB, _media_data_key(art_id))
    if data_raw is None:
        return None
    cache_root = cache_dir or CFG.WEB_MEDIA_CACHE_DIR
    cache_path = _write_cache_file(cache_root, art_id, entry.get("meta") or {}, bytes(data_raw))
    return {"status": "ok", "meta": entry.get("meta") or {}, "cache_path": cache_path}


def _get_ordered_storers(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    storer_addr: Optional[str] = None,
    cache_scope: Optional[str] = None,
    stor_list_ttl_sec: Optional[int] = None,
) -> List[Dict[str, Any]]:
    storers = fetch_storers(rpc_call, cache_scope=cache_scope, ttl_sec=stor_list_ttl_sec)
    if not storers:
        return []

    preferred, others = [], []
    storer_target = (storer_addr or "").strip().lower()
    for meta in storers:
        addr = str(meta.get("addr") or meta.get("address") or "").strip().lower()
        (preferred if storer_target and addr == storer_target else others).append(meta)
    return preferred + others


def _do_oneshot_fetch(
    host: str,
    port: int,
    msg_cap: int,
    log_tag: str,
    art_norm: str,
    payload: dict,
    timeout: float,
    cache_root: str,
    meta_info: dict,
) -> object:
    resp = _send_storage_request(host, port, payload, timeout=max(float(timeout), 12.0), max_len=msg_cap)
    is_ok, err_reason = _check_storage_response(resp)
    if not is_ok:
        return err_reason

    data_b64 = resp.get("data_b64") if resp else None
    if not data_b64:
        return "no_data"

    try:
        raw = base64.b64decode(data_b64)
    except Exception:
        log.warning("[webdb] oneshot b64 decode failed art=%s", art_norm[:16])
        return "bad_response"

    meta_out = resp.get("meta") or meta_info
    cache_path = _write_cache_file(cache_root, art_norm, meta_out, raw)
    _cache_media_success(art_norm, meta_out, cache_path, len(raw), ttl_sec=0)
    log.debug("[webdb] ok(%s) art=%s host=%s bytes=%s cache=%s", log_tag, art_norm[:16], host, len(raw), True)
    return {"status": "ok", "meta": meta_out, "cache_path": cache_path}
