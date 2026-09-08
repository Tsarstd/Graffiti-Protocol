# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import math
import base64
import hashlib

from typing import Any, Dict, Optional

from tsarchain.utils import config as CFG
from tsarchain.utils.benchmarks import benchmark
from tsarchain.contracts import graffiti as GRAFFITI


from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.wallet_route")


def handle_wallet_rpc(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    RPC handle sent from wallet to storage node.
    """
    t = str(msg.get("type", "")).upper()
    handlers = {
        "STOR_INIT": _handle_stor_init,
        "STOR_PUT": _handle_stor_put,
        "STOR_COMMIT": _handle_stor_commit,
        "STOR_GET_BY_ART": _handle_stor_get_by_art,
    }
    if t in handlers:
        return handlers[t](server, msg)
    return None

# =============================================================================
# RPC
# =============================================================================

@benchmark(label="STOR_INIT", threshold_ms=100.0)
def _handle_stor_init(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = str(msg.get("graffiti_id", "")).strip()
    size = int(msg.get("size_bytes", 0))
    sha = str(msg.get("sha256", "")).lower()
    fname = str(msg.get("filename", "")).strip() or "blob.bin"
    mime = str(msg.get("mime", "")).strip().lower()
    art_id = str(msg.get("art_id", "")).strip().lower()
    mroot = msg.get("mroot") or msg.get("merkle_root")
    mchunk = msg.get("mchunk") or msg.get("merkle_chunk")
    mcount = msg.get("mcount") or msg.get("merkle_count")
    chunk = int(CFG.STORAGE_UPLOAD_CHUNK)
    if not aid or size <= 0 or len(sha) != 64:
        return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_fields"}
    
    mime = GRAFFITI.validate_graffiti_file(size, mime, fname)
    projected = int(server.index.get("bytes_used", 0)) + size
    if projected > int(CFG.STORAGE_MAX_BYTES):
        return {"type": "STOR_ACK", "status": "rejected", "reason": "storage_full"}
    
    mem_err = _check_mempool_capacity(server)
    if mem_err:
        return mem_err
        
    inc_dir = os.path.join(server.storage_dir, "incoming")
    os.makedirs(inc_dir, exist_ok=True)
    path = os.path.join(inc_dir, f"{aid}.part")
    meta = {
        "size_bytes": size,
        "sha256": sha,
        "filename": fname,
        "mime": mime,
        "paid": False,
        "expire_at_height": 0,
        "confirmed_at_height": 0,
        "state": "receiving",
        "path": path,
        "received_bytes": 0,
        "chunk_size": chunk,
        "created_ts": int(time.time()),
    }
    ok, err_reason, parsed_merkle = _validate_merkle_meta(mroot, mchunk, mcount, size)
    if not ok:
        return {"type": "STOR_ACK", "status": "rejected", "reason": err_reason}
    meta.update(parsed_merkle)
    
    if art_id:
        meta["art_id"] = art_id
        server.index.setdefault("art_map", {})[art_id] = aid
    server.index["files"][aid] = meta
    server._save_index()
    open(path, "wb").close()
    
    return {
        "type": "STOR_ACK",
        "status": "ok",
        "upload_id": aid,
        "graffiti_id": aid,
        "chunk_size": chunk,
    }

@benchmark(label="STOR_PUT", threshold_ms=150.0)
def _handle_stor_put(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = str(msg.get("graffiti_id", "")).strip()
    b64 = str(msg.get("data", ""))
    if not aid or not b64:
        return {"type": "STOR_ACK", "status": "rejected", "reason": "bad_fields"}
    meta = server.index.get("files", {}).get(aid)
    if not meta or meta.get("state") not in ("receiving", "appending"):
        return {"type": "STOR_ACK", "status": "rejected", "reason": "no_init"}
    
    chunk_bytes = base64.b64decode(b64)
    max_chunk = int(meta.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
    if len(chunk_bytes) > max_chunk:
        return {"type": "STOR_ACK", "status": "rejected", "reason": "chunk_too_big"}
    try:
        received_total = server.db.append_incoming(aid, chunk_bytes, max_chunk)
    except ValueError as exc:
        return {"type": "STOR_ACK", "status": "rejected", "reason": str(exc)}
    meta["state"] = "appending"
    meta["received_bytes"] = int(received_total)
    meta["updated_ts"] = int(time.time())
    server.index["files"][aid] = meta
    
    return {
        "type": "STOR_ACK",
        "status": "ok",
        "received": int(meta["received_bytes"]),
        "of": int(meta.get("size_bytes", 0)),
    }

@benchmark(label="STOR_COMMIT", threshold_ms=250.0)
def _handle_stor_commit(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = str(msg.get("graffiti_id", "")).strip()
    req_receipt = str(msg.get("receipt_id", "")).strip()
    meta = server.index.get("files", {}).get(aid)
    if not meta:
        return {"type": "STOR_ACK", "status": "rejected", "reason": "no_such"}
    try:
        expected_size = int(meta.get("size_bytes", 0))
        tmp_path = meta.get("path")
        if not tmp_path or not os.path.isfile(tmp_path):
            inc_dir = os.path.join(server.storage_dir, "incoming")
            part_path = os.path.join(inc_dir, f"{aid}.part")
            bin_path = os.path.join(inc_dir, f"{aid}.bin")
            if os.path.isfile(bin_path):
                tmp_path = bin_path
            elif os.path.isfile(part_path):
                tmp_path = part_path
                
        ok, err_reason, actual_size = _verify_file_hash(tmp_path, expected_size, meta.get("sha256"))
        if not ok:
            return {"type": "STOR_ACK", "status": "rejected", "reason": err_reason}
        
        GRAFFITI.validate_graffiti_file(actual_size, meta.get("mime"), meta.get("filename"))
        now_ts = int(time.time())
        receipt_id = meta.get("receipt_id") or req_receipt or f"rcpt_{aid}_{now_ts}"
        receipt = {
            "id": receipt_id,
            "graffiti_id": aid,
            "sha256": meta.get("sha256"),
            "size_bytes": expected_size,
            "filename": meta.get("filename"),
            "ts": now_ts,
        }
        inc_dir = os.path.join(server.storage_dir, "incoming")
        os.makedirs(inc_dir, exist_ok=True)
        fin = os.path.join(inc_dir, f"{aid}.bin")
        if os.path.abspath(tmp_path) != os.path.abspath(fin):
            os.replace(tmp_path, fin)
        norm_fin = os.path.normpath(fin).replace("\\", "/")
        meta.update(
            {
                "path": norm_fin,
                "state": "pending_confirm",
                "receipt_id": receipt_id,
                "receipt": receipt,
                "stored_ts": now_ts,
                "received_bytes": actual_size,
            }
        )
        # set payment deadline height for unpaid blobs when caller supplies current tip height
        tip_h = int(msg.get("tip_height", 0) or msg.get("block_height", 0) or 0)
        expire_after = max(0, int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS))
        if (not meta.get("paid")) and expire_after > 0 and tip_h > 0:
            try:
                expire_h = int(meta.get("expire_at_height", 0) or 0)
            except Exception:
                log.exception("Failed to parse existing expire_at_height from metadata")
                expire_h = 0
            if expire_h <= 0:
                meta["expire_at_height"] = tip_h + expire_after
        art_id = str(meta.get("art_id", "")).strip().lower()
        if art_id:
            server.index.setdefault("art_map", {})[art_id] = aid
        server.index["files"][aid] = meta
        server.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in server.index["files"].values())
        server._save_index()
        
        return {"type": "STOR_ACK", "status": "ok", "receipt": receipt}
    except Exception as e:
        return {"type": "STOR_ACK", "status": "rejected", "reason": str(e)}

@benchmark(label="STOR_GET_BY_ART", threshold_ms=400.0)
def _handle_stor_get_by_art(server, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Public fetch by art_id (or direct graffiti_id). Supports optional chunked reads via offset/length.
    art_id = str(msg.get("art_id", "")).strip().lower()
    gid = str(msg.get("graffiti_id", "")).strip()

    if not art_id and not gid:
        return {"type": "STOR_GET_BY_ART", "found": False}

    if not gid and art_id:
        gid = (server.index.get("art_map") or {}).get(art_id) or ""

    meta = None
    if gid:
        meta = (server.index.get("files") or {}).get(gid)

    found = bool(meta)
    resp = {"type": "STOR_GET_BY_ART", "found": found, "graffiti_id": gid, "meta": meta}
    
    include_data = bool(msg.get("include_data"))
    if not include_data or not meta:
        return resp
        
    return _process_data_retrieval(server, msg, art_id, gid, meta, resp)

def _process_data_retrieval(server, msg: Dict[str, Any], art_id: str, gid: str, meta: Dict[str, Any], resp: Dict[str, Any]) -> Dict[str, Any]:
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)
    
    max_bytes = int(msg.get("max_bytes", 0) or 0)
    if max_bytes <= 0:
        max_bytes = int(CFG.GRAFFITI_MAX_SIZE_BYTES)
    max_bytes = max(32 * 1024, min(max_bytes, int(CFG.GRAFFITI_MAX_SIZE_BYTES), data_cap))

    chunk_mode = ("offset" in msg) or ("length" in msg)
    offset = int(msg.get("offset", 0) or 0)
    req_len = int(msg.get("length", 0) or 0)

    if offset < 0:
        offset = 0

    total_size = int(meta.get("size_bytes", 0) or 0)

    if (not chunk_mode) and total_size > 0 and total_size > max_bytes:
        resp["status"] = "error"
        resp["reason"] = "file_too_large"
        log.warning("[STOR_GET_BY_ART] file_too_large art=%s size=%s limit=%s", (art_id[:16] if art_id else "-"), total_size, max_bytes)
        return resp

    if total_size > 0 and offset >= total_size:
        resp.update({"status": "ok", "offset": int(offset), "length": 0, "total_size": int(total_size), "eof": True, "data_b64": ""})
        return resp

    if req_len <= 0:
        req_len = int(max_bytes)
    read_len = int(max(0, min(int(req_len), int(max_bytes))))
    if total_size > 0:
        read_len = int(min(read_len, int(total_size) - int(offset)))

    return _fetch_kv_data(server, gid, art_id, offset, read_len, total_size, resp)

def _fetch_kv_data(server, gid: str, art_id: str, offset: int, read_len: int, total_size: int, resp: Dict[str, Any]) -> Dict[str, Any]:
    data_bytes = _read_kv_chunk(server, gid, offset, read_len)
    if data_bytes is None:
        resp["status"] = "error"
        resp["reason"] = "file_missing"
        log.warning("[STOR_GET_BY_ART] file_missing art=%s gid=%s", (art_id[:16] if art_id else "-"), gid)
        return resp

    out_len = len(data_bytes)
    eof = bool(total_size > 0 and (int(offset) + out_len) >= int(total_size))
    resp.update({
        "data_b64": base64.b64encode(data_bytes).decode("ascii"),
        "status": "ok",
        "offset": int(offset),
        "length": int(out_len),
        "total_size": int(total_size),
        "eof": eof,
    })
    return resp

# =============================================================================
# HELPERS
# =============================================================================

def _check_mempool_capacity(server) -> Optional[Dict[str, Any]]:
    if int(CFG.MAX_GRAFFITI_ON_MEMPOOL) > 0:
        active = 0
        items = (server.index.get("files") or {}).values()
        for meta in items:
            if meta.get("paid"):
                continue
            state = str(meta.get("state") or "").lower()
            if state in ("receiving", "appending", "pending_confirm") or not meta.get("paid"):
                active += 1

        if active >= int(CFG.MAX_GRAFFITI_ON_MEMPOOL):
            return {"type": "STOR_ACK", "status": "rejected", "reason": "mempool_graffiti_full"}
    return None

def _validate_merkle_meta(mroot, mchunk, mcount, size) -> tuple[bool, str, dict]:
    if mroot or mchunk or mcount:
        if not (mroot and mchunk and mcount):
            return False, "bad_merkle_meta", {}
        mroot = str(mroot).strip().lower()
        if not GRAFFITI._is_valid_sha256_hex(mroot):
            return False, "bad_merkle_root", {}
        try:
            mchunk = int(mchunk)
            mcount = int(mcount)
        except Exception:
            return False, "bad_merkle_meta", {}
        if mchunk <= 0 or mcount <= 0:
            return False, "bad_merkle_meta", {}
        expected = int(math.ceil(int(size) / float(mchunk)))
        if expected != mcount:
            return False, "bad_merkle_meta", {}
        return True, "", {"mroot": mroot, "mchunk": mchunk, "mcount": mcount}
    return True, "", {}

def _verify_file_hash(tmp_path: str, expected_size: int, expected_sha256: str) -> tuple[bool, str, int]:
    if not tmp_path or not os.path.isfile(tmp_path):
        return False, "missing_file", 0
    actual_size = 0
    digest = hashlib.sha256()
    with open(tmp_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
            actual_size += len(chunk)
    digest_hex = digest.hexdigest().lower()
    if actual_size != expected_size:
        return False, "size_mismatch", actual_size
    if digest_hex != expected_sha256:
        return False, "hash_mismatch", actual_size
    return True, "", actual_size

def _read_kv_chunk(server, gid, offset, read_len):
    try:
        return server.db.get_final_bytes_range(gid, int(offset), int(read_len))
    except Exception:
        pass
    return None

__all__ = ["handle_wallet_rpc"]
