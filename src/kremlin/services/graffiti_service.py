# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP173

from __future__ import annotations

import os
import json
import time
import base64
import socket
import hashlib
import mimetypes

from urllib.parse import urlparse
from typing import Any, Callable, Dict, Optional, Tuple

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import connect_tcp_socket, parse_amount_sats
from tsarchain.utils.benchmarks import benchmark
from tsarchain.network.pow_token import solve_pow
from tsarchain.network.protocol import send_message, recv_message
from tsarchain.contracts.graffiti import (
    build_comment_metadata,
    build_metadata,
    build_opret_hex,
    calc_comment_split,
    calc_upload_fee_sats,
    compute_art_id,
    derive_pool_address,
    merkle_root_for_file,
    validate_graffiti_file,
)

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.graffiti_service")


def _pick_endpoint(meta: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    host = str(meta.get("ip") or meta.get("host") or "").strip()
    port = int(meta.get("port") or 0)
    if host and port > 0:
        return host, port

    url = str(meta.get("url") or "").strip()
    if url:
        parsed = urlparse(url if "://" in url else f"tcp://{url}")
        netloc = parsed.netloc or parsed.path
        if netloc:
            if ":" in netloc:
                host_part, port_part = netloc.split(":", 1)
                port = int(port_part)
            else:
                host_part = netloc
            host_part = host_part.strip()
            if host_part:
                if port <= 0:
                    port = int(CFG.STORAGE_PORT_START or CFG.PORT_START or 8090)
                if port <= 0:
                    return None
                return host_part, port
    return None


_connect_socket = connect_tcp_socket


def _send_storage_request(
    host: str,
    port: int,
    payload: Dict[str, Any],
    timeout: float | None = None,
    max_len: int | None = None,
    identity_hint: str | None = None,
    max_pow_retry: int = 1,
) -> Dict[str, Any]:

    timeout = timeout or CFG.RPC_TIMEOUT
    if max_len is None:
        max_len = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    base_payload = dict(payload)
    identity_norm = (identity_hint or base_payload.get("wallet_addr") or base_payload.get("creator_addr") or "").strip().lower()
    if identity_norm and "wallet_addr" not in base_payload:
        base_payload["wallet_addr"] = identity_norm

    resp: Dict[str, Any] = {}
    try:
        with _connect_socket(host, int(port), timeout) as s:
            raw = json.dumps(base_payload).encode("utf-8")
            send_message(s, raw, max_len=max_len)
            data = recv_message(s, timeout, max_len=max_len)
            if not data:
                return {"status": "error", "reason": "no_response"}
            obj = json.loads(data.decode("utf-8"))
            if type(obj) is dict:
                resp = obj
            else:
                resp = {"status": "error", "reason": "bad_response"}
    except OSError as exc:
        return {"status": "error", "reason": f"connection_failed: {exc}"}

    pow_challenge = resp.get("pow_challenge") if type(resp) is dict else None
    need_pow = resp.get("reason") in ("pow_required", "rate_limited") if type(resp) is dict else False
    if max_pow_retry > 0 and pow_challenge:
        identity_for_pow = identity_norm or str(pow_challenge.get("identity") or "")
        solution = solve_pow(pow_challenge, identity=identity_for_pow or "anon")
        if solution:
            retry_payload = dict(base_payload)
            retry_payload["pow"] = solution
            return _send_storage_request(
                host,
                port,
                retry_payload,
                timeout=timeout,
                max_len=max_len,
                identity_hint=identity_for_pow,
                max_pow_retry=max_pow_retry - 1,
            )
        if need_pow and "reason" not in resp:
            resp["reason"] = "pow_required"
    return resp


def fetch_storers(rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], limit: Optional[int] = None) -> list[Dict[str, Any]]:
    resp = rpc_call({"type": "STOR_LIST"}) or {}
    storers = resp.get("storers", [])
    valid: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port", 0))
        addr = str(meta.get("addr", "")).strip().lower()
        if not addr or port <= 0:
            continue
        valid.append(meta)
    valid.sort(key=lambda m: int(m.get("last_seen", 0)), reverse=True)
    if limit is not None and limit > 0:
        return valid[:limit]
    return valid


def _sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(chunk), b""):
            if not part:
                break
            h.update(part)
    return h.hexdigest()


def _infer_cache_mime(path: str) -> str:
    mime_raw, _ = mimetypes.guess_type(path)
    if mime_raw:
        return mime_raw
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg", ".jpeg"):
        return "image/jpeg"
    if ext == ".mp4":
        return "video/mp4"
    return "application/octet-stream"


def _find_cached_graffiti_path(art_id: str, cache_root: str) -> Optional[str]:
    if not cache_root or not os.path.isdir(cache_root):
        return None
    for ext in (".pdf", ".jpg", ".jpeg", ".mp4", ".mkv", ".bin"):
        candidate = os.path.join(cache_root, f"{art_id}{ext}")
        if os.path.isfile(candidate):
            return candidate
    try:
        for name in os.listdir(cache_root):
            if not name.startswith(f"{art_id}."):
                continue
            full_path = os.path.join(cache_root, name)
            if os.path.isfile(full_path):
                return full_path
    except FileNotFoundError:
        return None
    return None


def _read_cached_graffiti_file(art_id: str, cache_root: str) -> Optional[Dict[str, Any]]:
    cache_path = _find_cached_graffiti_path(art_id, cache_root)
    if not cache_path:
        return None
    try:
        size = os.path.getsize(cache_path)
    except OSError:
        return None
    if size <= 0:
        return None
    mime = _infer_cache_mime(cache_path)
    meta = {"size_bytes": int(size), "mime": mime, "filename": os.path.basename(cache_path)}
    data_bytes = None
    if size <= 8 * 1024 * 1024:
        try:
            with open(cache_path, "rb") as fh:
                data_bytes = fh.read()
        except OSError:
            return None
    return {"status": "ok", "bytes": data_bytes, "meta": meta, "cache_path": cache_path}


@benchmark(label="read_graffiti_file_info", threshold_ms=2.0)
def read_graffiti_file_info(path: str) -> Dict[str, Any]:
    """
    Read local file and return basic info (size, mime, sha256) while validating graffiti boundaries.
    """
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    mime_raw, _ = mimetypes.guess_type(path)
    mime = validate_graffiti_file(size, mime_raw, os.path.basename(path))
    sha = _sha256_file(path)
    mchunk = int(CFG.GRAFFITI_PROOF_CHUNK_BYTES)
    mroot, mcount = merkle_root_for_file(path, mchunk)
    log.info(
        "[graffiti_file] name=%s size=%s mime=%s sha=%s mroot=%s mchunk=%s mcount=%s",
        os.path.basename(path),
        size,
        mime,
        sha[:16],
        str(mroot or "")[:16],
        mchunk,
        mcount,
    )
    return {
        "size": size,
        "mime": mime,
        "sha": sha,
        "merkle_root": mroot,
        "merkle_chunk": mchunk,
        "merkle_count": mcount,
    }


def select_upload_storers(resp: Optional[Dict[str, Any]], *, replication_r: Optional[int] = None) -> list[Dict[str, Any]]:
    """
    Select candidate storage nodes based on metadata and sort by most trusted/recently seen.
    """
    storers = (resp or {}).get("storers", [])
    usable: list[Dict[str, Any]] = []
    for meta in storers:
        port = int(meta.get("port", 0))
        if port <= 0:
            continue
        usable.append(meta)
    usable.sort(key=lambda m: int(m.get("trusted", 0)) * 1_000_000 + int(m.get("last_seen", 0)), reverse=True)
    limit = max(1, int(replication_r if replication_r is not None else CFG.GRAFFITI_REPLICATION_R))
    return usable[:limit]


def filter_online_storers(storers: list[Dict[str, Any]], timeout: float = 2.0) -> list[Dict[str, Any]]:
    """
    Perform a quick TCP health check to ensure the storage node is reachable.
    """
    online: list[Dict[str, Any]] = []
    for meta in storers:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            host = str(meta.get("ip") or meta.get("host") or "").strip() or "127.0.0.1"
            port = int(meta.get("port") or 0)
            if port > 0:
                endpoint = (host, port)
        if not endpoint:
            continue
        host, port = endpoint
        try:
            with socket.create_connection((host, port), timeout=timeout):
                online.append(meta)
        except OSError:
            continue
    return online


def build_upload_context(sha256_hex: str, creator_addr: str, *, now_ts: Optional[int] = None) -> Dict[str, str]:
    """
    Create art_id + upload identity (graffiti_id and receipt_id) for one file.
    """
    creator = (creator_addr or "").strip().lower()
    if not creator:
        raise ValueError("creator wallet belum dipilih")
    art_id = compute_art_id(sha256_hex, creator)
    ts = int(now_ts or time.time())
    gid = f"{sha256_hex}_{ts}"
    receipt_id = f"rcpt_{gid}"
    return {"art_id": art_id, "graffiti_id": gid, "receipt_id": receipt_id}


def build_post_plan(
    *,
    sha256_hex: str,
    size_bytes: int,
    mime: str,
    creator_addr: str,
    storer_meta: Dict[str, Any],
    receipt_id: str,
    art_id: Optional[str] = None,
    merkle_root: Optional[str] = None,
    merkle_chunk: Optional[int] = None,
    merkle_count: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Arrange metadata and POST fees before and after upload.
    """
    if size_bytes is None:
        raise ValueError("upload metadata incomplete")
    creator = (creator_addr or "").strip().lower()
    if not creator:
        raise ValueError("creator wallet belum dipilih")
    storer_addr = str(storer_meta.get("addr", "")).strip().lower()
    art = art_id or compute_art_id(sha256_hex, creator)
    meta = build_metadata(
        sha256_hex=sha256_hex,
        size_bytes=int(size_bytes),
        mime=mime,
        storer_addr=storer_addr or "unknown",
        receipt_id=receipt_id,
        creator_addr=creator,
        merkle_root=merkle_root,
        merkle_chunk_bytes=merkle_chunk,
        merkle_chunks=merkle_count,
    )
    if merkle_root and merkle_chunk and merkle_count:
        log.info(
            "[post_plan] art=%s storer=%s mroot=%s mchunk=%s mcount=%s",
            str(art)[:16],
            str(storer_addr)[:16],
            str(merkle_root)[:16],
            int(merkle_chunk),
            int(merkle_count),
        )
    opret_hex = build_opret_hex(meta)
    pool_addr = derive_pool_address(art)
    fee_sats = calc_upload_fee_sats(int(size_bytes))
    tsar_fee = fee_sats / CFG.TSAR
    return {
        "pool_addr": pool_addr,
        "fee_sats": fee_sats,
        "opret_hex": opret_hex,
        "art_id": art,
        "tsar_fee": tsar_fee,
    }


def parse_amount_str(raw: str, default: int = 0) -> int:
    return parse_amount_sats(raw, default=default)


def build_comment_plan(
    *,
    art: Dict[str, Any],
    commenter_addr: str,
    base_amount_raw: str,
    tip_amount_raw: str,
    comment_text: str,
) -> Dict[str, Any]:
    """
    Validate comment input and arrange opret + payment output.
    """
    if not art:
        raise ValueError("Pilih karya terlebih dahulu.")
    art_id = str(art.get("art_id") or "").strip()
    if not art_id:
        raise ValueError("Art ID tidak tersedia.")

    commenter = (commenter_addr or "").strip().lower()
    if not commenter:
        raise ValueError("Pilih wallet untuk komentar.")

    text = (comment_text or "").strip()
    if not text:
        raise ValueError("Teks komentar belum diisi.")

    base_sats = parse_amount_str(base_amount_raw, int(CFG.GRAFFITI_COMMENT_MIN_FEE))
    if base_sats < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
        base_sats = int(CFG.GRAFFITI_COMMENT_MIN_FEE)
    tip_sats = parse_amount_str(tip_amount_raw, 0) if (tip_amount_raw or "").strip() else 0

    creator_addr = str(art.get("creator") or "").strip().lower()
    if not creator_addr:
        raise ValueError("Creator address is not available for this graffiti.")

    pool_addr = str(art.get("pool_address") or derive_pool_address(art_id)).strip().lower()
    try:
        meta = build_comment_metadata(
            art_id=art_id,
            comment_text=text,
            amount_sats=base_sats,
            creator_addr=creator_addr,
            commenter_addr=commenter,
            tip_sats=tip_sats,
        )
    except ValueError as exc:
        raise ValueError(f"Metadata komentar invalid: {exc}") from exc
    opret_hex = build_opret_hex(meta)
    split = calc_comment_split(base_sats, tip_sats)

    outputs = []
    if split["creator_total"] > 0:
        outputs.append({"address": creator_addr, "amount": split["creator_total"]})
    if split["storage"] > 0:
        outputs.append({"address": pool_addr, "amount": split["storage"]})
    if not outputs:
        raise ValueError("Tidak ada output pembayaran yang valid.")

    return {
        "opret_hex": opret_hex,
        "outputs": outputs,
        "base_sats": base_sats,
        "tip_sats": tip_sats,
        "split": split,
    }


def upload_graffiti(
    storer_meta: Dict[str, Any],
    file_path: str,
    creator_addr: str,
    *,
    graffiti_id: Optional[str] = None,
    sha256_hex: Optional[str] = None,
    art_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
    merkle_root: Optional[str] = None,
    merkle_chunk: Optional[int] = None,
    merkle_count: Optional[int] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Upload a file to a storage node discovered from the TsarChain node RPC.

    rpc_call    : callable that accepts a dict and returns a node RPC response (synchronous).
    storer_addr : bech32 address storage target.
    file_path   : path of the file to be uploaded.
    graffiti_id : unique id (default = sha256_hex).
    sha256_hex  : hash file (will be counted if None).
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "reason": "file_not_found"}
    creator_norm = (creator_addr or "").strip().lower()
    if not creator_norm:
        return {"status": "error", "reason": "missing_creator_addr"}

    total_size = os.path.getsize(file_path)
    mime_guess, _ = mimetypes.guess_type(file_path)
    mime_norm = validate_graffiti_file(total_size, mime_guess, os.path.basename(file_path))
    sha_hex = (sha256_hex or _sha256_file(file_path)).lower()
    gid = graffiti_id or sha_hex
    meta = dict(storer_meta or {})
    endpoint = _pick_endpoint(meta)
    if not endpoint:
        return {"status": "error", "reason": "storer_no_endpoint"}
    host, port = endpoint

    init_payload = {
        "type": "STOR_INIT",
        "graffiti_id": gid,
        "size_bytes": int(total_size),
        "sha256": sha_hex,
        "filename": os.path.basename(file_path) or "blob.bin",
        "mime": mime_norm,
        "wallet_addr": creator_norm,
    }
    if art_id:
        init_payload["art_id"] = str(art_id).strip().lower()
    if merkle_root and merkle_chunk and merkle_count:
        init_payload["mroot"] = str(merkle_root).strip().lower()
        init_payload["mchunk"] = int(merkle_chunk)
        init_payload["mcount"] = int(merkle_count)
    init_resp = _send_storage_request(host, port, init_payload, identity_hint=creator_norm, timeout=15.0)
    if init_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "init", "resp": init_resp}

    chunk_size = int(init_resp.get("chunk_size") or CFG.STORAGE_UPLOAD_CHUNK)
    sent = 0
    with open(file_path, "rb") as f:
        while True:
            buf = f.read(chunk_size)
            if not buf:
                break
            put_payload = {
                "type": "STOR_PUT",
                "graffiti_id": gid,
                "data": base64.b64encode(buf).decode("ascii"),
            }
            put_resp = _send_storage_request(host, port, put_payload, identity_hint=creator_norm, timeout=120.0)
            if put_resp.get("status") not in ("ok", "accepted"):
                return {"status": "error", "stage": "put", "resp": put_resp}
            sent += len(buf)
            if progress_cb:
                progress_cb(sent, total_size)

    commit_payload = {"type": "STOR_COMMIT", "graffiti_id": gid}
    if receipt_id:
        commit_payload["receipt_id"] = receipt_id
    commit_resp = _send_storage_request(host, port, commit_payload, identity_hint=creator_norm, timeout=30.0)
    if commit_resp.get("status") not in ("ok", "accepted"):
        return {"status": "error", "stage": "commit", "resp": commit_resp}

    receipt = commit_resp.get("receipt") or {"graffiti_id": gid, "sha256": sha_hex, "size_bytes": total_size}
    receipt.setdefault("id", f"rcpt_{gid}")
    return {
        "status": "ok",
        "graffiti_id": gid,
        "receipt": receipt,
        "storer": meta,
        "size_bytes": total_size,
        "sha256": sha_hex,
    }


def fetch_graffiti_file(
    rpc_call: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    art_id: str,
    *,
    storer_addr: Optional[str] = None,
    cache_dir: Optional[str] = None,
    max_bytes: int = CFG.GRAFFITI_MAX_SIZE_BYTES,
    timeout: float = 5.0,
) -> Dict[str, Any]:

    art_norm = (art_id or "").strip().lower()
    if not art_norm:
        return {"status": "error", "reason": "missing_art_id"}

    cache_root = cache_dir or os.path.join(CFG.WALLET_DATA_DIR, "graffiti_cache")
    cached = _read_cached_graffiti_file(art_norm, cache_root)
    if cached is not None:
        return cached

    max_bytes = max(32 * 1024, min(int(max_bytes), int(CFG.GRAFFITI_MAX_SIZE_BYTES)))
    msg_cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
    data_cap = int(msg_cap * 3 // 4)

    storers = fetch_storers(rpc_call)  # type: ignore[arg-type]
    if not storers:
        log.warning("[fetch] no_storers art=%s", art_norm[:16])
        return {"status": "error", "reason": "no_storers"}

    preferred, others = [], []
    storer_target = (storer_addr or "").strip().lower()
    for meta in storers:
        addr = str(meta.get("addr", "")).strip().lower()
        (preferred if storer_target and addr == storer_target else others).append(meta)
    candidates = preferred + others

    os.makedirs(cache_root, exist_ok=True)

    last_error = None
    for meta in candidates:
        endpoint = _pick_endpoint(meta)
        if not endpoint:
            continue
        host, port = endpoint

        # 1) Fetch metadata only (fast, small payload)
        meta_payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": False}
        meta_resp = _send_storage_request(host, port, meta_payload, timeout=max(timeout, 8.0), max_len=msg_cap)

        if type(meta_resp) is not dict:
            last_error = "bad_response"
            log.warning("[fetch] bad_meta_response art=%s host=%s port=%s meta=%s", art_norm[:16], host, port, meta)
            continue
        if not meta_resp.get("found"):
            last_error = meta_resp.get("reason") or "not_found"
            log.info("[fetch] not_found art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
            continue

        gid = str(meta_resp.get("graffiti_id") or "").strip()
        meta_info = meta_resp.get("meta") or {}
        try:
            total_size = int(meta_info.get("size_bytes") or 0)
        except Exception:
            total_size = 0
        if total_size <= 0:
            last_error = "bad_meta"
            log.warning("[fetch] bad_meta art=%s host=%s gid=%s size=%s", art_norm[:16], host, gid[:16], total_size)
            continue

        if total_size > max_bytes:
            last_error = "file_too_large"
            log.warning("[fetch] file_too_large art=%s size=%s limit=%s host=%s", art_norm[:16], total_size, max_bytes, host)
            continue

        fname = meta_info.get("filename") or f"{art_norm}.bin"
        mime = str(meta_info.get("mime") or "")
        ext = ".jpg" if mime.startswith("image/") else os.path.splitext(fname)[1] or ".bin"
        cache_path = os.path.join(cache_root, f"{art_norm}{ext}")
        tmp_path = cache_path + ".part"

        # 2) Small files: one-shot is fine
        one_shot_limit = min(data_cap, 8 * 1024 * 1024)
        if total_size <= one_shot_limit:
            payload = {"type": "STOR_GET_BY_ART", "art_id": art_norm, "include_data": True, "max_bytes": min(total_size, data_cap)}
            resp = _send_storage_request(host, port, payload, timeout=max(timeout, 8.0), max_len=msg_cap)
            if type(resp) is not dict:
                last_error = "bad_response"
                log.warning("[fetch] bad_response art=%s host=%s port=%s meta=%s", art_norm[:16], host, port, meta)
                continue
            if resp.get("status") == "error":
                last_error = resp.get("reason") or "error"
                log.warning("[fetch] storage_error art=%s host=%s port=%s reason=%s meta=%s", art_norm[:16], host, port, last_error, meta)
                continue
            data_b64 = resp.get("data_b64")
            if not data_b64:
                last_error = "no_data"
                log.warning("[fetch] no_data art=%s host=%s port=%s", art_norm[:16], host, port)
                continue

            raw = base64.b64decode(data_b64)
            with open(cache_path, "wb") as fh:
                fh.write(raw)
            log.info("[fetch] ok(one_shot) art=%s host=%s size=%s cache=%s", art_norm[:16], host, len(raw), bool(cache_path))
            return {"status": "ok", "bytes": raw, "meta": (resp.get("meta") or meta_info), "cache_path": cache_path}

        # 3) Large files: chunked download using STOR_GET_BY_ART + offset/length
        burst = int(CFG.STOR_GET_RL_IP_BURST)
        target_calls = max(1, min(max(1, burst - 1), 8))
        chunk_raw = (int(total_size) + int(target_calls) - 1) // int(target_calls)
        chunk_raw = max(1024 * 1024, chunk_raw)
        chunk_raw = min(int(chunk_raw), int(min(data_cap, 64 * 1024 * 1024)))

        dl_timeout = max(timeout, 60.0)
        offset = 0
        start_ts = time.time()
        try:
            with open(tmp_path, "wb") as out:
                while offset < total_size:
                    want = min(chunk_raw, total_size - offset)
                    chunk_payload = {
                        "type": "STOR_GET_BY_ART",
                        "art_id": art_norm,
                        "graffiti_id": gid,
                        "include_data": True,
                        "offset": int(offset),
                        "length": int(want),
                        "max_bytes": int(want),
                    }
                    resp = _send_storage_request(host, port, chunk_payload, timeout=dl_timeout, max_len=msg_cap)
                    if type(resp) is not dict:
                        last_error = "bad_response"
                        log.warning("[fetch] bad_chunk_response art=%s host=%s offset=%s", art_norm[:16], host, offset)
                        break
                    if resp.get("status") == "error":
                        last_error = resp.get("reason") or "error"
                        log.warning("[fetch] chunk_error art=%s host=%s offset=%s reason=%s", art_norm[:16], host, offset, last_error)
                        break
                    data_b64 = resp.get("data_b64")
                    if not data_b64:
                        last_error = "no_data"
                        log.warning("[fetch] no_data(chunk) art=%s host=%s offset=%s", art_norm[:16], host, offset)
                        break

                    chunk = base64.b64decode(data_b64)
                    if not chunk:
                        last_error = "empty_chunk"
                        log.warning("[fetch] empty_chunk art=%s host=%s offset=%s", art_norm[:16], host, offset)
                        break
                    out.write(chunk)
                    offset += len(chunk)

                    if resp.get("eof") and offset < total_size:
                        last_error = "short_read"
                        log.warning("[fetch] short_read art=%s host=%s got=%s of=%s", art_norm[:16], host, offset, total_size)
                        break

            if offset != total_size:
                try:
                    if os.path.isfile(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass
                continue

            os.replace(tmp_path, cache_path)
            raw = None
            if total_size <= 8 * 1024 * 1024:
                with open(cache_path, "rb") as fh:
                    raw = fh.read()

            dt = max(0.001, time.time() - start_ts)
            mbps = (float(total_size) / (1024 * 1024)) / dt
            log.info(
                "[fetch] ok(chunked) art=%s host=%s size=%s chunk=%s calls~%s speed=%.2fMB/s cache=%s",
                art_norm[:16],
                host,
                total_size,
                chunk_raw,
                int((total_size + chunk_raw - 1) // chunk_raw),
                mbps,
                bool(cache_path),
            )
            return {"status": "ok", "bytes": raw, "meta": meta_info, "cache_path": cache_path}

        except OSError:
            last_error = "io_error"
            log.exception("[fetch] io_error art=%s host=%s path=%s", art_norm[:16], host, tmp_path)
            try:
                if os.path.isfile(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            continue

    return {"status": "error", "reason": last_error or "unavailable"}


__all__ = [
    "build_comment_plan",
    "build_post_plan",
    "build_upload_context",
    "fetch_graffiti_file",
    "fetch_storers",
    "filter_online_storers",
    "parse_amount_str",
    "read_graffiti_file_info",
    "select_upload_storers",
    "upload_graffiti",
]
