# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import re
import time
import threading
from typing import Dict, Any, Optional, Tuple

from web.Backend.src.utils.search_kind import guess_kind, is_hex64
from web.Backend.src.services.explorer_service import ExplorerService
from web.Backend.src.core import main_web

_ART_ID_REGEX = re.compile(r"^graf[0-9a-fA-F]{60}$")
_ADDRESS_REGEX = re.compile(r"^tsar[0-9a-zA-Z]{16,}$")
_BLOCK_HEIGHT_REGEX = re.compile(r"^\d{1,7}$")
_RANGE_REGEX = re.compile(r"^bytes=(\d*)-(\d*)$")

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, "..", "..", "..", "..", ".."))
CACHE_DIR = os.path.abspath(os.path.join(_PROJECT_ROOT, "data", "web", "graffiti_cache"))

GRAFFITI_CACHE_TTL_SEC = 6 * 60 * 60    # 6 hours TTL for server disk cache
GRAFFITI_CACHE_SWEEP_SEC = 15 * 60      # 15 minutes sweep interval
STREAM_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB threshold: files < 10MB cached to disk, >= 10MB streamed
STREAM_CHUNK_BYTES = 4 * 1024 * 1024    # 4 MB chunk size for on-demand streaming

_last_graffiti_cache_sweep = 0.0
_cache_sweep_lock = threading.Lock()


class ExplorerRoutes:
    def __init__(self, service: ExplorerService, host: str = "127.0.0.1", port: int = 19000):
        self.svc = service
        self.node_host = host
        self.node_port = port


    def handle_receipt(self, query_params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        txid = query_params.get("txid")
        if not txid:
            return 400, {"error": "missing_txid"}
        if not is_hex64(txid):
            return 400, {"error": "invalid_txid"}

        data = self.svc.get_receipt(txid)
        if data and data.get("status") == "error":
            return 400, {"error": data.get("message", "receipt_error")}

        return 200, {"status": "ok", "data": data}


    def handle_history_book(self, query_params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        address = query_params.get("address")
        if not address:
            return 400, {"error": "missing_address"}
        if not _ADDRESS_REGEX.match(address):
            return 400, {"error": "invalid_address"}

        data = self.svc.get_history_book(address)
        if data and data.get("status") == "error":
            return 400, {"error": data.get("message", "history_book_error")}

        return 200, {"status": "ok", "data": data}


    def handle_network(self) -> Tuple[int, Dict[str, Any]]:
        snap = self.svc.get_network()
        return 200, {"status": "ok", "data": snap}


    def handle_blocks(self, query_params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        limit_raw = query_params.get("limit", "10")
        try:
            limit = min(max(int(limit_raw), 1), 500)
        except (ValueError, TypeError):
            limit = 10

        start_raw = query_params.get("start") or query_params.get("start_height") or query_params.get("height")
        start_height = None
        if start_raw is not None and str(start_raw).strip() != "":
            try:
                start_height = int(start_raw)
            except (ValueError, TypeError):
                start_height = None

        prefer_database = query_params.get("prefer_database") == "true"
        source = "database" if prefer_database else "auto"

        data = self.svc.get_block_range(start_height=start_height, limit=limit, source=source)
        return 200, {"status": "ok", "data": data}


    def handle_block(self, block_id: str) -> Tuple[int, Dict[str, Any]]:
        is_height = bool(_BLOCK_HEIGHT_REGEX.match(block_id))
        if not is_height and not is_hex64(block_id):
            return 400, {"error": "invalid_block_id"}

        data = self.svc.get_block(block_id)
        return 200, {"status": "ok", "data": data}


    def handle_tx(self, txid: str) -> Tuple[int, Dict[str, Any]]:
        if not is_hex64(txid):
            return 400, {"error": "invalid_txid"}

        data = self.svc.get_tx(txid)
        return 200, {"status": "ok", "data": data}


    def handle_address(self, addr: str) -> Tuple[int, Dict[str, Any]]:
        if not _ADDRESS_REGEX.match(addr):
            return 400, {"error": "invalid_address"}

        data = self.svc.get_address(addr)
        return 200, {"status": "ok", "data": data}


    def handle_graffiti_detail(self, art_id: str) -> Tuple[int, Dict[str, Any]]:
        if not is_art_id(art_id):
            return 400, {"error": "invalid_art_id"}

        data = self.svc.get_graffiti(art_id)
        if not data:
            return 404, {"error": "not_found"}

        return 200, {"status": "ok", "data": data}


    def handle_graffiti_list(self, query_params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        try:
            limit = min(max(int(query_params.get("limit", "24")), 1), 100)
        except (ValueError, TypeError):
            limit = 24
        try:
            offset = max(int(query_params.get("offset", "0")), 0)
        except (ValueError, TypeError):
            offset = 0

        data = self.svc.get_graffiti_posts(limit=limit, offset=offset)
        return 200, {"status": "ok", "data": data}


    def handle_search(self, query_params: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        query = (query_params.get("q") or "").strip()
        if not query:
            return 400, {"error": "missing_query"}

        inferred = guess_kind(query)
        result = self.svc.search(query)
        if not result or not result.get("data"):
            return 404, {"status": "not_found", "kind": inferred}

        return 200, {"status": "ok", "kind": result.get("kind"), "data": result.get("data")}


    def handle_prefetch_blocks(self) -> Tuple[int, Dict[str, Any]]:
        main_web.dispatch_rpc("prefetch_blocks", None, self.node_host, self.node_port)
        return 200, {"status": "ok", "message": "Prefetch started"}


# =============================================================================
# =============================================================================


def is_art_id(s: str | None) -> bool:
    if not s or type(s) is not str:
        return False
    return bool(_ART_ID_REGEX.match(s))


def touch_file(file_path: str) -> None:
    try:
        now = time.time()
        os.utime(file_path, (now, now))
    except Exception:
        pass


def cleanup_graffiti_cache() -> None:
    global _last_graffiti_cache_sweep
    now = time.time()
    if now - _last_graffiti_cache_sweep < GRAFFITI_CACHE_SWEEP_SEC:
        return
    with _cache_sweep_lock:
        if now - _last_graffiti_cache_sweep < GRAFFITI_CACHE_SWEEP_SEC:
            return
        _last_graffiti_cache_sweep = now

        if not os.path.isdir(CACHE_DIR):
            return
        try:
            for entry in os.listdir(CACHE_DIR):
                full_path = os.path.join(CACHE_DIR, entry)
                if os.path.isfile(full_path):
                    try:
                        stat = os.stat(full_path)
                        if now - stat.st_mtime > GRAFFITI_CACHE_TTL_SEC:
                            os.unlink(full_path)
                    except Exception:
                        pass
        except Exception:
            pass


def resolve_cache_path(cache_path: str | None) -> Optional[str]:
    if not cache_path or type(cache_path) is not str:
        return None
    if os.path.isabs(cache_path):
        resolved = os.path.abspath(os.path.normpath(cache_path))
    else:
        resolved = os.path.abspath(os.path.join(_PROJECT_ROOT, cache_path))

    rel = os.path.relpath(resolved, _PROJECT_ROOT)
    if rel.startswith("..") or os.path.isabs(rel):
        return None
    return resolved


def infer_media_type(meta: Optional[Dict[str, Any]], file_path: str | None) -> str:
    mime = (meta.get("mime") or meta.get("mime_type")) if type(meta) is dict else None
    if mime:
        mime_str = str(mime).lower()
        if "pdf" in mime_str:
            return "application/pdf"
        if "video/mp4" in mime_str or "mp4" in mime_str:
            return "video/mp4"
        if "video/x-matroska" in mime_str or "mkv" in mime_str:
            return "video/x-matroska"
        if "image/jpeg" in mime_str or "image" in mime_str:
            return "image/jpeg"

    ext = os.path.splitext(file_path or "")[1].lower()
    if ext == ".pdf":
        return "application/pdf"
    if ext == ".mp4":
        return "video/mp4"
    if ext == ".mkv":
        return "video/x-matroska"
    if ext in (".jpg", ".jpeg"):
        return "image/jpeg"
    return "application/octet-stream"


def find_cached_file(art_id: str) -> Optional[str]:
    if not os.path.isdir(CACHE_DIR):
        return None
    for ext in [".pdf", ".jpg", ".jpeg", ".mp4", ".mkv", ".bin"]:
        candidate = os.path.join(CACHE_DIR, f"{art_id}{ext}")
        if os.path.isfile(candidate):
            return candidate
    return None


def parse_range_header(range_header: str | None, size: int) -> Optional[Dict[str, Any]]:
    if not range_header or type(range_header) is not str:
        return None
    m = _RANGE_REGEX.match(range_header.strip())
    if not m:
        return {"invalid": True}

    start_str, end_str = m.group(1), m.group(2)
    try:
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else size - 1
    except ValueError:
        return {"invalid": True}

    if start > end or start >= size or start < 0 or end < 0:
        return {"invalid": True}

    end = min(end, size - 1)
    return {"start": start, "end": end}
