# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import json
import base64
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Dict, Any, Optional

from tsarchain.utils import config as CFG
from web.Backend.src.utils.rate_limit import RateLimiter
from web.Backend.src.routes.health import handle_health
from web.Backend.src.routes.explorer_routes import (
    ExplorerRoutes,
    is_art_id,
    touch_file,
    cleanup_graffiti_cache,
    resolve_cache_path,
    infer_media_type,
    find_cached_file,
    parse_range_header,
    STREAM_THRESHOLD_BYTES,
    STREAM_CHUNK_BYTES,
)

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.web.Backend.server")

# Rate limiters
api_limiter = RateLimiter(window_ms=60 * 1000, max_requests=120)
search_limiter = RateLimiter(window_ms=60 * 1000, max_requests=20)
graffiti_media_limiter = RateLimiter(window_ms=60 * 1000, max_requests=40)


def create_handler_class(routes: Optional[ExplorerRoutes] = None):
    class ExplorerHTTPRequestHandler(BaseHTTPRequestHandler):
        # Suppress default server version header
        server_version = "TsarWeb/1.0"
        sys_version = ""

        def log_message(self, format_str: str, *args: Any) -> None:
            log.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format_str % args)


        def do_OPTIONS(self) -> None:
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()


        def do_HEAD(self) -> None:
            try:
                self._handle_get(is_head=True)
            except Exception as exc:
                log.exception("[unhandled_server_error_head]")
                self.send_response(500)
                self._set_cors_headers()
                self.end_headers()


        def do_GET(self) -> None:
            try:
                self._handle_get(is_head=False)
            except Exception as exc:
                log.exception("[unhandled_server_error]")
                self._send_json(500, {"error": "internal_error", "detail": str(exc)})


        def do_POST(self) -> None:
            client_ip = self._get_client_ip()
            api_ok, api_hdrs, api_retry = api_limiter.check(client_ip)
            if not api_ok:
                self._send_json(429, {"error": "rate_limited", "retry_after": api_retry}, api_hdrs)
                return

            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path.rstrip("/")

            if path == "/api/prefetch-blocks":
                s_ok, s_hdrs, s_retry = search_limiter.check(client_ip)
                if not s_ok:
                    self._send_json(429, {"error": "rate_limited", "retry_after": s_retry}, s_hdrs)
                    return
                code, resp = routes.handle_prefetch_blocks()
                self._send_json(code, resp, api_hdrs)
                return

            self._send_json(404, {"error": "not_found"}, api_hdrs)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


        def _handle_get(self, is_head: bool = False) -> None:
            client_ip = self._get_client_ip()

            api_ok, api_hdrs, api_retry = api_limiter.check(client_ip)
            if not api_ok:
                self._send_json(429, {"error": "rate_limited", "retry_after": api_retry}, api_hdrs, is_head=is_head)
                return

            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            if len(path) > 1 and path.endswith("/"):
                path = path[:-1]

            query_dict = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

            # 1. Health check
            if path == "/api/health":
                self._send_json(200, handle_health(), api_hdrs, is_head=is_head)
                return

            # 2. Receipt
            if path == "/api/receipt":
                code, resp = routes.handle_receipt(query_dict)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 3. History book
            if path == "/api/history_book":
                code, resp = routes.handle_history_book(query_dict)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 4. Network
            if path == "/api/network":
                code, resp = routes.handle_network()
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 5. Blocks list
            if path == "/api/blocks":
                code, resp = routes.handle_blocks(query_dict)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 6. Single Block /api/block/:id
            if path.startswith("/api/block/"):
                block_id = urllib.parse.unquote(path[11:])
                code, resp = routes.handle_block(block_id)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 7. Single Transaction /api/tx/:id
            if path.startswith("/api/tx/"):
                txid = urllib.parse.unquote(path[8:])
                code, resp = routes.handle_tx(txid)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 8. Address /api/address/:addr
            if path.startswith("/api/address/"):
                addr = urllib.parse.unquote(path[13:])
                code, resp = routes.handle_address(addr)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 9. Graffiti Media Streaming /api/graffiti/:artId/media
            if path.startswith("/api/graffiti/") and path.endswith("/media"):
                media_ok, media_hdrs, media_retry = graffiti_media_limiter.check(client_ip)
                if not media_ok:
                    self._send_json(429, {"error": "rate_limited", "retry_after": media_retry}, media_hdrs, is_head=is_head)
                    return
                art_id = urllib.parse.unquote(path[14:-6])
                self._serve_graffiti_media(art_id, is_head=is_head)
                return

            # 10. Graffiti Detail /api/graffiti/:artId
            if path.startswith("/api/graffiti/"):
                art_id = urllib.parse.unquote(path[14:])
                code, resp = routes.handle_graffiti_detail(art_id)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 11. Graffiti List /api/graffiti
            if path == "/api/graffiti":
                code, resp = routes.handle_graffiti_list(query_dict)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 12. Search /api/search
            if path == "/api/search":
                s_ok, s_hdrs, s_retry = search_limiter.check(client_ip)
                if not s_ok:
                    self._send_json(429, {"error": "rate_limited", "retry_after": s_retry}, s_hdrs, is_head=is_head)
                    return
                code, resp = routes.handle_search(query_dict)
                self._send_json(code, resp, api_hdrs, is_head=is_head)
                return

            # 404 Fallback
            self._send_json(404, {"error": "not_found"}, api_hdrs, is_head=is_head)


        def _get_client_ip(self) -> str:
            xfwd = self.headers.get("X-Forwarded-For")
            ip = xfwd.split(",")[0].strip() if xfwd else (self.client_address[0] if self.client_address else "127.0.0.1")
            return ip[7:] if ip.startswith("::ffff:") else ip


        def _set_cors_headers(self) -> None:
            origin = self.headers.get("Origin")
            allowed = CFG.WEB_ALLOWED_ORIGINS
            if origin and (origin in allowed or "*" in allowed):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            elif allowed:
                self.send_header("Access-Control-Allow-Origin", str(allowed))
            else:
                self.send_header("Access-Control-Allow-Origin", "*")

            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Range, X-Requested-With")
            self.send_header("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")


        def _send_json(self, status_code: int, data: Any, extra_headers: Optional[Dict[str, str]] = None, is_head: bool = False) -> None:
            try:
                payload = json.dumps(data, ensure_ascii=True, default=str).encode("utf-8")
            except Exception:
                payload = b'{"error":"json_encode_failed"}'
                status_code = 500

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self._set_cors_headers()
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, str(v))
            self.end_headers()
            if not is_head:
                self.wfile.write(payload)


        def _serve_graffiti_media(self, art_id: str, is_head: bool = False) -> None:
            cleanup_graffiti_cache()
            if not is_art_id(art_id):
                self._send_json(400, {"error": "invalid_art_id"}, is_head=is_head)
                return

            meta_resp = routes.svc.get_graffiti_media_meta(art_id)
            meta = meta_resp.get("meta", {}) if (meta_resp and meta_resp.get("status") == "ok") else None

            # 1. Try local cached file
            cached_file = find_cached_file(art_id)
            if cached_file and self._serve_local_file(cached_file, meta, is_head=is_head):
                return

            if not meta or (meta_resp and meta_resp.get("status") != "ok"):
                self._send_json(404, {"error": "media_not_found"}, is_head=is_head)
                return

            try:
                total_size = int(meta.get("size_bytes") or meta.get("size") or meta_resp.get("size_bytes") or 0)
            except (ValueError, TypeError):
                total_size = 0

            # 2. Smart Caching: file size <= 10MB -> Try service cache
            if 0 < total_size <= STREAM_THRESHOLD_BYTES:
                info = routes.svc.get_graffiti_media_info(art_id)
                if info and info.get("status") == "ok" and info.get("cache_path"):
                    resolved = resolve_cache_path(info["cache_path"])
                    if resolved and os.path.isfile(resolved):
                        if self._serve_local_file(resolved, meta, is_head=is_head):
                            return

            # 3. On-demand chunk streaming
            self._stream_graffiti_chunks(art_id, total_size, meta, is_head=is_head)


        def _serve_local_file(self, file_path: str, meta: Optional[Dict[str, Any]], is_head: bool = False) -> bool:
            try:
                if not os.path.isfile(file_path):
                    return False
                touch_file(file_path)
                size = os.path.getsize(file_path)
                media_type = infer_media_type(meta, file_path)

                range_header = self.headers.get("Range")
                range_info = parse_range_header(range_header, size)

                if range_info:
                    if range_info.get("invalid"):
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{size}")
                        self._set_cors_headers()
                        self.end_headers()
                        return True

                    start = range_info["start"]
                    end = range_info["end"]
                    content_length = end - start + 1

                    self.send_response(206)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Cache-Control", "public, max-age=300")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                    self.send_header("Content-Length", str(content_length))
                    self._set_cors_headers()
                    self.end_headers()

                    if is_head:
                        return True

                    with open(file_path, "rb") as f:
                        f.seek(start)
                        remaining = content_length
                        while remaining > 0:
                            chunk_size = min(remaining, 64 * 1024)
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                    return True

                self.send_response(200)
                self.send_header("Content-Type", media_type)
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(size))
                self._set_cors_headers()
                self.end_headers()

                if is_head:
                    return True

                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                return True
            except Exception as exc:
                log.warning("[serve_local_file_failed] %s", exc)
                return False


        def _stream_graffiti_chunks(self, art_id: str, total_size: int, meta: Optional[Dict[str, Any]], is_head: bool = False) -> None:
            filename = meta.get("filename") if meta else art_id
            media_type = infer_media_type(meta, filename)

            start = 0
            end = max(0, total_size - 1) if total_size > 0 else 0

            range_header = self.headers.get("Range")
            range_info = parse_range_header(range_header, total_size) if total_size > 0 else None

            if range_info:
                if range_info.get("invalid"):
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{total_size}")
                    self._set_cors_headers()
                    self.end_headers()
                    return
                start = range_info["start"]
                end = range_info["end"]
                content_len = end - start + 1
                self.send_response(206)
                self.send_header("Content-Type", media_type)
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes {start}-{end}/{total_size}")
                self.send_header("Content-Length", str(content_len))
                self._set_cors_headers()
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", media_type)
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Accept-Ranges", "bytes")
                if total_size > 0:
                    self.send_header("Content-Length", str(total_size))
                self._set_cors_headers()
                self.end_headers()

            if is_head:
                return

            curr_offset = start
            target_end = end if total_size > 0 else sys.maxsize

            while curr_offset <= target_end:
                want = min(STREAM_CHUNK_BYTES, target_end - curr_offset + 1) if total_size > 0 else STREAM_CHUNK_BYTES
                chunk_resp = routes.svc.get_graffiti_chunk(art_id, curr_offset, want)
                if not chunk_resp or chunk_resp.get("status") != "ok" or not chunk_resp.get("data_b64"):
                    break

                try:
                    buf = base64.b64decode(chunk_resp["data_b64"])
                except Exception:
                    break

                if not buf:
                    break

                try:
                    self.wfile.write(buf)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break

                curr_offset += len(buf)
                if chunk_resp.get("eof"):
                    break

    return ExplorerHTTPRequestHandler
