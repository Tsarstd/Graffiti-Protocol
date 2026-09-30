# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import urllib.parse
import contextlib
from http.server import BaseHTTPRequestHandler
from typing import Dict, Any, Optional

from tsarchain.utils.fcm_service import FCMService
from web.Backend.src.routes.health import handle_health
from web.Backend.src.utils.rate_limit import RateLimiter
from web.Backend.src.routes.explorer_routes import ExplorerRoutes, find_cached_file
from web.Backend.src.services.call_signaling_service import CallSignalingService
from web.Backend.src.utils.http_helpers import (
    get_client_ip,
    set_cors_headers,
    send_json,
    read_request_body,
    upgrade_to_websocket,
)
from web.Backend.src.routes.fcm_routes import handle_fcm_register, handle_fcm_unregister
from web.Backend.src.routes.media_routes import (
    serve_graffiti_media,
    serve_graffiti_thumbnail,
    serve_local_file,
    serve_thumbnail_file,
)
from tsarchain.utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.web.Backend.server")


# Rate limiters
api_limiter = RateLimiter(window_ms=60 * 1000, max_requests=120)
search_limiter = RateLimiter(window_ms=60 * 1000, max_requests=20)
graffiti_media_limiter = RateLimiter(window_ms=60 * 1000, max_requests=120)
graffiti_thumbnail_limiter = RateLimiter(window_ms=60 * 1000, max_requests=180)


def create_handler_class(
    routes: Optional[ExplorerRoutes] = None,
    signaling: Optional[CallSignalingService] = None,
    fcm: Optional[FCMService] = None,
):
    if fcm is None:
        fcm = FCMService.get_instance()
    if signaling is None and routes is not None:
        signaling = CallSignalingService(node_host=routes.node_host, node_port=routes.node_port, fcm=fcm)

    class ExplorerHTTPRequestHandler(BaseHTTPRequestHandler):
        server_version = "TsarWeb/1.0"
        sys_version = ""

        def log_message(self, format_str: str, *args: Any) -> None:
            log.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format_str % args)

        def handle(self) -> None:
            with contextlib.suppress(ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                super().handle()

        def do_OPTIONS(self) -> None:
            self.send_response(200)
            set_cors_headers(self)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_HEAD(self) -> None:
            try:
                self._handle_get(is_head=True)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass
            except Exception as exc:
                log.exception("[unhandled_server_error_head] : %s", exc)
                with contextlib.suppress(Exception):
                    self.send_response(500)
                    set_cors_headers(self)
                    self.end_headers()

        def do_GET(self) -> None:
            try:
                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path.rstrip("/")
                if path == "/api/call/ws":
                    upgrade = (self.headers.get("Upgrade") or "").strip().lower()
                    if upgrade == "websocket":
                        upgrade_to_websocket(self, signaling)
                        return
                self._handle_get(is_head=False)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass
            except Exception as exc:
                log.exception("[unhandled_server_error] : %s", exc)
                with contextlib.suppress(Exception):
                    send_json(self, 500, {"error": "internal_error", "detail": str(exc)})

        def do_POST(self) -> None:
            try:
                client_ip = get_client_ip(self.headers, self.client_address)
                api_ok, api_hdrs, api_retry = api_limiter.check(client_ip)
                if not api_ok:
                    send_json(self, 429, {"error": "rate_limited", "retry_after": api_retry}, api_hdrs)
                    return

                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path.rstrip("/")

                if path == "/api/prefetch-blocks":
                    s_ok, s_hdrs, s_retry = search_limiter.check(client_ip)
                    if not s_ok:
                        send_json(self, 429, {"error": "rate_limited", "retry_after": s_retry}, s_hdrs)
                        return
                    code, resp = routes.handle_prefetch_blocks()
                    send_json(self, code, resp, api_hdrs)
                    return

                if path == "/api/fcm/register":
                    body_bytes = read_request_body(self)
                    code, resp = handle_fcm_register(body_bytes, client_ip, fcm)
                    send_json(self, code, resp, api_hdrs)
                    return

                if path == "/api/fcm/unregister":
                    body_bytes = read_request_body(self)
                    code, resp = handle_fcm_unregister(body_bytes, fcm)
                    send_json(self, code, resp, api_hdrs)
                    return

                send_json(self, 404, {"error": "not_found"}, api_hdrs)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass
            except Exception as exc:
                log.exception("[unhandled_server_error_post] : %s", exc)
                with contextlib.suppress(Exception):
                    send_json(self, 500, {"error": "internal_error", "detail": str(exc)})

        def _handle_get(self, is_head: bool = False) -> None:
            client_ip = get_client_ip(self.headers, self.client_address)
            api_ok, api_hdrs, api_retry = api_limiter.check(client_ip)
            if not api_ok:
                send_json(self, 429, {"error": "rate_limited", "retry_after": api_retry}, api_hdrs, is_head=is_head)
                return

            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            if len(path) > 1 and path.endswith("/"):
                path = path[:-1]

            query_dict = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

            # 1. Health check
            if path == "/api/health":
                send_json(self, 200, handle_health(), api_hdrs, is_head=is_head)
                return

            # 2. Receipt
            if path == "/api/receipt":
                code, resp = routes.handle_receipt(query_dict)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 3. History book
            if path == "/api/history_book":
                code, resp = routes.handle_history_book(query_dict)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 4. Network
            if path == "/api/network":
                code, resp = routes.handle_network()
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 5. Blocks list
            if path == "/api/blocks":
                code, resp = routes.handle_blocks(query_dict)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 6. Single Block /api/block/:id
            if path.startswith("/api/block/"):
                block_id = urllib.parse.unquote(path[11:])
                code, resp = routes.handle_block(block_id)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 7. Single Transaction /api/tx/:id
            if path.startswith("/api/tx/"):
                txid = urllib.parse.unquote(path[8:])
                code, resp = routes.handle_tx(txid)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 8. Address /api/address/:addr
            if path.startswith("/api/address/"):
                addr = urllib.parse.unquote(path[13:])
                code, resp = routes.handle_address(addr)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 9. Graffiti Media Streaming /api/graffiti/:artId/media
            if path.startswith("/api/graffiti/") and path.endswith("/media"):
                media_ok, media_hdrs, media_retry = graffiti_media_limiter.check(client_ip)
                if not media_ok:
                    send_json(self, 429, {"error": "rate_limited", "retry_after": media_retry}, media_hdrs, is_head=is_head)
                    return
                art_id = urllib.parse.unquote(path[14:-6])
                finder = globals().get("find_cached_file", find_cached_file)
                serve_graffiti_media(self, art_id, routes, is_head=is_head, cache_finder=finder)
                return

            # 9b. Graffiti Thumbnail /api/graffiti/:artId/thumbnail
            if path.startswith("/api/graffiti/") and path.endswith("/thumbnail"):
                thumb_ok, thumb_hdrs, thumb_retry = graffiti_thumbnail_limiter.check(client_ip)
                if not thumb_ok:
                    send_json(self, 429, {"error": "rate_limited", "retry_after": thumb_retry}, thumb_hdrs, is_head=is_head)
                    return
                art_id = urllib.parse.unquote(path[14:-10])
                finder = globals().get("find_cached_file", find_cached_file)
                serve_graffiti_thumbnail(self, art_id, routes, is_head=is_head, cache_finder=finder)
                return

            # 10. Graffiti Detail /api/graffiti/:artId
            if path.startswith("/api/graffiti/"):
                art_id = urllib.parse.unquote(path[14:])
                code, resp = routes.handle_graffiti_detail(art_id)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 11. Graffiti List /api/graffiti
            if path == "/api/graffiti":
                code, resp = routes.handle_graffiti_list(query_dict)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 12. Search /api/search
            if path == "/api/search":
                s_ok, s_hdrs, s_retry = search_limiter.check(client_ip)
                if not s_ok:
                    send_json(self, 429, {"error": "rate_limited", "retry_after": s_retry}, s_hdrs, is_head=is_head)
                    return
                code, resp = routes.handle_search(query_dict)
                send_json(self, code, resp, api_hdrs, is_head=is_head)
                return

            # 404 Fallback
            send_json(self, 404, {"error": "not_found"}, api_hdrs, is_head=is_head)

        # Compatibility methods for tests and external callers
        def _set_cors_headers(self) -> None:
            set_cors_headers(self)

        def _send_json(self, status_code: int, data: Any, extra_headers: Optional[Dict[str, str]] = None, is_head: bool = False) -> None:
            send_json(self, status_code, data, extra_headers, is_head=is_head)

        def _get_client_ip(self) -> str:
            return get_client_ip(self.headers, self.client_address)

        def _serve_local_file(self, *args: Any, **kwargs: Any) -> bool:
            return serve_local_file(self, *args, **kwargs)

        def _serve_thumbnail_file(self, *args: Any, **kwargs: Any) -> None:
            return serve_thumbnail_file(self, *args, **kwargs)

    return ExplorerHTTPRequestHandler
