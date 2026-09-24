# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import json
import base64
import hashlib
from typing import Dict, Any, Optional

from tsarchain.utils import config as CFG
from web.Backend.src.services.call_signaling_service import WS_RFC6455_GUID, CallSignalingService


def get_client_ip(headers: Any, client_address: Optional[tuple]) -> str:
    """Extract client IP from X-Forwarded-For or raw socket address."""
    xfwd = headers.get("X-Forwarded-For") if headers else None
    ip = xfwd.split(",")[0].strip() if xfwd else (client_address[0] if client_address else "127.0.0.1")
    return ip[7:] if ip.startswith("::ffff:") else ip


def set_cors_headers(handler: Any) -> None:
    """Set standard CORS headers on the HTTP response."""
    origin = handler.headers.get("Origin")
    allowed = CFG.WEB_ALLOWED_ORIGINS
    if origin and (origin in allowed or "*" in allowed):
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Access-Control-Allow-Credentials", "true")
    elif allowed:
        handler.send_header("Access-Control-Allow-Origin", str(allowed))
    else:
        handler.send_header("Access-Control-Allow-Origin", "*")

    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Range, X-Requested-With")
    handler.send_header(
        "Access-Control-Expose-Headers",
        "Content-Range, Accept-Ranges, Content-Length, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After",
    )


def send_json(
    handler: Any,
    status_code: int,
    data: Any,
    extra_headers: Optional[Dict[str, str]] = None,
    is_head: bool = False,
) -> None:
    """Serialize data to JSON, send response headers, and write payload."""
    try:
        payload = json.dumps(data, ensure_ascii=True, default=str).encode("utf-8")
    except Exception:
        payload = b'{"error":"json_encode_failed"}'
        status_code = 500

    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    set_cors_headers(handler)
    if extra_headers:
        for k, v in extra_headers.items():
            handler.send_header(k, str(v))
    handler.end_headers()
    if not is_head:
        handler.wfile.write(payload)


def read_request_body(handler: Any, max_bytes: int = 65536) -> bytes:
    """Read request body supporting Content-Length and chunked transfer encoding."""
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        chunks = []
        total = 0
        while True:
            line = handler.rfile.readline().strip()
            if not line:
                break
            try:
                chunk_len = int(line, 16)
            except ValueError:
                break
            if chunk_len == 0:
                handler.rfile.readline()
                break
            total += chunk_len
            if total > max_bytes:
                return b""
            chunks.append(handler.rfile.read(chunk_len))
            handler.rfile.readline()
        return b"".join(chunks)

    try:
        length_val = int(handler.headers.get("Content-Length") or 0)
    except Exception:
        length_val = 0
    if length_val <= 0 or length_val > max_bytes:
        return b""
    return handler.rfile.read(length_val)


def upgrade_to_websocket(handler: Any, signaling: Optional[CallSignalingService]) -> None:
    """Perform RFC6455 WebSocket handshake and hand socket off to signaling service."""
    ws_key = (handler.headers.get("Sec-WebSocket-Key") or "").strip()
    if not ws_key:
        handler.send_response(400)
        handler.end_headers()
        return
    accept_raw = hashlib.sha1((ws_key + WS_RFC6455_GUID).encode("ascii")).digest()
    accept_val = base64.b64encode(accept_raw).decode("ascii")
    handler.send_response(101, "Switching Protocols")
    handler.send_header("Upgrade", "websocket")
    handler.send_header("Connection", "Upgrade")
    handler.send_header("Sec-WebSocket-Accept", accept_val)
    handler.end_headers()

    client_ip = get_client_ip(handler.headers, handler.client_address)
    if signaling:
        signaling.handle_connection(handler.connection, client_ip)
