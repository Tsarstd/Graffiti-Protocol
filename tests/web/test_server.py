# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import json
import time
import socket
import base64
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from web.Backend.src.server import create_handler_class
from web.Backend.src.services.explorer_service import ExplorerService
from web.Backend.src.routes.explorer_routes import ExplorerRoutes


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_server_http_endpoints_and_streaming():
    port = _find_free_port()
    svc = ExplorerService("127.0.0.1", 19000)
    routes = ExplorerRoutes(svc, "127.0.0.1", 19000)
    handler_cls = create_handler_class(routes)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    base_url = f"http://127.0.0.1:{port}"
    hex64 = "0" * 64
    addr = "tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqq"
    art_id = "graf" + "0" * 60

    try:
        # 1. Health check GET
        req = urllib.request.Request(f"{base_url}/api/health", headers={"Origin": "http://localhost:7542"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] == "ok"
            assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:7542"

        # 2. CORS OPTIONS preflight
        req_opt = urllib.request.Request(f"{base_url}/api/blocks", method="OPTIONS", headers={"Origin": "http://localhost:7542"})
        with urllib.request.urlopen(req_opt) as resp:
            assert resp.status == 200
            assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:7542"
            assert "GET, POST, OPTIONS" in resp.headers.get("Access-Control-Allow-Methods")

        # 3. 404 route
        req_404 = urllib.request.Request(f"{base_url}/api/unknown_route")
        try:
            urllib.request.urlopen(req_404)
            assert False, "Should have raised 404"
        except urllib.error.HTTPError as err:
            assert err.code == 404

        # 4. POST prefetch-blocks
        with patch("web.Backend.src.core.main_web.dispatch_rpc", return_value={"status": "ok"}):
            req_post = urllib.request.Request(f"{base_url}/api/prefetch-blocks", data=b"", method="POST")
            with urllib.request.urlopen(req_post) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 5. GET /api/blocks
        with patch.object(svc, "get_block_range", return_value={"items": []}):
            with urllib.request.urlopen(f"{base_url}/api/blocks?limit=5") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 6. GET /api/block/:id
        with patch.object(svc, "get_block", return_value={"height": 1, "hash": hex64}):
            with urllib.request.urlopen(f"{base_url}/api/block/1") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 7. GET /api/tx/:id
        with patch.object(svc, "get_tx", return_value={"txid": hex64}):
            with urllib.request.urlopen(f"{base_url}/api/tx/{hex64}") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 8. GET /api/address/:addr
        with patch.object(svc, "get_address", return_value={"balance": 50}):
            with urllib.request.urlopen(f"{base_url}/api/address/{addr}") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 9. GET /api/receipt
        with patch.object(svc, "get_receipt", return_value={"status": "success"}):
            with urllib.request.urlopen(f"{base_url}/api/receipt?txid={hex64}") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 10. GET /api/history_book
        with patch.object(svc, "get_history_book", return_value={"status": "success"}):
            with urllib.request.urlopen(f"{base_url}/api/history_book?address={addr}") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 11. GET /api/graffiti
        with patch.object(svc, "get_graffiti_posts", return_value={"items": []}):
            with urllib.request.urlopen(f"{base_url}/api/graffiti?limit=10") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 12. GET /api/graffiti/:artId
        with patch.object(svc, "get_graffiti", return_value={"art_id": art_id}):
            with urllib.request.urlopen(f"{base_url}/api/graffiti/{art_id}") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"

        # 13. GET /api/search
        with patch.object(svc, "search", return_value={"kind": "block", "data": {"height": 1}}):
            with urllib.request.urlopen(f"{base_url}/api/search?q=1") as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode())
                assert data["status"] == "ok"
                assert data["kind"] == "block"

        # 14. GET /api/graffiti/:artId/media - chunk streaming with Range header
        chunk_data = b"HELLO_GRAFFITI_STREAM_DATA"
        chunk_b64 = base64.b64encode(chunk_data).decode("ascii")
        with patch.object(svc, "get_graffiti_media_meta", return_value={"status": "ok", "meta": {"size": len(chunk_data), "mime": "image/jpeg"}}):
            with patch.object(svc, "get_graffiti_chunk", return_value={"status": "ok", "data_b64": chunk_b64, "eof": True}):
                req_media = urllib.request.Request(f"{base_url}/api/graffiti/{art_id}/media", headers={"Range": f"bytes=0-{len(chunk_data)-1}"})
                with urllib.request.urlopen(req_media) as resp:
                    assert resp.status == 206
                    body = resp.read()
                    assert body == chunk_data
                    assert resp.headers.get("Content-Range") == f"bytes 0-{len(chunk_data)-1}/{len(chunk_data)}"

    finally:
        httpd.shutdown()
        httpd.server_close()


def test_create_handler_class_default_cfg():
    svc = ExplorerService("127.0.0.1", 19000)
    routes = ExplorerRoutes(svc, "127.0.0.1", 19000)
    handler_cls = create_handler_class(routes=routes)
    assert handler_cls is not None


def test_apps_web_server_main():
    from apps import web_server
    with patch("apps.web_server.run_server") as mock_run:
        with patch("sys.argv", ["web_server.py", "--port", "4001", "--host", "127.0.0.1", "--node-host", "127.0.0.1", "--node-port", "19001"]):
            web_server.main()
            mock_run.assert_called_once_with(
                host="127.0.0.1",
                port=4001,
                node_host="127.0.0.1",
                node_port=19001,
            )


def test_handler_suppresses_abrupt_disconnect():
    from unittest.mock import MagicMock
    from http.server import BaseHTTPRequestHandler

    handler_cls = create_handler_class(MagicMock())
    handler = handler_cls.__new__(handler_cls)
    with patch.object(BaseHTTPRequestHandler, "handle", side_effect=ConnectionResetError(104, "Connection reset by peer")):
        handler.handle()
    with patch.object(BaseHTTPRequestHandler, "handle", side_effect=BrokenPipeError(32, "Broken pipe")):
        handler.handle()
    with patch.object(BaseHTTPRequestHandler, "handle", side_effect=ConnectionAbortedError(103, "Connection aborted")):
        handler.handle()


