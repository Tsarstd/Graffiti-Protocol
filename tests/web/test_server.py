# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import io
import json
import time
import socket
import base64
import contextlib
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from PIL import Image as PILImage

import web.Backend.src.server as server_mod
from web.Backend.src.server import create_handler_class
from web.Backend.src.services.explorer_service import ExplorerService
from web.Backend.src.routes.explorer_routes import ExplorerRoutes


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_server_api_routes():
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

        # 15. GET /api/graffiti/:artId/thumbnail - dynamic thumbnail generation
        img_byte_arr = io.BytesIO()
        test_img = PILImage.new("RGB", (200, 200), color="red")
        test_img.save(img_byte_arr, format="JPEG")
        test_img_bytes = img_byte_arr.getvalue()

        with patch.object(svc, "get_graffiti_media_meta", return_value={"status": "ok", "meta": {"size": len(test_img_bytes), "mime": "image/jpeg"}}):
            with patch.object(server_mod, "find_cached_file", return_value=None):
                with patch.object(svc, "get_graffiti_chunk", return_value={"status": "ok", "data_b64": base64.b64encode(test_img_bytes).decode("ascii"), "eof": True}):
                    req_thumb = urllib.request.Request(f"{base_url}/api/graffiti/{art_id}/thumbnail")
                    with urllib.request.urlopen(req_thumb) as resp:
                        assert resp.status == 200
                        assert resp.headers.get("Content-Type") == "image/jpeg"
                        assert "max-age=31536000" in resp.headers.get("Cache-Control", "")
                        body = resp.read()
                        assert len(body) > 0
                        # Verify decoded thumbnail dimensions <= 128
                        thumb_pil = PILImage.open(io.BytesIO(body))
                        assert thumb_pil.size[0] <= 128 and thumb_pil.size[1] <= 128

        # 15b. Cache hit & HEAD on thumbnail
        req_thumb_cached = urllib.request.Request(f"{base_url}/api/graffiti/{art_id}/thumbnail")
        with urllib.request.urlopen(req_thumb_cached) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "image/jpeg"
            assert "max-age=31536000" in resp.headers.get("Cache-Control", "")

        req_thumb_head = urllib.request.Request(f"{base_url}/api/graffiti/{art_id}/thumbnail", method="HEAD")
        with urllib.request.urlopen(req_thumb_head) as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "image/jpeg"
            assert len(resp.read()) == 0

        # 15c. Invalid art_id & 404 media_not_found
        req_bad = urllib.request.Request(f"{base_url}/api/graffiti/invalid_art/thumbnail")
        try:
            urllib.request.urlopen(req_bad)
            assert False, "Should have 400"
        except urllib.error.HTTPError as e:
            assert e.code == 400

        art_id_404 = "graf" + "1" * 60
        with patch.object(svc, "get_graffiti_media_meta", return_value={"status": "error"}):
            with patch.object(server_mod, "find_cached_file", return_value=None):
                with patch.object(svc, "get_graffiti_media_info", return_value=None):
                    with patch.object(svc, "get_graffiti_chunk", return_value={"status": "error"}):
                        req_404_thumb = urllib.request.Request(f"{base_url}/api/graffiti/{art_id_404}/thumbnail")
                        try:
                            urllib.request.urlopen(req_404_thumb)
                            assert False, "Should have 404"
                        except urllib.error.HTTPError as e:
                            assert e.code == 404

    finally:
        httpd.shutdown()
        httpd.server_close()
        import os
        from web.Backend.src.routes.explorer_routes import CACHE_DIR
        test_thumb_file = os.path.join(CACHE_DIR, "thumbnails", f"{art_id}.jpg")
        if os.path.isfile(test_thumb_file):
            with contextlib.suppress(OSError):
                os.remove(test_thumb_file)


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


def test_get_video_duration():
    from unittest.mock import MagicMock
    from web.Backend.src.server import get_video_duration

    # 1. ffprobe success
    mock_res = MagicMock(returncode=0, stdout="42.50\n")
    with patch("subprocess.run", return_value=mock_res):
        dur = get_video_duration("dummy.mp4")
        assert dur == 42.50

    # 2. ffmpeg fallback success (ffprobe fails with code 1, ffmpeg succeeds with stderr Duration)
    mock_res_err = MagicMock(returncode=1, stderr="Duration: 00:01:30.00, start: 0.000000, bitrate: 1200 kb/s")
    with patch("subprocess.run", side_effect=[MagicMock(returncode=1, stdout=""), mock_res_err]):
        dur = get_video_duration("dummy.mp4")
        assert dur == 90.0

    # 3. No tools / process error
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert get_video_duration("dummy.mp4") is None


def test_generate_video_thumbnail_webp_midpoint(tmp_path):
    from web.Backend.src.server import generate_video_thumbnail_webp

    out_webp = str(tmp_path / "thumb.webp")

    # Mock duration = 20.0s -> midpoint = 10.0s
    with patch("web.Backend.src.server.get_video_duration", return_value=20.0):
        def fake_run(cmd, **kwargs):
            # Verify midpoint seeking -ss 10.00
            assert "-ss" in cmd
            ss_idx = cmd.index("-ss")
            assert cmd[ss_idx + 1] == "10.00"
            assert "-an" in cmd
            assert "-c:v" in cmd and "libwebp" in cmd
            assert "-pix_fmt" in cmd and "yuv420p" in cmd
            # write dummy file
            with open(out_webp, "wb") as f:
                f.write(b"RIFFdummyWEBP")
            from unittest.mock import MagicMock
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=fake_run):
            ok = generate_video_thumbnail_webp("input.mp4", out_webp)
            assert ok is True


def test_video_thumbnail_benchmark_threshold_warning(tmp_path):
    from web.Backend.src.server import generate_video_thumbnail_webp

    out_webp = str(tmp_path / "thumb.webp")
    with patch("web.Backend.src.server.get_video_duration", return_value=10.0):
        def slow_run(cmd, **kwargs):
            time.sleep(0.01)  # small sleep
            with open(out_webp, "wb") as f:
                f.write(b"RIFFWEBP")
            from unittest.mock import MagicMock
            return MagicMock(returncode=0)

        # Test benchmark warning when threshold is set low
        with patch("subprocess.run", side_effect=slow_run):
            with patch("tsarchain.utils.benchmarks.log.warning") as mock_warn:
                # Patch threshold to 1.0ms to simulate spike warning
                from tsarchain.utils.benchmarks import benchmark
                wrapped = benchmark("video_thumbnail_webp", threshold_ms=1.0)(lambda: slow_run(None))
                wrapped()
                mock_warn.assert_called_once()
                assert "video_thumbnail_webp" in mock_warn.call_args[0][1]


def test_disconnect_handling_in_media_and_thumbnail(tmp_path):
    from unittest.mock import MagicMock
    handler_cls = create_handler_class(MagicMock())
    handler = handler_cls.__new__(handler_cls)
    dummy_file = str(tmp_path / "test.mp4")
    with open(dummy_file, "wb") as f:
        f.write(b"0" * 1024)

    # 1. _serve_local_file on ConnectionResetError
    handler.headers = {}
    handler.wfile = MagicMock()
    handler.wfile.write.side_effect = ConnectionResetError(104, "Connection reset by peer")
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler._set_cors_headers = MagicMock()
    with patch("web.Backend.src.server.log.warning") as mock_warn:
        res = handler._serve_local_file(dummy_file, 1024, {})
        assert res is True
        mock_warn.assert_not_called()

    # 2. _serve_thumbnail_file on BrokenPipeError
    handler.wfile.write.side_effect = BrokenPipeError(32, "Broken pipe")
    with patch("web.Backend.src.server.log.warning") as mock_warn:
        handler._serve_thumbnail_file(dummy_file)
        mock_warn.assert_not_called()





