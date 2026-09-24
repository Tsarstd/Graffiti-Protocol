# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import base64
import contextlib
from PIL import Image as PILImage
from typing import Dict, Any, Optional

from tsarchain.utils.tsar_logging import get_ctx_logger
from web.Backend.src.utils.http_helpers import set_cors_headers, send_json
from web.Backend.src.utils.media_processing import generate_video_thumbnail_webp
from web.Backend.src.routes.explorer_routes import (
    ExplorerRoutes,
    CACHE_DIR,
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

log = get_ctx_logger("tsarchain.web.Backend.src.routes.media_routes")


def serve_graffiti_media(
    handler: Any,
    art_id: str,
    routes: ExplorerRoutes,
    is_head: bool = False,
    cache_finder: Optional[Any] = None,
) -> None:
    """Serve Graffiti media file, utilizing local cache or chunked RPC streaming."""
    cleanup_graffiti_cache()
    if not is_art_id(art_id):
        send_json(handler, 400, {"error": "invalid_art_id"}, is_head=is_head)
        return

    meta_resp = routes.svc.get_graffiti_media_meta(art_id)
    meta = meta_resp.get("meta", {}) if (meta_resp and meta_resp.get("status") == "ok") else None

    # 1. Try local cached file
    finder = cache_finder or find_cached_file
    cached_file = finder(art_id)
    if cached_file and serve_local_file(handler, cached_file, meta, is_head=is_head):
        return

    if not meta or (meta_resp and meta_resp.get("status") != "ok"):
        send_json(handler, 404, {"error": "media_not_found"}, is_head=is_head)
        return

    try:
        total_size = int(meta.get("size_bytes") or meta.get("size", 0))
    except (ValueError, TypeError):
        total_size = 0

    # 2. Smart Caching: file size <= 10MB -> Try service cache
    if 0 < total_size <= STREAM_THRESHOLD_BYTES:
        info = routes.svc.get_graffiti_media_info(art_id)
        if info and info.get("status") == "ok" and info.get("cache_path"):
            resolved = resolve_cache_path(info["cache_path"])
            if resolved and os.path.isfile(resolved):
                if serve_local_file(handler, resolved, meta, is_head=is_head):
                    return

    # 3. On-demand chunk streaming
    stream_graffiti_chunks(handler, art_id, total_size, meta, routes, is_head=is_head)


def serve_local_file(
    handler: Any,
    file_path: str,
    meta: Any = None,
    is_head: bool = False,
    *args: Any,
) -> bool:
    """Serve local media file supporting HTTP 206 Partial Content range requests."""
    # Compatibility shim if called with positional arguments (e.g. file_path, size, meta)
    if type(meta) is int and args:
        meta = args[0]
        is_head = bool(args[1]) if len(args) > 1 else False

    try:
        if not os.path.isfile(file_path):
            return False
        touch_file(file_path)
        size = os.path.getsize(file_path)
        media_type = infer_media_type(meta, file_path)

        range_header = handler.headers.get("Range")
        range_info = parse_range_header(range_header, size)

        if range_info:
            if range_info.get("invalid"):
                handler.send_response(416)
                handler.send_header("Content-Range", f"bytes */{size}")
                set_cors_headers(handler)
                handler.end_headers()
                return True

            start = range_info["start"]
            end = range_info["end"]
            content_length = end - start + 1

            handler.send_response(206)
            handler.send_header("Content-Type", media_type)
            handler.send_header("Cache-Control", "public, max-age=300")
            handler.send_header("Accept-Ranges", "bytes")
            handler.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            handler.send_header("Content-Length", str(content_length))
            set_cors_headers(handler)
            handler.end_headers()

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
                    handler.wfile.write(chunk)
                    remaining -= len(chunk)
            return True

        handler.send_response(200)
        handler.send_header("Content-Type", media_type)
        handler.send_header("Cache-Control", "public, max-age=300")
        handler.send_header("Accept-Ranges", "bytes")
        handler.send_header("Content-Length", str(size))
        set_cors_headers(handler)
        handler.end_headers()

        if is_head:
            return True

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                handler.wfile.write(chunk)
        return True
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return True
    except Exception as exc:
        log.warning("[serve_local_file_failed] %s", exc)
        return False


def stream_graffiti_chunks(
    handler: Any,
    art_id: str,
    total_size: int,
    meta: Optional[Dict[str, Any]],
    routes: ExplorerRoutes,
    is_head: bool = False,
) -> None:
    """Stream Graffiti chunks on demand from RPC service directly to client."""
    try:
        filename = meta.get("filename") if meta else art_id
        media_type = infer_media_type(meta, filename)

        start = 0
        end = max(0, total_size - 1) if total_size > 0 else 0

        range_header = handler.headers.get("Range")
        range_info = parse_range_header(range_header, total_size) if total_size > 0 else None

        if range_info:
            if range_info.get("invalid"):
                handler.send_response(416)
                handler.send_header("Content-Range", f"bytes */{total_size}")
                set_cors_headers(handler)
                handler.end_headers()
                return
            start = range_info["start"]
            end = range_info["end"]
            content_len = end - start + 1
            handler.send_response(206)
            handler.send_header("Content-Type", media_type)
            handler.send_header("Cache-Control", "public, max-age=300")
            handler.send_header("Accept-Ranges", "bytes")
            handler.send_header("Content-Range", f"bytes {start}-{end}/{total_size}")
            handler.send_header("Content-Length", str(content_len))
            set_cors_headers(handler)
            handler.end_headers()
        else:
            handler.send_response(200)
            handler.send_header("Content-Type", media_type)
            handler.send_header("Cache-Control", "public, max-age=300")
            handler.send_header("Accept-Ranges", "bytes")
            if total_size > 0:
                handler.send_header("Content-Length", str(total_size))
            set_cors_headers(handler)
            handler.end_headers()

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
                handler.wfile.write(buf)
                handler.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                break

            curr_offset += len(buf)
            if chunk_resp.get("eof"):
                break
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return


def serve_graffiti_thumbnail(
    handler: Any,
    art_id: str,
    routes: ExplorerRoutes,
    is_head: bool = False,
    cache_finder: Optional[Any] = None,
) -> None:
    """Serve cached or dynamically generated thumbnail for Graffiti media."""
    cleanup_graffiti_cache()
    if not is_art_id(art_id):
        send_json(handler, 400, {"error": "invalid_art_id"}, is_head=is_head)
        return

    thumbs_dir = os.path.join(CACHE_DIR, "thumbnails")
    os.makedirs(thumbs_dir, exist_ok=True)
    thumb_path_webp = os.path.join(thumbs_dir, f"{art_id}.webp")
    thumb_path_jpg = os.path.join(thumbs_dir, f"{art_id}.jpg")

    # 1. If cached thumbnail exists and is valid (> 0 bytes), serve directly
    if os.path.isfile(thumb_path_webp):
        if os.path.getsize(thumb_path_webp) > 0:
            serve_thumbnail_file(handler, thumb_path_webp, content_type="image/webp", is_head=is_head)
            return
        with contextlib.suppress(OSError):
            os.remove(thumb_path_webp)

    if os.path.isfile(thumb_path_jpg):
        if os.path.getsize(thumb_path_jpg) > 0:
            serve_thumbnail_file(handler, thumb_path_jpg, content_type="image/jpeg", is_head=is_head)
            return
        with contextlib.suppress(OSError):
            os.remove(thumb_path_jpg)

    # 2. Get source media
    finder = cache_finder or find_cached_file
    source_file = finder(art_id)

    if not source_file:
        info = routes.svc.get_graffiti_media_info(art_id)
        if type(info) is dict and info.get("status") == "ok" and info.get("cache_path"):
            resolved = resolve_cache_path(info["cache_path"])
            if resolved and os.path.isfile(resolved):
                source_file = resolved

    temp_source = None
    if not source_file:
        temp_source = os.path.join(CACHE_DIR, f"{art_id}.tmp")
        try:
            curr_offset = 0
            with open(temp_source, "wb") as f_out:
                while True:
                    try:
                        resp = routes.svc.get_graffiti_chunk(art_id, curr_offset, STREAM_CHUNK_BYTES)
                    except TypeError:
                        resp = routes.svc.get_graffiti_chunk(art_id, curr_offset)
                    if not resp or type(resp) is not dict or resp.get("status") != "ok":
                        break
                    b64 = resp.get("data_b64", "")
                    if b64 and type(b64) is str:
                        buf = base64.b64decode(b64)
                        f_out.write(buf)
                        curr_offset += len(buf)
                    if resp.get("eof"):
                        break
            if os.path.isfile(temp_source) and os.path.getsize(temp_source) > 0:
                source_file = temp_source
        except Exception as exc:
            log.warning("[thumbnail_fetch_failed] artId=%s err=%s", art_id, exc)

    if not source_file or not os.path.isfile(source_file):
        if temp_source and os.path.isfile(temp_source):
            with contextlib.suppress(OSError):
                os.remove(temp_source)
        send_json(handler, 404, {"error": "media_not_found"}, is_head=is_head)
        return

    meta_resp = routes.svc.get_graffiti_media_meta(art_id)
    meta = (
        meta_resp.get("meta", {})
        if (type(meta_resp) is dict and meta_resp.get("status") == "ok" and type(meta_resp.get("meta")) is dict)
        else None
    )
    media_type = infer_media_type(meta, source_file)

    try:
        # Video handling: MP4, MKV (Midpoint forward 11-frame animated WebP)
        if media_type.startswith("video/") or source_file.lower().endswith((".mp4", ".mkv")):
            if generate_video_thumbnail_webp(source_file, thumb_path_webp):
                serve_thumbnail_file(handler, thumb_path_webp, content_type="image/webp", is_head=is_head)
                return
            send_json(handler, 501, {"error": "video_thumbnail_generator_unavailable"}, is_head=is_head)
            return

        # Image handling using Pillow (WebP format, ~20% enlarged to 160x160)
        with PILImage.open(source_file) as img:
            if img.mode in ("RGBA", "LA"):
                thumb_img = img.copy()
            elif img.mode != "RGB":
                thumb_img = img.convert("RGB")
            else:
                thumb_img = img.copy()

            thumb_img.thumbnail((160, 160))
            thumb_img.save(thumb_path_webp, format="WEBP", quality=80)

        serve_thumbnail_file(handler, thumb_path_webp, content_type="image/webp", is_head=is_head)
    except Exception as exc:
        log.warning("[thumbnail_generate_failed] artId=%s err=%s", art_id, exc)
        send_json(handler, 400, {"error": "not_an_image"}, is_head=is_head)
    finally:
        if temp_source and os.path.isfile(temp_source):
            with contextlib.suppress(OSError):
                os.remove(temp_source)


def serve_thumbnail_file(
    handler: Any,
    file_path: str,
    content_type: Optional[str] = None,
    is_head: bool = False,
) -> None:
    """Serve generated thumbnail image with immutable long-term caching."""
    try:
        size = os.path.getsize(file_path)
        if not content_type:
            content_type = "image/webp" if file_path.lower().endswith(".webp") else "image/jpeg"
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Cache-Control", "public, max-age=31536000, immutable")
        handler.send_header("Content-Length", str(size))
        set_cors_headers(handler)
        handler.end_headers()

        if not is_head:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    handler.wfile.write(chunk)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        pass
    except Exception as exc:
        log.warning("[serve_thumbnail_failed] %s", exc)
