# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import re
import subprocess
import contextlib
import threading
from typing import Optional, Any

if sys.platform == "win32":
    _winget_links = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links")
    if os.path.isdir(_winget_links) and _winget_links not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _winget_links + os.pathsep + os.environ.get("PATH", "")

from PIL import Image as PILImage

from tsarchain.utils.benchmarks import benchmark
from tsarchain.utils.tsar_logging import get_ctx_logger

log = get_ctx_logger("tsarchain.web.Backend.src.utils.media_processing")

_VIDEO_THUMBNAIL_SEMAPHORE = threading.BoundedSemaphore(2)


@benchmark(label="video_duration_probe", threshold_ms=400.0)
def get_video_duration(video_path: str) -> Optional[float]:
    """Retrieve video duration in seconds via ffprobe or ffmpeg without extra dependencies."""
    with contextlib.suppress(Exception):
        cmd = [
            "ffprobe",
            "-v", "error",
            "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1",
            video_path,
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            val = float(res.stdout.strip())
            if val > 0:
                return val

    with contextlib.suppress(Exception):
        cmd = ["ffmpeg", "-i", video_path]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        m = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.?\d*)", res.stderr or "")
        if m:
            h, m_min, s = float(m.group(1)), float(m.group(2)), float(m.group(3))
            total = h * 3600 + m_min * 60 + s
            if total > 0:
                return total
    return None


@benchmark(label="video_thumbnail_webp", threshold_ms=1500.0)
def generate_video_thumbnail_webp(
    video_path: str,
    output_path: str,
    duration_getter: Optional[Any] = None,
) -> bool:
    """Generate 11-frame animated WebP thumbnail starting from video midpoint forward."""
    getter = duration_getter or get_video_duration
    with _VIDEO_THUMBNAIL_SEMAPHORE:
        dur = getter(video_path)
        if dur is not None and dur > 0:
            midpoint = dur / 2.0
            start_sec = max(0.0, min(midpoint, max(0.0, dur - 2.0)))
        else:
            start_sec = 0.0

        cmd = [
            "ffmpeg",
            "-y",
            "-ss", f"{start_sec:.2f}",
            "-i", video_path,
            "-t", "2.5",
            "-vf", "fps=6,scale=160:160:force_original_aspect_ratio=increase,crop=160:160",
            "-vframes", "11",
            "-c:v", "libwebp",
            "-pix_fmt", "yuv420p",
            "-loop", "0",
            "-an",
            output_path,
        ]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
            if res.returncode == 0 and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
                return True

            if start_sec > 0:
                # Fallback seek to start (0.00) if midpoint seek failed or produced 0 frames
                cmd_fallback = list(cmd)
                cmd_fallback[cmd_fallback.index("-ss") + 1] = "0.00"
                res = subprocess.run(cmd_fallback, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
                if res.returncode == 0 and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
                    return True

            if os.path.isfile(output_path):
                with contextlib.suppress(OSError):
                    os.remove(output_path)
            return False
        except Exception as exc:
            log.warning("[video_thumbnail_webp_err] %s", exc)
            if os.path.isfile(output_path):
                with contextlib.suppress(OSError):
                    os.remove(output_path)
            return False


def generate_image_thumbnail_webp(source_path: str, output_path: str) -> bool:
    """Generate static WebP thumbnail (160x160 max) using Pillow."""
    try:
        with PILImage.open(source_path) as img:
            if img.mode in ("RGBA", "LA"):
                thumb_img = img.copy()
            elif img.mode != "RGB":
                thumb_img = img.convert("RGB")
            else:
                thumb_img = img.copy()

            thumb_img.thumbnail((160, 160))
            thumb_img.save(output_path, format="WEBP", quality=80)
        return True
    except Exception as exc:
        log.warning("[image_thumbnail_webp_err] %s", exc)
        return False
