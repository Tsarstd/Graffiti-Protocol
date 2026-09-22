# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain – see LICENSE

"""
- LMDB: index_db + final_db, incoming always filesystem (temporary).
"""

from __future__ import annotations

import os
import json
import time
from typing import Dict, Iterator, Tuple, Optional

from tsarcore_native import open_storage as _native_open_storage

from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import clean_remove_file

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.database_archivist")


import shutil


def _iter_prefix(store, db_name: str, prefix: bytes) -> Iterator[Tuple[bytes, bytes]]:
    start_after: Optional[bytes] = None
    while True:
        chunk = store.iter_prefix_chunk(
            db_name,
            prefix,
            limit=int(CFG.KV_ITER_CHUNK),
            start_after=start_after,
        ) or []
        if not chunk:
            break
        for k, v in chunk:
            yield bytes(k), bytes(v)
            start_after = bytes(k)
        if len(chunk) < int(CFG.KV_ITER_CHUNK):
            break


class ArchivistDatabase:
    """
    Abstraksi backend LMDB untuk index + blob archivist.
    """

    def __init__(self, storage_dir: str | None = None, *, enable_blobs: bool = True, enable_index: bool = True):
        self.storage_dir = storage_dir or CFG.STORAGE_DIR
        self.enable_index = enable_index
        self.enable_blobs = enable_blobs
        self._mem_index = {"files": {}, "bytes_used": 0, "art_map": {}}
        self._mem_guard: dict = {}
        self._kv_guard = None

        if self.enable_index:
            index_path = os.path.join(self.storage_dir, "index_db") if storage_dir else CFG.ARCHIVIST_INDEX_DB_PATH
            guard_path = os.path.join(self.storage_dir, "payout_guard") if storage_dir else CFG.ARCHIVIST_PAYOUT_GUARD_DB_PATH
            guard_map_size = CFG.ARCHIVIST_PAYOUT_GUARD_MAP_SIZE
            self._kv_index = self._open_store(index_path)
            self._kv_guard = self._open_store(guard_path, init_size=guard_map_size)


    # ---------------- Index ----------------
    def load_index(self) -> Dict:
        if not self.enable_index:
            return dict(self._mem_index)
        files: Dict[str, Dict] = {}
        art_map: Dict[str, str] = {}
        for k, v in _iter_prefix(self._kv_index, "idx", b"file:"):
            gid = k.decode("utf-8")[5:]
            meta = json.loads(v.decode("utf-8"))
            files[gid] = meta
        for k, v in _iter_prefix(self._kv_index, "idx", b"art:"):
            art = k.decode("utf-8")[4:]
            art_map[art] = v.decode("utf-8")
            
        bytes_used = sum(int(m.get("size_bytes", 0)) for m in files.values())
        return {"files": files, "bytes_used": bytes_used, "art_map": art_map}


    def save_index(self, index: Dict) -> None:
        if not self.enable_index:
            # store in-memory only (node: no archivist index persistence)
            self._mem_index = {
                "files": dict(index.get("files", {})),
                "bytes_used": int(index.get("bytes_used", 0)),
                "art_map": dict(index.get("art_map", {})),
            }
            return
        # Prepare ops BEFORE clearing DB to prevent data loss on serialization failure
        ops = []
        for gid, meta in index.get("files", {}).items():
            ops.append((f"file:{gid}".encode("utf-8"), json.dumps(meta, separators=CFG.CANONICAL_SEP).encode("utf-8")))
        for art, gid in index.get("art_map", {}).items():
            ops.append((f"art:{art}".encode("utf-8"), str(gid).encode("utf-8")))

        self._kv_index.clear_db("idx")
        if ops:
            self._kv_index.put_batch("idx", ops)


    # ---------------- Blob operations (incoming filesystem, final filesystem + LMDB fallback) ----------------
    def _blobs_dir(self) -> str:
        path = os.path.join(self.storage_dir, "blobs")
        os.makedirs(path, exist_ok=True)
        return path

    def _final_blob_path(self, gid: str) -> str:
        return os.path.join(self._blobs_dir(), f"{gid}.bin")

    def get_final_blob_path(self, gid: str) -> str:
        return self._final_blob_path(gid)

    def append_incoming(self, gid: str, chunk: bytes, max_chunk: int, expected_offset: Optional[int] = None) -> int:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        if len(chunk) > int(max_chunk):
            raise ValueError("chunk_too_big")
        path = self._incoming_part_path(gid)
        try:
            current = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            current = 0
        if expected_offset is not None and int(expected_offset) != int(current):
            raise ValueError(f"offset_mismatch: expected {current}, got {expected_offset}")
        new_size = int(current) + int(len(chunk))
        if new_size > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
            raise ValueError("file_too_large")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "ab") as f:
            f.write(chunk)
        return new_size

    def get_incoming_bytes(self, gid: str) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        path = bin_path if os.path.isfile(bin_path) else part_path
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def has_final(self, gid: str) -> bool:
        if not self.enable_blobs:
            return False
        final_path = self._final_blob_path(gid)
        return os.path.isfile(final_path)

    def pop_incoming(self, gid: str) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        path = bin_path if os.path.isfile(bin_path) else part_path

        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            data = f.read()

        self.delete_blob(gid, incoming=True)
        return data

    def put_final(self, gid: str, data: bytes) -> None:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        final_path = self._final_blob_path(gid)
        os.makedirs(os.path.dirname(final_path) or ".", exist_ok=True)
        with open(final_path, "wb") as f:
            f.write(data)

    def promote_incoming(self, gid: str) -> bool:
        """
        Pindahkan blob dari incoming filesystem ke blobs/.
        Mengembalikan True jika ada data yang dipindah.
        """
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        src_path = bin_path if os.path.isfile(bin_path) else part_path

        if not os.path.isfile(src_path):
            return False

        final_path = self._final_blob_path(gid)
        os.makedirs(os.path.dirname(final_path) or ".", exist_ok=True)
        
        # OS fast rename/move
        try:
            os.replace(src_path, final_path)
        except OSError:
            with open(src_path, "rb") as sf, open(final_path, "wb") as df:
                shutil.copyfileobj(sf, df, length=64 * 1024)
            clean_remove_file(src_path)
        return True

    def get_final_bytes_range(self, gid: str, offset: int, length: int) -> Optional[bytes]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        
        # 1. Fast path: check filesystem blob
        final_path = self._final_blob_path(gid)
        if os.path.isfile(final_path):
            try:
                with open(final_path, "rb") as f:
                    f.seek(int(offset))
                    return f.read(int(length))
            except OSError:
                pass

        # 2. Fallback: check incoming file
        bin_path = self._incoming_bin_path(gid)
        part_path = self._incoming_part_path(gid)
        path = bin_path if os.path.isfile(bin_path) else part_path
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    f.seek(int(offset))
                    return f.read(int(length))
            except OSError:
                pass
        return None

    def get_final_merkle_path(self, gid: str, chunk_size: int, index: int) -> Optional[list]:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        blob_path = self._final_blob_path(gid)
        if not os.path.isfile(blob_path):
            blob_path = self._incoming_bin_path(gid)
        if not os.path.isfile(blob_path):
            blob_path = self._incoming_part_path(gid)
        if os.path.isfile(blob_path):
            from tsarchain.contracts import graffiti as GRAFFITI
            return GRAFFITI.merkle_path_for_file(blob_path, chunk_size, index)
        return None

    def delete_blob(self, gid: str, *, incoming: bool = False, final: bool = False) -> None:
        if not self.enable_blobs:
            raise RuntimeError("blobs_disabled")
        if incoming:
            for path in (self._incoming_part_path(gid), self._incoming_bin_path(gid)):
                clean_remove_file(path)
        if final:
            clean_remove_file(self._final_blob_path(gid))

    # ---------------- Payout Guard KV Store Integration ----------------
    def load_payout_guard(self) -> dict:
        if not self.enable_index or not self._kv_guard:
            return dict(self._mem_guard)
        guard: dict = {}
        for k, v in _iter_prefix(self._kv_guard, "guard", b""):
            raw_k = k.decode("utf-8")
            art_id = raw_k[6:] if raw_k.startswith("guard:") else raw_k
            entry = json.loads(v.decode("utf-8"))
            if type(entry) is dict:
                epoch = int(entry.get("epoch", -1))
                ts = int(entry.get("ts", 0))
                status = str(entry.get("status", "error")).lower()
                guard[art_id] = {"epoch": epoch, "ts": ts, "status": status}
        return guard

    def save_payout_guard(self, guard_data: dict) -> None:
        kv_guard = self._kv_guard
        if not self.enable_index or not kv_guard:
            self._mem_guard = dict(guard_data or {})
            return
        ops = []
        for art_id, entry in (guard_data or {}).items():
            ops.append((str(art_id).encode("utf-8"), json.dumps(entry).encode("utf-8")))
        if ops:
            self._kv_guard.put_batch("guard", ops)

    def cleanup_expired_payout_guards(self, max_age_seconds: int = 30 * 86400) -> int:
        kv_guard = self._kv_guard
        if not self.enable_index or not kv_guard:
            return 0
        now = int(time.time())
        cutoff = now - int(max_age_seconds)
        current = self.load_payout_guard()
        cleaned = {k: v for k, v in current.items() if int(v.get("ts", 0)) >= cutoff}
        removed = len(current) - len(cleaned)
        if removed > 0:
            self.save_payout_guard(cleaned)
        return removed

    def cleanup_expired_incoming(self, max_age_seconds: int = 7200) -> int:
        """
        Garbage collector untuk membersihkan file .part / unconfirmed uploads yang mengendap.
        """
        inc_dir = self._incoming_dir()
        if not os.path.isdir(inc_dir):
            return 0
        cleaned = 0
        now = time.time()
        try:
            for fname in os.listdir(inc_dir):
                full_path = os.path.join(inc_dir, fname)
                if os.path.isfile(full_path):
                    mtime = os.path.getmtime(full_path)
                    if (now - mtime) > max_age_seconds:
                        try:
                            os.remove(full_path)
                            cleaned += 1
                        except OSError:
                            pass
        except OSError:
            pass
        return cleaned

    # ---------------- KV helpers ----------------
    def _open_store(self, path: str, init_size: int | None = None, max_size: int | None = None):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        init_size = int(init_size or CFG.STORAGE_SIZE_INIT)
        max_size = int(max_size or CFG.STORAGE_MAX_BYTES)

        if os.path.isfile(path):
            try:
                existing = os.path.getsize(path)
                if existing > init_size:
                    init_size = existing
            except OSError:
                pass

        if max_size > 0 and max_size < init_size:
            max_size = init_size
        drive_override = CFG.STORAGE_DRIVE_TYPE
        store = _native_open_storage(
            "lmdb",
            path,
            map_size_init=int(init_size),
            map_size_max=int(max_size),
            pretty_json=False,
            drive_type=drive_override,
        )
        dt = store.drive_type
        log.info(f"Archivist LMDB storage initialized at '{path}' [Drive Profile: {dt.upper()}]")
        return store

    def _incoming_dir(self) -> str:
        path = os.path.join(self.storage_dir, "incoming")
        os.makedirs(path, exist_ok=True)
        return path

    def _incoming_part_path(self, gid: str) -> str:
        return os.path.join(self._incoming_dir(), f"{gid}.part")

    def _incoming_bin_path(self, gid: str) -> str:
        return os.path.join(self._incoming_dir(), f"{gid}.bin")

    def get_incoming_bin_path(self, gid: str) -> str:
        return self._incoming_bin_path(gid)

    def get_incoming_part_path(self, gid: str) -> str:
        return self._incoming_part_path(gid)


__all__ = ["ArchivistDatabase"]

