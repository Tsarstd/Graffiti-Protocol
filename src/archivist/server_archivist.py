# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import os
import time
import json
import socket
import base64
import threading
import contextlib
from typing import Any, Dict, Optional, Tuple

# ---------------- Local Project ----------------
from . import wallet_route
from .storage_guard import StorageGuard
from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI
from .database_archivist import ArchivistDatabase
from tsarchain.network.protocol import (
    is_envelope,
    send_message,
    recv_message,
    verify_and_unwrap,
)

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.contracts.storage_node.server")


class StorageServer:
    def __init__(self, host: str, port: int, storage_dir: str):
        self.host = host
        self.port = int(port)
        self.storage_dir = storage_dir
        self.db = ArchivistDatabase(storage_dir)
        self._load_index()
        self.guard = StorageGuard()
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _normalize_file_meta(self, aid: str, meta: dict) -> dict:
        if not meta:
            return {}

        meta.setdefault("paid", False)
        meta.setdefault("expire_at_height", 0)
        meta.setdefault("confirmed_at_height", 0)
        meta.setdefault("state", "stored")
        meta.setdefault("received_bytes", int(meta.get("received_bytes", 0)))
        meta.setdefault("chunk_size", int(meta.get("chunk_size", CFG.STORAGE_UPLOAD_CHUNK)))
        meta.setdefault("last_proof_epoch", -1)
        meta.setdefault("last_proof_ts", 0)
        meta.setdefault("last_proof_offset", 0)
        meta.setdefault("last_proof_length", 0)
        meta.setdefault("last_proof_hash", "")
        meta.setdefault("last_proof_height", 0)
        meta.setdefault("missed_proofs", 0)
        meta.setdefault("proof_fail_reason", "")
        meta.setdefault("proof_status", "")
        if "path" not in meta:
            meta["path"] = ""
        # Keep art_map in sync when art_id is present
        art_id = str(meta.get("art_id", "")).strip().lower()
        if art_id:
            self.index.setdefault("art_map", {})[art_id] = aid
        return meta

    def _load_index(self):
        os.makedirs(self.storage_dir, exist_ok=True)
        self.index = self.db.load_index()
        self.index.setdefault("files", {})
        self.index.setdefault("bytes_used", 0)
        self.index.setdefault("art_map", {})
        files = dict(self.index.get("files", {}))
        for aid, meta in list(files.items()):
            files[aid] = self._normalize_file_meta(aid, meta)
        self.index["files"] = files
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        self._save_index()

    def _save_index(self):
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in self.index.get("files", {}).values())
        self.db.save_index(self.index)

    # =========================================================================
    # DIRECT IN-MEMORY STORAGE ENGINE METHODS (Called by ArchivistOrchestrator)
    # =========================================================================

    def get_index_stats(self) -> Dict[str, Any]:
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in self.index.get("files", {}).values())
        return dict(self.index)

    def mark_paid(self, graffiti_id: str, art_id: str = "", txid: str = "", block_height: int = 0) -> Dict[str, Any]:
        aid = str(graffiti_id).strip()
        art_norm = str(art_id).strip().lower()
        txid_norm = str(txid).strip()
        block_h = int(block_height or 0)

        meta = self.index.get("files", {}).get(aid)
        if not meta and art_norm:
            real_gid = self.index.get("art_map", {}).get(art_norm)
            if real_gid:
                meta = self.index.get("files", {}).get(real_gid)
                aid = real_gid
        if not meta:
            for gid_k, m in self.index.get("files", {}).items():
                if m.get("sha256", "").lower() == aid.lower() or m.get("art_id", "").lower() == aid.lower():
                    meta = m
                    aid = gid_k
                    break
        if not aid or not meta:
            return {"status": "error", "reason": "no_such"}

        if art_norm:
            meta["art_id"] = art_norm
            self.index.setdefault("art_map", {})[art_norm] = aid

        success, err_reason = self._finalize_storage(aid, meta)
        if not success:
            return {"status": "error", "reason": err_reason}

        meta["paid"] = True
        if txid_norm:
            meta["txid_paid"] = txid_norm
        if block_h > 0:
            meta["confirmed_at_height"] = block_h
            meta["expire_at_height"] = 0
        self.index["files"][aid] = self._normalize_file_meta(aid, meta)
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in self.index["files"].values())
        self._save_index()

        return {
            "status": "ok",
            "graffiti_id": aid,
            "expire_at_height": meta.get("expire_at_height", 0),
            "confirmed_at_height": meta.get("confirmed_at_height", 0),
        }

    def run_gc(self, tip_height: int = 0) -> Dict[str, Any]:
        tip_h = int(tip_height or 0)
        expire_after = max(0, int(CFG.GRAFFITI_EXPIRE_AFTER_BLOCKS))
        files = self.index.get("files", {})

        remove_keys = self._find_expired_keys(files, tip_h, expire_after)
        expired = self._remove_expired_files(files, remove_keys)

        self.index["files"] = files
        self.index["bytes_used"] = sum(int(v.get("size_bytes", 0)) for v in files.values())
        self._save_index()
        if expired:
            log.info("[STOR_GC] expired=%s tip=%s", expired, tip_h)

        return {"status": "ok", "expired": expired}

    def prune_stale_incoming(self, max_age_sec: int = 600) -> int:
        now = int(time.time())
        files = self.index.get("files", {})
        stale_keys = []
        for gid, meta in files.items():
            state = str(meta.get("state", "")).lower()
            if state in ("receiving", "appending") and not meta.get("paid"):
                created = int(meta.get("created_ts", 0))
                if created > 0 and (now - created) > max_age_sec:
                    stale_keys.append(gid)
        pruned = 0
        for gid in stale_keys:
            p = files.get(gid, {}).get("path")
            if p and os.path.isfile(p):
                with contextlib.suppress(OSError):
                    os.unlink(p)
            files.pop(gid, None)
            pruned += 1
        if pruned:
            self._save_index()
            log.info("[STOR_PRUNE] Pruned %s stale incoming upload(s)", pruned)
        return pruned

    def generate_retention_proof(self, graffiti_id: str, art_id: str = "", tip_height: int = 0, block_hash: str | None = None) -> Dict[str, Any]:
        aid = str(graffiti_id).strip()
        art_norm = str(art_id).strip().lower()
        tip_h = int(tip_height or 0)
        files = self.index.get("files", {})
        if art_norm and not aid:
            aid = self.index.get("art_map", {}).get(art_norm, "")

        meta = files.get(aid) if aid else None
        if not meta:
            return {"status": "error", "reason": "no_such"}

        size = int(meta.get("size_bytes", 0))
        art_final = str(meta.get("art_id", art_norm)).strip().lower()
        if not art_final:
            meta["missed_proofs"] = int(meta.get("missed_proofs", 0)) + 1
            meta["proof_fail_reason"] = "missing_art_id"
            self.index["files"][aid] = self._normalize_file_meta(aid, meta)
            self._save_index()
            return {"status": "error", "reason": "missing_art_id"}

        merkle_chunk = int(CFG.GRAFFITI_PROOF_CHUNK_BYTES)
        challenge = GRAFFITI.calc_proof_challenge(art_final, size, tip_h, block_hash=block_hash, chunk_bytes=merkle_chunk)
        offset = int(challenge.get("offset", 0))
        length = int(challenge.get("length", 0))

        chunk_index = offset // merkle_chunk if merkle_chunk > 0 else 0
        chunk, merkle_path = self._get_chunk_and_merkle(aid, offset, length, merkle_chunk, chunk_index)

        proof_hash = GRAFFITI.hash_proof_chunk(chunk)
        chunk_b64 = base64.b64encode(chunk).decode("ascii")
        now_ts = int(time.time())
        meta.update(
            {
                "last_proof_epoch": int(challenge.get("epoch", 0)),
                "last_proof_ts": now_ts,
                "last_proof_offset": offset,
                "last_proof_length": length,
                "last_proof_hash": proof_hash,
                "proof_fail_reason": "",
                "proof_status": "ok",
                "missed_proofs": max(0, int(meta.get("missed_proofs", 0))),
                "last_proof_height": tip_h,
            }
        )
        if art_final:
            self.index.setdefault("art_map", {})[art_final] = aid
            meta["art_id"] = art_final
        self.index["files"][aid] = self._normalize_file_meta(aid, meta)
        self._save_index()

        return {
            "status": "ok",
            "graffiti_id": aid,
            "art_id": art_final,
            "epoch": int(challenge.get("epoch", 0)),
            "offset": offset,
            "length": length,
            "hash": proof_hash,
            "seed": challenge.get("seed"),
            "height": tip_h,
            "chunk": chunk_b64,
            "path": merkle_path,
        }

    # =========================================================================
    # INTERNAL STORAGE HELPERS
    # =========================================================================

    def _finalize_storage(self, aid: str, meta: dict) -> Tuple[bool, Optional[str]]:
        already_final = (self.db.has_final(aid) is True)
        if not already_final:
            promoted = (self.db.promote_incoming(aid) is True)
            if not promoted:
                data = self.db.pop_incoming(aid)
                if data is None:
                    p = meta.get("path")
                    if p and os.path.isfile(p):
                        final_p = self.db.get_final_blob_path(aid)
                        if final_p:
                            os.makedirs(os.path.dirname(final_p) or ".", exist_ok=True)
                            try:
                                os.replace(p, final_p)
                                promoted = True
                            except OSError:
                                pass

                if data is not None:
                    self.db.put_final(aid, data)
                    promoted = True

            if not promoted and not self.db.has_final(aid):
                return False, "missing_file"

        self.db.delete_blob(aid, incoming=True)
        blob_p = self.db.get_final_blob_path(aid)
        if blob_p and type(blob_p) is str:
            meta["path"] = os.path.normpath(blob_p).replace("\\", "/")
        else:
            meta["path"] = f"lmdb://final/{aid}"
        meta["state"] = "stored"
        return True, None


    def _find_expired_keys(self, files: dict, tip_h: int, expire_after: int) -> list[str]:
        remove_keys = []
        items = files.items()
        for gid, meta in items:
            if (not meta.get("paid")) and expire_after > 0 and tip_h > 0:
                expire_h = int(meta.get("expire_at_height", 0))
                if expire_h <= 0:
                    expire_h = tip_h + expire_after
                    meta["expire_at_height"] = expire_h
            expire_h = int(meta.get("expire_at_height", 0))
            if expire_h and tip_h and expire_h <= tip_h and not meta.get("paid"):
                remove_keys.append(gid)

        return remove_keys

    def _remove_expired_files(self, files: dict, remove_keys: list[str]) -> int:
        expired = 0
        for gid in remove_keys:
            meta = files.pop(gid, None) or {}
            expired += 1
            self.db.delete_blob(gid, incoming=True, final=True)
            art_id = str(meta.get("art_id", "")).strip().lower()
            if art_id and self.index.get("art_map", {}).get(art_id) == gid:
                self.index["art_map"].pop(art_id, None)
        return expired

    def _get_chunk_and_merkle(self, aid: str, offset: int, length: int, merkle_chunk: int, chunk_index: int):
        chunk = self.db.get_final_bytes_range(aid, offset, length)
        if chunk is None:
            raise FileNotFoundError("file_missing")
        merkle_path = self.db.get_final_merkle_path(aid, merkle_chunk, chunk_index)
        if merkle_path is None:
            blob_path = self.db.get_final_blob_path(aid)
            if not os.path.isfile(blob_path):
                blob_path = self.db.get_incoming_bin_path(aid)
            if not os.path.isfile(blob_path):
                blob_path = self.db.get_incoming_part_path(aid)
            if os.path.isfile(blob_path):
                merkle_path = GRAFFITI.merkle_path_for_file(blob_path, merkle_chunk, chunk_index)
                log.debug("use merkle_path_for_file")
            else:
                raise FileNotFoundError("file_missing")
        else:
            log.debug("use merkle_path_for_lmdb")
        return chunk, merkle_path

    # =========================================================================
    # INBOUND SOCKET TCP SERVER (Clients / Wallets)
    # =========================================================================

    def _respond(self, conn, obj):
        cap = int(CFG.GRAFFITI_MAX_MSG_BYTES)
        raw = json.dumps(obj).encode("utf-8")
        if len(raw) + len(CFG.NETWORK_MAGIC) > cap:
            t = obj.get("type") or "unknown"
            obj = {"type": t, "status": "error", "reason": "msg_too_large"}
            raw = json.dumps(obj).encode("utf-8")
        send_message(conn, raw, max_len=cap)

    def _client_ip(self, addr) -> str:
        if addr:
            return str(addr[0])
        return "0.0.0.0"

    def _handle(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        if str(msg.get("type", "")).upper() == "PING":
            return {"type": "PONG"}
        resp = wallet_route.handle_wallet_rpc(self, msg)
        if resp is not None:
            return resp
        return {"error": "unknown type"}

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(8)
            while not self._stop:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn, addr):
        ip = self._client_ip(addr)
        try:
            if self.guard.is_banned(ip):
                log.warning("[stor_guard] blocked banned ip=%s", ip)
                self._respond(conn, {"status": "error", "reason": "banned"})
                return

            raw = recv_message(conn, timeout=float(CFG.HANDSHAKE_TIMEOUT), max_len=CFG.GRAFFITI_MAX_MSG_BYTES)
            if not raw:
                return

            msg, mtype, identity, pow_obj = self._parse_incoming_message(raw)

            decision = self.guard.allow(ip, mtype, identity=identity, pow_obj=pow_obj)
            if not self._enforce_guard(conn, ip, mtype, decision):
                return

            resp = self._handle(msg)
            self._respond(conn, resp)
        finally:
            conn.close()

    def _parse_incoming_message(self, raw: bytes):
        outer = json.loads(raw.decode("utf-8"))
        identity = None
        if is_envelope(outer):
            msg = verify_and_unwrap(outer, lambda nid: None)
            identity = str(outer.get("from") or "").strip().lower() or None
        else:
            msg = outer if type(outer) is dict else {}

        wallet_ident = str(msg.get("wallet_addr") or "").strip().lower()
        node_ident = str(msg.get("node_id") or "").strip().lower()
        identity = wallet_ident or identity or node_ident or None
        mtype = str(msg.get("type", "")).strip().upper()
        pow_obj = msg.get("pow")

        return msg, mtype, identity, pow_obj

    def _enforce_guard(self, conn, ip: str, mtype: str, decision: dict) -> bool:
        if decision.get("ok"):
            return True
        reason = str(decision.get("error", "forbidden"))
        drop = bool(decision.get("drop"))
        log.warning("[stor_guard] deny ip=%s type=%s reason=%s drop=%s", ip, mtype or "-", reason, drop)
        if drop:
            return False
        resp_obj = {
            "type": mtype or "UNKNOWN",
            "status": "error",
            "reason": reason,
        }
        if "retry_after" in decision:
            resp_obj["retry_after"] = decision.get("retry_after")
        if decision.get("pow_challenge"):
            resp_obj["pow_challenge"] = decision["pow_challenge"]
        self._respond(conn, resp_obj)
        return False
