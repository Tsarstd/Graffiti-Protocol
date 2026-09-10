# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional, Callable

from tsarchain.utils import config as CFG
from archivist.connect import RPC, NodeDirectory
from archivist.server_archivist import StorageServer
from archivist import node_route
from tsarchain.contracts import graffiti as GRAFFITI

HEARTBEAT_SEC = 30
REFRESH_SEC = 30
STORAGE_PORT_OFFSET = 100


class ArchivistOrchestrator:
    def __init__(
        self,
        *,
        address: str,
        target_node: tuple[str, int],
        refresh_sec: int = REFRESH_SEC,
        log_callback: Optional[Callable[[str, bool], None]] = None,
        update_callback: Optional[Callable[[], None]] = None,
    ):
        self.rpc = RPC()
        self.directory = NodeDirectory()
        try:
            self.rpc.set_address_override(address)
        except Exception as exc:
            raise RuntimeError(f"Invalid payout address: {exc}") from exc
        self.rpc.set_trusted(True)

        self._target_node = target_node
        self._refresh_sec = max(3, int(refresh_sec))
        
        self.log_callback = log_callback
        self.update_callback = update_callback

        self._server: Optional[StorageServer] = None
        self.storage_port: Optional[int] = None
        self.connected = False

        self._stop = threading.Event()
        self._refresh_lock = threading.Lock()
        
        self.last_info: Dict[str, Any] | None = None
        self.last_index: Dict[str, Any] | None = None
        self.pending_paid: set[str] = set()
        self.pool_data: dict[str, Dict[str, Any]] = {}
        
        self._auto_payout_guard: dict[str, Dict[str, Any]] = {}
        self._auto_payout_lock = threading.Lock()
        self._load_auto_payout_guard()

    def attempt_reconnect(self) -> bool:
        try:
            target = self._target_node
        except AttributeError:
            target = None
        storage_port = self.storage_port
        if not target or storage_port is None:
            return False
        
        host, miner_port = target
        ok = self.rpc.connect(host, miner_port, my_listen_port=storage_port)
        
        if ok:
            self.connected = True
            return True
        
        return False

    def refresh_once(self) -> None:
        if self._refresh_lock.locked():
            return
        with self._refresh_lock:
            info = None
            idx = None
            info_ok = idx_ok = False
            try:
                raw_info = node_route.rpc_get_network_info(self.rpc, timeout=4.0) or {}
                info = self._normalize_network_info(raw_info)
                info_ok = type(info) is dict
            except Exception as exc:
                self._log(f"[refresh] GET_NETWORK_INFO error: {exc}", error=True)
            try:
                if self._server:
                    idx = self._server.get_index_stats()
                idx_ok = type(idx) is dict
            except Exception as exc:
                self._log(f"[refresh] get_index_stats error: {exc}", error=True)

            if info_ok:
                self.last_info = info
            else:
                self._handle_rpc_drop("refresh_info")
            if idx_ok:
                self.last_index = idx
                self._render_index(idx)
            else:
                self._handle_rpc_drop("refresh_index")
            if info_ok and idx_ok:
                self._trigger_update()

    def connect(self) -> bool:
        host, miner_port = self._target_node
        s_port = self.storage_port
        if self._server is None or s_port is None:
            fallback = miner_port + STORAGE_PORT_OFFSET
            s_port = self._launch_storage_server(fallback)
            self.storage_port = s_port

        ok = self.rpc.connect(host, miner_port, my_listen_port=s_port)
        if not ok:
            peers = self.directory.get_nodes() or []
            for ip, p in peers:
                if self.rpc.connect(ip, p, my_listen_port=s_port):
                    self.directory.mark_good((ip, p))
                    self._target_node = (ip, p)
                    ok = True
                    break

        if ok:
            self.directory.mark_good((self._target_node[0], self._target_node[1]))
            self.connected = True
            self._log(f"[connect] Connected to node {self._target_node[0]}:{self._target_node[1]}")
            return True
        self._log("[connect] Failed to connect to any node", error=True)
        return False

    # ---------- lifecycle ----------
    def start(self) -> bool:
        if not self.connect():
            return False
        # start loops
        threading.Thread(target=self._refresh_loop, name="ArchivistRefresh", daemon=True).start()
        threading.Thread(target=self._retention_loop, name="ArchivistRetention", daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, name="ArchivistHeartbeat", daemon=True).start()
        return True

    def stop(self) -> None:
        self._stop.set()
        self.connected = False
        self.rpc.disconnect()
        self.pending_paid.clear()
        self.pool_data.clear()
        self._log("Shutdown complete.")

    # =========================================================================
    # INTERNAL METHOD
    # =========================================================================

    def _log(self, msg: str, error: bool = False) -> None:
        if self.log_callback:
            self.log_callback(msg, error)

    def _trigger_update(self) -> None:
        if self.update_callback:
            self.update_callback()

    def _normalize_network_info(self, info_obj: Any) -> Optional[Dict[str, Any]]:
        if info_obj.get("error"):
            return None
        data = info_obj.get("data") if info_obj.get("type") == "NETWORK_INFO" else info_obj

        chain = data.get("chain")
        peers = data.get("peers")

        def _as_int(val: Any) -> Optional[int]:
            return int(val)

        height = _as_int(chain.get("tip_height"))
        if height is None:
            height = _as_int(data.get("height"))

        peers_cnt = _as_int(peers.get("count"))
        if peers_cnt is None:
            peers_cnt = _as_int(data.get("peers"))

        if height is None and peers_cnt is None:
            return None
        normalized = dict(info_obj)
        normalized["height"] = height
        normalized["peers"] = peers_cnt
        return normalized

    # ---------- bootstrap ----------
    def _launch_storage_server(self, fallback_start: Optional[int] = None) -> int:
        cand_ports: list[int] = []
        cfg_start = CFG.STORAGE_PORT_START
        cfg_end = CFG.STORAGE_PORT_END
        if cfg_start > 0 and cfg_end >= cfg_start:
            cand_ports.extend(range(cfg_start, cfg_end + 1))
        if fallback_start:
            base = max(1024, fallback_start)
            cand_ports.extend(range(base, base + 64))
        if not cand_ports:
            cand_ports.extend(range(39000, 39064))
        tried = set()
        for port in cand_ports:
            if port <= 0 or port in tried:
                continue
            self._server = StorageServer("0.0.0.0", port, CFG.STORAGE_DIR)
            self._load_auto_payout_guard()
            return port
        raise RuntimeError("No free port for storage server")

    # ---------- refresh loops ----------
    def _refresh_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                time.sleep(self._refresh_sec)
                continue
            try:
                self.refresh_once()
            except Exception as exc:
                self._log(f"[refresh] error: {exc}", error=True)
            time.sleep(self._refresh_sec)


    def _render_index(self, idx: Dict[str, Any]) -> None:
        files = idx.get("files") or {}
        art_map_idx = idx.get("art_map")
        self._mark_pending_payouts(idx)
        self._refresh_pool_listing(files, art_map_idx)


    def _refresh_pool_listing(self, files: Dict[str, Any], art_map_idx: Optional[Dict[str, Any]] = None) -> None:
        rpc = self.rpc
        if not rpc:
            return

        posts = node_route.rpc_get_graffiti_posts(rpc, limit=500, timeout=6.0)
        
        files_by_sha, files_by_art = self._build_file_maps(files, art_map_idx)
        self._populate_pool_data(posts, files_by_sha, files_by_art)
        
        self._auto_mark_paid(posts, files_by_art, files_by_sha)
        self._auto_payout()


    def _build_file_maps(self, files: Dict[str, Any], art_map_idx: Optional[Dict[str, Any]]) -> tuple[dict[str, dict], dict[str, dict]]:
        files_by_sha: dict[str, dict] = {}
        files_by_art: dict[str, dict] = {}
        art_map = art_map_idx or {}
        items = (files or {}).items()

        for gid, meta in items:
            sha = str(meta.get("sha256") or "").lower()
            if sha:
                files_by_sha[sha] = {"id": gid, "meta": meta}
            art_id = str(meta.get("art_id") or "").lower()
            if art_id:
                files_by_art[art_id] = {"id": gid, "meta": meta}
                
        if art_map:
            for art_id, gid in art_map.items():
                if art_id in files_by_art:
                    continue

                meta = files.get(gid)
                if meta:
                    files_by_art[str(art_id).lower()] = {"id": gid, "meta": meta}

                    
        return files_by_sha, files_by_art

    def _populate_pool_data(self, posts: list[dict], files_by_sha: dict[str, dict], files_by_art: dict[str, dict]) -> None:
        self.pool_data = {}
        for art in posts:
            aid = art.get("art_id")
            sha = str(art.get("sha256") or "").lower()
            file_meta = files_by_art.get(str(aid).lower()) or files_by_sha.get(sha)
            if not (aid and file_meta):
                continue
            
            stats = art.get("stats") or {}
            self.pool_data[aid] = {"post": art, "stats": stats, "file": file_meta["meta"]}

    def _auto_mark_paid(self, posts: list[dict], files_by_art: dict[str, dict], files_by_sha: dict[str, dict] = None) -> None:
        if not posts or not self._server:
            return
        files_by_sha = files_by_sha or {}
        files_by_art = files_by_art or {}
        marked = False
        for art in posts:
            aid = str(art.get("art_id") or "").lower()
            sha = str(art.get("sha256") or "").lower()
            if not aid and not sha:
                continue
            file_entry = files_by_art.get(aid) if aid else None
            if not file_entry and sha:
                file_entry = files_by_sha.get(sha)
            if not file_entry:
                continue
            meta = file_entry.get("meta") or {}
            if meta.get("paid"):
                continue
            bh = int(art.get("block_height", 0) or 0)
            if bh <= 0:
                continue
            gid = file_entry.get("id") or sha or aid
            txid = (art.get("txid") or "").strip()
            resp = self._server.mark_paid(graffiti_id=gid, art_id=aid, txid=txid, block_height=bh)
            if resp.get("status") in ("ok", None):
                marked = True
                self._log(f"[auto-paid] {gid} (art={aid}, h={bh})")
        if marked:
            self._log("[auto-paid] Updated file payment statuses.")


    def _load_auto_payout_guard(self) -> None:
        server_db = self._server.db if self._server else None
        if server_db is not None:
            server_db.cleanup_expired_payout_guards()
            server_db.cleanup_expired_incoming()
            self._auto_payout_guard = server_db.load_payout_guard()
        else:
            self._auto_payout_guard = {}


    def _save_auto_payout_guard(self) -> None:
        server_db = self._server.db if self._server else None
        if server_db is not None:
            try:
                server_db.save_payout_guard(self._auto_payout_guard)
            except Exception as exc:
                self._log(f"[auto-payout] guard save failed: {exc}", error=True)


    def _auto_payout(self) -> None:
        if not self.connected or not self.pool_data:
            return
        tip_height = int((self.last_info or {}).get("height") or 0)
        tip_epoch = GRAFFITI.compute_proof_epoch(tip_height)
        cooldown = int(CFG.ARCHIVIST_AUTO_PAYOUT_COOLDOWN_SEC)
        rpc_addr = self.rpc.address
        recipient = str(rpc_addr or "").strip().lower()
        if not recipient:
            return
        with self._auto_payout_lock:
            for art_id, entry in self.pool_data.items():
                self._process_auto_payout_for_art(art_id, entry, tip_epoch, cooldown, recipient)

    def _process_auto_payout_for_art(self, art_id: str, entry: dict, tip_epoch: int, cooldown: int, recipient: str) -> None:
        stats = entry.get("stats") or {}
        last_paid_epoch = int(stats.get("last_paid_epoch", -1))
        pool_balance = int(stats.get("pool_balance", 0))
        if pool_balance <= 0:
            return
            
        file_meta = entry.get("file") or {}
        if not file_meta.get("paid") or str(file_meta.get("state") or "") != "stored":
            return
            
        last_proof_epoch = int(file_meta.get("last_proof_epoch", -1))
        if last_proof_epoch < 0 or last_proof_epoch > tip_epoch or last_paid_epoch >= last_proof_epoch:
            return
            
        gap = tip_epoch - last_proof_epoch
        guard_entry = self._auto_payout_guard.get(art_id, {})
        guard_epoch = int(guard_entry.get("epoch", -1))
        guard_ts = int(guard_entry.get("ts", 0))
        guard_status = str(guard_entry.get("status") or "").lower()
        
        if guard_epoch > last_proof_epoch:
            return
        if guard_epoch == last_proof_epoch:
            if guard_status == "ok":
                return
            if cooldown > 0 and int(time.time()) - guard_ts < cooldown:
                return
                
        attempt_ts = int(time.time())
        self._auto_payout_guard[art_id] = {"epoch": last_proof_epoch, "ts": attempt_ts, "status": "attempt"}
        self._save_auto_payout_guard()
        self._log(
            f"[auto-payout] art={art_id[:64]} epoch={last_proof_epoch} gap={gap} pool={pool_balance}"
        )
        resp = node_route.rpc_build_payout(
            self.rpc,
            art_id=art_id,
            recipient=recipient,
            amount=pool_balance,
            epoch=last_proof_epoch,
            broadcast=True,
            timeout=8.0,
        )
        ok = resp.get("status") == "ok"
        
        self._auto_payout_guard[art_id] = {
            "epoch": last_proof_epoch,
            "ts": int(time.time()),
            "status": "ok" if ok else "error",
        }
        self._save_auto_payout_guard()
        if ok:
            txid = (resp.get("tx") or {}).get("txid") or "?"
            self._log(f"[auto-payout] broadcast tx {txid[:64]}... for {art_id[:64]}...")
            threading.Thread(target=self.refresh_once, name="ArchivistRefreshAutoPayout", daemon=True).start()
        else:
            self._log(f"[auto-payout] failed art={art_id[:64]} resp={resp}", error=True)

    # ---------- retention / heartbeat ----------
    def _retention_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                self._stop.wait(CFG.RETENTION_GC_SEC)
                continue
            
            tip = int((self.last_info or {}).get("height") or 0)
            try:
                gc_resp = self._server.run_gc(tip_height=tip) if self._server else None
                idx = self._server.get_index_stats() if self._server else None
                if gc_resp.get("expired"):
                    self._log(f"[retention] GC removed {gc_resp.get('expired')} expired item(s)")
                    
                if idx:
                    self.last_index = idx
                    self._run_retention_proofs(idx, tip)
                    self._mark_pending_payouts(idx)
                self._trigger_update()
                
            except Exception as exc:
                self._log(f"[retention] error: {exc}", error=True)
            self._stop.wait(CFG.RETENTION_GC_SEC)

    def _run_retention_proofs(self, idx: Dict[str, Any], tip_height: int) -> None:
        files = idx.get("files") or {}
        if not files:
            return
        epoch_target = GRAFFITI.compute_proof_epoch(tip_height)
        for gid, meta in files.items():
            self._process_single_retention_proof(gid, meta, epoch_target, tip_height)

    def _process_single_retention_proof(self, gid: str, meta: dict, epoch_target: int, tip_height: int) -> None:
        if not self._server or not meta:
            return
        
        if not meta.get("paid") or meta.get("state") != "stored":
            return
        last_epoch = int(meta.get("last_proof_epoch", -1))
        if last_epoch >= epoch_target:
            return
        art_id = str(meta.get("art_id") or "").strip().lower()
        if not art_id:
            self._log(f"[proof] skip {gid[:10]} (missing art_id)")
            return
            
        resp = self._server.generate_retention_proof(graffiti_id=gid, art_id=art_id, tip_height=tip_height)
        ok_proof = False
        if resp.get("status") == "ok":
            ok_proof = True
        if not ok_proof:
            reason = resp.get("reason")
            self._log(f"[proof] {gid[:10]} failed ({reason or 'error'})")
            return
            
        proof_epoch = int(resp.get("epoch", epoch_target))
        offset = int(resp.get("offset", 0))
        length = int(resp.get("length", 0))
        phash = str(resp.get("hash") or "")
        seed = str(resp.get("seed") or "")
        chunk = resp.get("chunk")
        mpath = resp.get("path")
        self._log(f"[proof] {gid[:10]} epoch {proof_epoch} offset {offset} len {length}")
        
        if not self.connected:
            return
            
        ack = node_route.rpc_submit_proof(
            self.rpc,
            art_id=art_id,
            epoch=proof_epoch,
            offset=offset,
            length=length,
            proof_hash=phash,
            height=tip_height,
            seed=seed,
            chunk=chunk,
            path=mpath,
            timeout=8.0,
        )
        ok_ack = bool(ack and isinstance(ack, dict) and ack.get("status") == "ok")
        if ok_ack:
            self._log(f"[proof] submitted epoch {proof_epoch} for {art_id[:12]}...")
        else:
            reason = str((ack or {}).get("error") if isinstance(ack, dict) else ack) or "submit_failed"
            self._log(f"[proof] submit failed: {ack}")
            if self._server and hasattr(self._server, "index") and isinstance(self._server.index, dict):
                files = self._server.index.get("files") or {}
                if gid in files:
                    fmeta = files[gid]
                    fmeta["last_proof_epoch"] = last_epoch
                    fmeta["proof_status"] = "error"
                    fmeta["proof_fail_reason"] = reason
                    if hasattr(self._server, "_normalize_file_meta"):
                        fmeta = self._server._normalize_file_meta(gid, fmeta)
                    self._server.index["files"][gid] = fmeta
                    if hasattr(self._server, "_save_index"):
                        self._server._save_index()

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                self._stop.wait(HEARTBEAT_SEC)
                continue
            ok = node_route.rpc_ping(self.rpc, timeout=2.0)
            if ok:
                self.refresh_once()
            else:
                self._handle_rpc_drop("heartbeat")
            self._stop.wait(HEARTBEAT_SEC)

    # ---------- state helpers ----------
    def _handle_rpc_drop(self, reason: str = "") -> None:
        if not self.connected:
            return
        note = "[rpc] connection lost"
        if reason:
            note += f" ({reason})"
        self._log(note)
        self.connected = False
        if self.attempt_reconnect():
            self._log("[rpc] reconnected automatically.")
        else:
            self._log("Reconnection failed. Use 'reconnect' command.")

    def _mark_pending_payouts(self, idx: Dict[str, Any]) -> None:
        files = idx.get("files") or {}
        current: set[str] = set()
        items = files.items()
        for aid, meta in items:
            if meta.get("state") == "stored" and not meta.get("paid"):
                current.add(aid)
                if aid not in self.pending_paid:
                    size = int(meta.get("size_bytes", 0))
                    self._log(f"[payout] Pending for {aid} ({size} bytes)")
            elif aid in self.pending_paid:
                self._log(f"[payout] Cleared for {aid}")
                
        self.pending_paid = current
