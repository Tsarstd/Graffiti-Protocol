# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import re
import time
import errno
import signal
import threading
import contextlib
import multiprocessing as mp
from multiprocessing.synchronize import Event as MpEvent

# ---------------- Local Project ----------------
from ..utils import config as CFG
from ..network.node import Network
from ..consensus.blockchain import Blockchain
from ..utils.bootstrap import maybe_bootstrap_snapshot

from .cosmetic import interface as COL
from tsarchain.utils.thread_check import get_thread_monitor, register_thread_monitoring_signal

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.miner.orchestrator")

INTERRUPTED_ERRNOS = {errno.EINTR}
with contextlib.suppress(AttributeError):
    INTERRUPTED_ERRNOS.add(errno.WSAEINTR)

ADDRESS_PATTERN = re.compile(r"^tsar1[0-9a-z]{20,120}$")


def _enable_siginterrupt():
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            signal.siginterrupt(sig, False)


def _register_bootstrap_peers(network: Network) -> int:
    fallback_nodes = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
    count = 0
    is_self = network._is_self_bootstrap

    for peer in fallback_nodes:
        if not peer or len(peer) != 2:
            continue
        host, port = peer
        host_s, port_i = str(host), int(port)
        if callable(is_self) and is_self(host_s, port_i):
            continue
        
        peer_tuple = (host_s, port_i)
        network.persistent_peers.add(peer_tuple)
        network.peers.add(peer_tuple)
        count += 1

    return count


def _run_snapshot_bootstrap(enabled: bool, log_fn=None):
    if not enabled:
        log_fn("[Bootstrap] Fast Sync Snapshot: DISABLED. Proceeding with Seed RPC sync.")
        return None

    if CFG.BACKUP_SNAPSHOT:
        log_fn(COL.badges(
        ("SNAPSHOTS", COL.BG_CYAN, COL.BOLD),
        ("ENABLED", COL.BG_GREEN, COL.BOLD),
        (f"every {CFG.BLOCK_BACKUP_SNAPSHOT} blocks -> '{CFG.SNAPSHOT_BACKUP_DIR}'", COL.ITALIC),
    ))
    else:
        log_fn("[Snapshot] Auto backup snapshots: DISABLED")

    def _printer(message: str):
        log_fn(f"[Bootstrap] {message}")

    result = maybe_bootstrap_snapshot(progress_cb=_printer)
    if result.status == "failed":
        log_fn(f"[Bootstrap] Snapshot fast sync failed: {result.reason}. Falling back to standard P2P Seed RPC sync.")
    elif result.status == "skipped":
        log_fn(f"[Bootstrap] Snapshot fast sync skipped ({result.reason}). Using standard P2P Seed RPC sync.")
    elif result.status == "installed":
        bytes_mb = float(result.bytes_written or 0) / (1024 * 1024)
        duration = float(result.duration_s or 0)
        log_fn(f"[Bootstrap] Snapshot SUCCESS! Restored local database to height {result.height} ({bytes_mb:.2f} MB in {duration:.1f}s)")
        log_fn("[Bootstrap] Database restored. Syncing remaining blocks...")
    else:
        log_fn(f"[Bootstrap] Snapshot status: {result.status} ({result.reason})")
    return result



class SimpleMiner:
    def __init__(
        self,
        address: str,
        cores: int,
        bootstrap_snapshot: bool = True,
        *,
        progress_queue: "mp.Queue | None" = None,
        log_fn=None,
    ):
        self.address = address
        self.cores = cores
        self.bootstrap_snapshot = bootstrap_snapshot
        self.log_fn = log_fn
        self.mining_alive = True
        self.cancel_mining = mp.Event()
        self.abort_block_mining = mp.Event()
        self.blockchain = None
        self.network = None
        self._progress_q: mp.Queue = progress_queue or mp.Queue()
        self.tui = None
        self._pending_blocks: list = []
        self._pending_block_hashes: set[str] = set()
        self._trusted_height_cache: int = -1
        self._last_trusted_probe: float = 0.0
        self._bootstrap_self_only: bool | None = None
        self._last_trusted_hash: str | None = None
        
        self.thread_monitor = get_thread_monitor()
        register_thread_monitoring_signal()

        signal.signal(signal.SIGTERM, self._signal_handler)
        
        def _sigint_with_report(signum, frame):
            try:
                self._signal_handler(signum, frame)
            finally:
                if self.tui is not None:
                    self.tui.stop()
                self.thread_monitor.print_thread_report(detailed=True)

        signal.signal(signal.SIGINT, _sigint_with_report)
        _enable_siginterrupt()


    def start_mining(self, timeout=560):
        if not self._validate_address():
            return False

        self.thread_monitor.start_monitoring()
        if not self._start_node():
            return False
        if not self._wait_for_sync(timeout=timeout):
            return False

        self.log_fn(COL.badges(
            ("Press", COL.BG_WHITE, COL.ORANGE),
            ("Ctrl+C", COL.BG_RED),
            ("to stop mining", COL.BG_WHITE, COL.ORANGE),
        ))

        if not self._ensure_genesis():
            return False

        self._mining_loop()
        return True


    def stop(self):
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
        if self.abort_block_mining:
            self.abort_block_mining.set()
            
        if self._progress_q:
            with contextlib.suppress(Exception):
                self._progress_q.cancel_join_thread()

        if self.network:
            self.network.shutdown()
        self.log_fn("Miner stopped")
        self.thread_monitor.stop_monitoring()


# =============================================================================
# INTERNAL METHODS
# =============================================================================


    def _ensure_genesis(self) -> bool:
        if (self.blockchain.height if self.blockchain else -1) < 0:
            created = self.blockchain.ensure_genesis(self.address, use_cores=self.cores)
            if created:
                self.log_fn("Genesis block created")
            else:
                self.log_fn("Failed to create genesis block")
                return False
        return True


    def _request_sync_wait(self) -> None:
        if self.network:
            self.network.request_sync(fast=True)
        time.sleep(2)


    def _check_mining_sync(self, last_gap_log: object = None) -> tuple[bool, object]:
        if not self._has_active_peers() and not self._bootstrap_is_self_only():
            if last_gap_log != "no_peers":
                self.log_fn("[mining] No active peers; pausing mining until peers are back.")
            time.sleep(2)
            return False, "no_peers"

        local_height = int(self.blockchain.height if self.blockchain else -1)
        trusted_height = self._trusted_best_height(force_refresh=True)
        trusted_hash = self._trusted_tip_hash(trusted_height) if trusted_height >= 0 else None
        _, local_hash = self._get_local_tip()

        if trusted_height < 0:
            if last_gap_log != "no_trusted":
                self.log_fn("[mining] Waiting for trusted bootstrap height before mining...")
            self._request_sync_wait()
            return False, "no_trusted"

        gap = trusted_height - local_height
        if gap > 0:
            if last_gap_log != gap:
                self.log_fn(
                    f"[mining] Local height {local_height} behind trusted {trusted_height} (gap {gap}); syncing before mining..."
                )
            self._request_sync_wait()
            return False, gap

        if trusted_hash and local_hash and local_hash.lower() != trusted_hash:
            if last_gap_log != "hash_mismatch":
                self.log_fn("[mining] Local tip hash differs from trusted; syncing before mining...")
            self._request_sync_wait()
            return False, "hash_mismatch"

        return True, None


    def _supervise_mine_thread(self, mine_thread: threading.Thread, worker_cancel: MpEvent) -> None:
        cancel_logged = False
        while mine_thread.is_alive() and self.mining_alive:
            mine_thread.join(timeout=0.2)
            if self.cancel_mining.is_set():
                worker_cancel.set()
                if not cancel_logged:
                    self.log_fn("[mining] Cancellation requested; waiting for miner thread to stop...")
                    cancel_logged = True
            elif self.abort_block_mining.is_set():
                worker_cancel.set()

        if mine_thread.is_alive():
            mine_thread.join(timeout=2.0)


    def _run_mine_worker(self):
        self.abort_block_mining.clear()
        worker_cancel = mp.Event()
        result_holder: dict = {}
        mine_thread = threading.Thread(
            target=self._mine_block_runner,
            args=(result_holder, worker_cancel),
            name="MineBlockWorker",
            daemon=True,
        )
        mine_thread.start()

        self._supervise_mine_thread(mine_thread, worker_cancel)

        exc = result_holder.get("exc")
        if exc:
            raise exc

        return result_holder.get("block")


    def _handle_mined_block(self, block) -> None:
        self.abort_block_mining.clear()
        if self.tui is not None:
            self.tui.note_block_mined(block.height)

        txs = block.transactions or []
        confirmed = max(len(txs) - 1, 0)
        tx_label = f"{confirmed} tx" if confirmed == 1 else f"{confirmed} txs"

        self.log_fn(COL.badges(
            ("Block Found!", COL.YELLOW),
            (block.height, COL.BG_GREEN),
            (block.hash().hex(), COL.ITALIC),
            (tx_label, COL.BG_RED),
        ))

        try:
            sent = self.network.publish_block(block, exclude=None, force=True)
            if sent <= 0:
                self.network.request_sync(fast=True)
                self._queue_block_for_broadcast(block)
        except Exception as exc:
            self.log_fn(f"Broadcast error: {exc}")
            self._queue_block_for_broadcast(block)


    def _handle_tip_abort(self) -> None:
        self.abort_block_mining.clear()
        tip_h, tip_hx = self._get_local_tip()
        hx_str = f" [{tip_hx[:16]}...]" if tip_hx else ""
        self.log_fn(f"Received new block at height {tip_h}{hx_str}; switch to latest tip.")


    def _process_mining_result(self, block) -> None:
        if block:
            self._handle_mined_block(block)
        elif self.abort_block_mining.is_set():
            self._handle_tip_abort()


    def _handle_mining_interrupt(self) -> None:
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
        if self.abort_block_mining:
            self.abort_block_mining.set()
        self.log_fn("[signal] Mining interrupted by user")


    def _handle_mining_os_error(self, exc: OSError) -> bool:
        if exc.errno in INTERRUPTED_ERRNOS:
            self.log_fn("[mining] Interrupted system call; stopping miners...")
            self.mining_alive = False
            self.cancel_mining.set()
            if self.abort_block_mining:
                self.abort_block_mining.set()
            return True
        self.log_fn(f"Mining error: {exc}")
        time.sleep(1)
        return False


    def _mining_loop(self) -> None:
        last_gap_log = None
        while self.mining_alive:
            try:
                synced, last_gap_log = self._check_mining_sync(last_gap_log)
                if not synced:
                    continue

                self._flush_pending_blocks()
                if self.network and self.network.peers:
                    self.network.request_sync(fast=True)

                block = self._run_mine_worker()

                if not self.mining_alive or self.cancel_mining.is_set():
                    break

                self._process_mining_result(block)

            except KeyboardInterrupt:
                self._handle_mining_interrupt()
                break
            except OSError as exc:
                if self._handle_mining_os_error(exc):
                    break
            except Exception as exc:
                self.log_fn(f"Mining error: {exc}")
                time.sleep(1)



    def _signal_handler(self, signum, _frame):
        self.log_fn(f"Received signal {signum}, shutting down...")
        self.mining_alive = False
        if self.cancel_mining:
            self.cancel_mining.set()
        if self.abort_block_mining:
            self.abort_block_mining.set()


    def _validate_address(self):
        if not self.address:
            self.log_fn("Error: Address is required (tsar1...).")
            return False
        addr = self.address.strip().lower()
        if not ADDRESS_PATTERN.match(addr):
            self.log_fn("Error: Address must start with 'tsar1' and contain only lowercase base32 chars (length 24-124).")
            return False
        self.address = addr
        return True


    def _queue_block_for_broadcast(self, block) -> None:
        hx = block.hash().hex()
        if hx and hx in self._pending_block_hashes:
            return
        self._pending_blocks.append(block)
        if hx:
            self._pending_block_hashes.add(hx)
        while len(self._pending_blocks) > 5:
            old = self._pending_blocks.pop(0)
            self._pending_block_hashes.discard(old.hash().hex())


    def _flush_pending_blocks(self) -> None:
        if not self.network or not self._pending_blocks:
            return
        remaining = []
        for blk in self._pending_blocks:
            try:
                sent = self.network.publish_block(blk, exclude=None, force=True)
                if sent and sent > 0:
                    self._pending_block_hashes.discard(blk.hash().hex())
                    continue
            except Exception as exc:
                self.log_fn(f"[broadcast] retry failed: {exc}")
            remaining.append(blk)
        self._pending_blocks = remaining


    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        return bool(self.network.inbound_peers or self.network.outbound_peers)


    def _bootstrap_seeds(self) -> list[tuple[str, int]]:
        seeds = []
        raw = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
        for peer in raw:
            if not peer or len(peer) != 2:
                continue
            host, port = peer
            seeds.append((str(host), int(port)))
        return seeds


    def _bootstrap_is_self_only(self) -> bool:
        if self._bootstrap_self_only is not None:
            return self._bootstrap_self_only
        seeds = self._bootstrap_seeds()
        if not seeds or not self.network:
            self._bootstrap_self_only = False
            return False

        is_self = self.network._is_self_bootstrap
        self._bootstrap_self_only = all(is_self(h, p) for h, p in seeds)
        return bool(self._bootstrap_self_only)


    def _get_local_tip(self) -> tuple[int, str | None]:
        if not self.blockchain:
            return -1, None
        tip = self.blockchain.get_last_block()
        return int(self.blockchain.height), tip.hash().hex() if tip else None


    def _on_tip_changed(self, new_height: int, new_hash: str):
        self.abort_block_mining.set()


    def _mine_block_runner(self, result: dict, cancel_event: MpEvent | None = None):
        """
        Run a single mine_block call in a worker thread so the main loop
        stays responsive to Ctrl+C and can flip cancel_mining immediately.
        """
        evt = cancel_event if cancel_event is not None else self.cancel_mining
        blk = self.blockchain.mine_block(
            miner_address=self.address,
            use_cores=self.cores,
            cancel_event=evt,
            progress_queue=self._progress_q,
        )
        result["block"] = blk


    def _trusted_best_height(self, force_refresh: bool = False) -> int:
        """
        Return best height seen from bootstrap peers (trusted seeds).
        Falls back to cached value unless forced or cache is stale.
        """
        if not self.network:
            return -1
        now = time.time()
        if (not force_refresh) and (now - self._last_trusted_probe < 5.0):
            return self._trusted_height_cache
        seeds = self._bootstrap_seeds()
        peers = list(self.network.persistent_peers or ())
        if seeds:
            peers = seeds
        heights: list[int] = []

        # Use recorded best heights first
        best_map = self.network._peer_best_height or {}
        for peer in peers:
            h = int(best_map.get(peer, -1))
            if h >= 0:
                heights.append(h)

        # Self-bootstrap fallback: trust local height if all seeds are self
        if self._bootstrap_is_self_only():
            local_h = int(self.blockchain.height if self.blockchain else -1)
            if local_h >= 0:
                best = local_h
                self._trusted_height_cache = best
                self._last_trusted_probe = now
                # cache local tip hash
                tip = self.blockchain.get_last_block()
                self._last_trusted_hash = tip.hash().hex() if tip else None
                return best

        # If nothing recorded, query seeds directly
        if not heights:
            for peer in peers:
                info = self.network.rpc_request(peer, {"type": "GET_INFO"}, timeout=max(8.0, CFG.SYNC_TIMEOUT))
                if not info:
                    continue
                h = int(info.get("height", -1))
                if h >= 0:
                    best_map[peer] = h  # keep network state aware of trusted height
                    heights.append(h)

        best = max(heights) if heights else -1
        self._trusted_height_cache = best
        self._last_trusted_probe = now
        return best


    def _trusted_tip_hash(self, height: int) -> str | None:
        if height < 0 or not self.network:
            return None
        if self._bootstrap_is_self_only():
            return self._get_local_tip()[1]
        seeds = self._bootstrap_seeds()
        if not seeds:
            return None
        peer = seeds[0]
        resp = self.network.rpc_request(
            peer, {"type": "GET_BLOCK_HASH", "height": int(height)}, timeout=max(8.0, CFG.SYNC_TIMEOUT)
        )
        if resp and resp.get("type") == "BLOCK":
            hx = resp.get("hash")
            if hx:
                return str(hx).lower()
        return None


    def _start_node(self):
        try:
            _run_snapshot_bootstrap(self.bootstrap_snapshot, log_fn=self.log_fn)
            self.blockchain = Blockchain(
                use_cores=self.cores,
                miner_address=self.address,
            )
            self.blockchain.register_tip_changed_callback(self._on_tip_changed)
            self.network = Network(blockchain=self.blockchain)
            self.network.start()
            self.network.warmup_background()
            peer_count = _register_bootstrap_peers(self.network)
            self.log_fn(f"Node started with {peer_count} bootstrap peers")
            return True
        except Exception as exc:
            log.exception("error")
            self.log_fn(f"Failed to start node: {exc}")
            return False


    def _wait_for_sync(self, timeout=560):
        self.log_fn("Waiting for blockchain sync...")
        start_time = time.time()
        last_progress = (-1, -1, -1)

        while self.mining_alive and (time.time() - start_time) < timeout:
            try:
                height = int(self.blockchain.height if self.blockchain else -1)

                trusted_height = self._trusted_best_height(force_refresh=True)
                trusted_hash = self._trusted_tip_hash(trusted_height) if trusted_height >= 0 else None
                best_height = int(self.network.get_best_peer_height())

                active_peers = self._has_active_peers()
                if not active_peers and not self._bootstrap_is_self_only():
                    self.log_fn("[Sync] Waiting for peer connection...")
                    time.sleep(3)
                    continue

                if self.network.peers:
                    self.network.request_sync(fast=True)

                best_known = trusted_height if trusted_height >= 0 else best_height
                local_h, local_hash = self._get_local_tip()
                if (
                    best_known >= 0
                    and local_h >= best_known
                    and (trusted_hash is None or (local_hash and local_hash.lower() == trusted_hash))
                ):
                    self.log_fn(f"Chain synced to height {local_h} (trusted tip {best_known})")
                    return True
                if trusted_hash and local_hash and local_hash.lower() != trusted_hash:
                    self.log_fn("[Sync] Local tip hash differs from trusted; requesting resync...")
                    if self.network:
                        self.network.request_sync(fast=True)
                    time.sleep(2)
                    continue

                progress = (height, best_known, trusted_height)
                if best_known >= 0 and progress != last_progress:
                    tip_label = trusted_height if trusted_height >= 0 else best_known
                    self.log_fn(f"Sync progress - local {height}, trusted best {tip_label}")
                    last_progress = progress
                time.sleep(2)
            except Exception as exc:
                self.log_fn(f"Sync error: {exc}")
                time.sleep(2)

        self.log_fn("Sync timeout or interrupted")
        return False



class NodeRunner:
    def __init__(self, bootstrap_snapshot: bool = True, log_fn=None):
        self.blockchain = None
        self.network = None
        self.running = True
        self._last_chain_height = -1
        self._sync_ready = False
        self.bootstrap_snapshot = bootstrap_snapshot
        self.log_fn = log_fn
        self._threads: list[threading.Thread] = []
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        _enable_siginterrupt()


    def start(self):
        self.log_fn("Starting TsarChain node (no mining)...")
        try:
            _run_snapshot_bootstrap(self.bootstrap_snapshot, log_fn=self.log_fn)
            self.blockchain = Blockchain(
                use_cores=None,
                miner_address=None,
            )
            
            self._last_chain_height = int(self.blockchain.height if self.blockchain else -1)
            self.log_fn(f"Local chain height: {self._last_chain_height}")
            
            self.network = Network(blockchain=self.blockchain)
            self.network.start()
            self.network.warmup_background()
            peer_count = _register_bootstrap_peers(self.network)
            self.log_fn(f"Node online on port {self.network.port}, bootstrap peers: {peer_count}")

            # == Early fast-sync ==
            def _early_sync():
                for _ in range(5):
                    try:
                        self.network.request_sync(fast=True)
                    except Exception:
                        log.exception("Early sync attempt failed")
                    time.sleep(1.0)
            t_early = threading.Thread(target=_early_sync, daemon=True)
            t_early.start()
            self._threads.append(t_early)

            # == Background sync daemon ==
            t_sync = threading.Thread(target=self._sync_daemon, daemon=True)
            t_sync.start()
            self._threads.append(t_sync)

            while self.running:
                time.sleep(2)
                
        except Exception as exc:
            self.log_fn(f"Node error: {exc}")
            
        finally:
            self._shutdown()


# =============================================================================
# INTERNAL METHODS
# =============================================================================


    def _handle_signal(self, *_args):
        self.log_fn("Stopping node...")
        log.info("Ctrl+C received - stopping node-only runner.")
        self.running = False


    def _has_active_peers(self) -> bool:
        if not self.network:
            return False
        return bool(self.network.peers or self.network.inbound_peers or self.network.outbound_peers)


    def _sync_daemon(self):
        last_status = ""
        while self.running and self.blockchain and self.network:
            try:
                # No peers yet
                if not self._has_active_peers():
                    msg = "[Sync] Waiting for peer connection..."
                    if msg != last_status:
                        self.log_fn(msg)
                        last_status = msg
                    self._sync_ready = False
                    time.sleep(5)
                    continue

                # Heights
                height = int(self.blockchain.height if self.blockchain else -1)
                # Progress print (only when changed)
                if height != self._last_chain_height:
                    if height >= 0:
                        self.log_fn(f"[Sync] Chain height now {height}")
                    self._last_chain_height = height

                peer_sync_map = self.network._peer_last_sync or {}
                latest_sync = max(peer_sync_map.values()) if peer_sync_map else 0.0
                synced_recently = latest_sync and (time.time() - latest_sync) < 10
                if not self._sync_ready and height >= 0 and synced_recently:
                    self._sync_ready = True
                    self.log_fn("Chain has been confirmed. Node is live (no mining).")

                if not self._sync_ready:
                    self.network.request_sync(fast=True)
                    time.sleep(5)
                else:
                    self.network.request_sync(fast=False)
                    time.sleep(30)

            except Exception as e:
                self.log_fn(f"[node-only] sync error: {e}")
                time.sleep(5)


    def _shutdown(self):
        self.running = False
        if self.network:
            self.network.shutdown()
            self.network = None
        for t in self._threads:
            if t and t.is_alive():
                t.join(timeout=2.5)
        self._threads.clear()
        self.log_fn("Node stopped.")
        log.info("Node-only runner stopped (cleanup complete).")