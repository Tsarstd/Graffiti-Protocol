# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: Merkle; Signal-X3DH

from __future__ import annotations

import socket
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Set

# ---------------- Local Project ----------------

from .rpc_helper.tx import TxHandler
from .rpc_helper.chat import ChatHandler
from .rpc_helper.guard import GuardHandler
from .rpc_helper.history import HistoryHandler
from .rpc_helper.explorer import ExplorerHandler

from .node_logic import (
    sync,
    peers,
    discovery,
    chat_state,
    rpc_client,
    server_node,
    storage_registry
)

from ..core.block import Block
from .broadcast import Broadcast
from ..utils import config as CFG
from .peers_storage import load_peer_keys, save_peer_keys
from .protocol import build_envelope, load_or_create_keypair_at


# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node")


class NetworkProxy:
    _tls = threading.local()

    def __getattr__(self, name):
        if self._tls.__dict__.get("in_getattr", False):
            raise AttributeError(name)
        self._tls.in_getattr = True
        try:
            if '_handlers' not in self.__dict__:
                self.chat_handler = ChatHandler(self)
                self.history_handler = HistoryHandler(self)
                self.explorer_handler = ExplorerHandler(self)
                self.tx_handler = TxHandler(self)
                self.guard_handler = GuardHandler(self)
                
                self.__dict__['_handlers'] = [
                    self.chat_handler,
                    self.history_handler,
                    self.explorer_handler,
                    self.tx_handler,
                    self.guard_handler,
                ]
            
            if name in self.__dict__:
                return self.__dict__[name]

            for handler in self._handlers:
                if name in handler.__dict__ or name in handler.__class__.__dict__:
                    return handler.__getattribute__(name)
        finally:
            self._tls.in_getattr = False
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

class Network(NetworkProxy):
    
    active_ports = set()
    _instance_lock = threading.Lock()

    def __init__(self, blockchain=None):
        self.lock = threading.RLock()
        self._init_port()
        self._init_identity_and_broadcast(blockchain)
        self._init_state_variables()
        self._init_bootstrap_peers()
        self._init_threads_and_services()

    def _init_port(self) -> None:
        self.port = self._find_available_port()
        if self.port is None:
            raise RuntimeError("[Network] No available ports. Cannot join network.")
        with Network._instance_lock:
            Network.active_ports.add(self.port)

    def _init_identity_and_broadcast(self, blockchain=None) -> None:
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at("node_key")
        self.node_ctx = {
            "net_id": CFG.DEFAULT_NET_ID,
            "node_id": self.node_id,
            "pubkey": self.pubkey,
            "privkey": self.privkey,
        }
        self.peer_pubkeys: dict[str, str] = load_peer_keys()

        self._peer_keys_lock = threading.RLock()

        self.broadcast = Broadcast(blockchain=blockchain)
        self.broadcast.port = self.port
        self.broadcast.network = self
        self.broadcast.node_id = self.node_id
        self.broadcast.pubkey = self.pubkey
        self.broadcast.privkey = self.privkey
        self.broadcast.peer_pubkeys = self.peer_pubkeys
        self.broadcast._encode = lambda inner: build_envelope(inner, self.node_ctx, extra={"pubkey": self.pubkey})

        storage_registry.init_storage_registry(self)
        chat_state.init_chat_state(self)

    def _init_state_variables(self) -> None:
        self.peers: Set[Tuple[str, int]] = set()
        self.inbound_peers: Set[Tuple[str, int]] = set()
        self.outbound_peers: Set[Tuple[str, int]] = set()
        self.peer_scores: Dict[Tuple[str, int], int] = {}
        self._inbound_ips: Dict[str, int] = {}

        self._peer_last_sync: Dict[Tuple[str, int], float] = {}
        self._peer_last_mempool_sync: Dict[Tuple[str, int], float] = {}
        self._peer_best_height: Dict[Tuple[str, int], int] = {}
        self._peer_last_dial: Dict[Tuple[str, int], float] = {}

        self._last_headers_locator: Dict[Tuple[str, int], List[str]] = {}
        self._snapshot_unreachable: Set[Tuple[str, int]] = set()

        self._rpc_backoff: Dict[Tuple[str, int], float] = {}
        self._rpc_conn_cache: "OrderedDict[Tuple[str, int], dict]" = OrderedDict()
        self._rpc_conn_cache_lock = threading.RLock()
        self._rpc_prefetched: Set[Tuple[str, int]] = set()

        self._recent_gap_requests: Dict[Tuple[str, int], float] = {}
        self._nonce_guard_table: Dict[str, Dict[str, float]] = {}
        self._nonce_guard_lock = threading.RLock()

        self._sync_event = threading.Event()
        self._sync_fast_until = 0.0
        self._pending_mempool_pull = False
        self.utxodb = self.broadcast.utxodb

        # --- Log throttles to reduce console spam
        self._last_p2p_log = 0.0
        self._last_sync_log = 0.0
        self._last_sync_count = -1

    def _init_bootstrap_peers(self) -> None:
        configured_bootstrap = tuple(CFG.BOOTSTRAP_NODES or (CFG.BOOTSTRAP_NODE,))
        bootstrap_nodes: Set[Tuple[str, int]] = set()
        for host, port in configured_bootstrap:
            bootstrap_nodes.add((str(host), int(port)))

        if not bootstrap_nodes:
            raise ValueError("No valid bootstrap peers configured")

        primary_peer = self.normalize_peer(CFG.BOOTSTRAP_NODE) or next(iter(bootstrap_nodes))

        is_bootstrap_self = any(self._is_self_bootstrap(h, p) for h, p in bootstrap_nodes)
        if is_bootstrap_self:
            self.persistent_peers = {peer for peer in bootstrap_nodes if not self._is_self_bootstrap(*peer)}
        else:
            self.persistent_peers = set(bootstrap_nodes)
            if self.port == primary_peer[1] and not self._is_local_address(primary_peer[0]):
                log.info("[__init__] Port %s matches bootstrap but host differs (%s); treating as client node", self.port, primary_peer[0])

        self.peers.update(self.persistent_peers)
        for peer in self.persistent_peers:
            self.peer_scores[peer] = CFG.PEER_SCORE_START

    def _init_threads_and_services(self) -> None:
        self._stop = threading.Event()
        self._server_sock = None
        self._threads: list[threading.Thread] = []

        self.server_thread = threading.Thread(target=server_node.start_server, args=(self,), daemon=True)
        self.discovery_thread = threading.Thread(target=discovery.discover_peers_loop, args=(self,), daemon=True)
        self.sync_thread = threading.Thread(target=sync.sync_loop, args=(self,), daemon=True)
        self._threads = [self.server_thread, self.discovery_thread, self.sync_thread]

    def _warmup_background(self) -> None:
        try:
            bc = self.broadcast.blockchain if self.broadcast else None
            if not bc:
                return
            tip_h = int(bc.height or 0)
            if tip_h >= 0:
                val = bc.validator
                if val:
                    val._ensure_warm(tip_h)
                    val._warm_pow_context(tip_h)

                utxo = self.broadcast.utxodb if self.broadcast else None
                if utxo:
                    with utxo._lock:
                        utxo._ensure_index_locked()

                hist = self.history_handler
                if hist and bc.chain:
                    opmap = hist.build_outpoint_map(bc.chain)
                    hist._sync_index_to_tip(bc.chain, tip_h, opmap)

                log.info("[warmup] Startup pre-warming completed for height=%d", tip_h)
        except Exception:
            log.debug("[warmup] Startup pre-warming skipped", exc_info=True)

    def warmup_background(self) -> None:
        """Starts a background thread to pre-warm RandomX context and chain indexes."""
        threading.Thread(target=self._warmup_background, name="node-warmup", daemon=True).start()

    def start(self) -> None:
        """Starts background network threads and performs initial RPC prefetching."""
        try:
            rpc_client.prefetch_rpc_connections(self)
        except Exception:
            log.debug("[start] rpc prefetch skipped", exc_info=True)

        self.server_thread.start()
        self.discovery_thread.start()
        self.sync_thread.start()


    # --------------------------- WRAPPER -------------------------
    
    def penalize_peer(self, peer: Any, amount: int) -> None:
        return peers.penalize_peer(self, peer, amount)

    def reward_peer(self, peer: Any, amount: int = CFG.PEER_SCORE_REWARD) -> None:
        return peers.reward_peer(self, peer, amount)

    def publish_block(self, block: "Block", exclude: Optional[Tuple[str, int]] = None, force: bool = True) -> int:
        return peers.publish_block(self, block, exclude=exclude, force=force)
    
    def normalize_peer(self, peer: Any) -> Optional[Tuple[str, int]]:
        return peers.normalize_peer(self, peer)
    
    def request_sync(self, fast: bool = False) -> None:
        return sync.request_sync(self, fast=fast)

    def sync_with_peers(self):
        return sync.sync_with_peers(self)

    def is_caught_up(self, freshness: float = 10.0, height_slack: int = 0) -> bool:
        return sync.is_caught_up(self, freshness=freshness, height_slack=height_slack)

    def get_best_peer_height(self) -> int:
        return sync.get_best_peer_height(self)

    def handle_block_gap(self, block, origin: Optional[Tuple[str, int]]) -> None:
        return sync.handle_block_gap(self, block, origin)

    def rpc_request(self, peer: Tuple[str, int], payload: dict, timeout: Optional[float] = None) -> Optional[dict]:
        return rpc_client.rpc_request(self, peer, payload, timeout)

    def request_mempool_inline(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        return rpc_client.request_mempool_inline(self, peer, force=force)

    def request_mempool_snapshot(self, peer: Tuple[str, int], *, force: bool = False) -> Optional[bool]:
        return rpc_client.request_mempool_snapshot(self, peer, force=force)
    
    # ------------------------------ END OF WRAPPER ------------------------------

    # ------------------------------ Shutdown ------------------------------

    def shutdown(self):
        self._stop.set()
        if self._server_sock:
            self._server_sock.close()
        
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=1.5)
            
        with Network._instance_lock:
            Network.active_ports.discard(self.port)
        self.broadcast.shutdown()
        
        log.info("[shutdown] Node at port %s stopped", self.port)
    
    # ------------------------------ Pinned ------------------------------
    
    def get_pinned(self, nid: str):
        # may return None if not yet available
        return self.peer_pubkeys.get(nid)

    def set_pinned(self, nid: str, pk: str) -> None:
        with self._peer_keys_lock:
            if self.peer_pubkeys.get(nid) == pk:
                return
            self.peer_pubkeys[nid] = pk
            save_peer_keys(self.peer_pubkeys)
            
    # -------------------------- Server / Accept ---------------------------

    def _find_available_port(self) -> Optional[int]:
        for port in range(CFG.PORT_START, CFG.PORT_END + 1):
            if port in Network.active_ports:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.bind(("0.0.0.0", port))
                    return port
            except (socket.error, OSError):
                continue
        return None

    def _is_self_bootstrap(self, host: str, port: int) -> bool:
        self_port = self.port
        if int(port) != int(self_port):
            return False
        return self._is_local_address(host)

    @staticmethod
    def _is_local_address(host: str) -> bool:
        if not host:
            return False
        
        host = str(host).strip()
        if not host:
            return False
        
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

        if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::") or host.startswith("fe80:"):
            return True

        target_ips: set[str] = set()
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            for info in infos:
                ip = info[4][0]
                if ip:
                    if ip.startswith("::ffff:"):
                        ip = ip[7:]
                    target_ips.add(ip)
        except (OSError):
            target_ips.add(host)
            
        if not target_ips:
            return False

        local_ips: set[str] = {"127.0.0.1", "127.0.1.1", "::1", "0.0.0.0", "::"}
        try:
            hn = socket.gethostname()
            local_ips.update(socket.gethostbyname_ex(hn)[2])
            fqdn = socket.getfqdn()
            local_ips.update(socket.gethostbyname_ex(fqdn)[2])
        except Exception:
            pass

        try:
            for info in socket.getaddrinfo(None, 0, proto=socket.IPPROTO_TCP):
                ip = info[4][0]
                if ip:
                    if ip.startswith("::ffff:"):
                        ip = ip[7:]
                    local_ips.add(ip)
        except Exception:
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                outbound_ip = s.getsockname()[0]
                if outbound_ip:
                    local_ips.add(outbound_ip)
        except Exception:
            pass

        return any(ip in local_ips for ip in target_ips)
