# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
import json
import base64
import socket
import threading

from collections import OrderedDict
from typing import Any, Dict, Optional, Set, Tuple

from ...core.tx import Tx
from ...core.block import Block
from ...utils import config as CFG
from .base import BroadcastHandlerProxy
from ..protocol import SecureChannel, send_message

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.cast.gossip")


class GossipHandler(BroadcastHandlerProxy):

    def send_gossip(
        self,
        peers: Set[Tuple[str, int]],
        message: Dict[str, Any],
        exclude: Optional[Tuple[str, int]] = None,
    ):
        success_count = 0
        now = time.time()
        backoff_s = CFG.BROADCAST_FAIL_BACKOFF_S
        thr = CFG.BROADCAST_FAIL_THRESHOLD
        port_start, port_end = int(CFG.PORT_START), int(CFG.PORT_END)
        for peer in peers:
            if exclude and peer == exclude:
                continue
            if not (port_start <= int(peer[1]) <= port_end):
                continue

            fm = self._failmap.get(peer)
            if fm and int(fm.get("fails", 0)) >= thr and (now - float(fm.get("last", 0.0)) < backoff_s):
                log.debug("[send_gossip] Skipping %s due to backoff (fails=%s)", peer, fm.get("fails"))
                continue

            if self.start_gossip(peer, message):
                success_count += 1

        return success_count


    def broadcast_block(
        self,
        block: Block,
        peers: Set[Tuple[str, int]],
        exclude: Optional[Tuple[str, int]] = None,
        force: bool = False,
    ):
        block_id = block.hash().hex()
        with self.lock:
            if not force and block_id in self.seen_blocks:
                return 0
            self.seen_blocks.add(block_id)

        p = self.port
        raw_b64 = base64.b64encode(block.to_storage_bytes()).decode("ascii")

        success = self.send_gossip(
            peers,
            {
                "type": "NEW_BLOCK",
                "data": raw_b64,
                "hash": block_id,
                "port": p or 0,
            },
            exclude,
        )

        return success


    def broadcast_tx_fluff(self, tx: Tx, tx_id: str, peers: Set[Tuple[str, int]], exclude: Optional[Tuple[str, int]] = None):
        with self.lock:
            if tx_id in self.seen_txs:
                return 0
            self.seen_txs.add(tx_id)

        msg = {"type": "NEW_TX", "data": tx.to_dict(), "phase": "fluff"}
        return self.send_gossip(peers, msg, exclude)  


    def start_gossip(self, peer: Tuple[str, int], message: Dict[str, Any]) -> bool:
        port_start, port_end = int(CFG.PORT_START), int(CFG.PORT_END)
        if not (port_start <= int(peer[1]) <= port_end):
            log.debug("[start_gossip] Skip peer %s out of port range %s-%s", peer, port_start, port_end)
            return False

        cache, cache_lock = self._get_gossip_cache()
        payload = json.dumps(self._encode(message)).encode("utf-8")
        entry = self._get_cached_connection(peer, cache, cache_lock)

        sock = None
        chan = None
        try:
            if entry:
                sock, chan = self._check_cached_socket(entry)

            if sock is None:
                sock, chan = self._create_new_connection(peer)

            if chan:
                chan.send(payload)
            else:
                send_message(sock, payload)

            fm = self._failmap.get(peer)
            if fm:
                self._failmap.pop(peer, None)

            max_cache = max(1, min(int(CFG.MAX_OUTBOUND_PEERS * 2), 64))
            with cache_lock:
                cache[peer] = {"sock": sock, "chan": chan, "ts": time.time()}
                while len(cache) > max_cache:
                    _, victim = cache.popitem(last=False)
                    self._cleanup_socket(victim)
            return True

        except TimeoutError:
            log.debug("[start_gossip] Connect to %s timed out", peer)
        except ConnectionRefusedError:
            log.debug("[start_gossip] Connect to %s refused", peer)
        except OSError as e:
            try:
                err_msg = e.strerror
            except AttributeError:
                err_msg = e
            log.debug("[start_gossip] OSError sending to %s: %s", peer, err_msg)

        self._handle_send_failure(peer, entry, sock)
        return False  


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _get_gossip_cache(self) -> Tuple[OrderedDict, threading.RLock]:
        cache = self._gossip_conn_cache
        cache_lock = self._gossip_conn_lock
        if cache is None or cache_lock is None:
            cache = self._gossip_conn_cache = OrderedDict()
            cache_lock = self._gossip_conn_lock = threading.RLock()
        return cache, cache_lock


    def _get_cached_connection(self, peer: Tuple[str, int], cache: OrderedDict, cache_lock: threading.RLock) -> Optional[Dict[str, Any]]:
        now = time.time()
        cache_ttl = max(1.0, float(CFG.GOSSIP_CONN_TTL))
        with cache_lock:
            e = cache.get(peer)
            if e and (now - e.get("ts", 0.0)) < cache_ttl:
                return cache.pop(peer, None)
            elif e:
                cache.pop(peer, None)
                self._cleanup_socket(e)
        return None


    def _check_cached_socket(self, entry: Dict[str, Any]) -> Tuple[Optional[socket.socket], Optional[SecureChannel]]:
        sock = entry.get("sock")
        chan = entry.get("chan")
        try:
            sock.settimeout(0.2)
            sock.send(b"")
            sock.settimeout(CFG.SYNC_TIMEOUT)
            return sock, chan
        except Exception:
            self._cleanup_socket(entry)
            return None, None


    def _create_new_connection(self, peer: Tuple[str, int]) -> Tuple[socket.socket, Optional[SecureChannel]]:
        connect_timeout = float(CFG.CONNECT_TIMEOUT)
        if connect_timeout <= 0:
            connect_timeout = float(CFG.SYNC_TIMEOUT)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
        sock.settimeout(connect_timeout)
        sock.connect(peer)
        sock.settimeout(CFG.SYNC_TIMEOUT)
        
        chan = SecureChannel(
            sock,
            role="client",
            node_id=self.node_id,
            node_pub=self.pubkey,
            node_priv=self.privkey,
            get_pinned=lambda nid: self.peer_pubkeys.get(nid),
            set_pinned=lambda nid, pk: self.peer_pubkeys.__setitem__(nid, pk),
        )
        chan.handshake()
        return sock, chan


    def _cleanup_socket(self, entry: Dict[str, Any]):
        sock = entry.get("sock")
        if sock:
            sock.close()
            log.debug("[_cleanup_socket]")


    def _handle_send_failure(self, peer: Tuple[str, int], entry: Optional[Dict[str, Any]], sock: Optional[socket.socket]):
        fm = self._failmap.get(peer) or {"fails": 0, "last": 0.0}
        fm["fails"] = int(fm["fails"]) + 1
        fm["last"] = time.time()
        self._failmap[peer] = fm
        if entry:
            self._cleanup_socket(entry)
        if sock is not None:
            self._cleanup_socket({"sock": sock})


__all__ = ["GossipHandler"]
