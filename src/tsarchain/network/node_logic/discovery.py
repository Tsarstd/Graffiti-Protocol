# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import json
import random
import socket
import time
from typing import List, Set, Tuple

from . import rpc_client
from ...utils import config as CFG
from ..protocol import SecureChannel, build_envelope

from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.node_logic.discovery")

_secure_random = random.SystemRandom()

def discover_peers_loop(self):
    while not self._stop.is_set():
        _discover_peers(self)
        gc_fn = self.gc_mailboxes
        if callable(gc_fn):
            gc_fn()
        time.sleep(CFG.DISCOVERY_INTERVAL)


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _discover_peers(self):
    limit = max(1, int(CFG.MAX_OUTBOUND_PEERS))
    found_peers: Set[Tuple[str, int]] = set()

    with self.lock:
        candidates: List[Tuple[str, int]] = list(self.persistent_peers)
        scored = sorted(
            (p for p in self.peers if p not in self.persistent_peers),
            key=lambda p: self.peer_scores.get(p, 0),
            reverse=True,
        )
    candidates.extend(scored)
    _secure_random.shuffle(candidates)

    _process_candidates(self, candidates, found_peers, limit)

    if len(found_peers) < limit:
        _process_fallback_ports(self, found_peers, limit)

    with self.lock:
        self.peers.update(found_peers)
        retained = {p for p in self.outbound_peers if p in found_peers}
        for peer in found_peers:
            if len(retained) < limit or peer in retained:
                retained.add(peer)
        self.outbound_peers = retained


def _process_candidates(self, candidates: List[Tuple[str, int]], found_peers: Set[Tuple[str, int]], limit: int):
    for peer in candidates:
        norm = self.normalize_peer(peer)
        if not norm or norm in found_peers:
            continue
        if limit > 0 and len(found_peers) >= limit and norm not in self.outbound_peers:
            break
        if _attempt_hello(self, norm):
            found_peers.add(norm)
            self.reward_peer(norm)
            rpc_client.prefetch_peer_channel(self, norm)
        else:
            self.penalize_peer(norm, CFG.PEER_SCORE_FAILURE_PENALTY)


def _process_fallback_ports(self, found_peers: Set[Tuple[str, int]], limit: int):
    for port in range(CFG.PORT_START, CFG.PORT_END + 1):
        if port == self.port:
            continue
        norm = ("127.0.0.1", port)
        if norm in found_peers:
            continue
        if limit > 0 and len(found_peers) >= limit and norm not in self.outbound_peers:
            break
        if _attempt_hello(self, norm):
            found_peers.add(norm)
            self.reward_peer(norm)


def _attempt_hello(self, peer: Tuple[str, int]) -> bool:
    norm = self.normalize_peer(peer)
    if not norm:
        return False
    ip, port = norm
    if port <= 0:
        return False
    if ip in ("127.0.0.1", "localhost") and port == self.port:
        return False
    if (port == self.port) and self._is_local_address(ip):
        return False

    now = time.time()
    last_dial = self._peer_last_dial.get(norm, 0.0)
    if now - last_dial < max(2.0, CFG.DISCOVERY_INTERVAL / 2):
        return norm in self.outbound_peers

    hello_msg = {
        "type": "HELLO",
        "port": self.port,
        "height": self.broadcast.blockchain.height,
        "peers": [{"ip": h, "port": p} for h, p in list(self.peers)[: CFG.HEADERS_FANOUT]],
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(CFG.BUFFER_SIZE))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(CFG.BUFFER_SIZE))
            timeout = float(CFG.HANDSHAKE_TIMEOUT)
            s.settimeout(timeout)
            s.connect(norm)
            chan = SecureChannel(
                s,
                role="client",
                node_id=self.node_id,
                node_pub=self.pubkey,
                node_priv=self.privkey,
                get_pinned=self.get_pinned,
                set_pinned=self.set_pinned,
            )
            chan.handshake()
            s.settimeout(1.0)
            env = build_envelope(hello_msg, self.node_ctx, extra={"pubkey": self.pubkey})
            env["pubkey"] = self.pubkey
            
            chan.send(json.dumps(env).encode("utf-8"))
            chan.recv(1)
                
    except OSError:
        return False
    except Exception as e:
        log.debug("[_attempt_hello] Handshake failed dialing %s: %s", norm, e)
        return False
    finally:
        self._peer_last_dial[norm] = now

    self.broadcast.send_mempool_to_peer(norm)
    self.request_mempool_snapshot(norm, force=True)
    return True