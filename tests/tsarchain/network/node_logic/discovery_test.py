# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import threading
from unittest.mock import MagicMock, patch

import pytest

from tsarchain.network.node_logic.discovery import (
    discover_peers_loop,
    _attempt_hello,
    _discover_peers,
)


class MockNode:
    def __init__(self):
        self._stop = threading.Event()
        self.lock = threading.RLock()
        self.port = 8333
        self.node_id = "test_node_id"
        self.pubkey = "test_pubkey"
        self.privkey = "test_privkey"
        self.node_ctx = {"test": "ctx"}
        self.outbound_peers = set()
        self.peers = set()
        self.persistent_peers = {("127.0.0.1", 8334)}
        self.peer_scores = {}
        self._peer_last_dial = {}

        self.broadcast = MagicMock()
        self.broadcast.blockchain.height = 100
        
        self.normalize_peer = MagicMock(side_effect=lambda x: x)
        self._is_local_address = MagicMock(return_value=False)

    def reward_peer(self, peer):
        pass

    def penalize_peer(self, peer, amount):
        pass

    def get_pinned(self, *args):
        return None

    def set_pinned(self, *args):
        pass

    def gc_mailboxes(self):
        pass

    def request_mempool_snapshot(self, peer, force=False):
        pass


@pytest.fixture
def mock_node():
    return MockNode()


# ---------------------------------------------------------
# discover_peers_loop tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.discovery._discover_peers")
@patch("tsarchain.network.node_logic.discovery.time.sleep")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_discover_peers_loop(mock_cfg, mock_sleep, mock_discover, mock_node):
    mock_cfg.DISCOVERY_INTERVAL = 1.0
    
    def set_stop(*args, **kwargs):
        mock_node._stop.set()
        
    mock_sleep.side_effect = set_stop
    
    discover_peers_loop(mock_node)
    
    mock_discover.assert_called_once()
    mock_sleep.assert_called_once_with(1.0)


# ---------------------------------------------------------
# _attempt_hello tests
# ---------------------------------------------------------
def test_attempt_hello_invalid_peer(mock_node):
    mock_node.normalize_peer.return_value = None
    assert _attempt_hello(mock_node, None) is False

    mock_node.normalize_peer.return_value = ("127.0.0.1", 0)
    assert _attempt_hello(mock_node, ("127.0.0.1", 0)) is False

    mock_node.normalize_peer.return_value = ("127.0.0.1", 8333)
    assert _attempt_hello(mock_node, ("127.0.0.1", 8333)) is False

@patch("tsarchain.network.node_logic.discovery.time.time")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_attempt_hello_recently_dialed(mock_cfg, mock_time, mock_node):
    mock_cfg.DISCOVERY_INTERVAL = 10.0
    mock_time.return_value = 1000.0
    peer = ("192.168.1.10", 8334)
    mock_node._peer_last_dial[peer] = 999.0
    
    assert _attempt_hello(mock_node, peer) is False
    
    mock_node.outbound_peers.add(peer)
    assert _attempt_hello(mock_node, peer) is True

@patch("tsarchain.network.node_logic.discovery.socket.socket")
@patch("tsarchain.network.node_logic.discovery.SecureChannel")
@patch("tsarchain.network.node_logic.discovery.build_envelope")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_attempt_hello_p2p_secure(mock_cfg, mock_env, mock_channel, mock_socket, mock_node):
    mock_cfg.DISCOVERY_INTERVAL = 10.0
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.HEADERS_FANOUT = 4
    mock_cfg.BUFFER_SIZE = 8192
    
    mock_env.return_value = {"env": "yes"}
    mock_chan_inst = MagicMock()
    mock_channel.return_value = mock_chan_inst
    
    peer = ("192.168.1.10", 8334)
    res = _attempt_hello(mock_node, peer)
    
    assert res is True
    mock_chan_inst.handshake.assert_called_once()
    mock_chan_inst.send.assert_called_once()
    mock_chan_inst.recv.assert_called_once()

@patch("tsarchain.network.node_logic.discovery.socket.socket")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_attempt_hello_exception(mock_cfg, mock_socket, mock_node):
    mock_cfg.DISCOVERY_INTERVAL = 10.0
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.BUFFER_SIZE = 8192
    
    mock_socket.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError()
    
    peer = ("192.168.1.10", 8334)
    res = _attempt_hello(mock_node, peer)
    
    assert res is False
    assert peer in mock_node._peer_last_dial


@patch("tsarchain.network.node_logic.discovery.socket.socket")
@patch("tsarchain.network.node_logic.discovery.SecureChannel")
@patch("tsarchain.network.node_logic.discovery.log")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_attempt_hello_handshake_value_error(mock_cfg, mock_log, mock_channel, mock_socket, mock_node):
    mock_cfg.DISCOVERY_INTERVAL = 10.0
    mock_cfg.HANDSHAKE_TIMEOUT = 5.0
    mock_cfg.BUFFER_SIZE = 8192

    mock_chan_inst = MagicMock()
    mock_chan_inst.handshake.side_effect = ValueError("bad P2P handshake (HS2)")
    mock_channel.return_value = mock_chan_inst

    peer = ("127.0.0.1", 38172)
    res = _attempt_hello(mock_node, peer)

    assert res is False
    assert peer in mock_node._peer_last_dial
    mock_log.debug.assert_called_once()
    mock_log.exception.assert_not_called()


# ---------------------------------------------------------
# _discover_peers tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.discovery._attempt_hello")
@patch("tsarchain.network.node_logic.discovery.rpc_client.prefetch_peer_channel")
@patch("tsarchain.network.node_logic.discovery.CFG")
def test_discover_peers(mock_cfg, mock_prefetch, mock_attempt, mock_node):
    mock_cfg.MAX_OUTBOUND_PEERS = 2
    mock_cfg.PORT_START = 8330
    mock_cfg.PORT_END = 8335
    
    mock_node.peers = {("1.1.1.1", 8334)}
    mock_node.peer_scores = {("1.1.1.1", 8334): 100}
    
    mock_attempt.side_effect = lambda node, peer: peer == ("127.0.0.1", 8334)
    
    _discover_peers(mock_node)
    
    # 1 from persistent, 1 from score, rest from port range
    assert mock_attempt.call_count >= 1
    assert ("127.0.0.1", 8334) in mock_node.outbound_peers
    assert ("127.0.0.1", 8334) in mock_node.peers
