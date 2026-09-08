# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import base64
import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.cast.gossip import GossipHandler
import tsarchain.utils.config as CFG

class DummyNode(GossipHandler):
    def __init__(self):
        self.node_id = "test_node_id"
        self.pubkey = b"pubkey"
        self.privkey = b"privkey"
        self.peer_pubkeys = {}
        self._failmap = {}
        self.lock = MagicMock()
        self.seen_blocks = set()
        self.seen_txs = set()
        self.port = 8333
        self._gossip_conn_cache = None
        self._gossip_conn_lock = None
        
    def _encode(self, msg):
        return msg

@pytest.fixture
def dummy_node():
    # Setup CFG mock values
    CFG.PORT_START = 8000
    CFG.PORT_END = 9000
    CFG.CONNECT_TIMEOUT = 1.0
    CFG.SYNC_TIMEOUT = 10.0
    CFG.BUFFER_SIZE = 1024
    CFG.BROADCAST_FAIL_BACKOFF_S = 60
    CFG.BROADCAST_FAIL_THRESHOLD = 3
    CFG.MAX_OUTBOUND_PEERS = 16
    
    return DummyNode()

def test_send_skip_port(dummy_node):
    assert dummy_node.start_gossip(("127.0.0.1", 7000), {"type": "TEST"}) is False
    assert dummy_node.start_gossip(("127.0.0.1", 9001), {"type": "TEST"}) is False

@patch("tsarchain.network.cast.gossip.socket.socket")
@patch("tsarchain.network.cast.gossip.SecureChannel")
def test_send_success_new_conn(mock_secure_channel, mock_socket, dummy_node):
    mock_sock = MagicMock()
    mock_socket.return_value = mock_sock
    mock_chan = MagicMock()
    mock_secure_channel.return_value = mock_chan
    
    peer = ("127.0.0.1", 8333)
    msg = {"type": "TEST"}
    
    assert dummy_node.start_gossip(peer, msg) is True
    
    mock_socket.assert_called_once()
    mock_sock.connect.assert_called_once_with(peer)
    mock_chan.send.assert_called_once_with(b'{"type": "TEST"}')
    
    # Check cache
    assert peer in dummy_node._gossip_conn_cache
    assert dummy_node._gossip_conn_cache[peer]["sock"] == mock_sock
    assert dummy_node._gossip_conn_cache[peer]["chan"] == mock_chan

@patch("tsarchain.network.cast.gossip.socket.socket")
def test_send_success_cached_conn(mock_socket, dummy_node):
    peer = ("127.0.0.1", 8333)
    mock_cached_sock = MagicMock()
    mock_cached_chan = MagicMock()
    
    dummy_node._gossip_conn_cache = {
        peer: {"sock": mock_cached_sock, "chan": mock_cached_chan, "ts": time.time()}
    }
    dummy_node._gossip_conn_lock = MagicMock()
    
    msg = {"type": "TEST"}
    assert dummy_node.start_gossip(peer, msg) is True
    
    # Existing socket used, no new socket created
    mock_socket.assert_not_called()
    mock_cached_sock.send.assert_called_with(b"") # keepalive ping
    mock_cached_chan.send.assert_called_once_with(b'{"type": "TEST"}')
    
    # Put back in cache
    assert peer in dummy_node._gossip_conn_cache

@patch("tsarchain.network.cast.gossip.socket.socket")
def test_send_fail_timeout(mock_socket, dummy_node):
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = TimeoutError("timeout")
    mock_socket.return_value = mock_sock
    
    peer = ("127.0.0.1", 8333)
    assert dummy_node.start_gossip(peer, {"type": "TEST"}) is False
    
    # Check failmap
    assert peer in dummy_node._failmap
    assert dummy_node._failmap[peer]["fails"] == 1
    
    # Second fail
    assert dummy_node.start_gossip(peer, {"type": "TEST"}) is False
    assert dummy_node._failmap[peer]["fails"] == 2

def test_send_gossip(dummy_node):
    peers = {("127.0.0.1", 8333), ("127.0.0.1", 8334), ("127.0.0.1", 9999)}
    dummy_node.start_gossip = MagicMock(side_effect=[True, False]) # 9999 is skipped due to port
    
    # One peer is in failmap with high fails and recent ts
    dummy_node._failmap[("127.0.0.1", 8334)] = {"fails": 5, "last": time.time()}
    
    success = dummy_node.send_gossip(peers, {"type": "TEST"}, exclude=("127.0.0.1", 8335))
    
    # 9999 skipped (port), 8334 skipped (failmap), 8333 attempted and succeeds
    assert success == 1
    dummy_node.start_gossip.assert_called_once_with(("127.0.0.1", 8333), {"type": "TEST"})

@patch("tsarchain.network.cast.gossip.Block")
def test_broadcast_block(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.hash.return_value.hex.return_value = "blockhash"
    mock_block.to_storage_bytes.return_value = b"binary_block_bytes"
    
    peers = {("127.0.0.1", 8333)}
    
    mock_send_gossip = patch('tsarchain.network.cast.gossip.GossipHandler.send_gossip', return_value=1).start()
    
    # 1. New block
    assert dummy_node.broadcast_block(mock_block, peers) == 1
    assert "blockhash" in dummy_node.seen_blocks
    mock_send_gossip.assert_called_once()
    sent_msg = mock_send_gossip.call_args[0][1]
    assert sent_msg["type"] == "NEW_BLOCK"
    assert sent_msg["hash"] == "blockhash"
    assert sent_msg["data"] == base64.b64encode(b"binary_block_bytes").decode("ascii")
    
    # 2. Seen block, not forced
    mock_send_gossip.reset_mock()
    assert dummy_node.broadcast_block(mock_block, peers) == 0
    mock_send_gossip.assert_not_called()
    
    # 3. Seen block, forced
    assert dummy_node.broadcast_block(mock_block, peers, force=True) == 1
    mock_send_gossip.assert_called_once()