# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import threading
from unittest.mock import MagicMock, patch

import pytest

from tsarchain.network.node_logic.sync import (
    sync_loop,
    request_sync,
    sync_with_peers,
    handle_block_gap,
    is_caught_up,
    get_best_peer_height,
    _sync_peer,
    _build_locator,
    _request_headers,
    _determine_missing_blocks,
    _download_blocks,
    _apply_block_from_sync,
)


class MockNode:
    def __init__(self):
        self._stop = threading.Event()
        self._sync_event = threading.Event()
        self._sync_fast_until = 0.0
        self.lock = threading.RLock()
        self.outbound_peers = [("127.0.0.1", 8333), ("127.0.0.1", 8334)]
        self.peers = {("127.0.0.1", 8333), ("127.0.0.1", 8334), ("127.0.0.1", 8335)}
        self.peer_scores = {("127.0.0.1", 8333): 10, ("127.0.0.1", 8334): 20, ("127.0.0.1", 8335): 30}
        self.port = 8333
        
        self._last_sync_count = -1
        self._last_sync_log = 0.0
        self._pending_mempool_pull = False
        self._snapshot_unreachable = set()
        self._recent_gap_requests = {}
        self._peer_last_sync = {}
        self._peer_best_height = {("127.0.0.1", 8333): 100, ("127.0.0.1", 8334): 105}

        self.broadcast = MagicMock()
        self.broadcast.lock = threading.RLock()
        self.broadcast.blockchain.height = 100
        
        # We need mock blocks with hash() method
        class MockBlock:
            def __init__(self, h):
                self.height = h
            def hash(self):
                mock_hash = MagicMock()
                mock_hash.hex.return_value = f"hash_{self.height}"
                return mock_hash
                
        self.broadcast.blockchain.chain = [MockBlock(i) for i in range(101)]

    def normalize_peer(self, peer):
        return peer

    def request_mempool_inline(self, peer, force=False):
        return True

    def request_mempool_snapshot(self, peer, force=False):
        return True

    def request_sync(self, fast=False):
        return request_sync(self, fast=fast)

    def penalize_peer(self, peer, amount):
        pass

    def reward_peer(self, peer):
        pass
        
    def rpc_request(self, peer, payload, timeout=None):
        return None

    # Attach unbound functions for testing convenience if needed
    is_caught_up = is_caught_up
    request_sync = request_sync


@pytest.fixture
def mock_node():
    return MockNode()


# ---------------------------------------------------------
# sync_loop tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync.CFG")
@patch("tsarchain.network.node_logic.sync.time.time")
def test_sync_loop_exits(mock_time, mock_cfg, mock_node):
    mock_cfg.SYNC_INTERVAL = 0.1
    mock_cfg.FAST_SYNC_INTERVAL = 0.05
    mock_time.return_value = 1000.0
    mock_node._sync_fast_until = 1001.0
    
    mock_node.sync_with_peers = MagicMock()
    
    def set_stop(*args, **kwargs):
        mock_node._stop.set()
        
    mock_node.sync_with_peers.side_effect = set_stop
    mock_node._sync_event.set()
    
    sync_loop(mock_node)
    
    mock_node.sync_with_peers.assert_called_once()


# ---------------------------------------------------------
# request_sync tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync.time.time")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_request_sync_fast(mock_cfg, mock_time, mock_node):
    mock_time.return_value = 1000.0
    mock_cfg.FAST_SYNC_INTERVAL = 10.0
    mock_node._sync_fast_until = 0.0
    
    request_sync(mock_node, fast=True)
    
    assert mock_node._sync_fast_until == 1010.0
    assert mock_node._sync_event.is_set()


# ---------------------------------------------------------
# sync_with_peers tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync.CFG")
@patch("tsarchain.network.node_logic.sync._sync_peer")
def test_sync_with_peers_success(mock_sync_peer, mock_cfg, mock_node):
    mock_cfg.MAX_OUTBOUND_PEERS = 2
    mock_cfg.SYNC_INFO_MIN_INTERVAL = 10.0
    
    mock_sync_peer.return_value = True
    
    # Needs a mock block chain to be caught up
    mock_node._peer_last_sync = {("127.0.0.1", 8333): time.time()}
    mock_node._peer_best_height = {("127.0.0.1", 8333): 100}
    
    mock_node._pending_mempool_pull = True
    mock_node.request_mempool_inline = MagicMock(return_value=False)
    mock_node.request_mempool_snapshot = MagicMock(return_value=True)
    
    sync_with_peers(mock_node)
    
    assert mock_sync_peer.call_count == 2
    mock_node.request_mempool_snapshot.assert_called()


@patch("tsarchain.network.node_logic.sync.CFG")
@patch("tsarchain.network.node_logic.sync._sync_peer")
def test_sync_with_peers_exception(mock_sync_peer, mock_cfg, mock_node):
    mock_cfg.MAX_OUTBOUND_PEERS = 1
    mock_sync_peer.side_effect = Exception("Test Error")
    mock_node.penalize_peer = MagicMock()
    
    sync_with_peers(mock_node)
    
    mock_node.penalize_peer.assert_called()


# ---------------------------------------------------------
# handle_block_gap tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync._download_blocks")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_handle_block_gap(mock_cfg, mock_download, mock_node):
    mock_cfg.HEADERS_SYNC_MIN_INTERVAL = 5.0
    mock_cfg.HEADERS_FANOUT = 4
    mock_cfg.BLOCK_DOWNLOAD_BATCH_MAX = 50
    mock_cfg.FAST_SYNC_INTERVAL = 10.0
    
    mock_block = MagicMock()
    mock_block.height = 200
    peer = ("127.0.0.1", 8333)
    
    handle_block_gap(mock_node, mock_block, peer)
    
    assert mock_node._sync_event.is_set()
    mock_download.assert_called_once()
    args, _ = mock_download.call_args
    assert args[1] == peer
    assert len(args[2]) == 33  # max(32, 4*2) = 32 span -> 200-32 to 200 is 33 blocks


# ---------------------------------------------------------
# is_caught_up & get_best_peer_height tests
# ---------------------------------------------------------
def test_is_caught_up(mock_node):
    mock_node._peer_last_sync = {("127.0.0.1", 8333): time.time()}
    mock_node._peer_best_height = {("127.0.0.1", 8333): 100}
    mock_node.broadcast.blockchain.height = 100
    
    assert is_caught_up(mock_node) is True
    
    mock_node._peer_best_height = {("127.0.0.1", 8333): 105}
    assert is_caught_up(mock_node, height_slack=2) is False
    assert is_caught_up(mock_node, height_slack=5) is True


def test_get_best_peer_height(mock_node):
    assert get_best_peer_height(mock_node) == 105
    
    mock_node._peer_best_height = {}
    assert get_best_peer_height(mock_node) == -1


# ---------------------------------------------------------
# _sync_peer tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync._build_locator")
@patch("tsarchain.network.node_logic.sync._request_headers")
@patch("tsarchain.network.node_logic.sync._determine_missing_blocks")
@patch("tsarchain.network.node_logic.sync._download_blocks")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_sync_peer_no_headers(
    mock_cfg,
    mock_download,
    mock_determine,
    mock_req_headers,
    mock_build_loc,
    mock_node,
):
    mock_req_headers.return_value = None
    peer = ("127.0.0.1", 8333)
    mock_node.penalize_peer = MagicMock()
    
    assert _sync_peer(mock_node, peer) is False
    mock_node.penalize_peer.assert_called_once()


@patch("tsarchain.network.node_logic.sync._build_locator")
@patch("tsarchain.network.node_logic.sync._request_headers")
@patch("tsarchain.network.node_logic.sync._determine_missing_blocks")
@patch("tsarchain.network.node_logic.sync._download_blocks")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_sync_peer_sync_reject(
    mock_cfg,
    mock_download,
    mock_determine,
    mock_req_headers,
    mock_build_loc,
    mock_node,
):
    mock_req_headers.return_value = {"type": "SYNC_REJECT", "retry_after": 20.0}
    peer = ("127.0.0.1", 8333)
    
    assert _sync_peer(mock_node, peer) is False


@patch("tsarchain.network.node_logic.sync._build_locator")
@patch("tsarchain.network.node_logic.sync._request_headers")
@patch("tsarchain.network.node_logic.sync._determine_missing_blocks")
@patch("tsarchain.network.node_logic.sync._download_blocks")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_sync_peer_success(
    mock_cfg,
    mock_download,
    mock_determine,
    mock_req_headers,
    mock_build_loc,
    mock_node,
):
    mock_cfg.FAST_SYNC_INTERVAL = 10.0
    mock_req_headers.return_value = {"type": "HEADERS", "headers": [{"h": 1}], "more": True}
    mock_determine.return_value = [101]
    peer = ("127.0.0.1", 8333)
    
    assert _sync_peer(mock_node, peer) is True
    mock_download.assert_called_once_with(mock_node, peer, [101])
    assert mock_node._sync_event.is_set()


# ---------------------------------------------------------
# _build_locator tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync.CFG")
def test_build_locator(mock_cfg, mock_node):
    mock_cfg.HEADERS_LOCATOR_DEPTH = 10
    zero_mock = MagicMock()
    zero_mock.hex.return_value = "zero_hash"
    mock_cfg.ZERO_HASH = zero_mock
    
    # mock_node.broadcast.blockchain.chain has 101 blocks
    locator = _build_locator(mock_node)
    
    assert len(locator) <= 11
    assert locator[0] == "hash_100"
    assert "zero_hash" in locator


# ---------------------------------------------------------
# _request_headers tests
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync.CFG")
def test_request_headers(mock_cfg, mock_node):
    mock_cfg.HEADERS_LOCATOR_DEPTH = 10
    mock_cfg.HEADERS_BATCH_MAX = 500
    mock_cfg.SYNC_TIMEOUT = 10.0
    
    mock_node.rpc_request = MagicMock(return_value={"status": "ok"})
    
    res = _request_headers(mock_node, ("127.0.0.1", 8333), ["hash1", "hash2"])
    assert res == {"status": "ok"}
    mock_node.rpc_request.assert_called_once()


# ---------------------------------------------------------
# _determine_missing_blocks tests
# ---------------------------------------------------------
def test_determine_missing_blocks(mock_node):
    headers = [
        {"height": 99, "hash": "hash_99"},  # matches local
        {"height": 100, "hash": "wrong_hash"}, # reorg point
        {"height": 101, "hash": "hash_101"}, # missing
    ]
    missing = _determine_missing_blocks(mock_node, headers)
    
    # Local chain has 101 blocks (0 to 100)
    # Reorg point is 100. Local has 100, so start=100.
    # Max remote is 101. Local length is 101 (idx 100). End = max(101, 100) = 101.
    # Should download 100 and 101.
    assert missing == [100, 101]


# ---------------------------------------------------------
# _download_blocks tests
# ---------------------------------------------------------
# _download_blocks tests (100% binary)
# ---------------------------------------------------------
@patch("tsarchain.network.node_logic.sync._apply_block_from_sync")
@patch("tsarchain.network.node_logic.sync.Block.from_storage_bytes")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_download_blocks_success(mock_cfg, mock_from_storage, mock_apply, mock_node):
    import base64
    import struct
    from tsarchain.core.block import Block

    mock_cfg.BLOCK_DOWNLOAD_BATCH_MAX = 10
    mock_cfg.SYNC_TIMEOUT = 10.0
    peer = ("127.0.0.1", 8333)
    heights = [101, 102]

    b1 = Block(height=101, prev_block_hash=b"\x00" * 32, transactions=[], nonce=1)
    b2 = Block(height=102, prev_block_hash=b"\x00" * 32, transactions=[], nonce=2)
    mock_from_storage.side_effect = [b1, b2]

    raw_payload = (
        struct.pack("<I", len(b"raw1")) + b"raw1" +
        struct.pack("<I", len(b"raw2")) + b"raw2"
    )
    b64_payload = base64.b64encode(raw_payload).decode("ascii")

    mock_node.rpc_request = MagicMock(return_value={
        "type": "BLOCKS_BIN",
        "count": 2,
        "data": b64_payload
    })
    mock_apply.return_value = True

    applied, elapsed = _download_blocks(mock_node, peer, heights)
    assert applied == 2
    assert mock_apply.call_count == 2
    assert mock_from_storage.call_count == 2


@patch("tsarchain.network.node_logic.sync.CFG")
def test_download_blocks_reject(mock_cfg, mock_node):
    mock_cfg.BLOCK_DOWNLOAD_BATCH_MAX = 10
    mock_cfg.SYNC_TIMEOUT = 10.0
    peer = ("127.0.0.1", 8333)
    heights = [101]
    
    mock_node.rpc_request = MagicMock(return_value={
        "type": "SYNC_REJECT",
        "retry_after": 20.0
    })
    
    applied, elapsed = _download_blocks(mock_node, peer, heights)
    assert applied == 0


@patch("tsarchain.network.node_logic.sync._apply_block_from_sync")
@patch("tsarchain.network.node_logic.sync.Block.from_storage_bytes")
@patch("tsarchain.network.node_logic.sync.CFG")
def test_download_blocks_reorg_mismatch(mock_cfg, mock_from_storage, mock_apply, mock_node):
    import base64
    import struct
    from tsarchain.core.block import Block

    mock_cfg.BLOCK_DOWNLOAD_BATCH_MAX = 10
    mock_cfg.SYNC_TIMEOUT = 10.0
    peer = ("127.0.0.1", 8333)
    heights = [100]  # Local chain already has height 100 with "hash_100"

    b_diff = Block(height=100, prev_block_hash=b"\x00" * 32, transactions=[], nonce=999)
    mock_from_storage.return_value = b_diff

    raw_payload = struct.pack("<I", len(b"raw")) + b"raw"
    b64_payload = base64.b64encode(raw_payload).decode("ascii")

    mock_node.rpc_request = MagicMock(return_value={
        "type": "BLOCKS_BIN",
        "count": 1,
        "data": b64_payload
    })
    mock_apply.return_value = False
    mock_node.request_sync = MagicMock()
    
    applied, elapsed = _download_blocks(mock_node, peer, heights)
    assert applied == 0
    mock_node.request_sync.assert_called_once_with(fast=True)


# ---------------------------------------------------------
# _apply_block_from_sync tests
# ---------------------------------------------------------
def test_apply_block_from_sync(mock_node):
    mock_node.broadcast.receive_block = MagicMock(return_value=True)
    res = _apply_block_from_sync(mock_node, {"hash": "test"}, ("127.0.0.1", 8333))
    assert res is True
    mock_node.broadcast.receive_block.assert_called_once()
