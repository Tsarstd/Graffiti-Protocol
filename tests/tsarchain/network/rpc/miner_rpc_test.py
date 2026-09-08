# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.rpc.miner_rpc import handle_miner_rpc

@pytest.fixture(autouse=True)
def mock_config():
    with patch("tsarchain.network.rpc.miner_rpc.CFG") as mock_cfg:
        mock_cfg.DEBUG_BENCHMARKS = False
        mock_cfg.REPLAY_WINDOW_SEC = 60
        
        # New Block RL
        mock_cfg.MINER_NEWBLOCK_RL_IP_BURST = 10
        mock_cfg.MINER_NEWBLOCK_RL_WINDOW_S = 60
        mock_cfg.MINER_NEWBLOCK_RL_BACKOFF_S = 10
        
        # Info RL (HELLO, GET_INFO, GET_BLOCK_HASH)
        mock_cfg.MINER_INFO_RL_IP_BURST = 10
        mock_cfg.MINER_INFO_RL_WINDOW_S = 60
        mock_cfg.MINER_INFO_RL_BACKOFF_S = 10
        
        # Headers RL
        mock_cfg.MINER_HEADERS_RL_IP_BURST = 10
        mock_cfg.MINER_HEADERS_RL_WINDOW_S = 60
        mock_cfg.MINER_HEADERS_RL_BACKOFF_S = 10
        
        # Blocks RL
        mock_cfg.MINER_BLOCKS_RL_IP_BURST = 10
        mock_cfg.MINER_BLOCKS_RL_WINDOW_S = 60
        mock_cfg.MINER_BLOCKS_RL_BACKOFF_S = 10
        
        # Mempool RL
        mock_cfg.MINER_MEMPOOL_RL_IP_BURST = 10
        mock_cfg.MINER_MEMPOOL_RL_WINDOW_S = 60
        mock_cfg.MINER_MEMPOOL_RL_BACKOFF_S = 10
        
        yield mock_cfg


@pytest.fixture
def network():
    net = MagicMock()
    net.rl_ip = {}
    net.backoff_until = {}
    net.tb_node_allow.return_value = True
    net._nonce_guard.return_value = True
    
    # Broadcast mocks
    net.broadcast.receive_block = MagicMock()
    net.broadcast.receive_mempool = MagicMock()
    
    # Chain state mocks for GET_INFO
    net.broadcast.blockchain.height = 100
    net.broadcast.blockchain.chain = [1] * 101
    net.broadcast.mempool._pool = {1: 1, 2: 2, 3: 3}
    net.broadcast.mempool.get_all_txs.return_value = [1, 2, 3]
    net.broadcast.utxodb.utxos = {1: 1, 2: 2}
    
    # Peers mock
    net.peers = {("127.0.0.1", 8333), ("192.168.1.1", 0), ("10.0.0.1", -1), ("1.1.1.1", "bad")}
    
    # Get Block Hash Mock
    net.handle_get_block_hash.return_value = {"hash": "abc", "cache_hit": True}
    
    return net


def test_unknown_mtype(network):
    res = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "UNKNOWN")
    assert res is None


@patch("tsarchain.network.rpc.miner_rpc.handlers.handle_hello")
def test_hello(mock_handle_hello, network):
    mock_handle_hello.return_value = {"status": "ok"}
    res = handle_miner_rpc(network, {"test": 1}, ("127.0.0.1", 1234), "HELLO", src_node_id="n1", src_pubkey="p1")
    assert res == {"status": "ok"}
    mock_handle_hello.assert_called_once_with(network, {"test": 1}, ("127.0.0.1", 1234), src_node_id="n1", src_pubkey="p1")

    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {"test": 1}, ("127.0.0.1", 1234), "HELLO")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}


def test_new_block(network, mock_config):
    # Success
    res = handle_miner_rpc(network, {"block": 1}, ("127.0.0.1", 1234), "NEW_BLOCK")
    assert res == {"status": "ok"}
    network.broadcast.receive_block.assert_called_once_with({"block": 1}, ("127.0.0.1", 1234), set(network.peers))
    
    # Test non-tuple addr and empty tuple
    res2 = handle_miner_rpc(network, {"block": 2}, None, "NEW_BLOCK")
    assert res2 == {"status": "ok"}
    res_empty_addr = handle_miner_rpc(network, {"block": 3}, (), "NEW_BLOCK")
    assert res_empty_addr == {"status": "ok"}
    
    # Rate limited
    network.tb_node_allow.return_value = False
    res3 = handle_miner_rpc(network, {"block": 1}, ("127.0.0.1", 1234), "NEW_BLOCK")
    assert res3 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}
    network.backoff_node.assert_called_once()


def test_get_block_hash(network, mock_config):
    res = handle_miner_rpc(network, {"height": 10}, ("127.0.0.1", 1234), "GET_BLOCK_HASH")
    assert res == {"hash": "abc", "cache_hit": True}
    network.handle_get_block_hash.assert_called_once_with(10)
    
    # Missing height
    res_missing = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_BLOCK_HASH")
    assert res_missing == {"type": "BLOCK_HASH", "error": "missing_height"}

    # Invalid height string
    res_invalid = handle_miner_rpc(network, {"height": "invalid_num"}, ("127.0.0.1", 1234), "GET_BLOCK_HASH")
    assert res_invalid == {"type": "BLOCK_HASH", "error": "invalid_height"}

    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {"height": 10}, ("127.0.0.1", 1234), "GET_BLOCK_HASH")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}


def test_get_info(network, mock_config):
    res = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_INFO")
    assert res["type"] == "INFO"
    assert res["height"] == 100
    assert res["blocks"] == 101
    assert res["mempool"] == 3
    assert res["utxos"] == 2
    assert res["peers"] == 1
    
    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_INFO")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}


@patch("tsarchain.network.rpc.miner_rpc.handlers.handle_get_headers")
def test_get_headers(mock_handler, network):
    mock_handler.return_value = {"ok": True}
    res = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_HEADERS")
    assert res == {"ok": True}
    
    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_HEADERS")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}


@patch("tsarchain.network.rpc.miner_rpc.handlers.handle_get_blocks")
def test_get_blocks(mock_handler, network):
    mock_handler.return_value = {"ok": True}
    res = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_BLOCKS")
    assert res == {"ok": True}
    
    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "GET_BLOCKS")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}


def test_mempool(network, mock_config):
    res = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "MEMPOOL")
    assert res == {"status": "mempool received"}
    network.broadcast.receive_mempool.assert_called_once_with({})
    
    # Rate limited
    network.tb_node_allow.return_value = False
    res2 = handle_miner_rpc(network, {}, ("127.0.0.1", 1234), "MEMPOOL")
    assert res2 == {"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}