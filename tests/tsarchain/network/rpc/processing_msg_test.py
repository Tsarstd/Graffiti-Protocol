# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from tsarchain.network.rpc.processing_msg import (
    process_message,
    _overlay_realtime_mempool_stats,
    _choose_relay_route,
    _relay_chain,
    _send_chat_relay
)

@pytest.fixture
def mock_config():
    with patch("tsarchain.network.rpc.processing_msg.CFG") as mock_cfg:
        mock_cfg.BAN_MALICIOUS_RPC = True
        yield mock_cfg

@pytest.fixture
def network():
    net = MagicMock()
    net.peer_pubkeys = {"miner1": "pub1"}
    net.storage_peers = {
        ("127.0.0.1", 1234): {"node_id": "stor1"}
    }
    
    class DummyLock:
        def __enter__(self): pass
        def __exit__(self, *args): pass
    net.lock = DummyLock()
    
    net.peers = [("1.1.1.1", 1), ("2.2.2.2", 2), ("3.3.3.3", 3)]
    return net


def test_process_message_invalid_format(network):
    # Not a dict
    assert process_message(network, "not_dict", ("127.0.0.1", 1234)) == {"error": "invalid message: expected JSON object"}
    
    # Missing type
    assert process_message(network, {}, ("127.0.0.1", 1234)) == {"error": "missing or invalid 'type'"}
    
    # Invalid type
    assert process_message(network, {"type": 123}, ("127.0.0.1", 1234)) == {"error": "missing or invalid 'type'"}


@patch("tsarchain.network.rpc.processing_msg.ban_ip")
def test_process_message_unknown_type(mock_ban, network, mock_config):
    msg = {"type": "UNKNOWN_TYPE"}
    res = process_message(network, msg, ("192.168.1.1", 1234))
    assert res == {"error": "unknown type", "drop": True}
    mock_ban.assert_not_called()

    # Without tuple addr
    mock_ban.reset_mock()
    res2 = process_message(network, msg, "not_tuple")
    assert res2 == {"error": "unknown type", "drop": True}
    mock_ban.assert_not_called()


@patch("tsarchain.network.rpc.processing_msg.ban_ip")
def test_process_message_unauthorized_miner(mock_ban, network, mock_config):
    # mtype NEW_BLOCK is MINER type but not in BOOTSTRAP_MINER_ALLOW
    # Sender is not a miner (no src_node_id)
    msg = {"type": "NEW_BLOCK"}
    res = process_message(network, msg, ("192.168.1.1", 1234))
    assert res == {"error": "forbidden: miners-only endpoint", "drop": True}
    mock_ban.assert_called_once_with("192.168.1.1", True)

    # Sender has node_id but not in peer_pubkeys
    mock_ban.reset_mock()
    res2 = process_message(network, msg, ("192.168.1.1", 1234), src_node_id="unknown_miner")
    assert res2 == {"error": "forbidden: miners-only endpoint", "drop": True}
    
    # Sender has correct node_id but wrong pubkey
    mock_ban.reset_mock()
    res3 = process_message(network, msg, ("192.168.1.1", 1234), src_node_id="miner1", src_pubkey="wrong_pub")
    assert res3 == {"error": "forbidden: miners-only endpoint", "drop": True}


@patch("tsarchain.network.rpc.processing_msg.handle_miner_rpc")
def test_process_message_miner_success(mock_handle, network):
    mock_handle.return_value = {"ok": True}
    
    # Bootstrap mtype doesn't need miner auth
    msg = {"type": "HELLO", "client": "client_miner"}
    res = process_message(network, msg, ("127.0.0.1", 1234))
    assert res == {"ok": True}
    assert msg["rpc_source"] == "client_miner"
    mock_handle.assert_called_once()

    mock_handle.reset_mock()
    # Non-bootstrap miner type, needs auth
    msg2 = {"type": "NEW_BLOCK"}
    res2 = process_message(network, msg2, ("127.0.0.1", 1234), src_node_id="miner1", src_pubkey="pub1")
    assert res2 == {"ok": True}
    assert msg2["rpc_source"] == "miner"
    mock_handle.assert_called_once()
    
    # Also valid auth without src_pubkey provided
    mock_handle.reset_mock()
    msg3 = {"type": "NEW_BLOCK"}
    res3 = process_message(network, msg3, ("127.0.0.1", 1234), src_node_id="miner1")
    assert res3 == {"ok": True}


@patch("tsarchain.network.rpc.processing_msg.handle_storage_rpc")
def test_process_message_storage(mock_handle, network):
    mock_handle.return_value = {"ok": True}
    
    # Normal user sending storage RPC (falls into storage_rpc which will do its own auth later)
    msg = {"type": "GRAFFITI_PROOF_SUBMIT"}
    res = process_message(network, msg, ("127.0.0.1", 1234))
    assert res == {"ok": True}
    assert msg["rpc_source"] == "storage"
    mock_handle.assert_called_once()
    
    # Storage sender (sets rpc_source = storage_node)
    mock_handle.reset_mock()
    msg2 = {"type": "GRAFFITI_PROOF_SUBMIT"}
    res2 = process_message(network, msg2, ("127.0.0.1", 1234), src_node_id="stor1")
    assert msg2["rpc_source"] == "storage_node"
    assert res2 == {"ok": True}

    # When src_node_id is not in storage_peers
    network.storage_peers = {}
    msg3 = {"type": "GRAFFITI_PROOF_SUBMIT"}
    res3 = process_message(network, msg3, ("127.0.0.1", 1234), src_node_id="stor1")
    assert msg3["rpc_source"] == "storage"


@patch("tsarchain.network.rpc.processing_msg.handle_user_rpc")
def test_process_message_user(mock_handle, network):
    mock_handle.return_value = {"ok": True}
    msg = {"type": "PING", "source": "  Val!d_SoUrce@#  "}
    
    res = process_message(network, msg, ("127.0.0.1", 1234))
    assert res == {"ok": True}
    assert msg["rpc_source"] == "vald_source" # sanitized

    # Empty rpc_source defaults
    msg2 = {"type": "PING", "rpc_source": "!!@@"}
    res2 = process_message(network, msg2, ("127.0.0.1", 1234))
    assert msg2["rpc_source"] == "user"
    
    # Empty after strip
    msg_empty = {"type": "PING", "rpc_source": "   "}
    process_message(network, msg_empty, ("127.0.0.1", 1234))
    assert msg_empty["rpc_source"] == "user"
    
    # Truncated rpc_source
    msg_trunc = {"type": "PING", "rpc_source": "a" * 50}
    process_message(network, msg_trunc, ("127.0.0.1", 1234))
    assert msg_trunc["rpc_source"] == "a" * 32
    
    # Test dispatch result is None
    mock_handle.return_value = None
    res3 = process_message(network, {"type": "PING"}, ("127.0.0.1", 1234))
    assert res3 == {"error": "Unknown message type"}

    # Test CHAT_CHECK_PREKEYS is in USER_RPC_TYPES and dispatched to user_rpc
    mock_handle.return_value = {"type": "CHAT_PREKEYS_STATUS"}
    res_chat = process_message(network, {"type": "CHAT_CHECK_PREKEYS", "address": "tsar1qtest"}, ("127.0.0.1", 1234))
    assert res_chat == {"type": "CHAT_PREKEYS_STATUS"}


def test_overlay_realtime_mempool_stats(network):
    # Invalid snapshot
    _overlay_realtime_mempool_stats(None, network)
    _overlay_realtime_mempool_stats("not_dict", network)

    # No broadcast/mempool
    network.broadcast = None
    snap = {}
    _overlay_realtime_mempool_stats(snap, network)
    assert snap == {"transactions": {}}

    # Tx section is not dict
    snap2 = {"transactions": "not_dict"}
    _overlay_realtime_mempool_stats(snap2, network)
    assert snap2 == {"transactions": "not_dict"}

    # Mempool with store list
    network.broadcast = MagicMock()
    network.broadcast.mempool._pool = ["tx1", "tx2", "tx3"]
    network.broadcast.mempool.current_size = 500
    
    tx_mock = MagicMock()
    tx_mock.outputs = [MagicMock(script_pubkey=b"graffiti_spk")]
    
    # Add a tx_mock2 without outputs or script_pubkey to cover branches
    tx_mock2 = MagicMock()
    tx_mock2.outputs = [MagicMock(script_pubkey=None)]
    
    network.broadcast.mempool.get_all_txs.return_value = [tx_mock, tx_mock, tx_mock2]

    with patch("tsarchain.network.rpc.processing_msg.GRAFFITI.parse_from_script") as mock_parse:
        mock_parse.return_value = {"event": "post"}
        snap3 = {}
        _overlay_realtime_mempool_stats(snap3, network)
        assert snap3["transactions"]["mempool_txs"] == 3
        assert snap3["transactions"]["mempool_vbytes_estimate"] == 500
        assert snap3["graffiti"]["graffiti_on_mempool"] == 2 # mock_parse not called for tx_mock2 due to spk=None

    # Mempool with store dict
    network.broadcast.mempool._pool = {"tx1": "t1"}
    snap4 = {}
    with patch("tsarchain.network.rpc.processing_msg.GRAFFITI.parse_from_script") as mock_parse:
        mock_parse.return_value = None
        _overlay_realtime_mempool_stats(snap4, network)
        assert snap4["transactions"]["mempool_txs"] == 1
        assert snap4["graffiti"]["graffiti_on_mempool"] == 0
        
    # Graffiti section is not a dict
    snap5 = {"graffiti": "not_dict"}
    _overlay_realtime_mempool_stats(snap5, network)
    assert snap5["graffiti"] == "not_dict"


def test_choose_relay_route(network):
    route = _choose_relay_route(network, hops=2)
    assert len(route) == 2
    for r in route:
        assert r in network.peers


def test_relay_chain(network):
    # Empty route
    assert _relay_chain(network, [], {}) is None

    # Normal route
    network._send_chat_relay = MagicMock()
    _relay_chain(network, [("1.1.1.1", 1), ("2.2.2.2", 2)], {"test": 1})
    network._send_chat_relay.assert_called_once_with(("1.1.1.1", 1), {"type": "CHAT_RELAY", "route": [("2.2.2.2", 2)], "inner": {"test": 1}})


def test_send_chat_relay(network):
    network.send_to_peer = MagicMock()
    res = _send_chat_relay(network, ("1.1.1.1", 1), {"test": 1})
    assert res == {"status": "ok"}
    network.send_to_peer.assert_called_once_with(("1.1.1.1", 1), {"test": 1})
    
    # Exception
    network.send_to_peer.side_effect = Exception("error")
    res2 = _send_chat_relay(network, ("1.1.1.1", 1), {"test": 1})
    assert res2 == {"status": "error"}
