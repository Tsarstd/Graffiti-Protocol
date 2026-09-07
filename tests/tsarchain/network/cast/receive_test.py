# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import base64
import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.cast.receive import ReceiveHandler
from tsarchain.core.tx import TxOut
from tsarchain.utils.helpers import Script, OP_0

class DummyNode(ReceiveHandler):
    def __init__(self):
        self.lock = MagicMock()
        self.blockchain = MagicMock()
        self.mempool = MagicMock()
        self.utxodb = MagicMock()
        self.network = MagicMock()
        self.seen_blocks = set()
        self._processing_blocks = set()
        self.seen_txs = set()
        self.state = {}
        self._utxo_shared = False
        self.broadcast_block = MagicMock()
        self.broadcast_tx_fluff = MagicMock()
        self.calc_chainwork_from_list = MagicMock(return_value=100)
        self.validate_incoming_chain = MagicMock(return_value=True)
        self.rebuild_utxo_from_chain_locked = MagicMock()
        self.maybe_flush_local_utxo = MagicMock()
        self.dandelion = MagicMock()
        self.dandelion.enabled.return_value = False

@pytest.fixture
def dummy_node():
    return DummyNode()

def test_log_block_reject(dummy_node):
    with patch("tsarchain.network.cast.receive.log") as mock_log:
        dummy_node._log_block_reject(
            stage="test_stage",
            block_id="1234567890abcdef1234567890abcdef",
            height=100,
            peer="1.2.3.4",
            reason="test_reason",
            extra={"foo": "bar"}
        )
        assert mock_log.warning.called
        args, kwargs = mock_log.warning.call_args
        assert "[_log_block_reject] stage=%s" in args[0]
        assert args[1] == "test_stage"
        assert args[2] == 100
        assert args[3] == "1234567890abcdef"
        assert args[4] == "1.2.3.4"
        assert args[5] == "test_reason"
        assert args[6] == {"foo": "bar"}

def test_native_script_bytes():
    assert ReceiveHandler._native_script_bytes(None) is None
    
    mock_obj = MagicMock()
    mock_obj.serialize.return_value = b"\xaa\xbb"
    assert ReceiveHandler._native_script_bytes(mock_obj) == b"\xaa\xbb"
    
    mock_wrapper = MagicMock()
    mock_wrapper.serialize = None
    mock_inner = MagicMock()
    mock_inner.serialize.return_value = b"\x11\x22\x33"
    mock_wrapper.script_pubkey = mock_inner
    assert ReceiveHandler._native_script_bytes(mock_wrapper) == b"\x11\x22\x33"

    # Real TxOut instance test (no serialize method on TxOut itself)
    real_script = Script([OP_0, b"\x12" * 20])
    real_txout = TxOut(amount=5000, script_pubkey=real_script)
    assert ReceiveHandler._native_script_bytes(real_txout) == real_script.serialize()

def test_normalize_native_prevout(dummy_node):
    # Test with real TxOut in dict entry (matching production UTXODB lookup_entry)
    real_script = Script([OP_0, b"\x34" * 20])
    real_txout = TxOut(amount=7777, script_pubkey=real_script)
    real_entry = {
        "tx_out": real_txout,
        "is_coinbase": False,
        "block_height": 21,
    }
    res = dummy_node._normalize_native_prevout(real_entry)
    assert res == (7777, real_script.serialize(), False, 21)

    mock_spk1 = MagicMock()
    mock_spk1.serialize.return_value = b"\xaa\xbb\xcc"
    mock_tx_out1 = MagicMock()
    mock_tx_out1.amount = 1000
    mock_tx_out1.script_pubkey = mock_spk1
    mock_entry1 = MagicMock()
    mock_entry1.tx_out = mock_tx_out1
    mock_entry1.is_coinbase = True
    mock_entry1.block_height = 50

    result = dummy_node._normalize_native_prevout(mock_entry1)
    assert result == (1000, b"\xaa\xbb\xcc", True, 50)
    
    mock_spk2 = MagicMock()
    mock_spk2.serialize.return_value = b"\xdd\xee"
    mock_tx_out2 = MagicMock()
    mock_tx_out2.amount = 2000
    mock_tx_out2.script_pubkey = mock_spk2
    mock_entry2 = MagicMock()
    mock_entry2.tx_out = mock_tx_out2
    mock_entry2.is_coinbase = False
    mock_entry2.block_height = 100
    
    result = dummy_node._normalize_native_prevout(mock_entry2)
    assert result == (2000, b"\xdd\xee", False, 100)
    
    mock_invalid = MagicMock()
    mock_invalid.tx_out = None
    mock_invalid.script_pubkey = None
    mock_invalid.serialize = None
    assert dummy_node._normalize_native_prevout(mock_invalid) is None

def test_build_native_prevout_snapshot(dummy_node):
    mock_block = MagicMock()
    mock_tx1 = MagicMock()
    mock_tx1.is_coinbase = True
    txid1 = "1111111111111111111111111111111111111111111111111111111111111111"
    mock_tx1.txid = txid1
    
    mock_tx2 = MagicMock()
    mock_tx2.is_coinbase = False
    txid2 = "2222222222222222222222222222222222222222222222222222222222222222"
    mock_tx2.txid = txid2
    
    mock_input = MagicMock()
    prev_txid = "3333333333333333333333333333333333333333333333333333333333333333"
    mock_input.txid = prev_txid
    mock_input.vout = 0
    mock_tx2.inputs = [mock_input]
    
    mock_block.transactions = [mock_tx1, mock_tx2]
    
    mock_spk = MagicMock()
    mock_spk.serialize.return_value = b"\x00"
    mock_tx_out = MagicMock()
    mock_tx_out.amount = 500
    mock_tx_out.serialize = None
    mock_tx_out.script_pubkey = mock_spk
    mock_entry = MagicMock()
    mock_entry.tx_out = mock_tx_out
    mock_entry.is_coinbase = False
    mock_entry.block_height = 10
    dummy_node.utxodb.lookup_entry.return_value = mock_entry
    
    snapshot, utxo_items = dummy_node._build_native_prevout_snapshot(mock_block)
    
    key = f"{prev_txid}:0"
    assert key in snapshot
    assert snapshot[key]["amount"] == 500
    assert snapshot[key]["script_pubkey"] == b"\x00"
    
    assert len(utxo_items) == 1
    assert utxo_items[0] == (bytes.fromhex(prev_txid), 0, 500, b"\x00", False, 10)

def test_native_precheck_block(dummy_node):
    mock_block = MagicMock()
    mock_block.hash.return_value = b"\x00" * 32
    # If snapshot is None, it returns True
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=None):
        assert dummy_node._native_precheck_block(mock_block) is True

    # Test with valid snapshot but native_validate_block_txs fails
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=({}, None)):
        with patch("tsarchain.network.cast.receive.native_validate_block_txs", return_value=(False, "error", [])):
            assert dummy_node._native_precheck_block(mock_block) is False

    # Test with valid snapshot and native_validate_block_txs succeeds
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=({}, None)):
        with patch("tsarchain.network.cast.receive.native_validate_block_txs", return_value=(True, "", [100])):
            assert dummy_node._native_precheck_block(mock_block) is True
            assert mock_block._native_fee_hint == [100]

def test_receive_block_empty(dummy_node):
    assert dummy_node.receive_block({}, ("127.0.0.1", 8333), set()) is False

def test_receive_block_already_seen(dummy_node):
    h = "a" * 64
    dummy_node.seen_blocks.add(h)
    
    msg = {"hash": h, "data": "dummy"}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True
    
    dummy_node.blockchain.add_block.assert_not_called()

def test_receive_block_legacy_dict_rejected(dummy_node):
    msg = {"data": {"height": 10, "hash": "abc"}}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is False

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_success(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.transactions = []
    mock_block.hash.return_value.hex.return_value = "newhash"
    mock_block_class.from_storage_bytes.return_value = mock_block
    
    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "prevhash"
    mock_block.prev_block_hash = "prevhash"
    
    dummy_node.blockchain.validate_block.return_value = True
    dummy_node.blockchain.add_block.return_value = True
    
    with patch.object(dummy_node, "_native_precheck_block", return_value=True):
        raw = base64.b64encode(b"raw_block_bytes").decode("ascii")
        msg = {"data": raw}
        assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True
        
        dummy_node.blockchain.add_block.assert_called_once_with(mock_block)
        dummy_node.mempool.flush.assert_called()
        dummy_node.broadcast_block.assert_called_once()

def test_receive_tx_already_seen(dummy_node):
    tx = MagicMock()
    tx.txid.hex.return_value = "txhash"
    dummy_node.seen_txs.add("txhash")
    
    msg = {"data": tx}
    assert dummy_node.receive_tx(msg, ("127.0.0.1", 8333), set()) is False

def test_receive_tx_success(dummy_node):
    tx = MagicMock()
    tx.txid.hex.return_value = "txhash"
    
    dummy_node.mempool.add_valid_tx.return_value = True
    
    msg = {"data": tx}
    assert dummy_node.receive_tx(msg, ("127.0.0.1", 8333), set()) is True
    
    dummy_node.mempool.add_valid_tx.assert_called_once_with(tx)
    dummy_node.broadcast_tx_fluff.assert_called_once()

def test_receive_mempool(dummy_node):
    dummy_node.blockchain.height = 100
    dummy_node.network.is_caught_up.return_value = True
    
    tx1 = MagicMock()
    tx2 = MagicMock()
    dummy_node.mempool.add_valid_tx.side_effect = [True, False]
    dummy_node.mempool.recheck_orphans = MagicMock(return_value=1)
    
    dummy_node.receive_mempool({"data": [tx1, tx2]})
    
    assert dummy_node.mempool.add_valid_tx.call_count == 2
    dummy_node.mempool.flush.assert_called_once()

def test_build_native_prevout_snapshot_no_lookup(dummy_node):
    dummy_node.utxodb.lookup_entry = None
    mock_block = MagicMock()
    assert dummy_node._build_native_prevout_snapshot(mock_block) is None

def test_build_native_prevout_snapshot_empty_txs(dummy_node):
    mock_block = MagicMock()
    mock_block.transactions = []
    assert dummy_node._build_native_prevout_snapshot(mock_block) == {}

def test_native_precheck_block_compact_validation(dummy_node):
    mock_block = MagicMock()
    mock_block.hash.return_value = b"\x00" * 32
    mock_block.height = 10
    
    mock_tx = MagicMock()
    mock_tx.version = 1
    mock_tx.locktime = 0
    mock_tx.is_coinbase = False
    mock_tx.txid = b"A" * 32
    
    mock_input = MagicMock()
    mock_input.txid = b"B" * 32
    mock_input.vout = 0
    mock_input.sequence = 0xffffffff
    mock_input.witness = [b"wit"]
    mock_tx.inputs = [mock_input]
    
    mock_spk = MagicMock()
    mock_spk.serialize.return_value = b"spk"
    mock_out = MagicMock()
    mock_out.amount = 100
    mock_out.serialize = None
    mock_out.script_pubkey = mock_spk
    mock_tx.outputs = [mock_out]
    
    mock_block.transactions = [mock_tx]
    
    utxo_items = [(b"B"*32, 0, 100, b"spk", False, 5)]
    snapshot = ({"key": "val"}, utxo_items)
    
    with patch.object(dummy_node, "_build_native_prevout_snapshot", return_value=snapshot):
        with patch("tsarchain.network.cast.receive.native_validate_block_txs_compact", return_value=(True, "", [50])):
            assert dummy_node._native_precheck_block(mock_block) is True

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_gap(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 20
    mock_block.hash.return_value.hex.return_value = "newhash"
    mock_block_class.from_storage_bytes.return_value = mock_block
    
    dummy_node.blockchain.get_last_block.return_value.height = 10
    
    raw = base64.b64encode(b"raw_block_bytes").decode("ascii")
    msg = {"data": raw}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), {("127.0.0.1", 8333)}) is False
    dummy_node.network.handle_block_gap.assert_called_once()

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_validation_fails_prevout(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.hash.return_value.hex.return_value = "newhash"
    mock_block.prev_block_hash = "prevhash"
    mock_block_class.from_storage_bytes.return_value = mock_block
    
    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "prevhash"
    
    patch('tsarchain.network.cast.receive.ReceiveHandler._native_precheck_block', return_value=True).start()
    dummy_node.blockchain.validate_block.return_value = False
    dummy_node.blockchain._last_block_validation_error = "prevout_missing: xyz"
    
    raw = base64.b64encode(b"raw_block_bytes").decode("ascii")
    msg = {"data": raw}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), {("127.0.0.1", 8333)}) is False

@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_add_block_exception_swap_tip(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.hash.return_value.hex.return_value = "newhash"
    mock_block.prev_block_hash = "parent_hash"
    mock_block_class.from_storage_bytes.return_value = mock_block
    
    parent_block = MagicMock()
    parent_block.height = 9
    parent_block.hash.return_value = "parent_hash"
    
    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "parent_hash"
    dummy_node.blockchain.chain = [parent_block, MagicMock()]
    
    patch('tsarchain.network.cast.receive.ReceiveHandler._native_precheck_block', return_value=True).start()
    dummy_node.blockchain.validate_block.return_value = True
    dummy_node.blockchain.add_block.side_effect = Exception("db_error")
    dummy_node.blockchain.swap_tip_if_better.return_value = MagicMock(transactions=[])
    
    raw = base64.b64encode(b"raw_block_bytes").decode("ascii")
    msg = {"data": raw}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), {("127.0.0.1", 8333)}) is True
    dummy_node.blockchain.swap_tip_if_better.assert_called_once()

def test_receive_tx_dandelion_stem_declined(dummy_node):
    tx = MagicMock()
    tx.txid.hex.return_value = "txhash"
    dummy_node.mempool.add_valid_tx.return_value = True
    dummy_node.dandelion.enabled.return_value = True
    dummy_node.dandelion.handle_inbound_stem.return_value = False # Declined
    
    msg = {"data": tx, "phase": "stem"}
    assert dummy_node.receive_tx(msg, ("127.0.0.1", 8333), set()) is True
    dummy_node.dandelion.handle_inbound_stem.assert_called_once()
    dummy_node.broadcast_tx_fluff.assert_called_once()

def test_receive_mempool_not_caught_up(dummy_node):
    dummy_node.network.is_caught_up.return_value = False
    dummy_node.receive_mempool({"data": []})
    dummy_node.network.request_sync.assert_called_once_with(fast=True)


@patch("tsarchain.network.cast.receive.Block")
def test_receive_block_raw_bytes(mock_block_class, dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.transactions = []
    mock_block.hash.return_value.hex.return_value = "byteshash"
    mock_block_class.from_storage_bytes.return_value = mock_block

    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "prevhash"
    mock_block.prev_block_hash = "prevhash"

    dummy_node.blockchain.validate_block.return_value = True
    dummy_node.blockchain.add_block.return_value = True

    with patch.object(dummy_node, "_native_precheck_block", return_value=True):
        msg = {"data": b"raw_block_bytes"}
        assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True
        mock_block_class.from_storage_bytes.assert_called_once_with(b"raw_block_bytes")


def test_receive_block_block_instance(dummy_node):
    mock_block = MagicMock()
    mock_block.height = 10
    mock_block.transactions = []
    mock_block.hash.return_value.hex.return_value = "instancehash"

    dummy_node.blockchain.get_last_block.return_value.height = 9
    dummy_node.blockchain.get_last_block.return_value.hash.return_value = "prevhash"
    mock_block.prev_block_hash = "prevhash"

    dummy_node.blockchain.validate_block.return_value = True
    dummy_node.blockchain.add_block.return_value = True

    with patch.object(dummy_node, "_native_precheck_block", return_value=True):
        # When type(block_data) is Block (e.g. from sync)
        with patch("tsarchain.network.cast.receive.Block", new=type(mock_block)):
            msg = {"data": mock_block}
            assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is True


def test_receive_block_corrupt_data(dummy_node):
    msg = {"data": "not_valid_base64!!!"}
    assert dummy_node.receive_block(msg, ("127.0.0.1", 8333), set()) is False

