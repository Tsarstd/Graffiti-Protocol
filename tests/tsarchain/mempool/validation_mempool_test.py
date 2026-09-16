# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from tsarchain.core.tx import Tx
from unittest.mock import MagicMock, patch
from tsarchain.mempool.validation import TxMempoolValidator

class DummyScript:
    def __init__(self, data):
        self.data = data
    def serialize(self):
        return self.data

class TestTxMempoolValidator:
    @pytest.fixture
    def validator(self):
        v = TxMempoolValidator()
        v.utxo = MagicMock()
        v.last_error_reason = None
        v._pool = {}
        return v

    def test_script_to_address(self, validator):
        assert validator._script_to_address(None) is None
        assert validator._script_to_address(DummyScript(b"")) is None
        assert validator._script_to_address(DummyScript(b"deadbeef")) is None
        
        # P2WPKH: 0x00 0x14 + 20 bytes
        p2wpkh_bytes = b'\x00\x14' + b'\x01' * 20
        addr1 = validator._script_to_address(DummyScript(p2wpkh_bytes))
        assert addr1 is not None

        # P2WSH: 0x00 0x20 + 32 bytes
        p2wsh_bytes = b'\x00\x20' + b'\x02' * 32
        addr2 = validator._script_to_address(DummyScript(p2wsh_bytes))
        assert addr2 is not None

        # object with serialize
        assert validator._script_to_address(DummyScript(p2wpkh_bytes)) == addr1

    def test_get_utxo_amount(self, validator):
        assert validator._get_utxo_amount({"amount": 100}) == 100
        assert validator._get_utxo_amount({"tx_out": {"amount": 200}}) == 200
        assert validator._get_utxo_amount({"tx_out": MagicMock(amount=300)}) == 300
        
        mock_obj = MagicMock()
        mock_obj.amount = 400
        assert validator._get_utxo_amount(mock_obj) == 400
        
        with pytest.raises((ValueError, AttributeError)):
            validator._get_utxo_amount("invalid")

    def test_txin_prev_txid(self, validator):
        tx_in = MagicMock()
        tx_in.txid = None
        tx_in.prev_tx = b'\xaa' * 32
        assert validator._txin_prev_txid(tx_in) == (b'\xaa' * 32).hex()

        tx_in.txid = "SOME_TXID"
        assert validator._txin_prev_txid(tx_in) == "some_txid"

        tx_in.txid = None
        tx_in.prev_tx = None
        assert validator._txin_prev_txid(tx_in) is None

    def test_lookup_utxo_entry(self, validator):
        snapshot = {
            "aaaa:0": "entry1",
            ("bbbb", 1): "entry2",
            "cccc": {2: "entry3"}
        }
        assert validator._lookup_utxo_entry(snapshot, "aaaa", 0) == "entry1"
        assert validator._lookup_utxo_entry(snapshot, "bbbb", 1) == "entry2"
        assert validator._lookup_utxo_entry(snapshot, "cccc", 2) == "entry3"

        validator.utxo.lookup_entry.return_value = "entry4"
        assert validator._lookup_utxo_entry(snapshot, "dddd", 3) == "entry4"

        assert validator._lookup_utxo_entry(snapshot, None, 0) is None
        
        # Test bytes variant
        snapshot_bytes = {
            (b'\xaa', 0): "entry5"
        }
        assert validator._lookup_utxo_entry(snapshot_bytes, "aa", 0) == "entry5"
        
        # Test key as bytes in dict
        snapshot_bytes_key = {
            b"aaaa:0": "entry6"
        }
        assert validator._lookup_utxo_entry(snapshot_bytes_key, "aaaa", 0) == "entry6"

    @patch("tsarchain.mempool.validation.get_utxo_script_bytes", return_value=b"script")
    def test_utxo_snapshot_to_items(self, mock_get_script, validator):
        validator.utxo._get_utxo_meta.return_value = (True, 123)
        txid_hex = "aa" * 32
        snapshot = {
            f"{txid_hex}:0": {"amount": 500},
            f"{txid_hex}:1".encode('utf-8'): {"amount": 600},
            "invalid_key": {"amount": 100}
        }
        items = validator._utxo_snapshot_to_items(snapshot)
        assert len(items) == 2
        assert items[0] == (bytes.fromhex(txid_hex), 0, 500, b"script", True, 123)
        assert items[1] == (bytes.fromhex(txid_hex), 1, 600, b"script", True, 123)
        assert validator._utxo_snapshot_to_items([]) == []

    @patch("tsarchain.mempool.validation.CFG")
    @patch("tsarchain.mempool.validation.GRAFFITI")
    @patch("tsarchain.mempool.validation.last_pushdata")
    def test_validate_graffiti_output(self, mock_last_pushdata, mock_graffiti, mock_cfg, validator):
        mock_cfg.GRAFFITI_MAGIC = b"ART\x00"
        mock_cfg.MAX_GRAFFITI_OPRET = 80
        mock_cfg.GRAFFITI_MAX_SIZE_BYTES = 1000
        mock_cfg.GRAFFITI_COMMENT_MAX_BYTES = 200
        mock_cfg.GRAFFITI_COMMENT_MIN_FEE = 10
        
        def _make_spk(raw=b""):
            m = MagicMock()
            m.serialize.return_value = raw
            return m

        # Test non-OP_RETURN or no magic
        mock_last_pushdata.return_value = b"NOT_MAGIC"
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is True
        
        # Test size too large
        mock_last_pushdata.return_value = b"ART\x00" + b"X" * 100
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_opreturn_too_large"
        
        # Test invalid payload
        mock_last_pushdata.return_value = b"ART\x00" + b"X" * 10
        mock_graffiti.parse_payload.return_value = None
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_payload_invalid"
        
        # Test POST
        mock_graffiti.parse_payload.return_value = {"event": "POST", "size": 0}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_size_invalid"
        
        mock_graffiti.parse_payload.return_value = {"event": "POST", "size": 2000}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_size_exceeds_limit"
        
        mock_graffiti.parse_payload.return_value = {"event": "POST", "size": 500}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is True
        
        # Test COMMENT
        mock_graffiti.parse_payload.return_value = {"event": "COMMENT", "comment_len": 0}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_comment_empty"
        
        mock_graffiti.parse_payload.return_value = {"event": "COMMENT", "comment_len": 300}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_comment_too_large"
        
        mock_graffiti.parse_payload.return_value = {"event": "COMMENT", "comment_len": 100, "amount": 5, "tip": 0}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_comment_fee_too_low"
        
        mock_graffiti.parse_payload.return_value = {"event": "COMMENT", "comment_len": 100, "amount": 15, "tip": -1}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is False
        assert validator.last_error_reason == "graffiti_comment_tip_negative"
        
        mock_graffiti.parse_payload.return_value = {"event": "COMMENT", "comment_len": 100, "amount": 15, "tip": 5}
        assert validator._validate_graffiti_output(_make_spk(b"some_bytes")) is True
        
        # Test formats
        assert validator._validate_graffiti_output(_make_spk(b"")) is True
        mock_obj = MagicMock()
        mock_obj.serialize.return_value = b"serialized"
        assert validator._validate_graffiti_output(mock_obj) is True
        assert validator._validate_graffiti_output(_make_spk(b"\xab\xcd\xef")) is True

    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    def test_validate_transaction_invalid_size(self, mock_compute, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.inputs = []
        tx.outputs = []
        tx.is_coinbase = True
        assert not validator.validate_transaction(tx, {})

        tx.is_coinbase = False
        # weight, vsize, base_size, total_size
        mock_compute.return_value = (10000000, 10000000, 0, 0) # Exceeds limit
        assert not validator.validate_transaction(tx, {})
        assert validator.last_error_reason == "tx_vsize_exceeds_limit"
        
        mock_compute.side_effect = Exception("error")
        assert not validator.validate_transaction(tx, {})
        assert validator.last_error_reason == "tx_weight_calc_failed"

    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    def test_validate_transaction_limits(self, mock_compute, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.is_coinbase = False
        tx.inputs = [MagicMock() for _ in range(10)]
        tx.outputs = [MagicMock() for _ in range(10)]
        
        with patch("tsarchain.mempool.validation.CFG") as mock_cfg:
            mock_cfg.DEBUG_BENCHMARKS = False
            mock_cfg.MAX_TX_VSIZE = 1000
            mock_cfg.MIN_TX_VSIZE = 100
            mock_cfg.MAX_TX_WEIGHT = 4000
            mock_cfg.MIN_TX_WEIGHT = 400
            mock_cfg.MAX_TX_INPUTS = 5
            mock_cfg.MAX_TX_OUTPUTS = 5
            
            # Vsize below min
            mock_compute.return_value = (1000, 50, 0, 0)
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "tx_vsize_below_min"
            
            # Weight exceeds limit
            mock_compute.return_value = (5000, 200, 0, 0)
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "tx_weight_exceeds_limit"
            
            # Weight below min
            mock_compute.return_value = (100, 200, 0, 0)
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "tx_weight_below_min"
            
            # Inputs exceed limit
            mock_compute.return_value = (1000, 200, 0, 0)
            mock_cfg.MAX_TX_INPUTS = 5
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "tx_inputs_exceed_limit"
            
            # Outputs exceed limit
            tx.inputs = [MagicMock() for _ in range(2)]
            mock_cfg.MAX_TX_OUTPUTS = 5
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "tx_outputs_exceed_limit"

    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    @patch.object(TxMempoolValidator, "_validate_graffiti_output")
    def test_validate_transaction_invalid_graffiti_output(self, mock_graffiti_val, mock_compute, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.is_coinbase = False
        tx.inputs = [MagicMock()]
        out1 = MagicMock()
        tx.outputs = [out1]
        
        mock_compute.return_value = (1000, 250, 0, 0)
        
        with patch("tsarchain.mempool.validation.CFG") as mock_cfg:
            mock_cfg.MAX_TX_VSIZE = 10000
            mock_cfg.MIN_TX_VSIZE = 10
            mock_cfg.MAX_TX_WEIGHT = 40000
            mock_cfg.MIN_TX_WEIGHT = 40
            mock_cfg.MAX_TX_INPUTS = 100
            mock_cfg.MAX_TX_OUTPUTS = 100
            
            mock_graffiti_val.return_value = False
            assert not validator.validate_transaction(tx, {})

    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    @patch.object(TxMempoolValidator, "_validate_graffiti_output", return_value=True)
    @patch("tsarchain.mempool.validation.GRAFFITI")
    @patch("tsarchain.mempool.validation.get_utxo_script_bytes")
    @patch("tsarchain.mempool.validation.is_p2wsh")
    @patch("tsarchain.mempool.validation.is_p2wpkh")
    def test_validate_transaction_payout(self, mock_is_p2wpkh, mock_is_p2wsh, mock_script_bytes, mock_graffiti, mock_val_graf, mock_compute, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.is_coinbase = False
        tx.inputs = [MagicMock()]
        tx.outputs = [MagicMock(), MagicMock()]
        tx.outputs[0].amount = 100
        tx.outputs[1].amount = 50
        
        mock_compute.return_value = (1000, 250, 0, 0)
        
        with patch("tsarchain.mempool.validation.CFG") as mock_cfg:
            mock_cfg.DEBUG_BENCHMARKS = False
            mock_cfg.MAX_TX_VSIZE = 10000
            mock_cfg.MIN_TX_VSIZE = 10
            mock_cfg.MAX_TX_WEIGHT = 40000
            mock_cfg.MIN_TX_WEIGHT = 40
            mock_cfg.MAX_TX_INPUTS = 100
            mock_cfg.MAX_TX_OUTPUTS = 100
            
            # Setup payout output detection
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5}, None]
            
            reg_mock = MagicMock()
            validator.utxo._graffiti_registry = reg_mock
            
            # Unknown art
            reg_mock.get_post.return_value = None
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_unknown_art"
            
            # Epoch rewind
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5}, None]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 5}}
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_epoch_rewind"
            
            # Missing proof (proof_height check)
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_height": 10}, None]
            mock_graffiti.compute_proof_epoch.return_value = 4
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 4}}
            reg_mock.get_latest_proof_epoch.return_value = 4
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_missing_proof"
            
            # No recipients
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5}, None]
            reg_mock.get_latest_proof_epoch.return_value = 5
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_no_recipients"
            
            # Bad recipient
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "", "amount": 100}]}, None]
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_bad_recipient"
            
            # Shortfall
            mock_is_p2wpkh.return_value = True
            validator._script_to_address = MagicMock(return_value="addr1")
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 200}]}, None]
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_shortfall"
            
            # Exceeds pool
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 50, "last_paid_epoch": 4}}
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_exceeds_pool"
            
            # Valid recipients, now checking inputs (pool P2WSH)
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 4}}
            
            # Missing prevout
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            validator._lookup_utxo_entry = MagicMock(return_value=None)
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "missing_prevout"
            
            # Prev not pool
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            validator._lookup_utxo_entry = MagicMock(return_value={"amount": 200})
            mock_script_bytes.return_value = b"\x00" * 10
            mock_is_p2wsh.return_value = False
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_prev_not_pool"
            
            # Wrong pool
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            mock_script_bytes.return_value = b"\x00\x20" + b"\x00" * 32
            mock_is_p2wsh.return_value = True
            mock_graffiti.hash_pool_redeem_script.return_value = "deadbeef"
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_wrong_pool"
            
            # Fee negative
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            mock_script_bytes.return_value = b"\x00\x20" + bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            mock_graffiti.hash_pool_redeem_script.return_value = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            validator._get_utxo_amount = MagicMock(return_value=100) # total_in
            # total_out is 150
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_fee_negative"
            
            # Valid Payout
            mock_graffiti.parse_from_script.side_effect = [{"event": "PAYOUT", "art_id": "art1", "epoch": 5, "proof_epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}, None]
            validator._get_utxo_amount = MagicMock(return_value=200) # total_in
            assert validator.validate_transaction(tx, {})
            assert tx.fee == 50

    @patch("tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact")
    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    def test_validate_transaction_native_reject(self, mock_compute, mock_native, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.is_coinbase = False
        tx.inputs = []
        tx.outputs = []
        mock_compute.return_value = (1000, 250, 250, 1000)
        
        with patch("tsarchain.mempool.validation.CFG") as mock_cfg:
            mock_cfg.MAX_TX_VSIZE = 100000
            mock_cfg.MIN_TX_VSIZE = 10
            mock_cfg.MAX_TX_WEIGHT = 400000
            mock_cfg.MIN_TX_WEIGHT = 40
            mock_cfg.MAX_TX_INPUTS = 100
            mock_cfg.MAX_TX_OUTPUTS = 100
            
            mock_native.return_value = (False, "some_reason", 0)
            validator.utxo._get_tip_height_from_state.return_value = 100
            
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "some_reason"

            # Native fail with exception
            mock_native.side_effect = Exception("err")
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "native_mempool_failed"

    @patch("tsarchain.mempool.validation.compute_tx_weight_vsize")
    @patch.object(TxMempoolValidator, "_validate_graffiti_output", return_value=True)
    @patch("tsarchain.mempool.validation.native_validate_tx_p2wpkh_compact")
    @patch("tsarchain.mempool.validation.tx_to_compact_tuple")
    @patch.object(TxMempoolValidator, "_utxo_snapshot_to_items")
    @patch("tsarchain.mempool.validation.GRAFFITI")
    def test_validate_transaction_native_success(self, mock_graffiti, mock_utxo_items, mock_compact, mock_native, mock_val_graf, mock_compute, validator):
        tx = MagicMock(spec=Tx)
        tx.txid = b"txid"
        tx.is_coinbase = False
        tx.inputs = [MagicMock()]
        tx.outputs = [MagicMock()]
        tx.outputs[0].amount = 100
        
        mock_compute.return_value = (1000, 250, 0, 0)
        
        with patch("tsarchain.mempool.validation.CFG") as mock_cfg:
            mock_cfg.DEBUG_BENCHMARKS = True
            mock_cfg.MAX_TX_VSIZE = 10000
            mock_cfg.MIN_TX_VSIZE = 10
            mock_cfg.MAX_TX_WEIGHT = 40000
            mock_cfg.MIN_TX_WEIGHT = 40
            mock_cfg.MAX_TX_INPUTS = 100
            mock_cfg.MAX_TX_OUTPUTS = 100
            mock_cfg.COINBASE_MATURITY = 100
            mock_cfg.MAX_SIGOPS_PER_TX = 100
            mock_cfg.MAX_SIGOPS_PER_BLOCK = 1000
            
            mock_native.return_value = (True, "", 500)
            mock_graffiti.parse_from_script.return_value = None
            
            # Test Mempool Graffiti full
            mock_cfg.MAX_GRAFFITI_ON_MEMPOOL = 1
            mock_graffiti.parse_from_script.side_effect = [None, {"event": "POST"}, {"event": "POST"}] # current tx (Payout check), current tx (POST check), pool tx
            
            pool_tx = MagicMock()
            pool_tx.txid = b"txid1"
            pool_tx.outputs = [MagicMock()]
            validator._pool = {"txid1": pool_tx}
            
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "mempool_graffiti_full"
            
            # Payout sanity check
            mock_cfg.MAX_GRAFFITI_ON_MEMPOOL = 0 # Disable limit
            
            reg_mock = MagicMock()
            validator.utxo._graffiti_registry = reg_mock
            validator._script_to_address = MagicMock(return_value="addr1")
            
            # Bad art ID
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "", "epoch": 5}]
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_bad_art_id"
            
            # Unknown art
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5}]
            reg_mock.get_post.return_value = None
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_unknown_art"
            
            # Epoch rewind
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5}]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 5}}
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_epoch_rewind"
            
            # Missing proof
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5}]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 4}}
            reg_mock.get_latest_proof_epoch.return_value = 4
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_missing_proof"
            
            # No recipients
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5}]
            reg_mock.get_latest_proof_epoch.return_value = 5
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_no_recipients"
            
            # Bad recipient
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5, "recipients": [{"addr": "", "amount": 100}]}]
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_bad_recipient"
            
            # Shortfall
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5, "recipients": [{"addr": "addr1", "amount": 200}]}]
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_shortfall"
            
            # Exceeds pool
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 50, "last_paid_epoch": 4}}
            assert not validator.validate_transaction(tx, {})
            assert validator.last_error_reason == "payout_exceeds_pool"
            
            # Valid payout sanity
            mock_graffiti.parse_from_script.side_effect = [None, None, {"event": "PAYOUT", "art_id": "art1", "epoch": 5, "recipients": [{"addr": "addr1", "amount": 100}]}]
            reg_mock.get_post.return_value = {"stats": {"pool_balance": 1000, "last_paid_epoch": 4}}
            assert validator.validate_transaction(tx, {})

    def test_enforce_mempool_post_limit_rejects_on_chain_duplicate(self, validator):
        sha = "1" * 64
        mroot = "2" * 64
        art_id = "art_onchain_dup"

        reg_mock = MagicMock()
        reg_mock.get_post.return_value = {
            "art_id": art_id,
            "sha256": sha,
            "mroot": mroot,
        }
        validator.utxo._graffiti_registry = reg_mock

        out = MagicMock()
        out.script_pubkey = MagicMock()
        tx = MagicMock()
        tx.txid = "tx123"
        tx.outputs = [out]

        with patch("tsarchain.mempool.validation.GRAFFITI.parse_from_script") as mock_parse:
            mock_parse.return_value = {
                "event": "POST",
                "art_id": art_id,
                "sha256": sha,
                "mroot": mroot,
                "size": 100,
            }
            res = validator._enforce_mempool_post_limit(tx)
            assert res is False
            assert validator.last_error_reason == "graffiti_duplicate_post"

    def test_enforce_mempool_post_limit_rejects_mempool_duplicate(self, validator):
        sha = "3" * 64
        mroot = "4" * 64
        art_id = "art_mempool_dup"

        reg_mock = MagicMock()
        reg_mock.get_post.return_value = None
        validator.utxo._graffiti_registry = reg_mock

        pool_out = MagicMock()
        pool_tx = MagicMock()
        pool_tx.txid = "tx_existing"
        pool_tx.outputs = [pool_out]
        validator._pool = {"tx_existing": pool_tx}

        new_out = MagicMock()
        new_tx = MagicMock()
        new_tx.txid = "tx_new"
        new_tx.outputs = [new_out]

        with patch("tsarchain.mempool.validation.GRAFFITI.parse_from_script") as mock_parse:
            mock_parse.return_value = {
                "event": "POST",
                "art_id": art_id,
                "sha256": sha,
                "mroot": mroot,
                "size": 100,
            }
            res = validator._enforce_mempool_post_limit(new_tx)
            assert res is False
            assert validator.last_error_reason == "graffiti_duplicate_post"

    def test_validate_graffiti_output_rejects_on_chain_duplicate(self, validator):
        sha = "5" * 64
        mroot = "6" * 64
        art_id = "7" * 64

        reg_mock = MagicMock()
        reg_mock.get_post.return_value = {
            "art_id": art_id,
            "sha256": sha,
            "mroot": mroot,
        }
        validator.utxo._graffiti_registry = reg_mock

        meta = {
            "event": "POST",
            "art_id": art_id,
            "sha256": sha,
            "mroot": mroot,
            "mchunk": 50,
            "mcount": 2,
            "size": 100,
            "mime": "image/jpeg",
            "storer": "tsar1qv9skzctpv9skzctpv9skzctpv9skzctphjeeqv",
            "receipt": "rcpt1",
        }
        from tsarchain.contracts import graffiti as GRAFF
        spk_obj = GRAFF.build_script(meta)

        res = validator._validate_graffiti_output(spk_obj)
        assert res is False
        assert validator.last_error_reason == "graffiti_duplicate_post"



def test_txpool_len_and_size():
    from tsarchain.mempool.pool import TxPool
    with patch.object(TxPool, '_load_storage_pool', return_value=([], {})):
        pool = TxPool(inherit_state=False)
        assert len(pool) == 0
        assert pool.size() == 0
        pool._pool["tx1"] = MagicMock()
        pool._pool["tx2"] = MagicMock()
        assert len(pool) == 2
        assert pool.size() == 2
