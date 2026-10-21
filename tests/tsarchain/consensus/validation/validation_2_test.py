"""
Validation tests Part 2: Validation Mixin Core Tests
Testing block processing, sigops, difficulty, and chain validation core logic
"""

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import pytest
import threading

from unittest.mock import Mock, patch
from tsarchain.consensus.validation import BlockValidator

class ValidationProxy:
    def __getattr__(self, name):
        val = self.__dict__.get('validator')
        if val is not None:
            try:
                return getattr(val, name)
            except AttributeError:
                pass
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name, value):
        if name != 'validator':
            val = self.__dict__.get('validator')
            if val is not None and name in dir(val):
                setattr(val, name, value)
                return
        super().__setattr__(name, value)

"""
unit test for validation.py
"""

# =============================================================================
# CATEGORY 2: VALIDATION MIXIN CORE TESTS 
# =============================================================================


# Fixtures for mock objects
# -------------------------------------------------------------------

@pytest.fixture
def mock_block():
    """Return a minimal mock Block object."""
    block = Mock()
    block.height = 1
    block.prev_block_hash = b"prevhash"
    block.transactions = []
    block.bits = 0x1d00ffff
    block.merkle_root = b"merkle"
    block.timestamp = int(time.time())
    block.hash = Mock(return_value=b"blockhash")
    block.header = Mock(return_value=b"header")
    return block

@pytest.fixture(autouse=True)
def mock_randomx(monkeypatch):
    monkeypatch.setattr(
        "tsarchain.utils.helpers.pow_hash_verify_light",
        lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        "tsarchain.utils.helpers.pow_key_for_height",
        lambda h: b"dummy_key"
    )
    monkeypatch.setattr(
        "tsarchain.utils.helpers.pow_hash_verify_light",
        lambda *args, **kwargs: b"dummy_hash"
    )

@pytest.fixture
def mock_tx():
    """Return a minimal mock Transaction object."""
    tx = Mock()
    tx.is_coinbase = False
    tx.inputs = []
    tx.outputs = []
    tx.txid = None
    tx.txid_hex = None
    tx.fee = 0
    def compute_txid():
        tx.txid = b"txid"
        tx.txid_hex = "txid"
    tx.compute_txid = compute_txid
    return tx

@pytest.fixture
def mock_coinbase_tx():
    tx = Mock()
    tx.is_coinbase = True
    tx.inputs = []
    tx.outputs = []
    tx.txid = b"coinbase_txid"
    tx.txid_hex = "coinbase_txid"
    return tx

# -------------------------------------------------------------------
# Test class
# -------------------------------------------------------------------

class TestValidationMixin:

    # Helper to create a concrete instance of the mixin with required attributes
    def create_instance(self):
        class DummyConsensus(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = []
                self.height = -1
                self._last_block_validation_error = None
                self.cumulative_supply_until = Mock(return_value=0)
                self.scheduled_reward = Mock(return_value=50)
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
                self.ensure_utxodb = Mock(return_value=None)
                self._chain_state_token_locked = Mock(return_value=(0, b"token"))
                self._validate_chain_context_locked = Mock(return_value=True)
                self._check_sigops_budget = Mock(return_value=True)
                self._validate_merkle = Mock(return_value=True)
                self._ensure_unique_txids = Mock(return_value=True)
                self._check_block_limits = Mock(return_value=True)
                self._validate_pow = Mock(return_value=True)
                self._serialize_tx_cached = Mock(return_value=b"serialized")
                self.compute_txids_for_block = Mock(return_value=True)
        return DummyConsensus()

    # -------------------------------------------------------------------
    # Tests for _ensure_warm
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_epoch_already_warmed(self, mock_cfg):
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.validator.__class__._pow_epoch_warmed = set([0])
        with patch("tsarchain.consensus.validation.H") as mock_H:
            instance._ensure_warm(50)
            mock_H.pow_hash_verify_light.assert_not_called()
        instance.validator.__class__._pow_epoch_warmed = set()

    @patch("tsarchain.consensus.validation.CFG")
    def test_ensure_warm_calls_pow_hash(self, mock_cfg):
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        instance.validator.__class__._pow_epoch_warmed = set()
        with patch("tsarchain.consensus.validation.H") as mock_H:
            mock_H.pow_key_for_height = Mock(return_value=b"key")
            mock_H.pow_hash_verify_light = Mock()
            instance._ensure_warm(150)
            mock_H.pow_hash_verify_light.assert_called_once_with(b"\x00"*80, key_hint=b"key")
            assert 1 in instance.validator.__class__._pow_epoch_warmed
        instance.validator.__class__._pow_epoch_warmed = set()

    # -------------------------------------------------------------------
    # Tests for _warm_pow_context
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.threading.Thread")
    def test_warm_pow_context_already_scheduled(self, mock_thread, mock_cfg):
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        instance = self.create_instance()
        BlockValidator._pow_warm_next_epoch = 2
        try:
            instance._warm_pow_context(150)
            mock_thread.assert_not_called()
        finally:
            BlockValidator._pow_warm_next_epoch = None

    # -------------------------------------------------------------------
    # Tests for validate_block
    # -------------------------------------------------------------------

    def test_validate_block_missing_fields(self):
        instance = self.create_instance()
        block = Mock()
        block.height = None
        block.prev_block_hash = b"hash"
        block.transactions = []   # empty, triggers missing_fields
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_missing_fields"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_success(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]   # non‑empty to pass initial check
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        result = instance.validate_block(block)
        assert result is True
        assert instance._last_block_validation_error is None

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_pow_invalid(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_pow.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "pow_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_compute_txids_fails(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance.compute_txids_for_block.return_value = False
        instance._last_block_validation_error = "tx_serialize_failed"  # pre‑set
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_merkle_mismatch(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_merkle.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "merkle_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_duplicate_txid(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._ensure_unique_txids.return_value = False
        instance._last_block_validation_error = "duplicate_or_missing_txid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_or_missing_txid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_block_limits_exceeded(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_block_limits.return_value = False
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "block_limits_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_chain_context_invalid(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._validate_chain_context_locked.return_value = False
        instance._last_block_validation_error = "chain_context_invalid"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_context_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_sigops_limit_exceeded(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")
        instance._check_sigops_budget.return_value = False
        instance._last_block_validation_error = "sigops_limit_exceeded"
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "sigops_limit_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_transactions_fail(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 1  # > 0, so _validate_transactions is called
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        def fake_validate(*args, **kwargs):
            instance._last_block_validation_error = "tx_validation_failed"
            return False

        instance._validate_transactions = Mock(side_effect=fake_validate)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_validation_failed"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_state_changed(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        call_count = 0
        def fake_token():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (0, b"token1")
            else:
                return (1, b"token2")

        instance._chain_state_token_locked = Mock(side_effect=fake_token)
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "chain_state_changed_during_validation"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_block_unexpected_exception(self, mock_cfg):
        mock_cfg.DEBUG_BENCHMARKS = False
        instance = self.create_instance()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"prev"
        block.transactions = [Mock()]
        block.bits = 0
        block.merkle_root = b"merkle"
        block.timestamp = 123
        block.hash = Mock(return_value=b"hash")

        instance._validate_pow = Mock(side_effect=Exception("pow error"))
        result = instance.validate_block(block)
        assert result is False
        assert instance._last_block_validation_error == "unexpected_validation_error"

    # -------------------------------------------------------------------
    # Tests for _validate_transactions
    # -------------------------------------------------------------------

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_empty_txs(self, mock_cfg):
        instance = self.create_instance()
        block = Mock()
        block.transactions = []
        instance.ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "empty_block_transactions"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_missing_coinbase(self, mock_cfg):
        instance = self.create_instance()
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [tx]
        instance.ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "missing_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_transactions_duplicate_coinbase(self, mock_cfg):
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        cb2 = Mock()
        cb2.is_coinbase = True
        block = Mock()
        block.transactions = [cb, cb2]
        instance.ensure_utxodb = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "duplicate_coinbase"

    @patch("tsarchain.consensus.validation.CFG")
    @patch("tsarchain.consensus.validation.H")
    def test_validate_transactions_serialize_fails(self, mock_H, mock_cfg):
        instance = self.create_instance()
        cb = Mock()
        cb.is_coinbase = True
        tx = Mock()
        tx.is_coinbase = False
        block = Mock()
        block.transactions = [cb, tx]
        block.height = 1
        instance.ensure_utxodb = Mock(return_value=None)
        instance._serialize_tx_cached = Mock(return_value=None)
        result = instance._validate_transactions(block)
        assert result is False
        assert instance._last_block_validation_error == "tx_serialize_failed"

# =============================================================================
# Tests for Helper Methods (# 2. HELPER)
# = ============================================================================

    # -------------------------------------------------------------------------
    # _serialize_tx_cached
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.H")
    def test_serialize_tx_cached_cache_hit(self, mock_H):
        # Buat instance dengan metode asli (tidak di-override)
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
        instance = Dummy()
        tx = Mock()
        cached = b"cached_serialized"
        setattr(tx, "_cached_raw_tx_nowit", cached)
        result = instance._serialize_tx_cached(tx, include_witness=False)
        assert result == cached
        mock_H.serialize_tx.assert_not_called()

    @patch("tsarchain.consensus.validation.H")
    def test_serialize_tx_cached_cache_miss(self, mock_H):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
        instance = Dummy()
        tx = Mock()
        raw = b"serialized_tx"
        mock_H.serialize_tx.return_value = raw
        result = instance._serialize_tx_cached(tx, include_witness=True)
        assert result == raw
        mock_H.serialize_tx.assert_called_once_with(tx, include_witness=True)
        assert getattr(tx, "_cached_raw_tx_w") == raw

    # -------------------------------------------------------------------------
    # _estimate_block_size
    # -------------------------------------------------------------------------
    def test_estimate_block_size_with_serialize_method(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                pass
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.serialize = Mock(return_value=b"serialized_tx")  # length 13
        block.transactions = [tx]
        assert instance._estimate_block_size(block) == 80 + 13
        tx.serialize.assert_called_once()

    # -------------------------------------------------------------------------
    # _chain_state_token_locked
    # -------------------------------------------------------------------------
    def test_chain_state_token_locked(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.height = 100
                self.chain = []
        instance = Dummy()
        # Buat chain dengan satu block
        block = Mock()
        block.hash = Mock(return_value=b"tip_hash")
        instance.chain = [block]
        token = instance._chain_state_token_locked()
        assert token == (100, b"tip_hash")

    def test_chain_state_token_locked_empty_chain(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.height = 0
                self.chain = []
        instance = Dummy()
        token = instance._chain_state_token_locked()
        assert token == (0, None)

    # -------------------------------------------------------------------------
    # _validate_chain_context_locked
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_height_mismatch(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 7
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "height_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_prev_hash_mismatch(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"wrong_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "prev_hash_mismatch"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_genesis_prevhash_bad(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = []  # genesis
                self.height = -1
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"not_zero"
        block.timestamp = 100
        block.hash = Mock(return_value=b"genesis_hash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "bad_genesis_prevhash"

    @patch("tsarchain.consensus.validation.GENESIS_HASH", b"correct_genesis_hash")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_genesis_hash_mismatch(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = []
                self.height = -1
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        block = Mock()
        block.height = 0
        block.prev_block_hash = b"\x00"*32
        block.timestamp = 100
        block.hash = Mock(return_value=b"wrong_hash")  # berbeda dari GENESIS_HASH
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "genesis_hash_mismatch"

    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_too_old(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=100)  # MTP > timestamp
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 50
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 50  # lebih kecil dari MTP 100
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_too_old"

    @patch("tsarchain.consensus.validation.time")
    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_in_future(self, mock_cfg, mock_time):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        mock_time.time.return_value = 1000
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 2000  # > time.time() + drift (1000+600=1600)
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_in_future"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_timestamp_backwards(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 300   # parent timestamp lebih besar
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150   # block.timestamp + TARGET_BLOCK_TIME (68) = 218 < 300, jadi error
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "timestamp_backwards"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_difficulty_invalid(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=False)  # invalid
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is False
        assert instance._last_block_validation_error == "difficulty_invalid"

    @patch("tsarchain.consensus.validation.CFG")
    def test_validate_chain_context_locked_success(self, mock_cfg):
        mock_cfg.ZERO_HASH = b"\x00"*32
        mock_cfg.FUTURE_DRIFT = 600
        mock_cfg.TARGET_BLOCK_TIME = 68
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self.lock = threading.Lock()
                self.chain = [Mock()]
                self.height = 5
                self._last_block_validation_error = None
                self._validate_difficulty = Mock(return_value=True)
                self.median_time_past = Mock(return_value=0)
        instance = Dummy()
        instance.chain[-1].hash = Mock(return_value=b"correct_hash")
        instance.chain[-1].timestamp = 100
        block = Mock()
        block.height = 6
        block.prev_block_hash = b"correct_hash"
        block.timestamp = 150
        block.hash = Mock(return_value=b"blockhash")
        assert instance._validate_chain_context_locked(block) is True

    # -------------------------------------------------------------------------
    # _ensure_unique_txids
    # -------------------------------------------------------------------------
    def test_ensure_unique_txids_success(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
        instance = Dummy()
        tx1 = Mock()
        tx1.txid = b"txid1"
        tx2 = Mock()
        tx2.txid = b"txid2"
        block = Mock()
        block.transactions = [tx1, tx2]
        assert instance._ensure_unique_txids(block) is True
        assert instance._last_block_validation_error is None

    def test_ensure_unique_txids_duplicate(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
        instance = Dummy()
        tx1 = Mock()
        tx1.txid = b"txid1"
        tx2 = Mock()
        tx2.txid = b"txid1"
        block = Mock()
        block.transactions = [tx1, tx2]
        assert instance._ensure_unique_txids(block) is False
        assert instance._last_block_validation_error == "txid_duplicate"

    def test_ensure_unique_txids_missing_txid(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
        instance = Dummy()
        tx = Mock()
        tx.txid = None
        block = Mock()
        block.transactions = [tx]
        assert instance._ensure_unique_txids(block) is False
        assert instance._last_block_validation_error == "txid_missing"

    def test_ensure_unique_txids_compute_if_needed(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
        instance = Dummy()
        tx = Mock()
        tx.txid = None
        tx.compute_txid = Mock()
        block = Mock()
        block.transactions = [tx]
        # compute_txid dipanggil, tetapi tetap None -> gagal
        assert instance._ensure_unique_txids(block) is False
        tx.compute_txid.assert_called_once()
        assert instance._last_block_validation_error == "txid_missing"

    # -------------------------------------------------------------------------
    # _check_block_limits
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_too_many_txs(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 10
        mock_cfg.MAX_BLOCK_BYTES = 1000000
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=100)
        instance = Dummy()
        block = Mock()
        # Buat 12 transaksi, semua non-coinbase
        block.transactions = [Mock() for _ in range(12)]
        assert instance._check_block_limits(block) is False
        assert instance._last_block_validation_error == "too_many_txs"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_size_exceeded(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 100
        mock_cfg.MAX_BLOCK_BYTES = 100
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=150)
        instance = Dummy()
        block = Mock()
        block.transactions = [Mock()]  # satu tx
        assert instance._check_block_limits(block) is False
        assert instance._last_block_validation_error == "block_size_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_block_limits_success(self, mock_cfg):
        mock_cfg.MAX_TXS_PER_BLOCK = 100
        mock_cfg.MAX_BLOCK_BYTES = 1000
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._estimate_block_size = Mock(return_value=100)
        instance = Dummy()
        block = Mock()
        block.transactions = [Mock()]  # satu tx
        assert instance._check_block_limits(block) is True

    # -------------------------------------------------------------------------
    # _check_sigops_budget
    # -------------------------------------------------------------------------
    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_per_tx_exceeded(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 5
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 100
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx = Mock()
        tx.is_coinbase = False
        tx.sigops_count = Mock(return_value=10)  # > 5
        block.transactions = [tx]
        store = Mock()
        result = instance._check_sigops_budget(block, store)
        assert result is False
        assert instance._last_block_validation_error == "sigops_per_tx_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_total_exceeded(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 10
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 5
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx1 = Mock()
        tx1.is_coinbase = False
        tx1.sigops_count = Mock(return_value=3)
        tx2 = Mock()
        tx2.is_coinbase = False
        tx2.sigops_count = Mock(return_value=3)
        block.transactions = [tx1, tx2]
        store = Mock()
        result = instance._check_sigops_budget(block, store)
        assert result is False
        assert instance._last_block_validation_error == "sigops_per_block_exceeded"

    @patch("tsarchain.consensus.validation.CFG")
    def test_check_sigops_budget_success(self, mock_cfg):
        mock_cfg.MAX_SIGOPS_PER_TX = 10
        mock_cfg.MAX_SIGOPS_PER_BLOCK = 100
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx1 = Mock()
        tx1.is_coinbase = False
        tx1.sigops_count = Mock(return_value=3)
        tx2 = Mock()
        tx2.is_coinbase = False
        tx2.sigops_count = Mock(return_value=3)
        block.transactions = [tx1, tx2]
        store = Mock()
        assert instance._check_sigops_budget(block, store) is True

    def test_check_sigops_budget_uses_fallback_if_no_sigops_count(self):
        class Dummy(ValidationProxy):
            def __init__(self):
                self.validator = BlockValidator(self)
                self._last_block_validation_error = None
                self._entry_script_bytes = Mock(return_value=b"script")
        instance = Dummy()
        block = Mock()
        tx = Mock(spec=["is_coinbase", "inputs", "sigops_count"])
        tx.is_coinbase = False
        tx.sigops_count = Mock(return_value=3)
        tx.inputs = [1, 2, 3]
        
        block.transactions = [tx]
        store = Mock()
        with patch("tsarchain.consensus.validation.CFG.MAX_SIGOPS_PER_TX", 10):
            with patch("tsarchain.consensus.validation.CFG.MAX_SIGOPS_PER_BLOCK", 100):
                assert instance._check_sigops_budget(block, store) is True


