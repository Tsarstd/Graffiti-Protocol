"""
Validation tests Part 1: Transaction Validation Tests
Testing graffiti, tx payouts, and transaction validation logic in validation.py
"""

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import pytest
import threading

from types import SimpleNamespace
from bech32 import bech32_encode, convertbits
from unittest.mock import Mock

from tsarchain.utils import config as CFG
from tsarchain.contracts import graffiti as GRAFFITI
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

class FakeTxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

# =============================================================================
# CATEGORY 1: TRANSACTION VALIDATION TESTS
# =============================================================================
class DummyTxOut:
    def __init__(self, amount, script_pubkey):
        self.validator = BlockValidator(self)
        self.amount = amount
        self.script_pubkey = script_pubkey


class DummyTxIn:
    def __init__(self, txid, vout):
        self.validator = BlockValidator(self)
        self.txid = txid
        self.vout = vout


class DummyTx:
    def __init__(self, inputs=None, outputs=None, is_coinbase=False, fee=0,
                 txid=None, block_id=None):
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.is_coinbase = is_coinbase
        self.fee = fee
        self.txid = txid
        self.block_id = block_id
        self._cached_raw_tx_nowit = None
        self._cached_raw_tx_w = None

    def compute_txid(self):
        if self.txid is None:
            self.txid = b'\x01' * 32
        return self.txid


class DummyBlock:
    def __init__(self, height, transactions, prev_block_hash=None,
                 bits=0x1d00ffff, merkle_root=None, timestamp=None):
        self.height = height
        self.transactions = transactions
        self.prev_block_hash = prev_block_hash or b'\x00' * 32
        self.bits = bits
        self.merkle_root = merkle_root
        self.timestamp = timestamp or int(time.time())
        self._cached_hash = None


class _TestChain(ValidationProxy):
    def __init__(self):
        self.validator = BlockValidator(self)
        self.chain = []
        self.height = -1
        self.lock = threading.Lock()
        self._last_block_validation_error = None

    def ensure_utxodb(self):
        pass

    def cumulative_supply_until(self, height):
        pass

    def scheduled_reward(self, height):
        pass


@pytest.fixture
def validation_chain(mocker):
    cfg_mock = SimpleNamespace(
        MAX_BLOCK_BYTES=1200000,
        MAX_TX_VSIZE=10000,
        MIN_TX_VSIZE=100,
        MAX_TX_WEIGHT=40000,
        MIN_TX_WEIGHT=400,
        MAX_TX_INPUTS=1000,
        MAX_TX_OUTPUTS=1000,
        COINBASE_MATURITY=3,
        MAX_SIGOPS_PER_TX=6000,
        MAX_SIGOPS_PER_BLOCK=40000,
        GRAFFITI_MAGIC=CFG.GRAFFITI_MAGIC,
        MAX_GRAFFITI_OPRET=580,
        GRAFFITI_MAX_SIZE_BYTES=CFG.GRAFFITI_MAX_SIZE_BYTES,
        GRAFFITI_COMMENT_MAX_BYTES=CFG.GRAFFITI_COMMENT_MAX_BYTES,
        GRAFFITI_COMMENT_MIN_FEE=CFG.GRAFFITI_COMMENT_MIN_FEE,
        ADDRESS_PREFIX=CFG.ADDRESS_PREFIX,
        MAX_SUPPLY=CFG.MAX_SUPPLY,
    )
    mocker.patch('tsarchain.consensus.validation.CFG', cfg_mock)

    mock_H = mocker.patch('tsarchain.consensus.validation.H')
    mock_H.serialize_tx.return_value = b'\x00' * 100
    mock_H.compute_tx_weight_vsize.return_value = (400, 100, 80, 100)
    mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])
    def _tx_to_compact(tx):
        return (tx.is_coinbase, [])
    mock_H.tx_to_compact_tuple.side_effect = _tx_to_compact
    mock_H.native_validate_block_txs.return_value = (True, None, [10])

    # Mock GRAFFITI
    mock_graffiti = mocker.patch('tsarchain.consensus.validation.GRAFFITI')
    # parse_payload default None
    mock_graffiti.parse_payload.return_value = None
    # parse_from_script default None
    mock_graffiti.parse_from_script.return_value = None

    # Mock GraffitiRegistry
    mock_reg = mocker.patch('tsarchain.consensus.validation.GraffitiRegistry')
    mock_reg_instance = Mock()
    mock_reg.return_value = mock_reg_instance
    mock_reg_instance.get_post.return_value = None
    mock_reg_instance.get_latest_proof_epoch.return_value = 0

    # Mock UTXODB dan lookup_entry
    mock_utxo = mocker.patch('tsarchain.consensus.validation.UTXODB')
    mock_utxo_instance = Mock()
    mock_utxo.return_value = mock_utxo_instance
    def lookup_entry(txid_hex, vout):
        return {
            'tx_out': FakeTxOut(100_000_000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'),
            'is_coinbase': False,
            'block_height': 1,
        }
    mock_utxo_instance.lookup_entry.side_effect = lookup_entry
    mock_utxo_instance.load_utxo_set.return_value = {}

    chain = _TestChain()
    chain.ensure_utxodb = Mock(return_value=mock_utxo_instance)
    chain.cumulative_supply_until = Mock(return_value=0)
    chain.scheduled_reward = Mock(return_value=50_000_000)  # 50 coin

    chain._mock_H = mock_H
    chain._mock_graffiti = mock_graffiti
    chain._mock_reg = mock_reg_instance
    chain._mock_utxo = mock_utxo_instance

    return chain


def create_coinbase_tx(amount, block_id=None, txid=None):
    out = DummyTxOut(amount, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    tx = DummyTx(inputs=[], outputs=[out], is_coinbase=True, txid=txid,
                 block_id=block_id)
    return tx


def create_normal_tx(inputs, outputs, fee=10, txid=None):
    tx = DummyTx(inputs=inputs, outputs=outputs, is_coinbase=False, fee=fee,
                 txid=txid)
    return tx

def create_utxo_input(prev_txid, vout):
    return DummyTxIn(prev_txid, vout)


def create_output(amount, script_pubkey):
    return DummyTxOut(amount, script_pubkey)


def create_graffiti_tx(meta, inputs=None, fee=10, txid=None):
    """Buat transaksi normal dengan satu output OP_RETURN berisi graffiti."""
    script = GRAFFITI.build_script(meta)
    out = DummyTxOut(0, script.serialize())
    inputs = inputs or [create_utxo_input(b'\xaa' * 32, 0)]
    return create_normal_tx(inputs, [out], fee=fee, txid=txid)

# =============================================================================
# GRAFFITI POIN 1: GRAFFITI POST
# =============================================================================

def test_validate_transactions_graffiti_post_ok(validation_chain):
    """Scenario 4: a single graffiti POST with a matching block_id."""
    chain = validation_chain

    art_id = "abc123"
    cb = create_coinbase_tx(50_000_000 + 10, block_id=art_id)

    graffiti_data = b'GRAFFITI' + b'\x01\x02\x03'  # mock magic + payload

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0:
            if script[0] == 0x6a:  # OP_RETURN
                return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return {
                'event': 'POST',
                'art_id': art_id,
                'sha256': 'x' * 64,
                'creator': 'creator',
                'size': 100,
            }
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            data = last_pushdata_side_effect(script)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    op_return_script = b'\x6a' + bytes([len(graffiti_data)]) + graffiti_data
    tx_out = create_output(0, op_return_script)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    normal_tx = create_normal_tx([tx_input], [tx_out], fee=10)

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True


def test_validate_transactions_graffiti_post_mismatch(validation_chain):
    """Scenario 5: POST graffiti with mismatched block_id -> failure."""
    import hashlib
    chain = validation_chain

    art_id = "graf" + "a" * 60
    cb = create_coinbase_tx(50_000_000 + 10, block_id="wrong_id")

    graffiti_data = b'GRAFFITI' + b'\x01\x02\x03'

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0:
            if script[0] == 0x6a:
                return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return {
                'event': 'POST',
                'art_id': art_id,
                'sha256': 'x' * 64,
                'creator': 'creator',
                'size': 100,
            }
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            data = last_pushdata_side_effect(script)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect
    chain._mock_graffiti.derive_pool_address.side_effect = GRAFFITI.derive_pool_address
    chain._mock_graffiti.calc_upload_fee_sats.side_effect = GRAFFITI.calc_upload_fee_sats

    op_return_script = b'\x6a' + bytes([len(graffiti_data)]) + graffiti_data
    tx_out = create_output(0, op_return_script)
    redeem = GRAFFITI._pool_redeem_script(art_id)
    pool_spk = b'\x00\x20' + hashlib.sha256(redeem).digest()
    tx_pool_out = create_output(5000000000, pool_spk)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    normal_tx = create_normal_tx([tx_input], [tx_out, tx_pool_out], fee=10)

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "block_id_mismatch_graffiti"

# =============================================================================
# GRAFFITI POIN 2: GRAFFITI COMMENT
# =============================================================================

def test_validate_transactions_graffiti_comment_ok(validation_chain):
    """Scenario: valid COMMENT graffiti."""
    chain = validation_chain

    cb = create_coinbase_tx(50_000_000 + 10)

    # Meta COMMENT yang valid dengan field yang dibutuhkan validasi
    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",  # hex "Hello"
        "comment_len": 5,         # panjang bytes comment
        "amount": 100_000_000,    # 1 TSAR >= MIN_FEE
        "tip": 0,
        "creator": "tsar1q...",
        "commenter": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        # script bisa bytes atau Script; kita coba ambil data
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True

def test_validate_transactions_graffiti_comment_fee_too_low(validation_chain):
    """COMMENT with amount < GRAFFITI_COMMENT_MIN_FEE -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",
        "comment_len": 5,
        "amount": 10_000_000,  # di bawah min fee (1 TSAR = 100_000_000)
        "tip": 0,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_fee_too_low"

def test_validate_transactions_graffiti_comment_too_large(validation_chain):
    """COMMENT with comment_len > GRAFFITI_COMMENT_MAX_BYTES -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    # comment_len 200 > 140 (max)
    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "61" * 200,  # hex string panjang
        "comment_len": 200,
        "amount": 100_000_000,
        "tip": 0,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_too_large"

def test_validate_transactions_graffiti_comment_empty(validation_chain):
    """COMMENT with comment_len = 0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "",
        "comment_len": 0,
        "amount": 100_000_000,
        "tip": 0,
        "creator": "tsar1q...",
    }
    # build_script akan menolak comment kosong, jadi kita buat script manual
    import json
    payload = CFG.GRAFFITI_MAGIC + json.dumps(meta, separators=CFG.CANONICAL_SEP).encode()
    script = b'\x6a' + bytes([len(payload)]) + payload

    out = DummyTxOut(0, script)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [out], fee=10)

    def last_pushdata_side_effect(script_bytes):
        if isinstance(script_bytes, bytes) and len(script_bytes) > 0 and script_bytes[0] == 0x6a:
            return payload
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == payload:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_empty"

def test_validate_transactions_graffiti_comment_tip_negative(validation_chain):
    """COMMENT with tip < 0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "COMMENT",
        "art_id": "abc123",
        "comment": "48656c6c6f",
        "comment_len": 5,
        "amount": 100_000_000,
        "tip": -1,
        "creator": "tsar1q...",
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "graffiti_comment_tip_negative"

# =============================================================================
# GRAFFITI POIN 3: GRAFFITI PAYOUT
# =============================================================================

def test_validate_transactions_graffiti_payout_ok(validation_chain, mocker):
    """Valid PAYOUT graffiti."""
    chain = validation_chain

    # Buat P2WPKH address dummy (hash 20 byte nol)
    hash20 = b'\x00' * 20
    spk_p2wpkh = b'\x00\x14' + hash20
    data = [0] + list(convertbits(hash20, 8, 5, True))
    address = bech32_encode(CFG.ADDRESS_PREFIX, data)

    cb = create_coinbase_tx(50_000_000 + 10)

    art_id = "abc123"
    recipients = [{"addr": address, "amount": 10_000_000}]
    meta = {
        "event": "PAYOUT",
        "art_id": art_id,
        "epoch": 1,
        "recipients": recipients,
        "proof_epoch": 1,
    }
    opret_script = GRAFFITI.build_script(meta).serialize()
    opret_out = DummyTxOut(0, opret_script)
    pay_out = DummyTxOut(10_000_000, spk_p2wpkh)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [opret_out, pay_out], fee=10)

    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True

def test_validate_transactions_graffiti_payout_sync_mode_inline_proof_ok(validation_chain, mocker):
    """PAYOUT with empty registry (regular sync from genesis) validates via inline proof metadata."""
    chain = validation_chain

    hash20 = b'\x00' * 20
    spk_p2wpkh = b'\x00\x14' + hash20
    data = [0] + list(convertbits(hash20, 8, 5, True))
    address = bech32_encode(CFG.ADDRESS_PREFIX, data)

    cb = create_coinbase_tx(50_000_000 + 10)
    art_id = "abc123"
    recipients = [{"addr": address, "amount": 10_000_000}]
    meta = {
        "event": "PAYOUT",
        "art_id": art_id,
        "epoch": 1,
        "recipients": recipients,
        "proof_epoch": 1,
        "proof_storer": address,
    }
    opret_script = GRAFFITI.build_script(meta).serialize()
    opret_out = DummyTxOut(0, opret_script)
    pay_out = DummyTxOut(10_000_000, spk_p2wpkh)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [opret_out, pay_out], fee=10)

    graffiti_data = GRAFFITI.encode_payload(meta)
    chain._mock_H.last_pushdata.side_effect = lambda script: graffiti_data if (isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a) else None
    chain._mock_graffiti.parse_payload.side_effect = lambda data: meta if data == graffiti_data else None

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            raw = ser() if callable(ser) else bytes(script)
            data = chain._mock_H.last_pushdata(raw)
            if data:
                return chain._mock_graffiti.parse_payload(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        },
        "storer": address,
    }
    # Simulated sync mode: registry has no proofs yet
    mock_registry.get_latest_proof_epoch.return_value = -1
    mock_registry.get_proof.return_value = None
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=18, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is True

def test_validate_transactions_graffiti_payout_bad_art_id(validation_chain, mocker):
    """PAYOUT with empty art_id -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "",  # empty
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_bad_art_id"

def test_validate_transactions_graffiti_payout_unknown_art(validation_chain, mocker):
    """PAYOUT for art_id not in registry -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "unknown_art",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = None
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_unknown_art"

def test_validate_transactions_graffiti_payout_epoch_rewind(validation_chain, mocker):
    """PAYOUT with epoch <= last_paid_epoch -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 0,  # <= last_paid_epoch (0)
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        "proof_epoch": 0,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_epoch_rewind"

def test_validate_transactions_graffiti_payout_missing_proof(validation_chain, mocker):
    """PAYOUT with epoch > latest_proof and no inline proof -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 2,
        "recipients": [{"addr": "tsar1q...", "amount": 10_000_000}],
        # tidak ada proof_epoch atau proof_height
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_missing_proof"

def test_validate_transactions_graffiti_payout_no_recipients(validation_chain, mocker):
    """PAYOUT with empty recipients -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [],  # empty
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_no_recipients"

def test_validate_transactions_graffiti_payout_bad_recipient(validation_chain, mocker):
    """PAYOUT with invalid recipient address or amount <=0 -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 0}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_bad_recipient"

def test_validate_transactions_graffiti_payout_shortfall(validation_chain, mocker):
    """PAYOUT where actual payment to address is less than requested -> error."""
    chain = validation_chain
    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": "tsar1q...", "amount": 20_000_000}],
        "proof_epoch": 1,
    }
    tx = create_graffiti_tx(meta)
    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_shortfall"

def test_validate_transactions_graffiti_payout_exceeds_pool(validation_chain, mocker):
    """PAYOUT where total requested exceeds pool_balance -> error."""
    chain = validation_chain

    # Buat P2WPKH address dummy (hash 20 byte nol)
    hash20 = b'\x00' * 20
    spk_p2wpkh = b'\x00\x14' + hash20
    data = [0] + list(convertbits(hash20, 8, 5, True))
    address = bech32_encode(CFG.ADDRESS_PREFIX, data)

    cb = create_coinbase_tx(50_000_000 + 10)

    meta = {
        "event": "PAYOUT",
        "art_id": "abc123",
        "epoch": 1,
        "recipients": [{"addr": address, "amount": 150_000_000}],
        "proof_epoch": 1,
    }
    opret_script = GRAFFITI.build_script(meta).serialize()
    opret_out = DummyTxOut(0, opret_script)
    pay_out = DummyTxOut(150_000_000, spk_p2wpkh)
    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx = create_normal_tx([tx_input], [opret_out, pay_out], fee=10)

    graffiti_data = GRAFFITI.encode_payload(meta)

    def last_pushdata_side_effect(script):
        if isinstance(script, bytes) and len(script) > 0 and script[0] == 0x6a:
            return graffiti_data
        return None
    chain._mock_H.last_pushdata.side_effect = last_pushdata_side_effect

    def parse_payload_side_effect(data):
        if data == graffiti_data:
            return meta
        return None
    chain._mock_graffiti.parse_payload.side_effect = parse_payload_side_effect

    def parse_from_script_side_effect(script):
        if script is not None:
            ser = getattr(script, "serialize", None)
            if callable(ser):
                raw = ser()
            else:
                raw = bytes(script)
            data = last_pushdata_side_effect(raw)
            if data:
                return parse_payload_side_effect(data)
        return None
    chain._mock_graffiti.parse_from_script.side_effect = parse_from_script_side_effect

    mock_registry = mocker.Mock()
    mock_registry.get_post.return_value = {
        "stats": {
            "pool_balance": 100_000_000,
            "last_paid_epoch": 0,
        }
    }
    mock_registry.get_latest_proof_epoch.return_value = 1
    chain._mock_utxo._graffiti_registry = mock_registry

    block = DummyBlock(height=10, transactions=[cb, tx])
    chain._mock_H.native_validate_block_txs_compact.return_value = (True, None, [10])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "payout_exceeds_pool"
# --- Tests from valid_tx_test.py ---
def test_validate_transactions_valid(validation_chain):
    """Scenario 1: A valid block with a coinbase and one normal transaction."""
    chain = validation_chain

    reward = 50_000_000
    fee = 10
    cb = create_coinbase_tx(reward + fee)

    txid_prev = b'\xaa' * 32
    tx_input = create_utxo_input(txid_prev, 0)
    tx_output = create_output(100_000_000, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    normal_tx = create_normal_tx([tx_input], [tx_output], fee=fee)

    chain._mock_H.last_pushdata.return_value = None

    block = DummyBlock(height=10, transactions=[cb, normal_tx])

    result = chain._validate_transactions(block)
    assert result is True


def test_validate_transactions_missing_coinbase(validation_chain):
    """Scenario 2: the first transaction is not a coinbase transaction -> fails."""
    chain = validation_chain

    tx_input = create_utxo_input(b'\xaa' * 32, 0)
    tx_output = create_output(100, b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac')
    normal_tx = create_normal_tx([tx_input], [tx_output])

    block = DummyBlock(height=10, transactions=[normal_tx])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "missing_coinbase"


def test_validate_transactions_duplicate_coinbase(validation_chain):
    """Scenario 3: more than one coinbase -> failure."""
    chain = validation_chain

    cb1 = create_coinbase_tx(50_000_000)
    cb2 = create_coinbase_tx(50_000_000)
    block = DummyBlock(height=10, transactions=[cb1, cb2])

    result = chain._validate_transactions(block)
    assert result is False
    assert chain._last_block_validation_error == "duplicate_coinbase"


def test_validation_pow_warmup_flag():
    """Verify that _pow_light_warmed flag is correctly updated to True."""
    from unittest.mock import MagicMock, patch
    from tsarchain.consensus.validation import BlockValidator
    validator = BlockValidator(blockchain=MagicMock())
    BlockValidator._pow_light_warmed = False

    block = MagicMock()
    block.height = 1
    block.prev_block_hash = b"\x01" * 32
    block.transactions = [MagicMock()]
    block.header.return_value = b"\x00" * 80

    with patch('tsarchain.consensus.validation.CFG.POW_ALGO', 'randomx'), \
         patch('tsarchain.utils.helpers.pow_hash_verify_light') as mock_verify:
        validator._warm_pow_context = MagicMock()
        validator._ensure_warm = MagicMock()
        validator._validate_pow = MagicMock(return_value=True)
        validator.compute_txids_for_block = MagicMock(return_value=True)
        validator._validate_merkle = MagicMock(return_value=True)
        validator._ensure_unique_txids = MagicMock(return_value=True)
        validator._check_block_limits = MagicMock(return_value=True)
        validator._validate_tx_scripts_and_balances = MagicMock(return_value=True)
        validator._validate_graffiti_rules = MagicMock(return_value=True)

        validator.validate_block(block)
        assert BlockValidator._pow_light_warmed is True
        mock_verify.assert_called_once()


def test_validate_graffiti_posts_duplicate_rejected():
    from unittest.mock import MagicMock, patch
    validator = BlockValidator(blockchain=MagicMock())
    sha = "8" * 64
    mroot = "9" * 64
    art_id = "a" * 64

    reg_mock = MagicMock()
    reg_mock.get_post.return_value = {
        "art_id": art_id,
        "sha256": sha,
        "mroot": mroot,
    }

    tx = MagicMock()
    out = MagicMock()
    out.script_pubkey = MagicMock()
    tx.outputs = [out]
    cb = MagicMock()
    cb.block_id = art_id

    with patch("tsarchain.consensus.validation.GRAFFITI.parse_from_script") as mock_parse:
        mock_parse.return_value = {
            "event": "POST",
            "art_id": art_id,
            "sha256": sha,
            "mroot": mroot,
            "size": 100,
        }
        res = validator._validate_graffiti_posts([MagicMock(), tx], cb, reg=reg_mock)
        assert res is False
        assert validator.blockchain._last_block_validation_error == "graffiti_duplicate_post"



