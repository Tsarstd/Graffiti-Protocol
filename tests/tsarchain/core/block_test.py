# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import patch, MagicMock
from tsarchain.core.block import BlockHeader, Block
from tsarchain.utils import config as CFG

def test_block_header_init_and_serialize():
    with patch("tsarchain.core.block.int_to_little_endian") as mock_le:
        mock_le.return_value = b"4444"
        bh = BlockHeader(
            version=1,
            prev_block_hash=b"prev",
            merkle_root=b"mr",
            timestamp=123,
            bits=456,
            nonce=789
        )
        assert bh.version == 1
        assert bh.prev_block_hash == b"prev"
        assert bh.merkle_root == b"mr"
        assert bh.timestamp == 123
        assert bh.bits == 456
        assert bh.nonce == 789

        s = bh.serialize_block()
        # 1 version, 1 timestamp, 1 bits, 1 nonce -> 4 calls to int_to_little_endian
        assert s == b"4444" + b"prev" + b"mr" + b"4444" + b"4444" + b"4444"
        
        # Test hex strings
        bh2 = BlockHeader(1, "0011", "2233", 123, 456, 789)
        s2 = bh2.serialize_block()
        assert bytes.fromhex("0011") in s2
        assert bytes.fromhex("2233") in s2

@patch("tsarchain.core.block.time.time")
@patch("tsarchain.core.block.merkle_root")
def test_block_init(mock_mr, mock_time):
    mock_time.return_value = 1000
    mock_mr.return_value = b"mr_computed"
    
    # Without precomputed mr
    b = Block(height=1, prev_block_hash=b"prev", transactions=[])
    assert b.height == 1
    assert b.prev_block_hash == b"prev"
    assert b.transactions == []
    assert b.version == 1
    assert b.merkle_root == b"mr_computed"
    assert b.timestamp == 1000
    assert b.bits == CFG.INITIAL_BITS
    assert b.nonce == 0
    assert b._cached_hash is None

    # With precomputed mr
    b2 = Block(height=2, prev_block_hash=b"p", transactions=[], merkle_root_precomputed=b"mr_pre")
    assert b2.merkle_root == b"mr_pre"

def test_block_parse_bits():
    # CFG.INITIAL_BITS mock if needed
    assert Block._parse_bits(None) == (int(CFG.INITIAL_BITS) & 0xFFFFFFFF)
    assert Block._parse_bits(True) == (int(CFG.INITIAL_BITS) & 0xFFFFFFFF)
    assert Block._parse_bits(123) == 123
    assert Block._parse_bits(123.0) == 123
    with pytest.raises(TypeError):
        Block._parse_bits(123.5)
    assert Block._parse_bits("123") == 123
    assert Block._parse_bits("0x123") == 0x123
    with pytest.raises(TypeError):
        Block._parse_bits([])

@patch("tsarchain.core.block.Block.hash")
@patch("tsarchain.core.block.merkle_root")
def test_block_to_dict(mock_mr, mock_hash):
    mock_mr.return_value = b"mr"
    mock_hash.return_value = b"blockhash"
    
    tx = MagicMock()
    tx.is_coinbase = False
    tx.fee = 250
    tx.to_dict.return_value = {"tx": 1}
    
    b = Block(height=1, prev_block_hash=b"prev", transactions=[tx], timestamp=1000, bits=456, nonce=789)
    b.difficulty = 1.0
    b.chainwork = "0001"
    
    d = b.to_dict()
    assert d["height"] == 1
    assert d["version"] == 1
    assert d["prev_block_hash"] == b"prev".hex()
    assert d["merkle_root"] == b"mr".hex()
    assert d["timestamp"] == 1000
    assert d["difficulty"] == 1.0
    assert d["chainwork"] == "0001"
    assert d["bits"] == 456
    assert d["nonce"] == 789
    assert d["hash"] == b"blockhash".hex()
    assert d["total_fee"] == 250
    assert d["transactions"] == [{"tx": 1}]

def test_block_from_dict():
    d = {
        "height": 1,
        "version": 2,
        "prev_block_hash": (b"prev").hex(),
        "merkle_root": (b"mr").hex(),
        "timestamp": 1000,
        "difficulty": 1.0,
        "chainwork": "0001",
        "bits": 456,
        "nonce": 789,
        "transactions": [
            {"type": "Coinbase", "to_address": "addr", "reward": 50, "block_id": "b1", "height": 1, "txid": "00"*32},
            {"type": "Tx", "txid": "11"*32}
        ],
        "hash": ("22"*32), # 64 chars
        "_meta": {"size_bytes": 100, "vbytes": 100, "weight": 400}
    }
    
    with patch("tsarchain.core.block.CoinbaseTx.from_dict") as mock_cb, \
         patch("tsarchain.core.block.Tx.from_dict") as mock_tx:
        mock_cb.return_value = "cb_tx"
        mock_tx.return_value = "std_tx"
        
        b = Block.from_dict(d)
        
        assert b.height == 1
        assert b.version == 2
        assert b.prev_block_hash == b"prev"
        assert b.merkle_root == b"mr"
        assert b.transactions == ["cb_tx", "std_tx"]
        assert b.difficulty == 1.0
        assert b.chainwork == "0001"
        assert b.size_bytes == 100
        assert b.vbytes == 100
        assert b.weight == 400
        assert b._cached_hash == bytes.fromhex("22"*32)

def test_block_from_dict_edge_cases():
    # Covers missing hash, bad hash, and _meta populating difficulty/chainwork
    d = {
        "height": 1,
        "prev_block_hash": b"prev".hex(),
        "transactions": [],
        "hash": "Z" * 64, # Cover lines 143-145 (exception on bytes.fromhex)
        "_meta": {"chainwork": "0002", "difficulty": 2.0} # Cover lines 151, 153
    }
    with patch("tsarchain.core.block.CoinbaseTx.from_dict"), \
         patch("tsarchain.core.block.Tx.from_dict"):
        b = Block.from_dict(d)
        assert b._cached_hash is None
        assert b.chainwork == "0002"
        assert b.difficulty == 2.0

def test_block_storage_bytes_roundtrip():
    d = {
        "height": 5,
        "version": 1,
        "prev_block_hash": ("00" * 32),
        "merkle_root": ("11" * 32),
        "timestamp": 12345678,
        "difficulty": 2048,
        "chainwork": 4096,
        "bits": 530579455,
        "nonce": 1475,
        "transactions": [],
    }
    b = Block.from_dict(d)
    raw = b.to_storage_bytes()
    assert len(raw) >= 108
    b_restored = Block.from_storage_bytes(raw)
    assert b_restored.height == b.height
    assert b_restored.difficulty == b.difficulty
    assert b_restored.chainwork == b.chainwork
    assert b_restored.bits == b.bits
    assert b_restored.nonce == b.nonce
    assert b_restored.timestamp == b.timestamp

@patch("tsarchain.core.block.BlockHeader.serialize_block")
def test_block_header(mock_serialize):
    mock_serialize.return_value = b"header_bytes"
    b = Block(1, b"prev", [])
    assert b.header() == b"header_bytes"

@patch("tsarchain.core.block.pow_hash_verify_light")
@patch("tsarchain.core.block.pow_key_for_height")
def test_block_hash(mock_key, mock_pow, monkeypatch):
    b = Block(1, b"prev", [])
    b.merkle_root = b"mr"
    
    mock_key.return_value = b"key"
    mock_pow.return_value = b"computed_hash"
    
    # 1. Not cached
    assert b._cached_hash is None
    h1 = b.hash()
    assert h1 == b"computed_hash"
    assert b._cached_hash == b"computed_hash"
    assert b._cached_hash_nonce == b.nonce
    
    # 2. Cached
    mock_pow.return_value = b"new_hash"
    h2 = b.hash()
    assert h2 == b"computed_hash" # Returned cached
    
    # 3. Inputs changed -> recompute
    b.nonce += 1
    h3 = b.hash()
    assert h3 == b"new_hash"
    
    # 4. Exception in pow_key_for_height
    mock_key.side_effect = Exception("test")
    mock_pow.return_value = b"hash_fallback"
    b.nonce += 1
    h4 = b.hash()
    assert h4 == b"hash_fallback"
    mock_pow.assert_called_with(b.header(), height=1)

@patch("tsarchain.core.block.mp.cpu_count")
@patch("tsarchain.core.block.bits_to_target")
@patch("tsarchain.core.block.pow_key_for_height")
@patch("tsarchain.core.block.native_randomx_mine")
@patch("tsarchain.core.block.pow_hash_verify_light")
def test_block_mine(mock_verify, mock_native, mock_key, mock_target, mock_cpu, monkeypatch):
    mock_cpu.return_value = 4
    b = Block(1, b"prev", [])
    
    # Stop event set
    stop_event = MagicMock()
    stop_event.is_set.return_value = True
    assert b.mine(stop_event=stop_event) is None
    
    stop_event.is_set.return_value = False
    
    # Target <= 0
    mock_target.return_value = 0
    assert b.mine(stop_event=stop_event) is None
    
    # Backend auto covering line 220 (where backend="auto" -> "randomx")
    monkeypatch.setattr(CFG, "POW_ALGO", "auto")
    mock_target.return_value = 100
    mock_key.return_value = b"key"
    mock_native.return_value = (123, b"mined_hash")
    mock_verify.return_value = b"mined_hash"
    assert b.mine(pow_backend="") == b"mined_hash"
    
    # Backend invalid
    mock_target.return_value = 100
    with pytest.raises(RuntimeError, match="Unsupported PoW backend"):
        b.mine(pow_backend="sha256")
        
    # No pow key
    mock_key.return_value = None
    with pytest.raises(RuntimeError, match="RandomX key derivation failed"):
        b.mine()
        
    # Successful mine
    mock_key.return_value = b"key"
    mock_native.return_value = (123, b"mined_hash")
    mock_verify.return_value = b"mined_hash"
    
    h = b.mine(use_cores=2)
    assert h == b"mined_hash"
    assert b.nonce == 123
    
    # Verification failed
    mock_native.return_value = (456, b"mined_hash")
    mock_verify.return_value = b"different_hash"
    assert b.mine() is None
    
    # None returned from native
    mock_native.return_value = None
    assert b.mine() is None

def test_block_repr():
    b = Block(1, b"prev", [], timestamp=1000)
    with patch("tsarchain.core.block.Block.hash", return_value=b"hash"):
        r = repr(b)
        assert "--- Block 1 ---" in r
        assert "PrevHash : " + b"prev".hex() in r
        assert "Hash     : " + b"hash".hex() in r


def test_block_storage_bytes_coinbase_validation():
    from tsarchain.core.coinbase import CoinbaseTx
    from tsarchain.consensus.validation import BlockValidator
    from tsarchain.utils.helpers import spkhex_to_address

    addr = spkhex_to_address("0014" + "00" * 20)
    cb = CoinbaseTx(to_address=addr, reward=5000000000, block_id="blk_0", height=0)
    b = Block(height=0, prev_block_hash=b"\x00" * 32, transactions=[cb], timestamp=1000, bits=0x1F00FFFF, nonce=123)
    raw = b.to_storage_bytes()
    restored = Block.from_storage_bytes(raw)
    assert len(restored.transactions) == 1
    assert restored.transactions[0].is_coinbase is True

    mock_bc = MagicMock()
    validator = BlockValidator(mock_bc)
    ok = validator.compute_txids_for_block(restored)
    assert ok is True


