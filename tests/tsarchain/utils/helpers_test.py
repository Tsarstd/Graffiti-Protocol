# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import hashlib
import pytest
from unittest.mock import patch, MagicMock
from tsarchain.utils.helpers import ( Script, 
    sha256, hash160, hash256,
    int_to_little_endian,
    is_p2wpkh, is_p2wsh,
    bits_to_target, target_to_bits,
    target_to_difficulty, difficulty_to_target,
    block_id_generator,
    parse_ops, last_pushdata,
    pow_hash_miner, pow_hash_verify_light,
    randomx_key_for_height, pow_key_for_height,
    to_bytes, compute_tx_weight_vsize,
    tx_to_compact_tuple,
    count_sigops_in_script, batch_verify_der_low_s, bip143_sig_hash,
    sign_digest_der_low_s_native, merkle_root,
    native_validate_block_txs,
    native_randomx_mine
)

def test_hashing():
    data = b"hello world"
    assert sha256(data) == hashlib.sha256(data).digest()

def test_endian_conversion():
    num = 123456
    b = int_to_little_endian(num, 4)
    assert len(b) == 4
    assert int.from_bytes(b, 'little') == num

def test_is_p2wpkh():
    valid_script = b'\x00\x14' + b'\x01' * 20
    assert is_p2wpkh(valid_script) is True
    assert is_p2wsh(valid_script) is False

    invalid_script1 = b'\x00\x14' + b'\x01' * 19
    assert is_p2wpkh(invalid_script1) is False

    valid_p2wsh = b'\x00\x20' + b'\x02' * 32
    assert is_p2wsh(valid_p2wsh) is True

def test_bits_target():
    target = 0x00000000ffff0000000000000000000000000000000000000000000000000000
    bits = target_to_bits(target)
    assert bits_to_target(bits) > 0
    assert target_to_bits(0) == 50397184
    
    assert bits_to_target(0x04000000) == 0

def test_difficulty():
    target = difficulty_to_target(100)
    diff = target_to_difficulty(target)
    assert diff > 0
    assert target_to_difficulty(0) > 0
    assert difficulty_to_target(0) > 0

def test_block_id_generator():
    bid = block_id_generator()
    assert isinstance(bid, str)
    assert len(bid) > 0

def test_script_serialization():
    s = Script([0x00, b"data"])
    b = s.serialize()
    s2 = Script.deserialize(b)
    assert s2.cmds == s.cmds
    assert s2.to_dict() == {"cmds": [0, "64617461"]}
    s3 = Script.from_dict(s2.to_dict())
    assert s3.cmds == s.cmds
    
    # OP_PUSHDATA1
    b_data = b"x" * 100
    s_push1 = Script([b_data])
    assert s_push1.serialize()[0] == 0x4c
    
    # Parse OP_PUSHDATA1
    parsed = Script.deserialize(s_push1.serialize())
    assert parsed.cmds == [b_data]

    # OP_PUSHDATA2
    b_data2 = b"x" * 300
    s_push2 = Script([b_data2])
    assert s_push2.serialize()[0] == 0x4d
    
    # OP_PUSHDATA4
    b_data4 = b"x" * 70000
    s_push4 = Script([b_data4])
    assert s_push4.serialize()[0] == 0x4e

def test_build_opreturn_script():
    s = Script.build_opreturn_script(b"test", 80)
    assert isinstance(s, str)
    
    with pytest.raises(ValueError):
        Script.build_opreturn_script(b"test", 2)
        
    # > 75 bytes
    s_76 = Script.build_opreturn_script(b"x" * 76, 100)
    assert s_76.startswith("6a4c4c")
    
    # > 255 bytes
    s_300 = Script.build_opreturn_script(b"x" * 300, 400)
    assert s_300.startswith("6a4d")

def test_parse_ops():
    script = b"\x04\x01\x02\x03\x04\x76" # Push 4 bytes, OP_DUP
    ops = parse_ops(script)
    assert ops[0][1] == b"\x01\x02\x03\x04"
    assert ops[1][0] == 0x76
    
    assert last_pushdata(script) == b"\x01\x02\x03\x04"



def test_randomx_helpers():
    with patch("tsarchain.utils.helpers.CFG") as mock_cfg:
        mock_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        mock_cfg.RANDOMX_KEY_SALT = b"salt"
        mock_cfg.RANDOMX_STATIC_KEY = "test"
        
        key = randomx_key_for_height(10)
        assert isinstance(key, bytes)
        assert pow_key_for_height(10) == key

@patch("tsarchain.utils.helpers._native_hash160", return_value=b"a"*20)
def test_native_hash160(m):
    assert hash160(b"data") == b"a"*20

@patch("tsarchain.utils.helpers._native_hash256", return_value=b"b"*32)
def test_native_hash256(m):
    assert hash256(b"data") == b"b"*32

@patch("tsarchain.utils.helpers._native_count_sigops", return_value=5)
def test_count_sigops(m):
    assert count_sigops_in_script(b"test") == 5

@patch("tsarchain.utils.helpers._native_verify_many", return_value=[True])
def test_batch_verify(m):
    assert batch_verify_der_low_s([1,2,3]) == [True]
    
@patch("tsarchain.utils.helpers._native_sighash_bip143", return_value=b"c"*32)
@patch("tsarchain.utils.helpers.serialize_tx", return_value=b"tx")
def test_bip143(m_s, m_b):
    tx = MagicMock()
    assert bip143_sig_hash(tx, 0, b"script", 100) == b"c"*32



@patch("tsarchain.utils.helpers._native_sign_der_low_s", return_value=b"sig")
def test_sign_digest(m):
    assert sign_digest_der_low_s_native("hex", b"y"*32) == b"sig"

@patch("tsarchain.utils.helpers._native_merkle_root", return_value=b"root")
def test_merkle(m):
    assert merkle_root([b"x"*32]) == b"root"
    assert merkle_root([]) == b"\x00" * 32
    
    # Objects with .txid attribute (e.g. Tx, CoinbaseTx)
    t1 = MagicMock()
    t1.txid = b"x"*32
    assert merkle_root([t1]) == b"root"

@patch("tsarchain.utils.helpers._native_validate_block_txs")
def test_native_calls(m):
    native_validate_block_txs({}, {}, 1, {})
    m.assert_called()

def test_to_bytes():
    assert to_bytes(b"x") == b"x"
    assert to_bytes("00") == b"\x00"
    s = Script([OP_0 := 0x00])
    assert to_bytes(s) == b"\x00"

@patch("tsarchain.utils.helpers.serialize_tx")
def test_tx_sizing(m_s):
    m_s.side_effect = [b"a"*10, b"a"*20] # base, full
    w, v, b, t = compute_tx_weight_vsize(MagicMock())
    assert b == 10
    assert t == 20
    assert w == 50
    assert v == 13

def test_tx_to_compact_tuple():
    tx = MagicMock()
    tx.version = 1
    tx.locktime = 0
    in1 = MagicMock()
    in1.txid = b"p"*32
    in1.vout = 0
    in1.sequence = 0
    in1.script_sig = b"sig"
    in1.witness = [b"w"]
    tx.inputs = [in1]
    
    out1 = MagicMock()
    out1.amount = 10
    out1.script_pubkey = b"spk"
    tx.outputs = [out1]
    
    with patch("tsarchain.utils.helpers.txid_from_compact", return_value=b"txid"):
        tup = tx_to_compact_tuple(tx)
        assert tup[0] == 1
        assert tup[4] == b"txid"

@patch("tsarchain.utils.helpers._native_randomx_mine", return_value=(1, b"hash"))
def test_native_randomx_mine(m):
    assert native_randomx_mine(b"hdr", b"tgt", b"key") == (1, b"hash")

@patch("tsarchain.utils.helpers._native_randomx_hash", return_value=b"hash")
def test_pow_hashes(m_hash):
    with patch("tsarchain.utils.helpers.CFG") as m_cfg:
        m_cfg.RANDOMX_KEY_SALT = b"salt"
        m_cfg.RANDOMX_KEY_EPOCH_BLOCKS = 100
        assert pow_hash_miner(b"h") == b"hash"
        assert pow_hash_verify_light(b"h") == b"hash"



def test_script_push_errors():
    from tsarchain.utils.helpers import Script
    with pytest.raises(ValueError):
        Script.deserialize(b"\x05\x00") # short read small push
    with pytest.raises(ValueError):
        Script.deserialize(b"\x4c") # short read push1 header
    with pytest.raises(ValueError):
        Script.deserialize(b"\x4c\x05\x00") # short read push1 payload
    with pytest.raises(ValueError):
        Script.deserialize(b"\x4d") # short read push2 header
    with pytest.raises(ValueError):
        Script.deserialize(b"\x4e") # short read push4 header

def test_to_bytes_fallback():
    from tsarchain.utils.helpers import to_bytes
    assert to_bytes(None) == b""
    assert to_bytes(123) == b""

def test_estimate_block_size():
    from tsarchain.utils.helpers import estimate_block_size_bytes
    b = MagicMock()
    tx = MagicMock()
    tx.inputs = []
    tx.outputs = []
    tx.to_dict.return_value = {}
    b.transactions = [tx]
    b.to_dict.return_value = {}
    assert estimate_block_size_bytes(b) >= 80

def test_spkhex_to_address():
    from tsarchain.utils.helpers import spkhex_to_address
    assert spkhex_to_address("0014" + "0"*40) is not None
    assert spkhex_to_address("0020" + "0"*64) is not None
    assert spkhex_to_address(bytes.fromhex("0014" + "0"*40)) is not None
    assert spkhex_to_address("0014" + "0"*10) is None
    assert spkhex_to_address("1114" + "0"*40) is None
    assert spkhex_to_address("0020" + "0"*10) is None
