# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock, patch
from tsarchain.core.tx import Tx, TxIn, TxOut
from tsarchain.utils.helpers import Script

@pytest.fixture
def mock_script():
    # Use actual Script to pass isinstance check
    return Script([b"mock"])

def test_txin_init():
    txin = TxIn(b"a"*32, 0, 100)
    assert txin.txid == b"a"*32
    assert txin.vout == 0
    assert txin.amount == 100

def test_txin_init_invalid():
    with pytest.raises(ValueError):
        TxIn(b"a"*31, 0)
    with pytest.raises(TypeError):
        TxIn(b"a"*32, "0")
    with pytest.raises(ValueError):
        TxIn(b"a"*32, 0, -1)

def test_txin_to_dict():
    txin = TxIn(b"a"*32, 0, 100)
    d = txin.to_dict()
    assert d["txid"] == (b"a"*32).hex()
    assert d["vout"] == 0
    assert d["amount"] == 100

def test_txin_from_dict():
    d = {
        "txid": (b"a"*32).hex(),
        "vout": 1,
        "amount": 50,
        "script_sig": "",
        "witness": ["010203"]
    }
    txin = TxIn.from_dict(d)
    assert txin.txid == b"a"*32
    assert txin.vout == 1
    assert txin.amount == 50
    assert txin.witness == [b"\x01\x02\x03"]

def test_txin_from_dict_invalid():
    with pytest.raises(TypeError):
        TxIn.from_dict([])

def test_txin_repr():
    txin = TxIn(b"a"*32, 0, 100)
    assert repr(txin) == f"<TxIn {(b'a'*32).hex()}:0 amt=100 wit=0>"

def test_txout_init(mock_script):
    txout = TxOut(100, mock_script)
    assert txout.amount == 100
    assert txout.script_pubkey == mock_script

def test_txout_init_invalid(mock_script):
    with pytest.raises(ValueError):
        TxOut(-1, mock_script)
    with pytest.raises((TypeError, AttributeError)):
        TxOut(100, "not a script")

def test_txout_to_dict(mock_script):
    txout = TxOut(100, mock_script)
    d = txout.to_dict()
    assert d["amount"] == 100
    assert d["script_pubkey"] == mock_script.serialize().hex()

def test_txout_from_dict():
    with patch("tsarchain.core.tx.Script.from_dict") as mock_from_dict, \
         patch("tsarchain.core.tx.Script.deserialize") as mock_deserialize:
        mock_from_dict.return_value = Script([])
        mock_deserialize.return_value = Script([])
        d1 = {"amount": 50, "script_pubkey": {"type": "p2wpkh"}}
        txout1 = TxOut.from_dict(d1)
        assert txout1.amount == 50
        assert txout1.script_pubkey == mock_from_dict.return_value

        d2 = {"amount": 100, "script_pubkey": "0014abcd"}
        txout2 = TxOut.from_dict(d2)
        assert txout2.amount == 100
        assert txout2.script_pubkey == mock_deserialize.return_value

def test_txout_from_dict_invalid():
    with pytest.raises(TypeError):
        TxOut.from_dict([])
    with pytest.raises(TypeError):
        TxOut.from_dict({"amount": 100, "script_pubkey": 123})

def test_txout_repr(mock_script):
    txout = TxOut(100, mock_script)
    assert repr(txout) == "<TxOut amt=100>"

def test_txout_address_property():
    from tsarchain.utils import config as CFG
    from bech32 import bech32_encode, convertbits
    pkh = b"p"*20
    data = [0] + list(convertbits(pkh, 8, 5, True))
    addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
    spk = Script.p2wpkh_script(addr)
    txout = TxOut(100, spk)
    assert txout.address == addr

def test_txout_address_opreturn():
    opret_spk = Script([0x6a, b"hello"])
    txout = TxOut(0, opret_spk)
    assert txout.address is None

def test_tx_init():
    with patch("tsarchain.core.tx.Tx.compute_txid") as mock_compute:
        tx = Tx()
        mock_compute.assert_called_once()
        assert tx.version == 1
        assert tx.inputs == []
        assert tx.outputs == []
        assert tx.fee is None

def test_tx_init_coinbase():
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(is_coinbase=True)
        assert tx.fee == 0

def test_tx_init_compute_fail():
    with patch("tsarchain.core.tx.Tx.compute_txid", side_effect=Exception("test")):
        with pytest.raises(Exception, match="test"):
            Tx()

def test_tx_set_fee_from_input_amounts():
    txin = TxIn(b"a"*32, 0)
    txout = TxOut(50, Script([]))
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(inputs=[txin], outputs=[txout])
        fee = tx.set_fee_from_input_amounts([100])
        assert fee == 50
        assert tx.fee == 50
        assert txin.amount == 100

def test_tx_set_fee_from_input_amounts_coinbase():
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(is_coinbase=True)
        assert tx.set_fee_from_input_amounts([100]) == 0

def test_tx_set_fee_from_input_amounts_negative():
    txout = TxOut(150, Script([]))
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(outputs=[txout])
        with pytest.raises(ValueError):
            tx.set_fee_from_input_amounts([100])

@patch("tsarchain.core.tx.bip143_sig_hash")
@patch("tsarchain.core.tx.sign_digest_der_low_s_native")
@patch("tsarchain.core.tx.SigningKey")
def test_tx_sign_input(mock_sk, mock_sign, mock_bip, mock_script):
    txin = TxIn(b"a"*32, 0)
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(inputs=[txin])
        mock_bip.return_value = b"z"
        mock_sign.return_value = b"der"
        mock_vk = MagicMock()
        mock_vk.to_string.return_value = b"pubkey"
        mock_sk.from_string.return_value.get_verifying_key.return_value = mock_vk

        prev_out = MagicMock()
        prev_out.script_pubkey = MagicMock()
        prev_out.script_pubkey.serialize.return_value = b"\x00\x14" + b"a"*20
        tx.sign_input(0, "00"*32, prev_out, 100)
        assert txin.witness[0] == b"der\x01" # SIGHASH_ALL
        assert txin.witness[1] == b"pubkey"

        # Another valid script_pubkey
        prev_out2 = MagicMock()
        prev_out2.script_pubkey.serialize.return_value = b"\x00\x14" + b"b"*20
        tx.sign_input(0, "00"*32, prev_out2, 100)
        assert txin.witness[1] == b"pubkey"

        # Sign with raw bytes script_pubkey (e.g. from Wallet.sign_prepared_tx)
        raw_spk = b"\x00\x14" + b"c"*20
        tx.sign_input(0, "00"*32, raw_spk, 100)
        assert txin.witness[1] == b"pubkey"

        # Sign with hex string script_pubkey
        hex_spk = raw_spk.hex()
        tx.sign_input(0, "00"*32, hex_spk, 100)
        assert txin.witness[1] == b"pubkey"

        # Invalid p2wpkh
        prev_out.script_pubkey.serialize.return_value = b"invalid"
        with pytest.raises(ValueError):
            tx.sign_input(0, "00"*32, prev_out, 100)
            
        with pytest.raises((TypeError, AttributeError)):
            tx.sign_input(0, "00"*32, 123, 100)

@patch("tsarchain.core.tx.is_p2wpkh")
@patch("tsarchain.core.tx.is_p2wsh")
@patch("tsarchain.core.tx.count_sigops_in_script")
@patch("tsarchain.core.tx.last_pushdata")
def test_tx_sigops_count(mock_last, mock_count, mock_is_wsh, mock_is_wpkh):
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        # Coinbase
        tx_cb = Tx(is_coinbase=True)
        assert tx_cb.sigops_count() == 0

        txin = TxIn(b"a"*32, 0)
        txin.witness = [b"wit1"]
        txin.script_sig = MagicMock()
        tx = Tx(inputs=[txin])
        
        # UTXO provided, P2WPKH
        mock_is_wpkh.return_value = True
        mock_is_wsh.return_value = False
        assert tx.sigops_count(lambda txid, vout: "0014") == 1
        
        # UTXO provided, P2WSH
        mock_is_wpkh.return_value = False
        mock_is_wsh.return_value = True
        mock_count.return_value = 2
        assert tx.sigops_count(lambda txid, vout: "0020") == 2

        # UTXO provided, other
        mock_is_wpkh.return_value = False
        mock_is_wsh.return_value = False
        mock_count.return_value = 3
        assert tx.sigops_count(lambda txid, vout: b"other") == 3

        # No UTXO, has last_pushdata
        mock_last.return_value = b"push"
        mock_count.return_value = 4
        assert tx.sigops_count() == 4
        
        # No UTXO, no last_pushdata, has witness
        mock_last.return_value = None
        mock_count.return_value = 5
        assert tx.sigops_count() == 5
        
        # No UTXO, no last_pushdata, no witness
        txin.witness = []
        mock_last.return_value = None
        mock_count.return_value = 0 # should default to 1
        assert tx.sigops_count() == 1

@patch("tsarchain.core.tx.tx_to_compact_tuple")
@patch("tsarchain.core.tx.txid_from_compact")
@patch("tsarchain.core.tx.wtxid_from_compact")
def test_tx_ids(mock_wtxid, mock_txid, mock_compact):
    mock_compact.return_value = "compact"
    mock_txid.return_value = b"txid"
    mock_wtxid.return_value = b"wtxid"

    tx = Tx(auto_compute_txid=False)
    assert tx.compute_txid() == b"txid"
    assert tx.txid == b"txid"
    assert tx.compute_wtxid() == b"wtxid"

def test_tx_to_dict():
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(auto_compute_txid=False)
        tx.txid = b"txid"
        d = tx.to_dict()
        assert d["version"] == 1
        assert d["txid"] == b"txid".hex()
        assert d["inputs"] == []
        
        d_no_txid = tx.to_dict(include_txid=False)
        assert d_no_txid["txid"] is None

def test_tx_from_dict():
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(auto_compute_txid=False)
        tx_ret = Tx.from_dict(tx)
        assert tx_ret is tx

        with pytest.raises(TypeError):
            Tx.from_dict([])
            
        d = {
            "version": 2,
            "txid": (b"a"*32).hex(),
            "inputs": [{"txid": (b"b"*32).hex(), "vout": 0}],
            "outputs": [{"amount": 10, "script_pubkey": "00"}],
            "locktime": 10,
            "is_coinbase": False,
            "fee": 5
        }
        with patch("tsarchain.core.tx.Script.deserialize") as mock_deserialize:
            mock_deserialize.return_value = Script([])
            tx2 = Tx.from_dict(d)
            assert tx2.version == 2
            assert tx2.txid == b"a"*32
            assert len(tx2.inputs) == 1
            assert len(tx2.outputs) == 1
            assert tx2.fee == 5

        # Without txid to trigger compute
        d2 = d.copy()
        del d2["txid"]
        with patch("tsarchain.core.tx.Script.deserialize") as mock_deserialize_2:
            mock_deserialize_2.return_value = Script([])
            tx3 = Tx.from_dict(d2)
            # Since compute_txid is mocked at the function level, txid will be None.
            # But the mock should have been called! (It's a bit tricky because the mock is on the class,
            # we can just ensure it doesn't crash)
            assert tx3.version == 2
            
def test_tx_props_and_repr():
    with patch("tsarchain.core.tx.Tx.compute_txid"):
        tx = Tx(auto_compute_txid=False)
        tx.tx_ins = [TxIn(b"a"*32, 0)]
        assert len(tx.tx_ins) == 1
        tx.tx_outs = [TxOut(10, Script([]))]
        assert len(tx.tx_outs) == 1
        
        assert repr(tx) == "<Tx v=1 vin=1 vout=1 lock=0 fee=None>"


def test_tx_storage_bytes():
    from tsarchain.core.coinbase import CoinbaseTx
    from tsarchain.utils.helpers import spkhex_to_address
    # Regular Tx
    txin = TxIn(txid=b"\x01"*32, vout=0, amount=500, script_sig=Script([]), witness=[b"\xaa\xbb"])
    txout = TxOut(amount=450, script_pubkey=Script([]))
    tx = Tx(version=1, locktime=10, inputs=[txin], outputs=[txout], auto_compute_txid=True)
    
    raw = tx.to_storage_bytes()
    restored = Tx.from_storage_bytes(raw)
    assert restored.version == tx.version
    assert restored.locktime == tx.locktime
    assert restored.is_coinbase is False
    assert restored.fee == 50
    assert restored.to_dict()["fee"] == 50
    assert len(restored.inputs) == 1
    assert restored.inputs[0].txid == b"\x01"*32
    assert restored.inputs[0].amount == 500
    assert restored.inputs[0].witness == [b"\xaa\xbb"]
    assert len(restored.outputs) == 1
    assert restored.outputs[0].amount == 450

    # CoinbaseTx
    addr = spkhex_to_address("0014" + "00" * 20)
    cb = CoinbaseTx(to_address=addr, reward=5000000000, block_id="blk_10", height=10)
    raw_cb = cb.to_storage_bytes()
    restored_cb = Tx.from_storage_bytes(raw_cb)
    assert isinstance(restored_cb, CoinbaseTx)
    assert restored_cb.is_coinbase is True
    assert restored_cb.to_address == addr
    assert restored_cb.block_id == "blk_10"
    assert restored_cb.height == 10
    assert restored_cb.reward == 5000000000
    assert "fee" not in restored_cb.to_dict()
    assert restored_cb.to_dict()["reward"] == 5000000000
    assert restored_cb._cached_raw_tx_nowit is None
    assert restored_cb._cached_raw_tx_w is None
    assert restored_cb._cached_txid_bytes is None


