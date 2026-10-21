# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import time
import pytest
from unittest.mock import Mock, patch

from tsarchain.consensus.mining import MiningManager
from tsarchain.mempool.pool import TxPool
from tsarchain.storage.utxo import UTXODB
from tsarchain.contracts import graffiti as GRAFFITI



@pytest.fixture
def mining_node():
    class MockBlockchain:
        def __init__(self):
            self.chain = []
            self.total_supply = 0
            self._utxodb = Mock(spec=UTXODB)
            self._utxodb.utxos = {}
            self._utxodb.load_utxo_set.return_value = {}
            self._utxodb.apply_tx_to_utxoset = Mock()
            self._mining_cooloff_until = 0.0

            self._has_pending_blocks = Mock(return_value=False)
            self._is_chain_consistent = Mock(return_value=True)
            self.get_block_reward = Mock(return_value=100)
            self.calculate_expected_bits = Mock(return_value=0x1f00ffff)
            self.validate_block = Mock(return_value=True)
            self.add_block = Mock(return_value=True)
            self.get_last_block = Mock(return_value=None)
            self.ensure_utxodb = Mock(return_value=self._utxodb)
            self.get_mempool = Mock(return_value=Mock(spec=TxPool))
            self.attach_mempool = Mock()
            self._reload_chain_from_kv = Mock(return_value=False)
            self._last_block_validation_error = None

    blockchain = MockBlockchain()
    blockchain._mempool = Mock(spec=TxPool)
    blockchain._mempool.get_all_txs.return_value = []
    blockchain._mempool.validate_transaction.return_value = True
    blockchain.get_mempool.return_value = blockchain._mempool

    manager = MiningManager(blockchain)
    # the tests expect manager to have _mempool accessible. Since we changed tests to manager, 
    # we can just attach it to manager or manager.blockchain
    manager._mempool = blockchain._mempool 
    return manager
# ------------------- Tests for _select_graffiti_art_id -------------------

def test_select_graffiti_art_id_found(mining_node):
    """Scenario: a transaction with a valid Graffiti POST exists -> returns art_id."""
    art_id = "graf" + "a" * 60
    pool_addr = GRAFFITI.derive_pool_address(art_id)
    tx = Mock()
    script_pubkey = b'dummy_script'
    tx.outputs = [Mock(script_pubkey=script_pubkey), Mock(script_pubkey=None, address=pool_addr, amount=5000000000)]
    tx.txid = b'feedface12345678'

    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script') as mock_parse:
        mock_parse.return_value = {'event': 'POST', 'art_id': art_id, 'size': 100}

        result = mining_node._select_graffiti_art_id([tx])

        assert result == art_id
        mock_parse.assert_called_once_with(script_pubkey)


def test_select_graffiti_art_id_not_found(mining_node):
    """Scenario: no Graffiti POST transaction -> returns None."""
    tx1 = Mock()
    tx1.outputs = [Mock()]
    tx1.outputs[0].script_pubkey = b'some_script'
    tx2 = Mock()
    tx2.outputs = [Mock()]
    tx2.outputs[0].script_pubkey = b'another_script'

    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script') as mock_parse:
        # Return non-POST events or empty
        mock_parse.side_effect = [None, {'event': 'PUT', 'art_id': 'ignored'}]

        result = mining_node._select_graffiti_art_id([tx1, tx2])
        assert result is None
        assert mock_parse.call_count == 2


def test_select_graffiti_art_id_computed_from_sha_creator(mining_node):
    """Scenario: POST event without explicit art_id -> computed from sha256+creator."""
    art_id = "graf" + "b" * 60
    pool_addr = GRAFFITI.derive_pool_address(art_id)
    tx = Mock()
    script_pubkey = b'post_script'
    tx.outputs = [Mock(script_pubkey=script_pubkey), Mock(script_pubkey=None, address=pool_addr, amount=5000000000)]
    tx.txid = b'abcd1234'

    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script') as mock_parse, \
         patch('tsarchain.consensus.mining.GRAFFITI.compute_art_id') as mock_compute:

        mock_parse.return_value = {'event': 'POST', 'sha256': 'sha', 'creator': 'creator', 'size': 100}
        mock_compute.return_value = art_id

        result = mining_node._select_graffiti_art_id([tx])

        assert result == art_id
        mock_compute.assert_called_once_with('sha', 'creator')


# ------------------- Tests for mine_block -------------------

def test_mine_block_success(mining_node):
    """
    Scenario: normal mining on a non-empty chain, no pending blocks,
    valid transactions, block mined and added successfully.
    """
    # Setup chain with a previous block
    prev_block = Mock()
    prev_block.hash.return_value = b'prev_hash'
    prev_block.height = 0
    mining_node.blockchain.chain = [prev_block]
    mining_node.blockchain.total_supply = 1000

    # Mock get_last_block to return prev_block (so tip check passes)
    mining_node.blockchain.get_last_block.return_value = prev_block

    # Mempool returns a few valid transactions
    tx1 = Mock()
    tx1.inputs = []
    tx1.outputs = []
    tx1.txid = b'tx1'
    tx1.fee = 10
    tx1._received_at = 0

    tx2 = Mock()
    tx2.inputs = []
    tx2.outputs = []
    tx2.txid = b'tx2'
    tx2.fee = 20
    tx2._received_at = 0

    mining_node._mempool.get_all_txs.return_value = [tx1, tx2]
    mining_node._mempool.validate_transaction.return_value = True

    # Mock Block.mine to succeed
    mock_block_instance = Mock()
    mock_block_instance.mine.return_value = True
    mock_block_instance.hash.return_value = b'new_block_hash'
    mock_block_instance.prev_block_hash = b'prev_hash'
    mock_block_instance.height = 1
    # Coinbase will be added later; we need to mock Block constructor
    with patch('tsarchain.consensus.mining.Block', return_value=mock_block_instance) as mock_block_cls, \
         patch('tsarchain.consensus.mining.CoinbaseTx') as mock_coinbase_cls, \
         patch('tsarchain.consensus.mining.CFG.MAX_SUPPLY', 21000000), \
         patch('tsarchain.consensus.mining.CFG.MINING_COOLDOWN_AFTER_BLOCK', 0), \
         patch('tsarchain.consensus.mining.CFG.ZERO_HASH', b'\x00'*32):

        # Coinbase creation
        coinbase_mock = Mock()
        coinbase_mock.compute_txid = Mock()
        mock_coinbase_cls.return_value = coinbase_mock

        result = mining_node.mine_block('miner_address', use_cores=2)

        # Assertions
        assert result is mock_block_instance
        mock_block_cls.assert_called_once_with(1, b'prev_hash', [coinbase_mock, tx2, tx1])
        mock_block_instance.mine.assert_called_once_with(
            use_cores=2, stop_event=None, progress_queue=None
        )
        mining_node.blockchain.validate_block.assert_called_once_with(mock_block_instance)
        mining_node.blockchain.add_block.assert_called_once_with(mock_block_instance)
        # Coinbase constructed with correct args
        mock_coinbase_cls.assert_called_once_with(
            to_address='miner_address', reward=100 + 30, height=1
        )


def test_mine_block_fail_chain_empty_and_no_genesis(mining_node):
    """
    Scenario: chain is empty -> mine_block returns None.
    """
    mining_node.blockchain.chain = []  # empty
    mining_node.blockchain.total_supply = 0

    with patch('tsarchain.consensus.mining.log') as mock_log:

        result = mining_node.mine_block('miner_address')

        assert result is None
        mock_log.warning.assert_called_once()
        # Ensure no mining occurred
        assert 'mine' not in [call[0] for call in mock_log.method_calls]  # simplified check


def test_mine_block_fail_pending_blocks(mining_node):
    """
    Scenario: _has_pending_blocks returns True -> skip mining.
    """
    mining_node.blockchain.chain = [Mock()]  # non-empty
    mining_node.blockchain._has_pending_blocks.return_value = True

    with patch('tsarchain.consensus.mining.log') as mock_log:
        result = mining_node.mine_block('miner_address')

        assert result is None
        mock_log.warning.assert_called_once_with(
            "[_validate_chain_state] pending blocks detected; skipping mining"
        )


def test_mine_block_fail_chain_inconsistent(mining_node):
    """
    Scenario: _is_chain_consistent returns False -> skip mining.
    """
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain._has_pending_blocks.return_value = False
    mining_node.blockchain._is_chain_consistent.return_value = False

    with patch('tsarchain.consensus.mining.log') as mock_log:
        result = mining_node.mine_block('miner_address')

        assert result is None
        mock_log.warning.assert_called_once_with(
            "[_validate_chain_state] chain inconsistency detected; syncing first"
        )


def test_mine_block_with_graffiti_post_anchoring(mining_node):
    """
    Scenario: a valid Graffiti POST is included; coinbase receives block_id.
    """
    prev_block = Mock()
    prev_block.hash.return_value = b'prev_hash'
    prev_block.height = 0
    mining_node.blockchain.chain = [prev_block]
    mining_node.blockchain.total_supply = 1000
    mining_node.blockchain.get_last_block.return_value = prev_block

    art_id = "graf" + "c" * 60
    pool_addr = GRAFFITI.derive_pool_address(art_id)

    # Create a tx that is a Graffiti POST
    post_tx = Mock()
    post_tx.inputs = []
    post_tx.outputs = [
        Mock(script_pubkey=Mock(serialize=lambda: b'post_script'), address=None, amount=0),
        Mock(script_pubkey=None, address=pool_addr, amount=5000000000),
    ]
    post_tx.txid = b'post_tx'
    post_tx.fee = 5
    post_tx._received_at = 0

    mining_node._mempool.get_all_txs.return_value = [post_tx]
    mining_node._mempool.validate_transaction.return_value = True

    # Mock GRAFFITI.parse_from_script to return a POST
    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script') as mock_parse, \
         patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
         patch('tsarchain.consensus.mining.CoinbaseTx') as mock_coinbase_cls, \
         patch('tsarchain.consensus.mining.CFG.MAX_SUPPLY', 21000000), \
         patch('tsarchain.consensus.mining.CFG.MINING_COOLDOWN_AFTER_BLOCK', 0), \
         patch('tsarchain.consensus.mining.CFG.ZERO_HASH', b'\x00'*32):

        mock_parse.return_value = {'event': 'POST', 'art_id': art_id, 'size': 100}

        # Block mock
        mock_block = Mock()
        mock_block.mine.return_value = True
        mock_block.hash.return_value = b'new_hash'
        mock_block.prev_block_hash = b'prev_hash'
        mock_block.height = 1
        mock_block_cls.return_value = mock_block

        coinbase_mock = Mock()
        coinbase_mock.compute_txid = Mock()
        mock_coinbase_cls.return_value = coinbase_mock

        result = mining_node.mine_block('miner_addr')

        assert result is mock_block
        # Coinbase should be created with block_id
        mock_coinbase_cls.assert_called_once_with(
            to_address='miner_addr', reward=100 + 5, height=1, block_id=art_id
        )


def test_mine_block_reload_chain(mining_node):
    mining_node.blockchain.chain = []
    mining_node.blockchain._reload_chain_from_kv.return_value = True
    res = mining_node.mine_block('miner_address')
    assert res is None

def test_mine_block_reward_exceeds_supply(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    mining_node.blockchain.total_supply = 20999990
    with patch('tsarchain.consensus.mining.CFG.MAX_SUPPLY', 21000000), \
        patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx') as mock_cb:
        
        mock_block_cls.return_value.mine.return_value = True
        mining_node.mine_block('miner_address')
        mock_cb.assert_called_once()
        args, kwargs = mock_cb.call_args
        assert kwargs['reward'] == 10

def test_mine_block_no_mempool(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    mining_node.blockchain.get_mempool.return_value = None
    with patch('tsarchain.consensus.mining.TxPool') as mock_txpool, \
        patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mining_node.mine_block('miner_address')
        mock_txpool.assert_called_once()
        mining_node.blockchain.attach_mempool.assert_called_once()

def test_mine_block_double_spend_in_block(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    
    tx1 = Mock()
    tx1.txid = b'tx1'
    tx1.inputs = [Mock(txid=b'prev1', vout=0)]
    tx1.outputs = []
    tx1.fee = 10
    tx1._received_at = 1
    
    tx2 = Mock()
    tx2.txid = b'tx2'
    tx2.inputs = [Mock(txid=b'prev1', vout=0)]
    tx2.outputs = []
    tx2.fee = 10
    tx2._received_at = 2
    
    mining_node._mempool.get_all_txs.return_value = [tx1, tx2]
    mining_node._mempool.validate_transaction.return_value = True
    
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mining_node.mine_block('miner_address')
        block_txs = mock_block_cls.call_args[0][2]
        assert len(block_txs) == 2
        assert block_txs[1] == tx1

def test_mine_block_validate_transaction_fails(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    
    tx = Mock()
    tx.txid = b'tx_fail'
    tx.inputs = []
    tx.outputs = []
    tx.fee = 10
    tx._received_at = 1
    
    mining_node._mempool.get_all_txs.return_value = [tx]
    mining_node._mempool.validate_transaction.return_value = False
    mining_node._mempool.last_error_reason = 'bad_tx'
    
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mining_node.mine_block('miner_address')
        block_txs = mock_block_cls.call_args[0][2]
        assert len(block_txs) == 1

def test_mine_block_multiple_graffiti_posts(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    
    art_id1 = "graf" + "1" * 60
    pool_addr1 = GRAFFITI.derive_pool_address(art_id1)
    post1 = Mock()
    post1.txid = b'post1'
    post1.inputs = []
    post1.fee = 10
    post1.outputs = [Mock(script_pubkey=Mock(serialize=lambda: b'post1_spk'), address=None, amount=0), Mock(script_pubkey=None, address=pool_addr1, amount=5000000000)]
    post1._received_at = 1
    
    art_id2 = "graf" + "2" * 60
    pool_addr2 = GRAFFITI.derive_pool_address(art_id2)
    post2 = Mock()
    post2.txid = b'post2'
    post2.inputs = []
    post2.fee = 10
    post2.outputs = [Mock(script_pubkey=Mock(serialize=lambda: b'post2_spk'), address=None, amount=0), Mock(script_pubkey=None, address=pool_addr2, amount=5000000000)]
    post2._received_at = 2
    
    mining_node._mempool.get_all_txs.return_value = [post1, post2]
    
    def parse_mock(spk):
        raw = spk.serialize() if callable(getattr(spk, 'serialize', None)) or hasattr(spk, 'serialize') else spk
        if raw == b'post1_spk' or spk == b'post1_spk': return {'event': 'POST', 'art_id': art_id1, 'size': 100}
        if raw == b'post2_spk' or spk == b'post2_spk': return {'event': 'POST', 'art_id': art_id2, 'size': 100}
        return None
    
    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script', side_effect=parse_mock), \
        patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mining_node.mine_block('miner_address')
        block_txs = mock_block_cls.call_args[0][2]
        assert len(block_txs) == 2
        assert block_txs[1] == post1

def test_mine_block_mine_fails(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = False
        res = mining_node.mine_block('miner_address')
        assert res is None

def test_mine_block_stale_candidate(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = Mock(hash=lambda: b'different_hash', height=10)
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        res = mining_node.mine_block('miner_address')
        assert res is None

def test_mine_block_cooloff(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    mining_node.blockchain._mining_cooloff_until = time.time() + 0.1
    with patch('tsarchain.consensus.mining.CFG.MINING_COOLDOWN_AFTER_BLOCK', 1.0), \
        patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.time.sleep') as mock_sleep, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mock_block_cls.return_value.hash.return_value = b'new_hash'
        mining_node.mine_block('miner_address')
        mock_sleep.assert_called_once()

def test_mine_block_validate_block_fails(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    mining_node.blockchain.validate_block.return_value = False
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mock_block_cls.return_value.hash.return_value = b'new_hash'
        res = mining_node.mine_block('miner_address')
        assert res is None

def test_mine_block_add_block_fails(mining_node):
    mining_node.blockchain.chain = [Mock()]
    mining_node.blockchain.chain[0].hash.return_value = b'prev_hash'
    mining_node.blockchain.chain[0].height = 0
    mining_node.blockchain.get_last_block.return_value = mining_node.blockchain.chain[0]
    mining_node.blockchain.add_block.return_value = False
    with patch('tsarchain.consensus.mining.Block') as mock_block_cls, \
        patch('tsarchain.consensus.mining.CoinbaseTx'):

        mock_block_cls.return_value.mine.return_value = True
        mock_block_cls.return_value.prev_block_hash = b'prev_hash'
        mock_block_cls.return_value.height = 1
        mock_block_cls.return_value.hash.return_value = b'new_hash'
        res = mining_node.mine_block('miner_address')
        assert res is None

def test_select_graffiti_art_id_script_none(mining_node):
    tx = Mock()
    tx.outputs = [Mock(script_pubkey=None)]
    res = mining_node._select_graffiti_art_id([tx])
    assert res is None

def test_select_graffiti_art_id_txid_str(mining_node):
    art_id = "graf" + "d" * 60
    pool_addr = GRAFFITI.derive_pool_address(art_id)
    tx = Mock()
    tx.outputs = [Mock(script_pubkey=Mock(serialize=lambda: b'spk'), address=None, amount=0), Mock(script_pubkey=None, address=pool_addr, amount=5000000000)]
    tx.txid = 'txid_str'
    with patch('tsarchain.consensus.mining.GRAFFITI.parse_from_script') as p:
        p.return_value = {'event': 'POST', 'art_id': art_id, 'size': 100}
        res = mining_node._select_graffiti_art_id([tx])
        assert res == art_id


def test_is_graffiti_post_with_real_txout(mining_node):
    from tsarchain.core.tx import Tx, TxOut
    from tsarchain.utils.helpers import Script
    from bech32 import bech32_encode, convertbits
    from tsarchain.utils import config as CFG
    creator = bech32_encode(CFG.ADDRESS_PREFIX, [0] + list(convertbits(b"c"*20, 8, 5, True)))
    storer = bech32_encode(CFG.ADDRESS_PREFIX, [0] + list(convertbits(b"s"*20, 8, 5, True)))
    meta = GRAFFITI.build_metadata(
        sha256_hex="a" * 64,
        size_bytes=100,
        mime="image/jpeg",
        storer_addr=storer,
        receipt_id="rcpt_1",
        creator_addr=creator,
    )
    art_id = GRAFFITI.compute_art_id("a" * 64, creator)
    pool_addr = GRAFFITI.derive_pool_address(art_id)
    pool_spk = Script.p2wsh_script(pool_addr)
    opret_spk = GRAFFITI.build_script(meta)
    tx = Tx(outputs=[TxOut(0, opret_spk), TxOut(5000000000, pool_spk)])
    assert mining_node._is_graffiti_post(tx) is True


def test_fetch_sorted_mempool_txs_with_real_graffiti_tx(mining_node):
    from tsarchain.core.tx import Tx, TxOut
    from tsarchain.utils.helpers import Script
    from bech32 import bech32_encode, convertbits
    from tsarchain.utils import config as CFG
    creator = bech32_encode(CFG.ADDRESS_PREFIX, [0] + list(convertbits(b"c"*20, 8, 5, True)))
    storer = bech32_encode(CFG.ADDRESS_PREFIX, [0] + list(convertbits(b"s"*20, 8, 5, True)))
    meta = GRAFFITI.build_metadata(
        sha256_hex="b" * 64,
        size_bytes=100,
        mime="image/jpeg",
        storer_addr=storer,
        receipt_id="rcpt_2",
        creator_addr=creator,
    )
    art_id = GRAFFITI.compute_art_id("b" * 64, creator)
    pool_addr = GRAFFITI.derive_pool_address(art_id)
    pool_spk = Script.p2wsh_script(pool_addr)
    opret_spk = GRAFFITI.build_script(meta)
    graff_tx = Tx(outputs=[TxOut(0, opret_spk), TxOut(5000000000, pool_spk)])
    normal_tx = Tx(outputs=[TxOut(1000, pool_spk)])
    mining_node._mempool.get_all_txs.return_value = [normal_tx, graff_tx]
    sorted_txs = mining_node._fetch_sorted_mempool_txs(mining_node._mempool)
    assert sorted_txs == [graff_tx, normal_tx]

