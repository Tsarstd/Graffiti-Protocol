# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock, patch
from tsarchain.network.rpc.user_rpc.category.transactions import (
    new_tx,
    create_tx,
    create_tx_multi
    )


@pytest.fixture
def mock_node():
    """Create a mock object representing the Network node instance."""
    node = MagicMock()
    # Rate limiting tables
    node.rl_ip = {}
    node.rl_addr = {}

    # Broadcast and mempool
    node.broadcast = MagicMock()
    node.broadcast.mempool = MagicMock()
    node.broadcast.mempool.last_error_reason = None
    node.peers = []

    # Template creation methods
    node.create_template_tx = MagicMock(return_value={"tx": "template"})
    node.create_template_tx_multi = MagicMock(return_value={"tx": "multi_template"})

    # Rate limiting methods (they may be called)
    def tb_allow(table, key, burst, window, limit, backoff_key=None):
        # For tests, we assume allowed by default unless we override
        return True
    node.tb_node_allow = MagicMock(side_effect=tb_allow)
    node.backoff = MagicMock()

    # Other methods used in common.allow_rpc_with_pow? Not needed as we mock that function.
    return node

@pytest.fixture
def patch_allow_rpc_with_pow():
    """Patch the CM.allow_rpc_with_pow function to control its return."""
    with patch('tsarchain.network.rpc.user_rpc.category.transactions.CM.allow_rpc_with_pow') as mock_func:
        # Default: allow with no challenge
        mock_func.return_value = (True, None)
        yield mock_func

@pytest.fixture
def patch_config(monkeypatch):
    """Set config values relevant for tests."""
    monkeypatch.setattr('tsarchain.network.rpc.user_rpc.category.transactions.CFG', MagicMock())
    import tsarchain.network.rpc.user_rpc.category.transactions as module
    module.CFG.DEBUG_BENCHMARKS = False
    module.CFG.ENABLE_DANDELION_PP = False
    module.CFG.TX_SUBMIT_RL_IP_BURST = 10
    module.CFG.TX_SUBMIT_RL_WINDOW_S = 5
    module.CFG.TX_SUBMIT_RL_BACKOFF_S = 5
    module.CFG.TX_SUBMIT_RL_ADDR_BURST = 10
    module.CFG.TX_SUBMIT_RL_ADDR_WINDOW_S = 5
    module.CFG.TX_SUBMIT_RL_ADDR_BACKOFF_S = 5
    module.CFG.RPC_POW_DIFFICULTY_TX = 16
    module.CFG.DEFAULT_FEE_RATE_SATVB = 34
    module.CFG.MIN_FEE_RATE_SATVB = 34
    module.CFG.MAX_FEE_RATE_SATVB = 10000
    # For create_tx_multi
    return module.CFG

# ---------- Tests ----------

def test_new_tx_success(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test new_tx succeeds when all checks pass."""
    message = {
        "from_addr": "sender123",
        "data": {"txid": "abc"}
    }
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    # Ensure broadcast.receive_tx returns True
    mock_node.broadcast.receive_tx.return_value = True

    result = new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    assert result == {"status": "ok", "txid": "abc"}
    # Check that allow_rpc_with_pow called twice (IP and addr) because sender_addr exists
    assert patch_allow_rpc_with_pow.call_count == 2
    # Check that broadcast.receive_tx was called with correct args
    mock_node.broadcast.receive_tx.assert_called_once_with(message, addr, mock_node.peers)

def test_new_tx_no_sender_addr(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test new_tx when no sender_addr in message, so no address RL."""
    message = {"data": {}}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.broadcast.receive_tx.return_value = True

    result = new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    # Should only call allow_rpc_with_pow once (IP only)
    assert patch_allow_rpc_with_pow.call_count == 1
    assert result["status"] == "ok"

def test_new_tx_pow_fails_ip(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test new_tx when IP PoW check fails."""
    # First call (IP) fails with challenge
    patch_allow_rpc_with_pow.side_effect = [
        (False, {"error": "pow_required", "pow_challenge": "challenge"}),
    ]

    message = {"from_addr": "sender123"}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    assert result == {"status": "error", "error": "pow_required", "pow_challenge": "challenge"}
    # The second call (addr) should not be made because first failed
    assert patch_allow_rpc_with_pow.call_count == 1

def test_new_tx_pow_fails_addr(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test new_tx when address PoW check fails (IP passes, addr fails)."""
    patch_allow_rpc_with_pow.side_effect = [
        (True, None),  # IP ok
        (False, {"error": "pow_required_addr", "pow_challenge": "challenge"}),  # addr fails
    ]

    message = {"from_addr": "sender123"}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    assert result == {"status": "error", "error": "pow_required_addr", "pow_challenge": "challenge"}

def test_new_tx_broadcast_fails(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test new_tx when broadcast.receive_tx returns False."""
    message = {"from_addr": "sender123", "data": {"txid": "abc"}}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.broadcast.receive_tx.return_value = False
    mock_node.broadcast.mempool.last_error_reason = "insufficient fee"

    result = new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    assert result == {"status": "error", "reason": "insufficient fee"}

def test_new_tx_dandelion_phase_added(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test that phase is added when ENABLE_DANDELION_PP is True and no phase in message."""
    patch_config.ENABLE_DANDELION_PP = True  # override
    message = {"from_addr": "sender123", "data": {"txid": "abc"}}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.broadcast.receive_tx.return_value = True

    new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)

    # The message passed to receive_tx should have "phase": "stem"
    called_message = mock_node.broadcast.receive_tx.call_args[0][0]
    assert called_message["phase"] == "stem"
    # Original message should not be modified? It does dict(message) so original remains.
    assert "phase" not in message  # original unaffected

def test_create_tx_success(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx returns template successfully."""
    message = {
        "from": "alice",
        "to": "bob",
        "amount": 1000,
        "fee_rate": 50
    }
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.create_template_tx.return_value = {"template": "created"}

    result = create_tx(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"type": "TX_TEMPLATE", "data": {"template": "created"}}
    mock_node.create_template_tx.assert_called_once_with("alice", "bob", 1000, 50)
    patch_allow_rpc_with_pow.assert_called_once_with(
        mock_node,
        scope="rpc:tx",
        table=mock_node.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="txsub",
        burst=patch_config.TX_SUBMIT_RL_IP_BURST,
        window_s=patch_config.TX_SUBMIT_RL_WINDOW_S,
        backoff_s=patch_config.TX_SUBMIT_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=patch_config.RPC_POW_DIFFICULTY_TX
    )

def test_create_tx_pow_fails(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx when PoW fails."""
    patch_allow_rpc_with_pow.return_value = (False, {"error": "pow_required"})

    message = {"from": "alice", "to": "bob", "amount": 1000}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = create_tx(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"error": "pow_required"}
    mock_node.create_template_tx.assert_not_called()

def test_create_tx_template_exception(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx when create_template_tx raises exception."""
    mock_node.create_template_tx.side_effect = ValueError("invalid address")

    message = {"from": "alice", "to": "bob", "amount": 1000}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = create_tx(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"error": "invalid address"}

def test_create_tx_fee_rate_clamping(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test that fee_rate is clamped between min and max."""
    # Provide fee_rate below min
    message = {
        "from": "alice",
        "to": "bob",
        "amount": 1000,
        "fee_rate": 5
    }
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.create_template_tx.return_value = {"template": "created"}

    create_tx(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    # Should be clamped to MIN_FEE_RATE_SATVB (34)
    mock_node.create_template_tx.assert_called_once_with("alice", "bob", 1000, 34)

    # Test above max
    message["fee_rate"] = 20000
    create_tx(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)
    mock_node.create_template_tx.assert_called_with("alice", "bob", 1000, 10000)

def test_create_tx_multi_success(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx_multi returns template successfully."""
    message = {
        "from": "alice",
        "outputs": [{"to": "bob", "amount": 100}],
        "fee_rate": 50,
        "force_inputs": ["input1"]
    }
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    mock_node.create_template_tx_multi.return_value = {"multi": "template"}

    result = create_tx_multi(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"type": "TX_TEMPLATE", "data": {"multi": "template"}}
    mock_node.create_template_tx_multi.assert_called_once_with("alice", [{"to": "bob", "amount": 100}], 50, ["input1"])
    patch_allow_rpc_with_pow.assert_called_once()

def test_create_tx_multi_missing_params(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx_multi returns error if from or outputs missing."""
    # Missing outputs
    message = {"from": "alice"}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = create_tx_multi(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)
    assert result == {"error": "missing from/outputs"}

    # Missing from
    message = {"outputs": []}
    result = create_tx_multi(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)
    assert result == {"error": "missing from/outputs"}

def test_create_tx_multi_template_exception(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx_multi when create_template_tx_multi raises exception."""
    mock_node.create_template_tx_multi.side_effect = RuntimeError("insufficient funds")

    message = {"from": "alice", "outputs": [{"to": "bob", "amount": 100}]}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = create_tx_multi(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"error": "insufficient funds"}

def test_create_tx_multi_pow_fails(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test create_tx_multi when PoW fails."""
    patch_allow_rpc_with_pow.return_value = (False, {"error": "pow_required"})

    message = {"from": "alice", "outputs": [{"to": "bob", "amount": 100}]}
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"

    result = create_tx_multi(mock_node, message, pow_obj, base_identity, addr, "mtype", client_ip=client_ip, is_miner_sender=False)

    assert result == {"error": "pow_required"}
    mock_node.create_template_tx_multi.assert_not_called()

# Additional test: new_tx with sender_addr from data dict if from_addr not present
def test_new_tx_sender_from_data(mock_node, patch_allow_rpc_with_pow, patch_config):
    """Test that sender_addr is extracted from data dict if not at top level."""
    message = {
        "data": {"from_addr": "sender456"}
    }
    pow_obj = {"nonce": 123}
    base_identity = "base_id"
    addr = "some_addr"
    client_ip = "1.2.3.4"
    mock_node.broadcast.receive_tx.return_value = True
    new_tx(mock_node, message, pow_obj, base_identity, addr, client_ip=client_ip)
    calls = patch_allow_rpc_with_pow.call_args_list
    assert calls[1][1]['identity'] == "sender456"


def test_new_tx_triggers_fcm_push(mock_node, patch_allow_rpc_with_pow, patch_config, monkeypatch):
    """Test that new_tx parses outputs and triggers FCM push for recipient."""
    from unittest.mock import MagicMock
    from tsarchain.utils.fcm_service import FCMService
    from tsarchain.utils.helpers import Script
    from bech32 import bech32_encode, convertbits

    mock_fcm = MagicMock()
    monkeypatch.setattr(FCMService, "get_instance", lambda: mock_fcm)

    addr_recipient = bech32_encode("tsar", [0] + list(convertbits(b"r" * 20, 8, 5, True)))
    addr_sender = bech32_encode("tsar", [0] + list(convertbits(b"s" * 20, 8, 5, True)))

    spk_recipient = Script.p2wpkh_script(addr_recipient).serialize().hex()
    spk_sender = Script.p2wpkh_script(addr_sender).serialize().hex()

    valid_txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    message = {
        "from_addr": addr_sender,
        "data": {
            "txid": valid_txid,
            "outputs": [
                {"script_pubkey": spk_recipient, "amount": 50000000},
                {"script_pubkey": spk_sender, "amount": 100000000},
            ],
        },
    }
    mock_node.broadcast.receive_tx.return_value = True

    result = new_tx(mock_node, message, None, "id", "addr", client_ip="1.2.3.4")
    assert result["status"] == "ok"
    mock_fcm.send_tx_push.assert_called_once_with(
        target_addr=addr_recipient,
        txid=valid_txid,
        amount_sat=50000000,
        is_incoming=True,
        sender_addr=addr_sender,
    )