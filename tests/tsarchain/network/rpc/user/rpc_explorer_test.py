# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock, patch

from tsarchain.network.rpc.user_rpc.category.explorer import (
    get_balances,
    get_network_info,
    get_block,
    get_block_range,
    get_mempool,
    get_tx_history,
    get_tx_detail,
    get_total_utxo,
)


# ---------- Fixtures ----------

@pytest.fixture(autouse=True)
def mock_config():
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.CFG") as mock_cfg:
        mock_cfg.DEBUG_BENCHMARKS = False
        mock_cfg.MAX_ADDRS_PER_REQ = 100
        mock_cfg.MAX_UTXO_ADDR_LEN = 100
        mock_cfg.ADDRESS_PREFIX = "ts"
        mock_cfg.COINBASE_MATURITY = 100
        mock_cfg.CANONICAL_SEP = (",", ":")
        mock_cfg.MAX_MSG = 1024 * 1024
        mock_cfg.NETWORK_MAGIC = b"TSC"
        mock_cfg.MEMPOOL_INLINE_MAX_TX = 50
        # Rate limit configs
        mock_cfg.BALANCE_RL_IP_BURST = 10
        mock_cfg.BALANCE_RL_IP_WINDOW_S = 60
        mock_cfg.BALANCE_RL_BACKOFF_S = 5
        mock_cfg.INFO_RL_IP_BURST = 10
        mock_cfg.INFO_RL_IP_WINDOW_S = 60
        mock_cfg.INFO_RL_BACKOFF_S = 5
        mock_cfg.BLOCK_FETCH_RL_IP_BURST = 10
        mock_cfg.BLOCK_FETCH_RL_WINDOW_S = 60
        mock_cfg.BLOCK_FETCH_RL_BACKOFF_S = 5
        mock_cfg.BLOCK_RANGE_RL_IP_BURST = 10
        mock_cfg.BLOCK_RANGE_RL_WINDOW_S = 60
        mock_cfg.BLOCK_RANGE_RL_BACKOFF_S = 5
        mock_cfg.MEMPOOL_INLINE_RL_BURST = 10
        mock_cfg.MEMPOOL_INLINE_RL_WINDOW_S = 60
        mock_cfg.MEMPOOL_INLINE_RL_BACKOFF = 5
        mock_cfg.HISTORY_RL_IP_BURST = 10
        mock_cfg.HISTORY_RL_IP_WINDOW_S = 60
        mock_cfg.HISTORY_RL_BACKOFF_S = 5
        mock_cfg.MAX_HISTORY_LIMIT = 200
        mock_cfg.RPC_POW_DIFFICULTY_READ = 1
        yield mock_cfg


@pytest.fixture
def mock_pow_allow():
    """Mock CM.allow_rpc_with_pow agar selalu sukses (True, None)."""
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
        mock.return_value = (True, None)
        yield mock


@pytest.fixture
def mock_summarize_block():
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.summarize_block") as mock:
        mock.return_value = {"hash": "abc", "height": 10, "tx_count": 5}
        yield mock


@pytest.fixture
def mock_handlers():
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.handlers") as mock:
        mock.handle_get_block_at.return_value = {"type": "BLOCK", "height": 100}
        mock.handle_get_block_by_hash.return_value = {"type": "BLOCK", "hash": "abc"}
        yield mock


@pytest.fixture
def mock_logger():
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.log") as mock:
        yield mock


@pytest.fixture
def mock_time():
    with patch("tsarchain.network.rpc.user_rpc.category.explorer.time") as mock:
        mock.perf_counter.return_value = 0.0
        yield mock


@pytest.fixture
def mock_self(mock_summarize_block):
    """Membangun objek self yang diperlukan oleh semua RPC."""
    self = MagicMock()

    # broadcast
    self.broadcast = MagicMock()
    self.broadcast.lock = MagicMock()
    self.broadcast.blockchain = MagicMock()
    self.broadcast.blockchain.chain = [
        MagicMock(),  # block 0
        MagicMock(),  # block 1
    ]
    self.broadcast.blockchain.height = 100
    self.broadcast.mempool = MagicMock()
    self.broadcast.mempool.get_all_txs.return_value = []
    self.broadcast.utxodb = MagicMock()
    self.broadcast.utxodb._load = MagicMock()
    self.broadcast.utxodb.get_balance = MagicMock(
        return_value={"total": 1000, "mature": 800, "immature": 200}
    )
    self.broadcast.utxodb.count_utxos = MagicMock(return_value=42)
    self.broadcast.send_mempool_to_peer = MagicMock(return_value=5)

    # peer & IP
    self.rl_ip = MagicMock()
    self.peers = [("1.2.3.4", 8333)]
    self.lock = MagicMock()

    # internal methods
    self.build_outpoint_map = MagicMock(return_value=({}, {}))
    patcher = patch('tsarchain.network.rpc.user_rpc.category.explorer.spkhex_to_address', return_value="ts1address")
    self._spkhex_to_address = patcher.start()
    self.txout_to_address = MagicMock(return_value="ts1address")
    self.txin_prevkey = MagicMock(return_value="prev_outpoint_key")
    self.process_history_lookup = MagicMock(return_value={"items": [], "total": 0})
    self.process_tx_lookup = MagicMock(return_value={"txid": "abc123", "detail": "..."})
    self.normalize_peer = MagicMock(return_value=("1.2.3.4", 8333))
    self._read_snapshot_state = MagicMock(return_value={"height": 100, "difficulty": 1.0})

    yield self
    patcher.stop()


# ---------- Tests ----------

class TestGetBalances:
    def test_missing_addresses(self, mock_self, mock_pow_allow):
        msg = {}
        result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"error": "missing addresses"}

    def test_too_many_addresses(self, mock_self, mock_pow_allow, mock_config):
        msg = {"addresses": ["a"] * (mock_config.MAX_ADDRS_PER_REQ + 1)}
        result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert "too many addresses" in result["error"]

    def test_address_normalization(self, mock_self, mock_pow_allow):
        msg = {"addresses": ["ts1abc", "  TS1DEF  ", ""]}
        mock_self.broadcast.utxodb.get_balance.return_value = {"total": 500, "mature": 400, "immature": 100}
        result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result["type"] == "BALANCES"
        items = result["items"]
        assert "ts1abc" in items
        assert "ts1def" in items
        assert items["ts1abc"]["balance"] == 500
        assert items["ts1def"]["spendable"] == 400

    def test_with_pending_transactions(self, mock_self, mock_pow_allow):
        # Buat mock transaksi dengan input dan output yang jelas
        mock_tx = MagicMock()
        mock_tx.inputs = [MagicMock()]
        mock_tx.outputs = [MagicMock(amount=100)]  # pastikan amount tersedia

        mock_self.broadcast.mempool.get_all_txs.return_value = [mock_tx]

        # Map outpoint untuk input (spent) dan output (tidak perlu untuk output karena diambil langsung)
        mock_self.build_outpoint_map.return_value = (
            {},
            {"prevkey": (50, "spk_hex")}
        )
        mock_self.txin_prevkey.return_value = "prevkey"
        mock_self._spkhex_to_address.return_value = "ts1spender"
        mock_self.txout_to_address.return_value = "ts1spender"

        msg = {"addresses": ["ts1spender"]}
        result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")

        # Pastikan method-method internal dipanggil
        assert mock_self.txout_to_address.call_count > 0
        assert mock_self._spkhex_to_address.call_count > 0

        items = result["items"]
        assert items["ts1spender"]["pending_outgoing"] == 0
        assert items["ts1spender"]["pending_incoming"] == 50

    def test_with_confirmed_utxo_spent_in_mempool(self, mock_self, mock_pow_allow):
        mock_tx = MagicMock()
        mock_tx.inputs = [MagicMock()]
        mock_tx.outputs = [MagicMock(amount=60)]
        mock_self.broadcast.mempool.get_all_txs.return_value = [mock_tx]

        mock_self.build_outpoint_map.return_value = ({}, {})
        mock_self.txin_prevkey.return_value = "utxo_txid:0"
        mock_self.broadcast.utxodb.utxos = {
            "utxo_txid:0": {"tx_out": {"amount": 100, "script_pubkey": "0014sender"}}
        }
        mock_self.broadcast.utxodb._amount_from_tx_out.return_value = 100
        mock_self.broadcast.utxodb._script_hex_from_tx_out.return_value = "0014sender"
        mock_self._spkhex_to_address.return_value = "ts1sender"
        mock_self.txout_to_address.return_value = "ts1recipient"
        mock_self.broadcast.utxodb.get_balance.return_value = {"total": 500, "mature": 500, "immature": 0}

        msg = {"addresses": ["ts1sender", "ts1recipient"]}
        result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")

        items = result["items"]
        assert items["ts1sender"]["pending_outgoing"] == 100
        assert items["ts1recipient"]["pending_incoming"] == 60

    def test_pow_failure(self, mock_self, mock_pow_allow):
        # Override allow_rpc_with_pow to fail
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow required"})
            msg = {"addresses": ["ts1abc"]}
            result = get_balances(mock_self, msg, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow required"}


class TestGetNetworkInfo:
    def test_success(self, mock_self, mock_pow_allow):
        msg = {}
        mock_self.broadcast.blockchain.chain_storage._read_snapshot_state.return_value = {
            "height": 200,
            "difficulty": 2.5,
        }
        # Buat mock untuk overlay function, langsung berikan sebagai argumen
        mock_overlay = MagicMock()
        result = get_network_info(
            mock_self, msg, None, None, client_ip="1.2.3.4",
            overlay_realtime_mempool_stats=mock_overlay
        )
        mock_overlay.assert_called_once()
        assert result["type"] == "NETWORK_INFO"
        assert result["data"]["height"] == 200
        assert result["data"]["peers"]["count"] == 1

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_network_info(
                mock_self, {}, None, None, client_ip="1.2.3.4",
                overlay_realtime_mempool_stats=MagicMock()
            )
            assert result == {"error": "pow"}


class TestGetBlock:
    def test_by_height(self, mock_self, mock_pow_allow, mock_handlers):
        msg = {"height": 42}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_handlers.handle_get_block_at.assert_called_once_with(mock_self, 42, src_tag=None)
        assert result == {"type": "BLOCK", "height": 100}

    def test_by_hash(self, mock_self, mock_pow_allow, mock_handlers):
        msg = {"hash": "deadbeef"}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_handlers.handle_get_block_by_hash.assert_called_once_with(mock_self, "deadbeef", src_tag=None)
        assert result == {"type": "BLOCK", "hash": "abc"}

    def test_missing_both(self, mock_self, mock_pow_allow):
        msg = {}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"type": "BLOCK", "error": "missing_height_or_hash"}

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_block(mock_self, {"height": 1}, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow"}

    def test_by_height_str(self, mock_self, mock_pow_allow, mock_handlers):
        msg = {"height": "42"}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_handlers.handle_get_block_at.assert_called_once_with(mock_self, 42, src_tag=None)
        assert result == {"type": "BLOCK", "height": 100}

    def test_by_height_invalid(self, mock_self, mock_pow_allow, mock_handlers):
        msg = {"height": "invalid_height"}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"type": "BLOCK", "error": "invalid_height"}

    def test_by_height_none_with_hash(self, mock_self, mock_pow_allow, mock_handlers):
        msg = {"height": None, "hash": "deadbeef"}
        result = get_block(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_handlers.handle_get_block_by_hash.assert_called_once_with(mock_self, "deadbeef", src_tag=None)
        assert result == {"type": "BLOCK", "hash": "abc"}


class TestGetBlockRange:
    def test_default_start_tip(self, mock_self, mock_pow_allow, mock_summarize_block):
        # Buat chain dengan 150 blok (indeks 0..149)
        chain_length = 150
        mock_self.broadcast.blockchain.chain = [MagicMock() for _ in range(chain_length)]
        mock_self.broadcast.blockchain.height = chain_length - 1  # tip = 149

        msg = {}
        result = get_block_range(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result["type"] == "BLOCK_RANGE"
        assert result["start_height"] == 149
        assert result["limit"] == 200
        assert result["tip_height"] == 149
        # Karena semua blok (149..0) diambil, tidak ada lagi
        assert result["has_more"] is False
        assert len(result["items"]) == chain_length

    def test_custom_start_and_limit(self, mock_self, mock_pow_allow):
        mock_self.broadcast.blockchain.chain = [MagicMock() for _ in range(100)]
        mock_self.broadcast.blockchain.height = 99
        msg = {"start_height": 50, "limit": 10}
        result = get_block_range(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result["start_height"] == 50
        assert result["limit"] == 10
        assert len(result["items"]) == 10
        assert result["next_height"] == 40
        assert result["has_more"] is True

    def test_start_below_zero(self, mock_self, mock_pow_allow):
        mock_self.broadcast.blockchain.chain = [MagicMock() for _ in range(10)]
        mock_self.broadcast.blockchain.height = 9
        msg = {"start_height": -5}
        result = get_block_range(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result["items"] == []
        assert result["has_more"] is False

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_block_range(mock_self, {}, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow"}


class TestGetMempool:
    def test_default_mode_txids(self, mock_self, mock_pow_allow):
        tx1 = MagicMock()
        tx1.txid = b"abc123"
        tx2 = MagicMock()
        tx2.txid = b"def456"
        mock_self.broadcast.mempool.get_all_txs.return_value = [tx1, tx2]
        msg = {}
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4",
                             addr=None, is_miner_sender=lambda: False)
        assert result["type"] == "MEMPOOL"
        assert result["mode"] == "txids"
        # txid.hex() menghasilkan string heksadesimal
        assert result["txs"] == [b"abc123".hex(), b"def456".hex()]

    def test_inline_mode(self, mock_self, mock_pow_allow):
        tx = MagicMock()
        tx.to_dict.return_value = {"txid": "tx1", "inputs": [], "outputs": []}
        mock_self.broadcast.mempool.get_all_txs.return_value = [tx]
        msg = {"mode": "inline"}
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4", addr=None, is_miner_sender=lambda: False)
        assert result["type"] == "MEMPOOL"
        assert result["mode"] == "inline_full"
        assert result["total"] == 1
        assert len(result["txs"]) == 1
        assert result["txs"][0]["txid"] == "tx1"

    def test_inline_full_explicit(self, mock_self, mock_pow_allow):
        tx = MagicMock()
        tx.to_dict.return_value = {"txid": "tx2"}
        mock_self.broadcast.mempool.get_all_txs.return_value = [tx]
        msg = {"mode": "inline_full"}
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4", addr=None, is_miner_sender=lambda: False)
        assert result["mode"] == "inline_full"

    def test_inline_size_limit(self, mock_self, mock_pow_allow, mock_config):
        # Create many transactions to test cap
        txs = []
        for i in range(100):
            tx = MagicMock()
            tx.to_dict.return_value = {"txid": f"tx{i}", "data": "x" * 1000}  # large payload
            txs.append(tx)
        mock_self.broadcast.mempool.get_all_txs.return_value = txs
        # We need to simulate size cap; set MAX_MSG small
        mock_config.MAX_MSG = 5000  # small
        msg = {"mode": "inline_full"}
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4", addr=None, is_miner_sender=lambda: False)
        # It should include as many as fit
        assert result["total"] == 100
        # count should be less than 100 due to size
        assert result["count"] < 100

    def test_snapshot_mode_miner_only(self, mock_self, mock_pow_allow):
        msg = {"mode": "snapshot", "port": 8333}
        # is_miner_sender returns False
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4", addr=("1.2.3.4", 8333), is_miner_sender=lambda: False)
        assert result == {"error": "forbidden: miners-only endpoint"}

    def test_snapshot_mode_success(self, mock_self, mock_pow_allow):
        msg = {"mode": "snapshot", "port": 8333}
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4", addr=("1.2.3.4", 8333), is_miner_sender=lambda: True)
        assert result["type"] == "MEMPOOL_SYNC"
        assert result["count"] == 5  # from mock send_mempool_to_peer

    def test_snapshot_missing_port(self, mock_self, mock_pow_allow):
        # Kosongkan daftar peer agar fallback tidak menemukan target
        mock_self.peers = []
        msg = {"mode": "snapshot"}  # tidak ada port
        result = get_mempool(mock_self, msg, None, None, client_ip="1.2.3.4",
                             addr=("1.2.3.4", 8333), is_miner_sender=lambda: True)
        assert result == {"error": "missing_peer_port"}

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_mempool(mock_self, {}, None, None, client_ip="1.2.3.4", addr=None, is_miner_sender=lambda: False)
            assert result == {"error": "pow"}


class TestGetTxHistory:
    def test_missing_address(self, mock_self, mock_pow_allow):
        msg = {}
        result = get_tx_history(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"error": "missing address"}

    def test_success(self, mock_self, mock_pow_allow):
        mock_self.process_history_lookup.return_value = {"items": [{"txid": "abc"}], "total": 1}
        msg = {"address": "ts1addr", "limit": 10, "offset": 0}
        result = get_tx_history(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result["type"] == "TX_HISTORY"
        assert result["address"] == "ts1addr"
        assert result["items"] == [{"txid": "abc"}]
        assert result["total"] == 1
        assert result["height"] == 100  # from mock self.broadcast.blockchain.height

    def test_limit_cap(self, mock_self, mock_pow_allow, mock_config):
        mock_config.MAX_HISTORY_LIMIT = 50
        msg = {"address": "ts1addr", "limit": 100}
        result = get_tx_history(mock_self, msg, None, None, client_ip="1.2.3.4")
        # get_tx_history should be called with limit=50
        mock_self.process_history_lookup.assert_called_with(
            "ts1addr", limit=50, offset=0,
            direction=None, status=None
        )

    def test_since_height(self, mock_self, mock_pow_allow):
        msg = {"address": "ts1addr", "limit": 20, "since_height": 500}
        result = get_tx_history(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_self.process_history_lookup.assert_called_with(
            "ts1addr", limit=20, offset=0,
            direction=None, status=None,
            since_height=500
        )

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_tx_history(mock_self, {"address": "addr"}, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow"}


class TestGetTxDetail:
    def test_missing_txid(self, mock_self, mock_pow_allow):
        msg = {}
        result = get_tx_detail(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"error": "missing txid"}

    def test_success(self, mock_self, mock_pow_allow):
        mock_self.process_tx_lookup.return_value = {"txid": "abc", "detail": "foo"}
        msg = {"txid": "abc"}
        result = get_tx_detail(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_self.process_tx_lookup.assert_called_with("abc", None)
        assert result == {"txid": "abc", "detail": "foo"}

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_tx_detail(mock_self, {"txid": "abc"}, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow"}


class TestGetTotalUtxo:
    def test_missing_address(self, mock_self, mock_pow_allow):
        msg = {}
        result = get_total_utxo(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"error": "missing address"}

    def test_success(self, mock_self, mock_pow_allow):
        mock_self.broadcast.utxodb.count_utxos.return_value = 42
        msg = {"address": "ts1addr"}
        result = get_total_utxo(mock_self, msg, None, None, client_ip="1.2.3.4")
        mock_self.broadcast.utxodb.count_utxos.assert_called_with("ts1addr")
        assert result == {"type": "UTXOS_COUNT", "count": 42}

    def test_address_too_long(self, mock_self, mock_pow_allow, mock_config):
        mock_config.MAX_UTXO_ADDR_LEN = 10
        msg = {"address": "verylongaddress"}
        result = get_total_utxo(mock_self, msg, None, None, client_ip="1.2.3.4")
        assert result == {"error": "address too long"}

    def test_pow_failure(self, mock_self):
        with patch("tsarchain.network.rpc.user_rpc.category.explorer.CM.allow_rpc_with_pow") as mock:
            mock.return_value = (False, {"error": "pow"})
            result = get_total_utxo(mock_self, {"address": "addr"}, None, None, client_ip="1.2.3.4")
            assert result == {"error": "pow"}