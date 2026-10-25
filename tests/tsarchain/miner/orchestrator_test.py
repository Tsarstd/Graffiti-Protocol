# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import pytest
import signal
from unittest.mock import MagicMock, patch


from tsarchain.miner.orchestrator import (
    SimpleMiner, 
    NodeRunner, 
    _enable_siginterrupt, 
    _register_bootstrap_peers,
    _run_snapshot_bootstrap,
)


# --- Setup & Fixtures ---

@pytest.fixture
def mock_config(monkeypatch):
    monkeypatch.setattr("tsarchain.miner.orchestrator.CFG.BOOTSTRAP_NODES", [("127.0.0.1", 8080)])
    monkeypatch.setattr("tsarchain.miner.orchestrator.CFG.SYNC_TIMEOUT", 1)

@pytest.fixture
def mock_network_cls():
    with patch("tsarchain.miner.orchestrator.Network") as mock:
        yield mock

@pytest.fixture
def mock_blockchain_cls():
    with patch("tsarchain.miner.orchestrator.Blockchain") as mock:
        yield mock


# --- Helper Functions Tests ---

def test_miner_custom_log_fn():
    out = []
    miner = SimpleMiner(
        address="tsar1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        cores=1,
        log_fn=lambda msg, col: out.append((msg, col)),
    )
    miner.log_fn("miner message", "green")
    assert out == [("miner message", "green")]

def test_noderunner_custom_log_fn():
    out = []
    runner = NodeRunner(
        bootstrap_snapshot=False,
        log_fn=lambda msg, col: out.append((msg, col)),
    )
    runner.log_fn("runner message", "blue")
    assert out == [("runner message", "blue")]

def test_enable_siginterrupt():
    # Calling this should not raise any exceptions
    _enable_siginterrupt()

def test_register_bootstrap_peers(mock_config):
    net_mock = MagicMock()
    net_mock.persistent_peers = set()
    net_mock.peers = set()
    net_mock._is_self_bootstrap = lambda h, p: False
    
    count = _register_bootstrap_peers(net_mock)
    assert count == 1
    assert ("127.0.0.1", 8080) in net_mock.peers
    assert ("127.0.0.1", 8080) in net_mock.persistent_peers

@patch("tsarchain.miner.orchestrator.maybe_bootstrap_snapshot")
def test_run_snapshot_bootstrap(mock_maybe_bootstrap):
    mock_maybe_bootstrap.return_value = MagicMock(status="installed", reason="")
    res = _run_snapshot_bootstrap(True, log_fn=MagicMock())
    assert res.status == "installed"
    
    # If disabled, should return None
    res_false = _run_snapshot_bootstrap(False, log_fn=MagicMock())
    assert res_false is None


# --- SimpleMiner Tests (Skipping start_mining) ---

@pytest.fixture
def miner():
    # Using a valid length tsarchain address
    return SimpleMiner("tsar1" + "a" * 24, cores=1, bootstrap_snapshot=False, log_fn=MagicMock())

def test_miner_validate_address():
    m_invalid = SimpleMiner("invalid_addr", 1, log_fn=MagicMock())
    assert m_invalid._validate_address() is False
    
    m_valid = SimpleMiner("tsar1" + "a" * 24, 1, log_fn=MagicMock())
    assert m_valid._validate_address() is True

def test_miner_signal_handler(miner):
    assert miner.mining_alive is True
    assert not miner.cancel_mining.is_set()
    
    miner._signal_handler(signal.SIGINT, None)
    
    assert miner.mining_alive is False
    assert miner.cancel_mining.is_set()

def test_miner_queue_block_for_broadcast(miner):
    block_mock = MagicMock()
    block_mock.hash.return_value.hex.return_value = "deadbeef"
    
    # Queue new block
    miner._queue_block_for_broadcast(block_mock)
    assert "deadbeef" in miner._pending_block_hashes
    assert len(miner._pending_blocks) == 1
    
    # Queue duplicate block (should be ignored)
    miner._queue_block_for_broadcast(block_mock)
    assert len(miner._pending_blocks) == 1

def test_miner_flush_pending_blocks(miner):
    miner.network = MagicMock()
    miner.network.publish_block.return_value = 1
    
    block_mock = MagicMock()
    block_mock.hash.return_value.hex.return_value = "deadbeef"
    miner._queue_block_for_broadcast(block_mock)
    
    miner._flush_pending_blocks()
    
    # Ensure block is removed from pending list
    assert len(miner._pending_blocks) == 0
    assert "deadbeef" not in miner._pending_block_hashes
    miner.network.publish_block.assert_called_once()

def test_miner_has_active_peers(miner):
    assert miner._has_active_peers() is False
    miner.network = MagicMock()
    miner.network.inbound_peers = {("127.0.0.1", 1234)}
    assert miner._has_active_peers() is True

def test_miner_start_node(miner, mock_network_cls, mock_blockchain_cls):
    res = miner._start_node()
    assert res is True
    assert miner.blockchain is not None
    assert miner.network is not None

@patch("tsarchain.miner.orchestrator.time.sleep", return_value=None)
def test_miner_wait_for_sync_timeout(mock_sleep, miner, mock_network_cls):
    miner.network = mock_network_cls()
    miner.blockchain = MagicMock(height=-1)
    miner._trusted_best_height = MagicMock(return_value=10)
    
    # timeout immediately
    res = miner._wait_for_sync(timeout=0)
    assert res is False

@patch("tsarchain.miner.orchestrator.time.sleep", return_value=None)
def test_miner_wait_for_sync_success(mock_sleep, miner, mock_network_cls):
    miner.network = mock_network_cls()
    miner.blockchain = MagicMock(height=10)
    miner.blockchain.get_last_block.return_value.hash.return_value.hex.return_value = "abc"
    miner._trusted_best_height = MagicMock(return_value=10)
    miner._trusted_tip_hash = MagicMock(return_value="abc")
    
    # The loop should break returning True when height >= trusted_best_height
    res = miner._wait_for_sync(timeout=10)
    assert res is True

def test_miner_stop(miner):
    miner.network = MagicMock()
    miner.thread_monitor = MagicMock()
    
    miner.stop()
    
    assert miner.mining_alive is False
    assert miner.cancel_mining.is_set()
    miner.network.shutdown.assert_called_once()
    miner.thread_monitor.stop_monitoring.assert_called_once()


# --- NodeRunner Tests ---

def test_noderunner_init():
    nr = NodeRunner(log_fn=MagicMock())
    assert nr.running is True

def test_noderunner_handle_signal():
    nr = NodeRunner(log_fn=MagicMock())
    nr._handle_signal(signal.SIGINT, None)
    assert nr.running is False

def test_noderunner_has_active_peers():
    nr = NodeRunner(log_fn=MagicMock())
    assert nr._has_active_peers() is False
    
    nr.network = MagicMock()
    nr.network.peers = {("127.0.0.1", 8080)}
    assert nr._has_active_peers() is True

@patch("tsarchain.miner.orchestrator.time.sleep")
def test_noderunner_start(mock_sleep, mock_network_cls, mock_blockchain_cls):
    nr = NodeRunner(bootstrap_snapshot=False, log_fn=MagicMock())
    
    # We want to kill the infinite while-loop after the first sleep
    def sleep_side_effect(*args, **kwargs):
        nr.running = False
        
    mock_sleep.side_effect = sleep_side_effect
    
    nr.start()
    
    assert nr.blockchain is not None
    assert nr.network is None
    assert nr.running is False
    # Shutdown should be called implicitly inside start()'s finally block
    # so _threads should be empty
    assert len(nr._threads) == 0

@patch("tsarchain.miner.orchestrator.time.sleep")
def test_noderunner_sync_daemon(mock_sleep):
    nr = NodeRunner(log_fn=MagicMock())
    nr.running = True
    nr.blockchain = MagicMock(height=5)
    nr.network = MagicMock()
    nr.network.peers = {("127.0.0.1", 8080)}
    # Provide a recent sync time so _sync_ready becomes True
    nr.network._peer_last_sync = {("127.0.0.1", 8080): time.time()}
    
    def sleep_side_effect(*args, **kwargs):
        nr.running = False
        
    mock_sleep.side_effect = sleep_side_effect
    
    nr._sync_daemon()
    assert nr._sync_ready is True


# --- Tests for start_mining ---

def test_miner_start_mining_invalid_address(miner):
    miner.address = "invalid"
    assert miner.start_mining() is False

@patch.object(SimpleMiner, '_start_node', return_value=False)
def test_miner_start_mining_start_node_fails(mock_start, miner):
    assert miner.start_mining() is False

@patch.object(SimpleMiner, '_start_node', return_value=True)
@patch.object(SimpleMiner, '_wait_for_sync', return_value=False)
def test_miner_start_mining_sync_fails(mock_sync, mock_start, miner):
    assert miner.start_mining() is False

@patch.object(SimpleMiner, '_start_node', return_value=True)
@patch.object(SimpleMiner, '_wait_for_sync', return_value=True)
def test_miner_start_mining_genesis_fails(mock_sync, mock_start, miner, mock_blockchain_cls):
    # Simulate height < 0 and genesis fails
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = -1
    miner.blockchain.ensure_genesis.return_value = False
    
    assert miner.start_mining() is False

@patch.object(SimpleMiner, '_start_node', return_value=True)
@patch.object(SimpleMiner, '_wait_for_sync', return_value=True)
def test_miner_start_mining_behind_trusted(mock_sync, mock_start, miner, mock_blockchain_cls):
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = 1
    miner._has_active_peers = MagicMock(return_value=True)
    
    # Gap detected
    miner._trusted_best_height = MagicMock(return_value=5)
    
    # We want it to break after hitting the gap block
    with patch("tsarchain.miner.orchestrator.time.sleep") as mock_sleep:
        def sleep_effect(*args):
            miner.mining_alive = False
        mock_sleep.side_effect = sleep_effect
        
        miner.start_mining()
        
    assert mock_sleep.called

@patch.object(SimpleMiner, '_start_node', return_value=True)
@patch.object(SimpleMiner, '_wait_for_sync', return_value=True)
def test_miner_start_mining_hash_mismatch(mock_sync, mock_start, miner, mock_blockchain_cls):
    miner.blockchain = mock_blockchain_cls.return_value
    miner.blockchain.height = 1
    miner._has_active_peers = MagicMock(return_value=True)
    
    # Heights match but hashes differ
    miner._trusted_best_height = MagicMock(return_value=1)
    miner._trusted_tip_hash = MagicMock(return_value="trusted_hash")
    miner._get_local_tip = MagicMock(return_value=(1, "local_hash"))
    
    with patch("tsarchain.miner.orchestrator.time.sleep") as mock_sleep:
        def sleep_effect(*args):
            miner.mining_alive = False
        mock_sleep.side_effect = sleep_effect
        
        miner.start_mining()
        
    assert mock_sleep.called


def test_miner_sigint_stops_tui(miner):
    mock_tui = MagicMock()
    miner.tui = mock_tui
    miner.thread_monitor = MagicMock()
    
    # Trigger signal handler logic
    with patch.object(miner, "_signal_handler") as mock_handler:
        # Call the sigint handler registered on miner init
        handler = signal.getsignal(signal.SIGINT)
        if callable(handler):
            handler(signal.SIGINT, None)
            mock_tui.stop.assert_called_once()
            mock_handler.assert_called_once()


def test_tui_dynamic_log_buffer():
    from tsarchain.miner.cosmetic.tui import MinerTUI
    tui = MinerTUI(address="tsar1test", cores=1)
    assert tui.log_lines.maxlen == 200
    
    for i in range(25):
        tui.add_log(f"log line {i}")
    assert len(tui.log_lines) == 25
    
    layout = tui._make_layout()
    assert layout is not None


def test_thread_monitor_stack_trace_option():
    from tsarchain.utils.thread_check import get_thread_monitor
    tm = get_thread_monitor()
    threads_fast = tm.get_all_threads(include_stack=False)
    assert len(threads_fast) > 0
    # Fast path should not extract stack_info
    assert all(t.stack_info is None for t in threads_fast)

    threads_detailed = tm.get_all_threads(include_stack=True)
    assert len(threads_detailed) > 0


def test_tui_stop_terminal_cleanup():
    from tsarchain.miner.cosmetic.tui import MinerTUI
    tui = MinerTUI(address="tsar1test", cores=1)
    # Stopping TUI should execute without error and restore terminal cursor
    tui.stop()


def test_tui_node_only_layout():
    from tsarchain.miner.cosmetic.tui import MinerTUI
    tui = MinerTUI(
        address="Node Only",
        cores=0,
        mode="Node Only",
        chain_height_fn=lambda: 100,
        peer_counts_fn=lambda: (2, 3),
        mempool_count_fn=lambda: 5,
        node_only=True,
    )
    assert tui.node_only is True
    layout = tui._make_layout()
    assert layout is not None
    tui.stop()


def test_safe_mempool_count():
    import sys, os
    apps_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    if apps_dir not in sys.path:
        sys.path.insert(0, apps_dir)
    from apps.cli_node_miner import _safe_mempool_count
    
    # 1. Test null runner
    assert _safe_mempool_count(None) == 0

    # 2. Test runner with network broadcast mempool
    mock_runner = MagicMock()
    mock_runner.blockchain = None
    mock_pool = MagicMock()
    mock_pool._pool = {"tx1": "data", "tx2": "data"}
    mock_runner.network.broadcast.mempool = mock_pool
    assert _safe_mempool_count(mock_runner) == 2

    # 3. Test runner with blockchain mempool size
    mock_runner_bc = MagicMock()
    mock_runner_bc.blockchain.get_mempool_size.return_value = 5
    assert _safe_mempool_count(mock_runner_bc) == 5

    # 4. Test runner with real Network proxy (empty mempool without raising AttributeError)
    from tsarchain.network.node import Network
    real_runner = MagicMock()
    real_runner.blockchain = None
    real_runner.network = Network()
    assert _safe_mempool_count(real_runner) == 0


def test_simple_miner_abort_on_tip_changed():
    """Verify SimpleMiner._on_tip_changed sets abort_block_mining event."""
    from tsarchain.miner.orchestrator import SimpleMiner
    with patch('tsarchain.miner.orchestrator.signal.signal'), \
         patch('tsarchain.miner.orchestrator.register_thread_monitoring_signal'):
        miner = SimpleMiner(address="tsar1qtest", cores=1, log_fn=MagicMock())
        assert miner.abort_block_mining.is_set() is False
        miner._on_tip_changed(10, "0000hash")
        assert miner.abort_block_mining.is_set() is True


def test_cli_main_dispatches_node_only():
    """Verify main() routes to run_node_only when --node-only is passed."""
    import sys, os
    apps_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    if apps_dir not in sys.path:
        sys.path.insert(0, apps_dir)
    from apps import cli_node_miner

    with patch.object(cli_node_miner, "_parse_args") as mock_parse, \
         patch.object(cli_node_miner, "_run_node_only") as mock_node_only, \
         patch.object(cli_node_miner, "_run_miner") as mock_miner:
        mock_parse.return_value = MagicMock(
            thread_report=False,
            init_genesis=False,
            node_only=True,
            yes=True,
            address=None,
            cores=None,
        )
        cli_node_miner.main()
        mock_node_only.assert_called_once()
        mock_miner.assert_not_called()


def test_cli_main_dispatches_mining():
    """Verify main() routes to run_miner when --node-only is not passed."""
    import sys, os
    apps_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    if apps_dir not in sys.path:
        sys.path.insert(0, apps_dir)
    from apps import cli_node_miner

    with patch.object(cli_node_miner, "_parse_args") as mock_parse, \
         patch.object(cli_node_miner, "_run_node_only") as mock_node_only, \
         patch.object(cli_node_miner, "_run_miner") as mock_miner:
        mock_parse.return_value = MagicMock(
            thread_report=False,
            init_genesis=False,
            node_only=False,
            yes=True,
            address="tsar1qtest",
            cores=2,
        )
        cli_node_miner.main()
        mock_miner.assert_called_once()
        mock_node_only.assert_not_called()


def test_cli_main_dispatches_init_genesis():
    """Verify main() routes to run_init_genesis when --init-genesis is passed."""
    import sys, os
    apps_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    if apps_dir not in sys.path:
        sys.path.insert(0, apps_dir)
    from apps import cli_node_miner

    with patch.object(cli_node_miner, "_parse_args") as mock_parse, \
         patch.object(cli_node_miner, "_run_init_genesis") as mock_genesis, \
         patch.object(cli_node_miner, "_run_node_only") as mock_node_only, \
         patch.object(cli_node_miner, "_run_miner") as mock_miner:
        mock_parse.return_value = MagicMock(
            thread_report=False,
            init_genesis=True,
            node_only=False,
            yes=True,
            address=None,
            cores=None,
        )
        cli_node_miner.main()
        mock_genesis.assert_called_once()
        mock_node_only.assert_not_called()
        mock_miner.assert_not_called()



# --- Tests for Extracted Internal Mining Methods ---

def test_miner_ensure_genesis(miner):
    miner.blockchain = MagicMock(height=10)
    assert miner._ensure_genesis() is True
    miner.blockchain.ensure_genesis.assert_not_called()

    miner.blockchain.height = -1
    miner.blockchain.ensure_genesis.return_value = True
    assert miner._ensure_genesis() is True
    miner.blockchain.ensure_genesis.assert_called_once()

    miner.blockchain.ensure_genesis.return_value = False
    assert miner._ensure_genesis() is False


def test_miner_check_mining_sync_no_peers(miner):
    miner._has_active_peers = MagicMock(return_value=False)
    miner._bootstrap_is_self_only = MagicMock(return_value=False)
    with patch("tsarchain.miner.orchestrator.time.sleep"):
        synced, gap_log = miner._check_mining_sync(None)
    assert synced is False
    assert gap_log == "no_peers"


def test_miner_check_mining_sync_no_trusted(miner):
    miner._has_active_peers = MagicMock(return_value=True)
    miner._trusted_best_height = MagicMock(return_value=-1)
    miner._trusted_tip_hash = MagicMock(return_value=None)
    miner._get_local_tip = MagicMock(return_value=(0, "hash0"))
    miner.network = MagicMock()
    with patch("tsarchain.miner.orchestrator.time.sleep"):
        synced, gap_log = miner._check_mining_sync(None)
    assert synced is False
    assert gap_log == "no_trusted"
    miner.network.request_sync.assert_called_once_with(fast=True)


def test_miner_check_mining_sync_gap(miner):
    miner._has_active_peers = MagicMock(return_value=True)
    miner._trusted_best_height = MagicMock(return_value=10)
    miner._trusted_tip_hash = MagicMock(return_value="trusted_hash")
    miner._get_local_tip = MagicMock(return_value=(5, "local_hash"))
    miner.blockchain = MagicMock(height=5)
    miner.network = MagicMock()
    with patch("tsarchain.miner.orchestrator.time.sleep"):
        synced, gap_log = miner._check_mining_sync(None)
    assert synced is False
    assert gap_log == 5
    miner.network.request_sync.assert_called_once_with(fast=True)


def test_miner_check_mining_sync_hash_mismatch(miner):
    miner._has_active_peers = MagicMock(return_value=True)
    miner._trusted_best_height = MagicMock(return_value=5)
    miner._trusted_tip_hash = MagicMock(return_value="trusted_hash")
    miner._get_local_tip = MagicMock(return_value=(5, "different_hash"))
    miner.blockchain = MagicMock(height=5)
    miner.network = MagicMock()
    with patch("tsarchain.miner.orchestrator.time.sleep"):
        synced, gap_log = miner._check_mining_sync(None)
    assert synced is False
    assert gap_log == "hash_mismatch"
    miner.network.request_sync.assert_called_once_with(fast=True)


def test_miner_check_mining_sync_success(miner):
    miner._has_active_peers = MagicMock(return_value=True)
    miner._trusted_best_height = MagicMock(return_value=5)
    miner._trusted_tip_hash = MagicMock(return_value="same_hash")
    miner._get_local_tip = MagicMock(return_value=(5, "same_hash"))
    miner.blockchain = MagicMock(height=5)
    miner.network = MagicMock()
    synced, gap_log = miner._check_mining_sync(None)
    assert synced is True
    assert gap_log is None


def test_miner_handle_mined_block(miner):
    miner.network = MagicMock()
    miner.network.publish_block.return_value = 1
    miner.tui = MagicMock()

    block = MagicMock(height=42, transactions=[MagicMock(), MagicMock()])
    block.hash.return_value.hex.return_value = "beef" * 16

    miner._handle_mined_block(block)

    miner.tui.note_block_mined.assert_called_once_with(42)
    miner.network.publish_block.assert_called_once_with(block, exclude=None, force=True)


def test_miner_handle_tip_abort(miner):
    miner._get_local_tip = MagicMock(return_value=(10, "deadbeef" * 4))
    miner.abort_block_mining.set()
    miner._handle_tip_abort()
    assert not miner.abort_block_mining.is_set()


def test_miner_process_mining_result(miner):
    block = MagicMock()
    with patch.object(miner, "_handle_mined_block") as mock_mined,          patch.object(miner, "_handle_tip_abort") as mock_abort:
        miner._process_mining_result(block)
        mock_mined.assert_called_once_with(block)
        mock_abort.assert_not_called()

    with patch.object(miner, "_handle_mined_block") as mock_mined,          patch.object(miner, "_handle_tip_abort") as mock_abort:
        miner.abort_block_mining.set()
        miner._process_mining_result(None)
        mock_mined.assert_not_called()
        mock_abort.assert_called_once()


def test_miner_handle_mining_interrupt(miner):
    miner.mining_alive = True
    miner._handle_mining_interrupt()
    assert miner.mining_alive is False
    assert miner.cancel_mining.is_set()
    assert miner.abort_block_mining.is_set()


def test_miner_handle_mining_os_error(miner):
    import errno
    eintr = OSError()
    eintr.errno = errno.EINTR
    assert miner._handle_mining_os_error(eintr) is True
    assert miner.mining_alive is False

    miner.mining_alive = True
    eother = OSError()
    eother.errno = errno.EACCES
    with patch("tsarchain.miner.orchestrator.time.sleep"):
        assert miner._handle_mining_os_error(eother) is False
    assert miner.mining_alive is True


def test_miner_run_mine_worker_exception(miner):
    miner.blockchain = MagicMock()
    def raise_runner(result, cancel):
        result["exc"] = RuntimeError("Worker failure")

    with patch.object(miner, "_mine_block_runner", side_effect=raise_runner):
        with pytest.raises(RuntimeError, match="Worker failure"):
            miner._run_mine_worker()


def test_cosmetic_badge_and_badges():
    from tsarchain.miner.cosmetic import interface as COL
    multi = COL._badges(
        ("FIRST", COL.BG_RED),
        ("SECOND", COL.BG_WHITE, COL.ORANGE),
    )
    assert "FIRST" in multi
    assert "SECOND" in multi
    assert COL.BG_RED in multi
    assert COL.BG_WHITE in multi
    assert COL.ORANGE in multi



def test_cosmetic_snapshot_info_flags():
    from tsarchain.miner.cosmetic import interface as COL
    assert "SNAPSHOTS" in COL.snapshot_info("backup")
    assert "ENABLED" in COL.snapshot_info("backup")
    assert "DISABLED" in COL.snapshot_info("backup_disabled")
    assert "DISABLED" in COL.snapshot_info("disabled")
    assert "BOOTSTRAP" in COL.snapshot_info("disabled")
    assert "SUCCESS" in COL.snapshot_info("installed", "height 100")
    assert "FAILED" in COL.snapshot_info("failed", "network timeout")
    assert "SKIPPED" in COL.snapshot_info("skipped", "already synced")
    assert "SYNC" in COL.snapshot_info("progress", "downloading chunk 1")


def test_cosmetic_node_sync_genesis_badges():
    from tsarchain.miner.cosmetic import interface as COL

    # node_info
    assert "ONLINE" in COL.node_info("started", "3 peers")
    assert "STARTING" in COL.node_info("starting", "node runner")
    assert "STOPPING" in COL.node_info("stopping", "shutting down")
    assert "STOPPED" in COL.node_info("stopped", "miner stopped")
    assert "INTERRUPT" in COL.node_info("interrupted", "user abort")

    # sync_info
    assert "WAITING" in COL.sync_info("waiting")
    assert "PEERS" in COL.sync_info("waiting_peers")
    assert "BOOTSTRAP" in COL.sync_info("waiting_trusted")
    assert "PAUSED" in COL.sync_info("paused_peers")
    assert "READY" in COL.sync_info("synced", "10", "10")
    assert "CATCHUP" in COL.sync_info("gap", "5", "10")
    assert "PROGRESS" in COL.sync_info("progress", "5", "10")
    assert "RESYNC" in COL.sync_info("mismatch")
    assert "TIMEOUT" in COL.sync_info("timeout")
    assert "CONFIRMED" in COL.sync_info("confirmed", "live")
    assert "HEIGHT" in COL.sync_info("height", "42")

    # genesis_info
    assert "CREATED" in COL.genesis_info(True)
    assert "FAILED" in COL.genesis_info(False)

    # tip_switch_info
    assert "NEW TIP" in COL.tip_switch_info(50, "deadbeefcafebabe")

    # error & warn
    assert "ERROR" in COL.error_info("BROADCAST", "connection refused")
    assert "WARN" in COL.warn_info("BROADCAST", "retry 1")
