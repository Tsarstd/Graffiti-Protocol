# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import json
import pytest
from unittest.mock import MagicMock, patch

from archivist.archivist_orchestrator import ArchivistOrchestrator


@pytest.fixture
def mock_orchestrator():
    with patch("archivist.archivist_orchestrator.RPC") as mock_rpc, \
         patch("archivist.archivist_orchestrator.NodeDirectory") as mock_dir:
        
        mock_rpc_instance = MagicMock()
        mock_rpc_instance.address = "tsar1_mock_addr"
        mock_rpc.return_value = mock_rpc_instance
        
        orchestrator = ArchivistOrchestrator(
            address="tsar1est", 
            target_node=("127.0.0.1", 8000), 
            refresh_sec=10,
            log_callback=MagicMock(),
            update_callback=MagicMock()
        )
        orchestrator._server = MagicMock()
        yield orchestrator


def test_init_invalid_address():
    with patch("archivist.archivist_orchestrator.RPC") as mock_rpc:
        mock_rpc_instance = MagicMock()
        mock_rpc_instance.set_address_override.side_effect = Exception("Invalid address")
        mock_rpc.return_value = mock_rpc_instance
        
        with pytest.raises(RuntimeError, match="Invalid payout address: Invalid address"):
            ArchivistOrchestrator(address="invalid", target_node=("127.0.0.1", 8000))


def test_normalize_network_info(mock_orchestrator):
    # Test valid NETWORK_INFO type
    info_obj = {
        "type": "NETWORK_INFO",
        "data": {
            "chain": {"tip_height": 100},
            "peers": {"count": 5}
        }
    }
    normalized = mock_orchestrator._normalize_network_info(info_obj)
    assert normalized["height"] == 100
    assert normalized["peers"] == 5

    # Test invalid info
    assert mock_orchestrator._normalize_network_info({"error": True}) is None


@patch("archivist.archivist_orchestrator.StorageServer")
def test_launch_storage_server(mock_server, mock_orchestrator):
    # Mock config to test port selection
    with patch("archivist.archivist_orchestrator.CFG") as mock_cfg:
        mock_cfg.STORAGE_PORT_START = 40000
        mock_cfg.STORAGE_PORT_END = 40005
        
        port = mock_orchestrator._launch_storage_server()
        assert port == 40000
        mock_server.assert_called_once()


def test_connect_success(mock_orchestrator):
    mock_orchestrator.rpc.connect.return_value = True
    with patch.object(mock_orchestrator, "_launch_storage_server", return_value=40000):
        res = mock_orchestrator.connect()
        assert res is True
        assert mock_orchestrator.connected is True
        assert mock_orchestrator.storage_port == 40000
        mock_orchestrator.directory.mark_good.assert_called_with(("127.0.0.1", 8000))


def test_connect_fail_fallback(mock_orchestrator):
    # initial connect fails, but fallback to peer works
    mock_orchestrator.rpc.connect.side_effect = [False, True]
    mock_orchestrator.directory.get_nodes.return_value = [("192.168.1.1", 8001)]
    
    with patch.object(mock_orchestrator, "_launch_storage_server", return_value=40000):
        res = mock_orchestrator.connect()
        assert res is True
        assert mock_orchestrator._target_node == ("192.168.1.1", 8001)


def test_connect_all_fail(mock_orchestrator):
    mock_orchestrator.rpc.connect.return_value = False
    mock_orchestrator.directory.get_nodes.return_value = []
    
    with patch.object(mock_orchestrator, "_launch_storage_server", return_value=40000):
        res = mock_orchestrator.connect()
        assert res is False
        assert mock_orchestrator.connected is False


def test_log_callback(mock_orchestrator):
    mock_orchestrator._log("Test message")
    mock_orchestrator.log_callback.assert_called_with("Test message", False)

    mock_orchestrator._log("Error message", error=True)
    mock_orchestrator.log_callback.assert_called_with("Error message", True)


@patch("archivist.archivist_orchestrator.threading.Thread.start")
def test_refresh_once(mock_thread_start, mock_orchestrator):
    mock_orchestrator.rpc.call.return_value = {
        "type": "NETWORK_INFO",
        "data": {"chain": {"tip_height": 100}, "peers": {"count": 5}},
    }
    mock_orchestrator._server.get_index_stats.return_value = {"files": {}}
    
    mock_orchestrator.refresh_once()
        
    assert mock_orchestrator.last_info["height"] == 100
    assert mock_orchestrator.last_index == {"files": {}}
    assert mock_orchestrator.pool_data == {}
    mock_orchestrator.update_callback.assert_called_once()


def test_refresh_pool_listing_and_auto_payout(mock_orchestrator):
    mock_orchestrator.connected = True
    mock_orchestrator.last_info = {"height": 100}
    
    # Mock GRAFFITI_GET_POSTS response & GRAFFITI_BUILD_PAYOUT response
    mock_orchestrator.rpc.call.side_effect = [
        # First call for GRAFFITI_GET_POSTS
        {
            "posts": [
                {
                    "art_id": "art1",
                    "sha256": "hash1",
                    "stats": {"pool_balance": 5000, "last_paid_epoch": 0}
                }
            ]
        },
        # Second call for GRAFFITI_BUILD_PAYOUT
        {"status": "ok", "tx": {"txid": "tx123"}}
    ]
    
    files = {
        "gid1": {
            "art_id": "art1", 
            "sha256": "hash1", 
            "paid": True, 
            "state": "stored",
            "last_proof_epoch": 10
        }
    }
    
    with patch("archivist.archivist_orchestrator.GRAFFITI") as mock_graf:
        mock_graf.compute_proof_epoch.return_value = 20
        mock_orchestrator._refresh_pool_listing(files)
        
    assert "art1" in mock_orchestrator.pool_data
    # Check if auto_payout guard was updated
    assert mock_orchestrator._auto_payout_guard["art1"]["status"] == "ok"
    assert mock_orchestrator._auto_payout_guard["art1"]["epoch"] == 10


def test_auto_mark_paid(mock_orchestrator):
    posts = [
        {"art_id": "art1", "block_height": 100, "txid": "tx1"}
    ]
    files_by_art = {
        "art1": {"id": "gid1", "meta": {"paid": False}}
    }
    mock_orchestrator._server.mark_paid.return_value = {"status": "ok"}
    
    with patch("archivist.archivist_orchestrator.threading.Thread.start"):
        mock_orchestrator._auto_mark_paid(posts, files_by_art)
        mock_orchestrator._server.mark_paid.assert_called_once_with(
            graffiti_id="gid1", art_id="art1", txid="tx1", block_height=100
        )


def test_run_retention_proofs(mock_orchestrator):
    mock_orchestrator.connected = True
    files = {
        "gid1": {
            "art_id": "art1",
            "paid": True,
            "state": "stored",
            "last_proof_epoch": 5
        }
    }
    idx = {"files": files}
    tip_height = 100
    
    with patch("archivist.archivist_orchestrator.GRAFFITI") as mock_graf:
        mock_graf.compute_proof_epoch.return_value = 10
        
        mock_orchestrator._server.generate_retention_proof.return_value = {
            "status": "ok", 
            "epoch": 10, 
            "offset": 0, 
            "length": 1024, 
            "hash": "h", 
            "seed": "s"
        }
        
        mock_orchestrator.rpc.call.return_value = {"status": "ok"}
        
        mock_orchestrator._run_retention_proofs(idx, tip_height)
        
        # Should have called RPC to submit proof
        mock_orchestrator.rpc.call.assert_called_with({
            "type": "GRAFFITI_PROOF_SUBMIT",
            "art_id": "art1",
            "epoch": 10,
            "offset": 0,
            "length": 1024,
            "hash": "h",
            "height": 100,
            "seed": "s",
            "storer": "tsar1_mock_addr",
            "ts": mock_orchestrator.rpc.call.call_args[0][0]["ts"],
            "nonce": mock_orchestrator.rpc.call.call_args[0][0]["nonce"]
        }, timeout=8.0)


def test_run_retention_proofs_failure_rollback(mock_orchestrator):
    mock_orchestrator.connected = True
    files = {
        "gid1": {
            "art_id": "art1",
            "paid": True,
            "state": "stored",
            "last_proof_epoch": 5,
            "proof_status": "ok",
        }
    }
    idx = {"files": files}
    mock_orchestrator._server.index = {"files": {"gid1": dict(files["gid1"])}}
    mock_orchestrator._server._normalize_file_meta = lambda gid, m: m
    mock_orchestrator._server._save_index = MagicMock()
    tip_height = 100

    with patch("archivist.archivist_orchestrator.GRAFFITI") as mock_graf:
        mock_graf.compute_proof_epoch.return_value = 10
        mock_orchestrator._server.generate_retention_proof.return_value = {
            "status": "ok",
            "epoch": 10,
            "offset": 0,
            "length": 1024,
            "hash": "h",
            "seed": "s",
        }
        # Simulate node error
        mock_orchestrator.rpc.call.return_value = {"error": "merkle_path_required"}

        mock_orchestrator._run_retention_proofs(idx, tip_height)

        # Meta should be rolled back to last_epoch (5), not remain 10
        fmeta = mock_orchestrator._server.index["files"]["gid1"]
        assert fmeta["last_proof_epoch"] == 5
        assert fmeta["proof_status"] == "error"
        assert fmeta["proof_fail_reason"] == "merkle_path_required"
        mock_orchestrator._server._save_index.assert_called()


def test_start_stop(mock_orchestrator):
    with patch.object(mock_orchestrator, "connect", return_value=True), \
         patch("archivist.archivist_orchestrator.threading.Thread") as mock_thread:
        
        res = mock_orchestrator.start()
        assert res is True
        assert mock_thread.call_count == 3
        
        mock_orchestrator.stop()
        assert mock_orchestrator._stop.is_set()
        assert mock_orchestrator.connected is False


def test_heartbeat_loop(mock_orchestrator):
    mock_orchestrator.connected = True
    mock_orchestrator.rpc.call.return_value = {"type": "PONG"}
    
    def side_effect(*args, **kwargs):
        mock_orchestrator._stop.set()
        
    with patch.object(mock_orchestrator, "refresh_once", side_effect=side_effect) as mock_refresh:
        mock_orchestrator._heartbeat_loop()
        mock_refresh.assert_called_once()


def test_retention_loop(mock_orchestrator):
    mock_orchestrator.connected = True
    mock_orchestrator.last_info = {"height": 100}
    mock_orchestrator._server.run_gc.return_value = {"expired": 1}
    mock_orchestrator._server.get_index_stats.return_value = {"files": {}}
    
    def side_effect(*args, **kwargs):
        mock_orchestrator._stop.set()
        
    with patch.object(mock_orchestrator, "_trigger_update", side_effect=side_effect) as mock_update:
        mock_orchestrator._retention_loop()
        mock_update.assert_called_once()


def test_attempt_reconnect(mock_orchestrator):
    mock_orchestrator._target_node = ("127.0.0.1", 8000)
    mock_orchestrator.storage_port = 40000
    mock_orchestrator.rpc.connect.return_value = True
    
    assert mock_orchestrator.attempt_reconnect() is True
    assert mock_orchestrator.connected is True
    
    mock_orchestrator.rpc.connect.return_value = False
    assert mock_orchestrator.attempt_reconnect() is False


def test_handle_rpc_drop(mock_orchestrator):
    mock_orchestrator.connected = True
    with patch.object(mock_orchestrator, "attempt_reconnect", return_value=True) as mock_reconnect:
        mock_orchestrator._handle_rpc_drop("test reason")
        mock_reconnect.assert_called_once()
        mock_orchestrator.log_callback.assert_any_call("[rpc] reconnected automatically.", False)
        
    mock_orchestrator.connected = True
    with patch.object(mock_orchestrator, "attempt_reconnect", return_value=False) as mock_reconnect_fail:
        mock_orchestrator._handle_rpc_drop("test reason 2")
        mock_reconnect_fail.assert_called_once()
        mock_orchestrator.log_callback.assert_any_call("Reconnection failed. Use 'reconnect' command.", False)


def test_mark_pending_payouts(mock_orchestrator):
    files = {
        "gid1": {"state": "stored", "paid": False, "size_bytes": 100},
        "gid2": {"state": "stored", "paid": True}
    }
    mock_orchestrator.pending_paid = {"gid2", "gid3"}
    
    idx = {"files": files}
    mock_orchestrator._mark_pending_payouts(idx)
    
    assert "gid1" in mock_orchestrator.pending_paid
    assert "gid2" not in mock_orchestrator.pending_paid
    assert "gid3" not in mock_orchestrator.pending_paid

