# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import json
import pytest
import base64
from unittest.mock import patch, MagicMock

from archivist.server_archivist import StorageServer

@pytest.fixture
def mock_db():
    with patch("archivist.server_archivist.ArchivistDatabase") as mock:
        db_inst = MagicMock()
        db_inst.load_index.return_value = {"files": {}, "bytes_used": 0, "art_map": {}}
        mock.return_value = db_inst
        yield db_inst

@pytest.fixture
def server(tmp_path, mock_db):
    with patch("threading.Thread"):  # prevent actual socket binding
        srv = StorageServer("127.0.0.1", 12345, str(tmp_path / "stor"))
        return srv

def test_normalize_file_meta(server):
    res = server._normalize_file_meta("art123", {"state": "uploading", "art_id": "art_1"})
    assert res["paid"] is False
    assert res["state"] == "uploading"
    assert res["received_bytes"] == 0
    assert "art_1" in server.index["art_map"]
    assert server.index["art_map"]["art_1"] == "art123"

def test_load_and_save_index(server, mock_db):
    mock_db.load_index.return_value = {
        "files": {"file1": {"size_bytes": 500, "state": "stored"}},
        "bytes_used": 0,
        "art_map": {}
    }
    server._load_index()
    assert server.index["bytes_used"] == 500
    assert server.index["files"]["file1"]["paid"] is False
    
    server._save_index()
    mock_db.save_index.assert_called_with(server.index)

def test_get_index_stats(server):
    server.index["files"]["gid1"] = {"size_bytes": 100}
    stats = server.get_index_stats()
    assert stats["bytes_used"] == 100
    assert "gid1" in stats["files"]

def test_mark_paid(server):
    server.db.has_final.return_value = False
    server.db.promote_incoming.return_value = True
    server.db.get_final_blob_path.return_value = "/data/final/gid1.bin"

    server.index["files"]["gid1"] = {"size_bytes": 50, "state": "receiving", "paid": False}
    res = server.mark_paid(graffiti_id="gid1", art_id="art1", txid="tx123", block_height=10)
    assert res["status"] == "ok"
    assert server.index["files"]["gid1"]["paid"] is True
    assert server.index["files"]["gid1"]["txid_paid"] == "tx123"
    assert server.index["files"]["gid1"]["confirmed_at_height"] == 10

def test_mark_paid_missing(server):
    res = server.mark_paid(graffiti_id="nonexistent")
    assert res["status"] == "error"
    assert res["reason"] == "no_such"

def test_run_gc(server):
    server.index["files"]["gid1"] = {"size_bytes": 50, "paid": False, "expire_at_height": 100}
    res = server.run_gc(tip_height=105)
    assert res["status"] == "ok"
    assert res["expired"] == 1
    assert server.db.delete_blob.call_count == 1

@patch("archivist.server_archivist.GRAFFITI.calc_proof_challenge")
@patch("archivist.server_archivist.GRAFFITI.hash_proof_chunk")
def test_generate_retention_proof(mock_hash, mock_chal, server):
    server.index["files"]["gid1"] = {"size_bytes": 50, "art_id": "art1"}
    mock_chal.return_value = {"offset": 0, "length": 50, "epoch": 1, "seed": "seed123"}
    mock_hash.return_value = "hash123"

    server.db.get_final_bytes_range.return_value = b"sample_bytes"
    server.db.get_final_merkle_path.return_value = ["path1", "path2"]

    res = server.generate_retention_proof(graffiti_id="gid1", tip_height=10)
    assert res["status"] == "ok"
    assert res["hash"] == "hash123"
    assert res["chunk"] == base64.b64encode(b"sample_bytes").decode("ascii")
    assert res["path"] == ["path1", "path2"]

@patch("archivist.server_archivist.send_message")
def test_respond(mock_send, server):
    conn = MagicMock()
    server._respond(conn, {"type": "OK", "data": "123"})
    assert mock_send.call_count == 1
    
    # Test message too large
    with patch("archivist.server_archivist.CFG.GRAFFITI_MAX_MSG_BYTES", 10):
        server._respond(conn, {"type": "BIG", "data": "a" * 100})
        args, kwargs = mock_send.call_args
        raw = args[1]
        assert b"msg_too_large" in raw

def test_client_ip(server):
    assert server._client_ip(("1.2.3.4", 1234)) == "1.2.3.4"
    assert server._client_ip(None) == "0.0.0.0"

@patch("archivist.server_archivist.wallet_route.handle_wallet_rpc")
def test_handle(mock_wallet, server):
    # PING
    assert server._handle({"type": "PING"}) == {"type": "PONG"}

    # Wallet responds
    mock_wallet.return_value = {"status": "ok_wallet"}
    assert server._handle({"type": "STOR_INIT"}) == {"status": "ok_wallet"}
    
    # Unknown
    mock_wallet.return_value = None
    assert server._handle({"type": "UNKNOWN_ACTION"}) == {"error": "unknown type"}

@patch("archivist.server_archivist.recv_message")
@patch("archivist.server_archivist.send_message")
def test_handle_conn_banned(mock_send, mock_recv, server):
    conn = MagicMock()
    server.guard.ban_ip("1.2.3.4", 100)
    server._handle_conn(conn, ("1.2.3.4", 1234))
    assert mock_recv.call_count == 0
    args, kwargs = mock_send.call_args
    assert b"banned" in args[1]

@patch("archivist.server_archivist.recv_message")
@patch("archivist.server_archivist.send_message")
def test_handle_conn_rate_limit(mock_send, mock_recv, server):
    conn = MagicMock()
    mock_recv.return_value = json.dumps({"type": "STOR_INIT"}).encode("utf-8")
    
    # Mock allow to fail (PoW required)
    server.guard.allow = MagicMock(return_value={"ok": False, "error": "pow_required", "pow_challenge": {"nonce": 1}, "retry_after": 5})
    
    server._handle_conn(conn, ("5.5.5.5", 1234))
    args, kwargs = mock_send.call_args
    raw = args[1]
    assert b"pow_required" in raw
    assert b"pow_challenge" in raw

@patch("archivist.server_archivist.recv_message")
@patch("archivist.server_archivist.send_message")
@patch("archivist.server_archivist.verify_and_unwrap")
def test_handle_conn_success(mock_verify, mock_send, mock_recv, server):
    conn = MagicMock()
    mock_recv.return_value = json.dumps({"type": "PING"}).encode("utf-8")
    server.guard.allow = MagicMock(return_value={"ok": True})
    
    with patch.object(server, "_handle", return_value={"status": "pong"}):
        server._handle_conn(conn, ("8.8.8.8", 1234))
    
    args, kwargs = mock_send.call_args
    assert b"pong" in args[1]
    
    # Test envelope
    mock_recv.return_value = json.dumps({"env": 1, "payload": "xyz", "from": "addr1"}).encode("utf-8")
    mock_verify.return_value = {"type": "PING"}
    with patch.object(server, "_handle", return_value={"status": "pong_env"}):
        server._handle_conn(conn, ("8.8.8.8", 1234))
    args, kwargs = mock_send.call_args
    assert b"pong_env" in args[1]


def test_reconcile_blobs_on_disk(tmp_path, mock_db):
    stor_dir = tmp_path / "stor_reconcile"
    blobs_dir = stor_dir / "blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    dummy_sha = "a" * 64
    blob_file = blobs_dir / f"{dummy_sha}_123456.bin"
    blob_file.write_bytes(b"dummy_graffiti_payload_data")

    with patch("threading.Thread"):
        srv = StorageServer("127.0.0.1", 12346, str(stor_dir))

    gid = f"{dummy_sha}_123456"
    assert gid in srv.index["files"]
    meta = srv.index["files"][gid]
    assert meta["sha256"] == dummy_sha
    assert meta["size_bytes"] == len(b"dummy_graffiti_payload_data")
    assert meta["state"] == "stored"
    assert meta["paid"] is True
