# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import os
import pytest
import base64
import hashlib

from unittest.mock import patch, MagicMock
from archivist.wallet_route import handle_wallet_rpc

@pytest.fixture
def server(tmp_path):
    srv = MagicMock()
    srv.index = {"files": {}, "bytes_used": 0, "art_map": {}}
    srv.storage_dir = str(tmp_path)
    srv.db = MagicMock()
    return srv

def test_stor_init_bad_fields(server):
    res = handle_wallet_rpc(server, {"type": "STOR_INIT"})
    assert res["status"] == "rejected"
    assert res["reason"] == "bad_fields"
    
    res2 = handle_wallet_rpc(server, {"type": "STOR_INIT", "graffiti_id": "123", "size_bytes": 10, "sha256": "short"})
    assert res2["status"] == "rejected"
    assert res2["reason"] == "bad_fields"

@patch("archivist.wallet_route.GRAFFITI.validate_graffiti_file", side_effect=lambda s, m, f: (m or "text/plain"))
def test_stor_init_success(mock_val, server):
    sha = "a" * 64
    msg = {
        "type": "STOR_INIT",
        "graffiti_id": "gid1",
        "size_bytes": 100,
        "sha256": sha,
        "mime": "text/plain",
        "art_id": "art1",
        "mroot": sha,
        "mchunk": 50,
        "mcount": 2
    }
    res = handle_wallet_rpc(server, msg)
    assert res["status"] == "ok"
    assert res["upload_id"] == "gid1"
    
    meta = server.index["files"]["gid1"]
    assert meta["state"] == "receiving"
    assert meta["size_bytes"] == 100
    assert meta["sha256"] == sha
    assert meta["mroot"] == sha
    assert meta["mchunk"] == 50
    assert meta["mcount"] == 2
    
    # Path created
    assert os.path.exists(meta["path"])

@patch("archivist.wallet_route.GRAFFITI.validate_graffiti_file", side_effect=lambda s, m, f: (m or "text/plain"))
def test_stor_init_mempool_full(mock_val, server):
    sha = "a" * 64
    msg = {
        "type": "STOR_INIT",
        "graffiti_id": "gid1",
        "size_bytes": 100,
        "sha256": sha,
    }
    
    with patch("archivist.wallet_route.CFG.MAX_GRAFFITI_ON_MEMPOOL", 1):
        # Add 1 active
        server.index["files"]["active1"] = {"state": "receiving", "paid": False}
        res = handle_wallet_rpc(server, msg)
        assert res["status"] == "rejected"
        assert res["reason"] == "mempool_graffiti_full"

def test_stor_put_bad(server):
    res = handle_wallet_rpc(server, {"type": "STOR_PUT"})
    assert res["status"] == "rejected"
    assert res["reason"] == "bad_fields"
    
    res2 = handle_wallet_rpc(server, {"type": "STOR_PUT", "graffiti_id": "gid1", "data": "abc"})
    assert res2["status"] == "rejected"
    assert res2["reason"] == "no_init"

def test_stor_put_success(server):
    server.index["files"]["gid1"] = {"state": "receiving", "chunk_size": 1000}
    b64 = base64.b64encode(b"hello").decode("ascii")
    
    server.db.append_incoming.return_value = 5
    
    res = handle_wallet_rpc(server, {"type": "STOR_PUT", "graffiti_id": "gid1", "data": b64})
    assert res["status"] == "ok"
    assert res["received"] == 5
    
    meta = server.index["files"]["gid1"]
    assert meta["state"] == "appending"
    assert meta["received_bytes"] == 5

def test_stor_put_too_big(server):
    server.index["files"]["gid1"] = {"state": "receiving", "chunk_size": 2}
    b64 = base64.b64encode(b"hello").decode("ascii")
    res = handle_wallet_rpc(server, {"type": "STOR_PUT", "graffiti_id": "gid1", "data": b64})
    assert res["status"] == "rejected"
    assert res["reason"] == "chunk_too_big"

def test_stor_commit_missing(server):
    res = handle_wallet_rpc(server, {"type": "STOR_COMMIT", "graffiti_id": "gid1"})
    assert res["status"] == "rejected"
    assert res["reason"] == "no_such"

@patch("archivist.wallet_route.GRAFFITI.validate_graffiti_file", side_effect=lambda s, m, f: (m or "text/plain"))
def test_stor_commit_success(mock_val, server, tmp_path):
    data = b"hello world"
    sha = hashlib.sha256(data).hexdigest()
    
    part_path = tmp_path / "gid1.part"
    part_path.write_bytes(data)
    
    server.index["files"]["gid1"] = {
        "state": "appending",
        "size_bytes": len(data),
        "sha256": sha,
        "path": str(part_path),
        "mime": "text/plain",
        "filename": "hello.txt",
        "paid": False,
        "expire_at_height": 0
    }
    
    res = handle_wallet_rpc(server, {"type": "STOR_COMMIT", "graffiti_id": "gid1", "tip_height": 100})
    assert res["status"] == "ok"
    assert "receipt" in res
    
    meta = server.index["files"]["gid1"]
    assert meta["state"] == "pending_confirm"
    assert meta["expire_at_height"] > 100
    assert "final" not in meta["path"]
    assert meta["path"].endswith(".bin")

def test_stor_get_by_art_missing(server):
    res = handle_wallet_rpc(server, {"type": "STOR_GET_BY_ART", "art_id": "art1"})
    assert res["found"] is False

def test_stor_get_by_art_no_data(server):
    server.index["art_map"]["art1"] = "gid1"
    server.index["files"]["gid1"] = {"size_bytes": 100, "paid": True}
    
    res = handle_wallet_rpc(server, {"type": "STOR_GET_BY_ART", "art_id": "art1"})
    assert res["found"] is True
    assert "data_b64" not in res

def test_stor_get_by_art_with_data_kv(server):
    server.index["art_map"]["art2"] = "gid2"
    server.index["files"]["gid2"] = {"size_bytes": 100, "paid": True}
    
    server.db.get_final_bytes_range = MagicMock(return_value=b"y" * 5)
    
    res = handle_wallet_rpc(server, {"type": "STOR_GET_BY_ART", "art_id": "art2", "include_data": True, "offset": 10, "length": 5})
    assert res["status"] == "ok"
    assert res["offset"] == 10
    assert res["length"] == 5
    
    decoded = base64.b64decode(res["data_b64"])
    assert decoded == b"y" * 5
    server.db.get_final_bytes_range.assert_called_with("gid2", 10, 5)

def test_unknown_wallet_rpc(server):
    res = handle_wallet_rpc(server, {"type": "UNKNOWN"})
    assert res is None

@patch("archivist.wallet_route.GRAFFITI.validate_graffiti_file", side_effect=lambda s, m, f: (m or "text/plain"))
def test_stor_init_merkle_bad(mock_val, server):
    sha = "a" * 64
    base_msg = {"type": "STOR_INIT", "graffiti_id": "gid1", "size_bytes": 100, "sha256": sha}
    
    # Missing some merkle parts
    res1 = handle_wallet_rpc(server, {**base_msg, "mroot": sha, "mchunk": 50})
    assert res1["reason"] == "bad_merkle_meta"
    
    # Bad merkle root hex
    res2 = handle_wallet_rpc(server, {**base_msg, "mroot": "invalid_hex", "mchunk": 50, "mcount": 2})
    assert res2["reason"] == "bad_merkle_root"
    
    # Non-integer chunk
    res3 = handle_wallet_rpc(server, {**base_msg, "mroot": sha, "mchunk": "x", "mcount": 2})
    assert res3["reason"] == "bad_merkle_meta"

def test_stor_get_by_art_eof(server):
    server.index["files"]["gid1"] = {"size_bytes": 100, "paid": True}
    res = handle_wallet_rpc(server, {"type": "STOR_GET_BY_ART", "graffiti_id": "gid1", "include_data": True, "offset": 105})
    assert res["status"] == "ok"
    assert res["eof"] is True
    assert res["length"] == 0

def test_stor_get_by_art_file_too_large(server):
    server.index["files"]["gid1"] = {"size_bytes": 10 * 1024 * 1024, "paid": True} # 10MB
    with patch("archivist.wallet_route.CFG.GRAFFITI_MAX_SIZE_BYTES", 5 * 1024 * 1024):
        res = handle_wallet_rpc(server, {"type": "STOR_GET_BY_ART", "graffiti_id": "gid1", "include_data": True})
        assert res["status"] == "error"
        assert res["reason"] == "file_too_large"


@patch("archivist.wallet_route.GRAFFITI.validate_graffiti_file", side_effect=lambda s, m, f: (m or "text/plain"))
def test_stor_init_rejects_duplicate_permanent_graffiti(mock_val, server):
    sha = "b" * 64
    mroot = "c" * 64
    server.index["art_map"]["art_dup"] = "gid_permanent"
    server.index["files"]["gid_permanent"] = {
        "state": "stored",
        "paid": True,
        "sha256": sha,
        "mroot": mroot,
    }
    server.db.has_final.return_value = True

    msg = {
        "type": "STOR_INIT",
        "graffiti_id": "gid_new",
        "size_bytes": 100,
        "sha256": sha,
        "mime": "text/plain",
        "art_id": "art_dup",
        "mroot": mroot,
        "mchunk": 50,
        "mcount": 2,
    }
    res = handle_wallet_rpc(server, msg)
    assert res["status"] == "rejected"
    assert res["reason"] == "duplicate_graffiti"


def test_stor_commit_rejects_duplicate_permanent_graffiti(server):
    sha = "d" * 64
    mroot = "e" * 64
    server.index["art_map"]["art_dup2"] = "gid_final"
    server.index["files"]["gid_final"] = {
        "state": "stored",
        "paid": True,
        "sha256": sha,
        "mroot": mroot,
    }
    server.index["files"]["gid_pending"] = {
        "state": "appending",
        "paid": False,
        "art_id": "art_dup2",
        "sha256": sha,
        "mroot": mroot,
        "size_bytes": 100,
    }
    server.db.has_final.side_effect = lambda gid: gid == "gid_final"

    msg = {
        "type": "STOR_COMMIT",
        "graffiti_id": "gid_pending",
    }
    res = handle_wallet_rpc(server, msg)
    assert res["status"] == "rejected"
    assert res["reason"] == "duplicate_graffiti"

