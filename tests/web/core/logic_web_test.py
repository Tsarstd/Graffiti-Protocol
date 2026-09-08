# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import pytest
import base64
from unittest.mock import patch, MagicMock

from web.Backend.src.core.logic_web import db_cache, db_blocks, db_media, db_files, rpc_client, rpc_handlers


@pytest.fixture
def mock_store():
    store = MagicMock()
    with patch("web.Backend.src.core.logic_web.db_cache.open_web_store", return_value=store):
        yield store


@pytest.fixture
def mock_client():
    return MagicMock()


# ==================== DB_CACHE TESTS ====================

def testopen_web_store():
    db_cache._store = None
    with patch("web.Backend.src.core.logic_web.db_cache._native_open_storage") as mock_open:
        mock_open.return_value = "db"
        assert db_cache.open_web_store() == "db"
        assert db_cache.open_web_store() == "db"  # cached


def testopen_web_store_exceptions():
    with patch("web.Backend.src.core.logic_web.db_cache._store", None):
        with patch("web.Backend.src.core.logic_web.db_cache._native_open_storage", None):
            assert db_cache.open_web_store() is None
        with patch("web.Backend.src.core.logic_web.db_cache._native_open_storage", side_effect=Exception("lmdb err")):
            assert db_cache.open_web_store() is None


def test_cache_keys():
    assert db_cache.make_cache_key("web", "prefix", "test") == "web:prefix:test"
    assert db_cache.make_cache_key("web", None, "test") == "web:test"


def test_is_not_found_error():
    assert db_cache.is_not_found_error("not_found") is True
    assert db_cache.is_not_found_error("height_out_of_range") is True
    assert db_cache.is_not_found_error("not found something") is True
    assert db_cache.is_not_found_error("other error") is False


def test_get_error_cache_ttl():
    assert db_cache.get_error_cache_ttl("pow_required") == db_cache.WEB_CACHE_ERROR_TTL_SHORT
    assert db_cache.get_error_cache_ttl("rate limit exceeded") == db_cache.WEB_CACHE_ERROR_TTL_SHORT
    assert db_cache.get_error_cache_ttl("timeout") == db_cache.WEB_CACHE_ERROR_TTL_SHORT
    assert db_cache.get_error_cache_ttl("not_found") == db_cache.WEB_CACHE_TTL_SEC
    assert db_cache.get_error_cache_ttl("unknown_error") is None


def test_cache_set_get(mock_store):
    mock_store.get_bytes.return_value = None
    assert db_cache.cache_get("key1") is None
    
    expired_entry = db_cache._serialize_payload({"ts": 0, "ttl": 10, "payload": "data"})
    mock_store.get_bytes.return_value = expired_entry
    assert db_cache.cache_get("key2") is None
    
    valid_entry = db_cache._serialize_payload({"ts": int(time.time()), "ttl": 100, "payload": "data"})
    mock_store.get_bytes.return_value = valid_entry
    assert db_cache.cache_get("key3", refresh_ttl=True) == "data"
    
    db_cache.cache_set("key4", {"test": 123}, ttl_sec=50)


def test_is_expired():
    assert db_cache._is_expired({"ts": 0}) is True
    assert db_cache._is_expired({"ts": 0, "ttl": -1}) is False


# ==================== DB_BLOCKS TESTS ====================

def test_block_storage(mock_store):
    db_blocks.save_blocks_to_storage([{"height": 1, "hash": "A"}, "invalid", {"height": 2, "hash": "B"}])
    
    mock_store.get_bytes.return_value = db_cache._serialize_payload({"height": 1, "hash": "A"})
    assert db_blocks.get_block_from_storage(1)["hash"] == "A"
    
    def mock_get(db, k):
        if k == db_blocks._meta_max_height_key():
            return b"2"
        h = int(k.decode("utf-8").split(":")[1])
        if h <= 2:
            return db_cache._serialize_payload({"height": h, "hash": "A"})
        return None
    mock_store.get_bytes.side_effect = mock_get
    
    res = db_blocks.get_block_range_from_storage(1, 5)
    assert len(res["items"]) == 2
    assert res["start_height"] == 1
    assert res["items"][0]["height"] == 1
    assert res["items"][1]["height"] == 0
    assert res["next_height"] == -1
    assert res["has_more"] is False
    
    assert db_blocks.get_last_stored_height() == 2


def test_block_storage_edge_cases(mock_store):
    db_blocks.save_blocks_to_storage(None)
    db_blocks.save_blocks_to_storage(["not_a_dict"])
    db_blocks.save_blocks_to_storage([{}])
    
    mock_store.put_bytes.side_effect = Exception("err")
    db_blocks.save_blocks_to_storage([{"height": 1}])
    
    mock_store.get_bytes.side_effect = Exception("err")
    assert db_blocks.get_block_from_storage(1) is None
    
    mock_store.iter_prefix.return_value = [(b"block:abc", b""), (b"block:", b"")]
    assert db_blocks.get_last_stored_height() == 0
    mock_store.iter_prefix.side_effect = Exception("err")
    assert db_blocks.get_last_stored_height() == -1


def test_prefetch_blocks(mock_store):
    mock_store.iter_prefix.return_value = [(b"block:00000001", b"")]
    
    rpc_call = MagicMock(return_value={"height": 5, "items": [{"height": 2}, {"height": 3}]})
    db_blocks.prefetch_blocks(rpc_call)
    
    with patch("web.Backend.src.core.logic_web.db_blocks.prefetch_blocks") as mock_pb:
        db_blocks.start_prefetch_thread(rpc_call)
        time.sleep(0.1)
        db_blocks.stop_prefetch_thread()
        mock_pb.assert_called()


def test_prefetch_branches(mock_store):
    mock_store.get_bytes.return_value = b"100"
    assert db_blocks.get_prefetch_last_height() == 100
    
    mock_store.get_bytes.side_effect = Exception("test")
    assert db_blocks.get_prefetch_last_height() == -1
    
    db_blocks.set_prefetch_last_height(200)


def test_prefetch_blocks_edge_cases(mock_store):
    mock_store.iter_prefix.return_value = [(b"block:00000001", b"")]
    
    rpc1 = MagicMock(side_effect=[{"type": "GET_NETWORK_INFO"}, {"tip_height": 5}, {"items": [{"height": 2}]}])
    db_blocks.prefetch_blocks(rpc1)
    
    rpc2 = MagicMock(return_value={"height": 5, "error": "some_err"})
    db_blocks.prefetch_blocks(rpc2)
    
    rpc3 = MagicMock(return_value={"height": 5, "items": []})
    db_blocks.prefetch_blocks(rpc3)
    
    rpc4 = MagicMock(side_effect=Exception("network_fail"))
    db_blocks.prefetch_blocks(rpc4)


def test_prefetch_blocks_has_more(mock_store):
    mock_store.get_bytes.return_value = b"100"
    rpc_call = MagicMock(return_value={
        "height": 500,
        "items": [{"height": h} for h in range(101, 301)]
    })
    has_more = db_blocks.prefetch_blocks(rpc_call)
    assert has_more is True
    
    mock_store.get_bytes.return_value = b"100"
    rpc_call_no_more = MagicMock(return_value={
        "height": 250,
        "items": [{"height": h} for h in range(101, 251)]
    })
    has_more_no = db_blocks.prefetch_blocks(rpc_call_no_more)
    assert has_more_no is False


# ==================== DB_MEDIA TESTS ====================

def test_media_cache(mock_store):
    db_media._cache_media_error("art1", "not_found", 10)
    db_media._cache_media_success("art2", {"mime": "image/jpeg"}, "/path/x.jpg", 100)
    
    mock_store.get_bytes.return_value = db_cache._serialize_payload({"ts": int(time.time()), "ttl": 100, "status": "ok"})
    assert db_media._load_media_entry("art2") is not None
    
    mock_store.get_bytes.return_value = None
    assert db_media._load_media_entry("art3") is None


def test_fetch_storers(mock_store):
    mock_store.get_bytes.return_value = None
    rpc_call = MagicMock(return_value={"storers": [{"addr": "127.0.0.1", "port": 8080, "last_seen": 10}]})
    res = db_media.fetch_storers(rpc_call, limit=1)
    assert len(res) == 1
    
    rpc_call_err = MagicMock(return_value={"error": "not_found"})
    assert len(db_media.fetch_storers(rpc_call_err)) == 0


@patch("web.Backend.src.core.logic_web.db_media._send_storage_request")
@patch("web.Backend.src.core.logic_web.db_media.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}])
def test_fetch_graffiti_file_network(mock_fetch, mock_send, mock_store, tmp_path):
    mock_store.get_bytes.return_value = None
    
    def send_effect(h, p, payload, *args, **kwargs):
        if not payload.get("include_data"):
            return {"status": "ok", "found": True, "meta": {"size_bytes": 10}}
        else:
            return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"hello world").decode("utf-8")}
    
    mock_send.side_effect = send_effect
    res = db_media.fetch_graffiti_file(lambda p: None, "art4", cache_dir=str(tmp_path))
    assert res["status"] == "ok"
    assert "cache_path" in res


def test_chunked_download(mock_store, tmp_path):
    mock_store.get_bytes.return_value = None
    
    with patch("web.Backend.src.core.logic_web.db_media.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.core.logic_web.db_media._send_storage_request") as mock_send:
            def send_effect(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    return {"status": "ok", "found": True, "meta": {"size_bytes": 20 * 1024 * 1024}}
                else:
                    return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"a" * payload["length"]).decode("utf-8")}
            mock_send.side_effect = send_effect
            
            res = db_media.fetch_graffiti_file(lambda p: None, "art5", cache_dir=str(tmp_path), max_bytes=50 * 1024 * 1024)
            assert res["status"] == "ok"
            assert "cache_path" in res


def test_fetch_graffiti_unknown_size_and_errors(mock_store, tmp_path):
    mock_store.get_bytes.return_value = db_cache._serialize_payload({"ts": int(time.time()), "ttl": 100, "status": "error", "reason": "banned"})
    assert db_media.fetch_graffiti_file(lambda p: None, "art6")["status"] == "error"
    
    mock_store.get_bytes.side_effect = [db_cache._serialize_payload({"ts": int(time.time()), "ttl": 100, "status": "ok"}), None]
    assert db_media._get_cached_graffiti_file("art7", None) is None
    
    db_media._write_cache_file("/invalid/dir", "art8", {}, b"data")
    
    mock_store.get_bytes.side_effect = None
    mock_store.get_bytes.return_value = None
    
    with patch("web.Backend.src.core.logic_web.db_media.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.core.logic_web.db_media._send_storage_request") as mock_send:
            def send_effect1(h, p, payload, *args, **kwargs):
                if not payload.get("include_data"):
                    return {"status": "ok", "found": True, "meta": {}}
                else:
                    return {"status": "ok", "found": True, "data_b64": base64.b64encode(b"hello").decode("utf-8")}
            mock_send.side_effect = send_effect1
            assert db_media.fetch_graffiti_file(lambda p: None, "art_unknown", cache_dir=str(tmp_path))["status"] == "ok"
            
            mock_send.side_effect = [None]
            assert db_media.fetch_graffiti_file(lambda p: None, "art_bad")["status"] == "error"
            
            mock_send.side_effect = [{"found": False}]
            assert db_media.fetch_graffiti_file(lambda p: None, "art_notfound")["status"] == "error"


# ==================== DB_FILES TESTS ====================

def test_receipt_cache(tmp_path):
    with patch("web.Backend.src.core.logic_web.db_files.os.path.getmtime", return_value=time.time()):
        assert db_files.is_receipt_fresh("/does/not/exist", 100) is False
        
    f = tmp_path / "test.jpg"
    f.write_bytes(b"image")
    assert db_files.is_receipt_fresh(str(f), 100) is True
    assert db_files.is_receipt_fresh(str(f), -100) is False
    
    res = db_files.read_receipt_file_as_dict(str(f), "txid")
    assert res["status"] == "success"


def test_receipt_cleanup_and_timer():
    with patch("threading.Timer") as mock_timer:
        t1 = MagicMock()
        mock_timer.return_value = t1
        db_files.schedule_receipt_deletion("tx1", 10)
        mock_timer.assert_called_once()
        t1.start.assert_called_once()
        
        # Reschedule should cancel previous timer
        t2 = MagicMock()
        mock_timer.return_value = t2
        db_files.schedule_receipt_deletion("tx1", 20)
        t1.cancel.assert_called_once()
        t2.start.assert_called_once()
        
    with patch("os.path.exists", return_value=True):
        with patch("os.listdir", return_value=["tx1.jpg"]):
            with patch("os.path.getmtime", return_value=time.time() - 100):
                with patch("os.remove") as mock_remove:
                    db_files.cleanup_receipt_files(50)
                    mock_remove.assert_called()


def test_history_book_cache(tmp_path):
    with patch("web.Backend.src.core.logic_web.db_files.os.path.getmtime", return_value=time.time()):
        assert db_files.is_history_book_fresh("/does/not/exist", 100) is False
        
    f = tmp_path / "history_test.pdf"
    f.write_bytes(b"pdf_data")
    assert db_files.is_history_book_fresh(str(f), 100) is True
    assert db_files.is_history_book_fresh(str(f), -100) is False
    
    res = db_files.read_history_book_file_as_dict(str(f), "tsar123")
    assert res["status"] == "success"
    assert res["data_url"].startswith("data:application/pdf;base64,")


def test_history_book_cleanup_and_timer():
    with patch("threading.Timer") as mock_timer:
        db_files.schedule_history_book_deletion("tsar123", 10)
        mock_timer.assert_called_once()
        
    with patch("os.path.exists", return_value=True):
        with patch("os.listdir", return_value=["history_123.pdf"]):
            with patch("os.path.getmtime", return_value=time.time() - 100):
                with patch("os.remove") as mock_remove:
                    db_files.cleanup_history_book_files(50)
                    mock_remove.assert_called()


def test_path_traversal_sanitization():
    safe_path1 = db_files.get_receipt_file_path("../../../secret_file")
    assert ".." not in safe_path1
    assert "/" not in os.path.basename(safe_path1)
    
    assert db_files.get_receipt_file_path("../..") == ""
    
    res = db_media.fetch_graffiti_file(lambda p: None, "../../..")
    assert res["status"] == "error"
    assert res["reason"] == "missing_art_id"


# ==================== RPC_CLIENT & RPC_HANDLERS TESTS ====================

def test_client_cache():
    with patch("web.Backend.src.core.logic_web.rpc_client.load_or_create_keypair_at", return_value=("id", "pub", "priv")):
        c1 = rpc_client.get_client("127.0.0.1", 19000)
        c2 = rpc_client.get_client("127.0.0.1", 19000)
        assert c1 is c2
        rpc_client.drop_client("127.0.0.1", 19000)
        c3 = rpc_client.get_client("127.0.0.1", 19000)
        assert c1 is not c3


def test_cache_policy():
    ok, ttl = rpc_client._determine_cache_policy(None)
    assert not ok
    ok, ttl = rpc_client._determine_cache_policy({"error": "not_found"})
    assert ok
    ok, ttl = rpc_client._determine_cache_policy({"status": "error", "reason": "timeout"})
    assert ok
    assert ttl == db_cache.WEB_CACHE_ERROR_TTL_SHORT


def test_rpc_network(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        with patch("web.Backend.src.core.logic_web.rpc_client.cache_set") as mock_set:
            def mock_send(c, p):
                if p["type"] == "GET_NETWORK_INFO":
                    return {"type": "NETWORK_INFO", "data": {"height": 10}}
                elif p["type"] == "GET_PEERS":
                    return {"peers": ["127.0.0.1:19000"]}
            
            with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", side_effect=mock_send):
                res = rpc_handlers.rpc_network(mock_client)
                assert res["height"] == 10
                mock_set.assert_called_once()


def test_rpc_block(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", return_value={"height": 10, "hash": "A"}):
            res = rpc_handlers.rpc_block(mock_client, "10")
            assert res["height"] == 10


def test_rpc_block_range(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        with patch("web.Backend.src.core.logic_web.db_blocks.get_block_range_from_storage", return_value={"items": [1,2], "has_more": False}):
            res = rpc_handlers.rpc_block_range(mock_client, {"start_height": 1, "limit": 2})
            assert len(res["items"]) == 2


def test_rpc_address(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        def mock_send(c, p):
            if p["type"] == "GET_BALANCES":
                return {"items": {"addr1": {"spendable": 100}}}
            elif p["type"] == "GET_TOTAL_UTXO":
                return {"count": 5}
            elif p["type"] == "GET_TX_HISTORY":
                return {"items": [{"txid": "T1"}], "total": 1, "height": 100}
                
        with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", side_effect=mock_send):
            res = rpc_handlers.rpc_address(mock_client, "addr1")
            assert res["spendable"] == 100
            assert res["utxo_count"] == 5


def test_rpc_graffiti(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        def mock_send(c, p):
            if p["type"] == "GRAFFITI_GET_ART":
                return {"post": {"art_id": "art1"}}
            elif p["type"] == "GRAFFITI_GET_COMMENTS":
                return {"comments": [{"id": "c1"}]}
                
        with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", side_effect=mock_send):
            res = rpc_handlers.rpc_graffiti(mock_client, "art1")
            assert res["post"]["art_id"] == "art1"


def test_rpc_graffiti_file(mock_client):
    with patch("web.Backend.src.core.logic_web.db_media.fetch_graffiti_file", return_value={"status": "ok", "cache_path": "/path"}):
        res = rpc_handlers.rpc_graffiti_file(mock_client, {"art_id": "art1"}, None)
        assert res["status"] == "ok"
        assert res["cache_path"] == "/path"


def test_rpc_receipt(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        with patch("web.Backend.src.core.logic_web.rpc_handlers.rpc_tx", return_value={"txid": "T1"}):
            with patch("web.Backend.src.core.build_receipt.PaymentReceiptGenerator") as mock_gen:
                mock_inst = MagicMock()
                mock_inst.generate_receipt_base64.return_value = {"status": "success"}
                mock_gen.return_value = mock_inst
                
                res = rpc_handlers.rpc_receipt(mock_client, "T1")
                assert res["status"] == "success"


def test_rpc_history_book(mock_client):
    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", return_value=None):
        with patch("web.Backend.src.core.logic_web.rpc_handlers.rpc_address", return_value={"address": "tsar123", "balance": 10, "total_txs": 20}):
            with patch("web.Backend.src.core.build_history_book.HistoryBookGenerator") as mock_gen:
                mock_inst = MagicMock()
                mock_inst.generate_history_book_base64.return_value = {"status": "success"}
                mock_gen.return_value = mock_inst
                
                res = rpc_handlers.rpc_history_book(mock_client, "tsar123")
                assert res["status"] == "success"


def test_get_graffiti_media_meta(mock_store, tmp_path):
    mock_store.get_bytes.return_value = None
    with patch("web.Backend.src.core.logic_web.db_media.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.core.logic_web.db_media._send_storage_request") as mock_send:
            mock_send.return_value = {
                "status": "ok",
                "found": True,
                "graffiti_id": "gid123",
                "meta": {"size_bytes": 15000000, "mime": "video/mp4", "filename": "sample.mp4"},
            }
            res = db_media.get_graffiti_media_meta(lambda p: None, "art_meta1", cache_dir=str(tmp_path))
            assert res["status"] == "ok"
            assert res["size_bytes"] == 15000000
            assert res["meta"]["mime"] == "video/mp4"


def test_fetch_graffiti_chunk(mock_store):
    mock_store.get_bytes.return_value = None
    with patch("web.Backend.src.core.logic_web.db_media.fetch_storers", return_value=[{"ip": "127.0.0.1", "port": 8080}]):
        with patch("web.Backend.src.core.logic_web.db_media._send_storage_request") as mock_send:
            mock_send.return_value = {
                "status": "ok",
                "found": True,
                "data_b64": base64.b64encode(b"chunk_bytes").decode("utf-8"),
                "offset": 0,
                "length": 11,
                "total_size": 15000000,
                "eof": False,
            }
            res = db_media.fetch_graffiti_chunk(lambda p: None, "art_chunk1", offset=0, length=4096)
            assert res["status"] == "ok"
            assert res["data_b64"] == base64.b64encode(b"chunk_bytes").decode("utf-8")
            assert res["total_size"] == 15000000


def test_rpc_graffiti_media_meta_and_chunk(mock_client):
    with patch("web.Backend.src.core.logic_web.db_media.get_graffiti_media_meta", return_value={"status": "ok", "size_bytes": 100}):
        res = rpc_handlers.rpc_graffiti_media_meta(mock_client, {"art_id": "art1"})
        assert res["status"] == "ok"
        assert res["size_bytes"] == 100

    with patch("web.Backend.src.core.logic_web.db_media.fetch_graffiti_chunk", return_value={"status": "ok", "data_b64": "abc"}):
        res2 = rpc_handlers.rpc_graffiti_chunk(mock_client, {"art_id": "art1", "offset": 0, "length": 4096})
        assert res2["status"] == "ok"
        assert res2["data_b64"] == "abc"


def test_rpc_address_two_tier_fast_path(mock_client):
    vol = {
        "spendable": 500, "immature": 0, "outgoing": 0, "incoming": 0,
        "balance": 500, "utxo_count": 3,
        "unconfirmed_items": [{"txid": "unconf1", "status": "unconfirmed"}],
        "height": 100
    }
    hist = {
        "last_synced_height": 100,
        "items": [{"txid": "conf1", "status": "confirmed", "height": 95}],
        "total": 1
    }
    def mock_cache_get(key, **kwargs):
        if "addr_vol" in key:
            return vol
        if "addr_hist" in key:
            return hist
        return None

    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", side_effect=mock_cache_get):
        with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send") as mock_send:
            res = rpc_handlers.rpc_address(mock_client, "addr_fast")
            assert mock_send.call_count == 0  # Zero RPC calls on fast path!
            assert res["spendable"] == 500
            assert res["total_txs"] == 2
            assert len(res["history"]) == 2
            # Check dynamic confirmations
            assert res["history"][0]["txid"] == "unconf1"
            assert res["history"][0]["confirmations"] == 0
            assert res["history"][1]["txid"] == "conf1"
            assert res["history"][1]["confirmations"] == 6  # 100 - 95 + 1


def test_rpc_address_delta_same_height(mock_client):
    hist = {
        "last_synced_height": 100,
        "items": [{"txid": "conf1", "status": "confirmed", "height": 98}],
        "total": 1
    }
    def mock_cache_get(key, **kwargs):
        if "addr_hist" in key:
            return hist
        return None

    sent_payloads = []
    def mock_send(c, p):
        sent_payloads.append(p)
        if p["type"] == "GET_BALANCES":
            return {"height": 100, "items": {"addr_same": {"spendable": 200}}}
        elif p["type"] == "GET_TOTAL_UTXO":
            return {"count": 2}
        elif p["type"] == "GET_TX_HISTORY":
            assert p.get("status") == "unconfirmed"
            return {"height": 100, "items": [], "total": 0}

    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", side_effect=mock_cache_get):
        with patch("web.Backend.src.core.logic_web.rpc_client.cache_set"):
            with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", side_effect=mock_send):
                res = rpc_handlers.rpc_address(mock_client, "addr_same")
                assert res["spendable"] == 200
                assert res["total_txs"] == 1
                assert res["history"][0]["txid"] == "conf1"
                assert res["history"][0]["confirmations"] == 3  # 100 - 98 + 1
                # Confirm we only asked for unconfirmed mempool txs!
                tx_hist_reqs = [p for p in sent_payloads if p.get("type") == "GET_TX_HISTORY"]
                assert len(tx_hist_reqs) == 1
                assert tx_hist_reqs[0].get("status") == "unconfirmed"


def test_rpc_address_delta_new_blocks(mock_client):
    hist = {
        "last_synced_height": 100,
        "items": [{"txid": "conf1", "status": "confirmed", "height": 98}],
        "total": 1
    }
    def mock_cache_get(key, **kwargs):
        if "addr_hist" in key:
            return hist
        return None

    sent_payloads = []
    def mock_send(c, p):
        sent_payloads.append(p)
        if p["type"] == "GET_BALANCES":
            return {"height": 102, "items": {"addr_new": {"spendable": 300}}}
        elif p["type"] == "GET_TOTAL_UTXO":
            return {"count": 3}
        elif p["type"] == "GET_TX_HISTORY":
            assert p.get("since_height") == 100
            return {
                "height": 102,
                "items": [{"txid": "conf2", "status": "confirmed", "height": 101}],
                "total": 1
            }

    with patch("web.Backend.src.core.logic_web.rpc_client.cache_get", side_effect=mock_cache_get):
        with patch("web.Backend.src.core.logic_web.rpc_client.cache_set") as mock_set:
            with patch("web.Backend.src.core.logic_web.rpc_client.rpc_send", side_effect=mock_send):
                res = rpc_handlers.rpc_address(mock_client, "addr_new")
                assert res["spendable"] == 300
                assert res["total_txs"] == 2
                assert len(res["history"]) == 2
                assert res["history"][0]["txid"] == "conf2"
                assert res["history"][0]["confirmations"] == 2  # 102 - 101 + 1
                assert res["history"][1]["txid"] == "conf1"
                assert res["history"][1]["confirmations"] == 5  # 102 - 98 + 1


