# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import MagicMock

from archivist.node_route import (
    rpc_hello,
    rpc_ping,
    rpc_get_network_info,
    rpc_get_graffiti_posts,
    rpc_submit_proof,
    rpc_build_payout,
)


@pytest.fixture
def mock_rpc():
    rpc = MagicMock()
    rpc.pub = "mock_pub_hex"
    rpc.address = "tsar1mockaddress"
    return rpc


def test_rpc_hello(mock_rpc):
    mock_rpc.call.side_effect = [
        {"type": "HELLO_RESPONSE", "port": 8000},
        {"type": "PONG"},
    ]
    ok = rpc_hello(mock_rpc, my_listen_port=39000, trusted=True)
    assert ok is True
    assert mock_rpc.call.call_count == 2
    hello_call = mock_rpc.call.call_args_list[0][0][0]
    assert hello_call["type"] == "HELLO"
    assert hello_call["role"] == "NODE_STORAGE"
    assert hello_call["port"] == 39000
    assert hello_call["trusted"] is True


def test_rpc_ping(mock_rpc):
    mock_rpc.call.return_value = {"type": "PONG"}
    assert rpc_ping(mock_rpc) is True

    mock_rpc.call.return_value = {"type": "ERROR"}
    assert rpc_ping(mock_rpc) is False


def test_rpc_get_network_info(mock_rpc):
    mock_rpc.call.return_value = {
        "type": "NETWORK_INFO",
        "data": {"chain": {"tip_height": 100}, "peers": {"count": 4}},
    }
    info = rpc_get_network_info(mock_rpc)
    assert type(info) is dict
    assert info["data"]["chain"]["tip_height"] == 100

    # Error case
    mock_rpc.call.return_value = {"error": "rate_limited"}
    assert rpc_get_network_info(mock_rpc) is None


def test_rpc_get_graffiti_posts(mock_rpc):
    mock_rpc.call.return_value = {
        "type": "GRAFFITI_POSTS",
        "posts": [{"art_id": "art1", "size": 100}],
    }
    posts = rpc_get_graffiti_posts(mock_rpc, limit=10)
    assert len(posts) == 1
    assert posts[0]["art_id"] == "art1"

    # Empty / error case
    mock_rpc.call.return_value = {"posts": []}
    assert rpc_get_graffiti_posts(mock_rpc) == []


def test_rpc_submit_proof(mock_rpc):
    mock_rpc.call.return_value = {"status": "ok", "art_id": "art1", "epoch": 2}
    res = rpc_submit_proof(
        mock_rpc,
        art_id="art1",
        epoch=2,
        offset=0,
        length=4096,
        proof_hash="hash123",
        height=20,
        seed="seed123",
        chunk="chunk_b64",
        path=["path_elem"],
    )
    assert res["status"] == "ok"
    sent_payload = mock_rpc.call.call_args[0][0]
    assert sent_payload["type"] == "GRAFFITI_PROOF_SUBMIT"
    assert sent_payload["art_id"] == "art1"
    assert sent_payload["epoch"] == 2
    assert sent_payload["chunk"] == "chunk_b64"
    assert sent_payload["storer"] == "tsar1mockaddress"
    assert sent_payload["path"] == ["path_elem"]


def test_rpc_submit_proof_single_chunk_empty_path(mock_rpc):
    mock_rpc.call.return_value = {"status": "ok", "art_id": "art_single", "epoch": 5}
    res = rpc_submit_proof(
        mock_rpc,
        art_id="art_single",
        epoch=5,
        offset=0,
        length=10201,
        proof_hash="hash_single",
        height=50,
        seed="seed_single",
        chunk="chunk_b64",
        path=[],
    )
    assert res["status"] == "ok"
    sent_payload = mock_rpc.call.call_args[0][0]
    assert sent_payload["type"] == "GRAFFITI_PROOF_SUBMIT"
    assert sent_payload["art_id"] == "art_single"
    assert sent_payload["path"] == []
    assert type(sent_payload["path"]) is list


def test_rpc_build_payout(mock_rpc):
    mock_rpc.call.return_value = {"status": "ok", "tx": {"txid": "tx123"}}
    res = rpc_build_payout(
        mock_rpc,
        art_id="art1",
        recipient="tsar1recipient",
        amount=50000,
        epoch=2,
        broadcast=True,
    )
    assert res["status"] == "ok"
    sent_payload = mock_rpc.call.call_args[0][0]
    assert sent_payload["type"] == "GRAFFITI_BUILD_PAYOUT"
    assert sent_payload["art_id"] == "art1"
    assert sent_payload["recipients"] == [{"addr": "tsar1recipient", "amount": 50000}]
    assert sent_payload["broadcast"] is True

