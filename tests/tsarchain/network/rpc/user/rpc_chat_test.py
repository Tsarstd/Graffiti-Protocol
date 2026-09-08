# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain - see LICENSE

import pytest
from unittest.mock import Mock, patch
from threading import Lock

from tsarchain.network.rpc.user_rpc.category.chat import (
    chat_register,
    chat_lookup_pub,
    chat_presence,
    chat_publish_prekeys,
    chat_get_prekey,
    chat_send,
    chat_read,
    chat_pull,
    chat_relay,
)


# ---------- Fixtures ----------
@pytest.fixture
def mock_config():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.CFG") as mock:
        mock.ADDRESS_PREFIX = "tsar"
        mock.DEBUG_BENCHMARKS = False
        mock.CHAT_REG_RL_IP_BURST = 5
        mock.CHAT_REG_RL_WINDOW_S = 60
        mock.CHAT_REG_RL_BACKOFF_S = 10
        mock.CHAT_REG_RL_ADDR_BURST = 3
        mock.CHAT_REG_RL_ADDR_WINDOW_S = 60
        mock.CHAT_REG_RL_ADDR_BACKOFF_S = 10
        mock.RPC_POW_DIFFICULTY_CHAT = "0000"
        mock.PRESENCE_TTL_S = 300
        mock.PRESENCE_MAX_HOPS = 3
        mock.CHAT_RL_IP_BURST = 10
        mock.CHAT_RL_IP_WINDOWS = 60
        mock.CHAT_BACKOFF_S = 5
        mock.PRESENCE_RL_ADDR_BURST = 2
        mock.PRESENCE_RL_ADDR_WINDOWS = 30
        mock.CHAT_RL_ADDR_BURST = 5
        mock.CHAT_RL_ADDR_WINDOWS = 60
        mock.CHAT_LOOKUP_RL_IP_BURST = 5
        mock.CHAT_LOOKUP_RL_IP_WINDOW_S = 60
        mock.CHAT_LOOKUP_RL_BACKOFF_S = 10
        mock.CHAT_LOOKUP_RL_ADDR_BURST = 3
        mock.CHAT_LOOKUP_RL_ADDR_WINDOW_S = 60
        mock.CHAT_LOOKUP_RL_ADDR_BACKOFF_S = 10
        mock.CHAT_TS_DRIFT_S = 300
        mock.CHAT_MAX_CT_BYTES = 1024
        mock.CHAT_TTL_S = 3600
        mock.CHAT_MAILBOX_MAX = 100
        mock.CHAT_GLOBAL_QUEUE_MAX = 1000
        mock.CHAT_NUM_HOPS = 2
        mock.CHAT_FORCE_RELAY = False
        mock.CHAT_PULL_MAX_ITEMS = 50
        mock.CHAT_RELAY_RL_IP_BURST = 5
        mock.CHAT_RELAY_RL_WINDOW_S = 60
        mock.CHAT_RELAY_RL_BACKOFF_S = 10
        mock.CHAT_RELAY_MAX_HOPS = 5
        mock.CHAT_RELAY_MAX_INNER_BYTES = 4096
        mock.CHAT_RATCHET_INDEX_MAX = 2**32 - 1
        mock.CANONICAL_SEP = (",", ":")
        yield mock


@pytest.fixture
def mock_common():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.CM") as mock:
        # Default: allow_rpc_with_pow returns (True, {})
        mock.allow_rpc_with_pow.return_value = (True, {})
        # Default: verify_chat_signatures returns all True
        def verify_side_effect(sig_list):
            return {name: True for name, _, _, _ in sig_list}
        mock.verify_chat_signatures.side_effect = verify_side_effect
        yield mock


@pytest.fixture
def mock_bech32():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.bech32_decode") as mock_decode:
        with patch("tsarchain.network.rpc.user_rpc.category.chat.convertbits") as mock_convert:
            def decode_side_effect(addr):
                if addr.startswith("tsar"):
                    return ("tsar", [0] + [0]*32)   # dummy data
                return (None, None)
            mock_decode.side_effect = decode_side_effect
            # Match the value returned by hash160 fixture
            mock_convert.return_value = list(b"0123456789abcdef0123")  # 20 ints
            yield mock_decode, mock_convert


@pytest.fixture
def mock_hash160():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.hash160") as mock:
        # Return a fixed 20-byte hash
        mock.return_value = b"0123456789abcdef0123"  # 20 bytes
        yield mock


@pytest.fixture
def mock_time():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.time") as mock:
        mock.time.return_value = 1000000.0
        mock.perf_counter.return_value = 0.0
        yield mock


@pytest.fixture
def mock_secrets():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.secrets") as mock:
        mock.token_hex.return_value = "abcdef" * 4  # 24 hex chars
        yield mock


@pytest.fixture
def mock_logger():
    with patch("tsarchain.network.rpc.user_rpc.category.chat.log") as mock:
        yield mock


@pytest.fixture
def server(mock_config, mock_common, mock_bech32, mock_hash160, mock_time, mock_secrets, mock_logger):
    """Create a mock server instance with required attributes."""
    server = Mock()
    server.chat_lock = Lock()
    server.chat_spend_pub = {}
    server.chat_presence_pub = {}
    server.chat_presence_ts = {}
    server.chat_presence_seen = set()
    server.chat_prekeys = {}
    server.rl_ip = {}
    server.rl_addr = {}
    server.peers = {}

    # Methods
    server.get_prekey_bundle = Mock(side_effect=lambda addr: dict(server.chat_prekeys.get(addr) or {}))
    def _put_bundle(addr, bundle):
        server.chat_prekeys[addr] = dict(bundle)
    server.put_prekey_bundle = Mock(side_effect=_put_bundle)
    server.delete_prekey_bundle = Mock(side_effect=lambda addr: server.chat_prekeys.pop(addr, None))
    def _get_spend(addr):
        if not addr:
            return None
        sp = server.chat_spend_pub.get(addr)
        if sp:
            return sp
        b = server.chat_prekeys.get(addr) or {}
        sp = b.get("spend_pub")
        if sp:
            server.chat_spend_pub[addr] = sp
            return sp
        return None
    server.get_spend_pub = Mock(side_effect=_get_spend)

    server.relay_presence_async = Mock()
    server.record_presence_seen = Mock(side_effect=lambda pid: server.chat_presence_seen.add(pid))
    server.dedup_mid = Mock(return_value=False)
    server.dedup_pull = Mock(return_value=False)
    server.mailbox_put = Mock(return_value=True)
    server.mailbox_pull = Mock(return_value=[])
    server.enqueue_rcpt = Mock()
    server.gc_mailboxes = Mock()

    return server


# ---------- Helper functions ----------
def make_valid_address(prefix="tsar"):
    return f"{prefix}1qw508d6qejxtdg4y5r3zarvary0c5xw7k"  # dummy


def make_valid_pubkey():
    return "a" * 64  # 64 hex chars


def make_valid_spend_pub():
    return "b" * 66  # 66 hex chars


def make_valid_sig():
    return "c" * 128  # arbitrary sig


def make_valid_ts(mock_time):
    return int(mock_time.time.return_value)


# ---------- Tests ----------
class TestChatRegister:
    def test_success(self, server, mock_common, mock_bech32, mock_hash160, mock_time, mock_secrets):
        addr = make_valid_address()
        chat_pub = make_valid_pubkey()
        spend_pub = make_valid_spend_pub()
        presence_sig = make_valid_sig()
        reg_sig = make_valid_sig()
        ts = int(mock_time.time.return_value)

        message = {
            "address": addr,
            "chat_pub": chat_pub,
            "spend_pub": spend_pub,
            "presence_sig": presence_sig,
            "reg_sig": reg_sig,
            "ts": ts,
            "spk": None,
            "sig": None,
            "opk": None,
        }
        pow_obj = {}
        base_identity = "test"
        client_ip = "127.0.0.1"

        # Mock hash160 to return the same as our prog from convertbits
        # We'll set hash160 to return b"0123456789abcdef0123" and convertbits returns that
        # Actually we need to match: hash160(bytes.fromhex(spend_pub)) == prog
        # We'll set hash160 to return the expected prog.
        mock_hash160.return_value = b"0123456789abcdef0123"  # 20 bytes

        # Mock bech32_decode to return proper data, convertbits to return that prog
        # Already set in fixture

        result = chat_register(
            server, message, pow_obj, base_identity, addr,
            client_ip=client_ip
        )

        assert result == {"type": "CHAT_REGISTERED", "address": addr, "pubkey": chat_pub}
        # Check state updates
        assert server.chat_spend_pub[addr] == spend_pub
        assert server.chat_presence_pub[addr] == chat_pub
        assert len(server.chat_presence_seen) == 1
        assert server.chat_prekeys[addr]["ik"] == chat_pub
        assert "ts" in server.chat_prekeys[addr]
        server.relay_presence_async.assert_called_once()
        # Verify signature calls
        mock_common.verify_chat_signatures.assert_called_once()
        # Rate limit calls
        assert mock_common.allow_rpc_with_pow.call_count == 2

    def test_missing_fields(self, server):
        message = {}
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "missing fields"}

    def test_bad_address_format(self, server, mock_time):
        message = {
            "address": "invalid",
            "chat_pub": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "bad address format"}

    def test_bad_chat_pub(self, server, mock_time):
        addr = make_valid_address()
        message = {
            "address": addr,
            "chat_pub": "invalid",
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "bad chat_pub"}

    def test_stale_ts(self, server, mock_time):
        mock_time.time.return_value = 1000
        message = {
            "address": make_valid_address(),
            "chat_pub": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": 100,  # old
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "stale ts"}

    def test_bad_presence_sig(self, server, mock_common, mock_time):
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"presence": False, "register": True}
        message = {
            "address": make_valid_address(),
            "chat_pub": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "bad_presence_sig"}

    def test_bad_reg_sig(self, server, mock_common, mock_time):
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"presence": True, "register": False}
        message = {
            "address": make_valid_address(),
            "chat_pub": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "bad reg_sig"}

    def test_rate_limit_ip(self, server, mock_common, mock_time):
        mock_common.allow_rpc_with_pow.side_effect = [(False, {"error": "rate_limited"}), (True, {})]
        message = {"address": make_valid_address(), "chat_pub": make_valid_pubkey(), "spend_pub": make_valid_spend_pub(), "presence_sig": make_valid_sig(), "reg_sig": make_valid_sig(), "ts": int(mock_time.time.return_value)}
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "rate_limited"}

    def test_spk_validation_success(self, server, mock_time):
        addr = make_valid_address()
        chat_pub = make_valid_pubkey()
        spend_pub = make_valid_spend_pub()
        spk_reg = "d" * 64
        sig_reg = make_valid_sig()
        message = {
            "address": addr,
            "chat_pub": chat_pub,
            "spend_pub": spend_pub,
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
            "spk": spk_reg,
            "sig": sig_reg,
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result["type"] == "CHAT_REGISTERED"
        assert server.chat_prekeys[addr]["spk"] == spk_reg
        assert server.chat_prekeys[addr]["sig"] == sig_reg

    def test_spk_bad_sig(self, server, mock_common, mock_time):
        # Override verify to return spk=False
        def verify_side_effect(sig_list):
            return {name: (name != "spk") for name, _, _, _ in sig_list}
        mock_common.verify_chat_signatures.side_effect = verify_side_effect
        message = {
            "address": make_valid_address(),
            "chat_pub": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "reg_sig": make_valid_sig(),
            "ts": int(mock_time.time.return_value),
            "spk": "d" * 64,
            "sig": make_valid_sig(),
        }
        result = chat_register(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "bad_spk_sig"}


class TestChatLookupPub:
    def test_success(self, server):
        addr = make_valid_address()
        server.chat_presence_pub[addr] = "pubkey123"
        server.chat_prekeys[addr] = {"ts": 123456}
        message = {"address": addr}
        result = chat_lookup_pub(server, message, {}, "id", client_ip="ip")
        assert result == {"type": "CHAT_PUBKEY", "address": addr, "pubkey": "pubkey123", "found": True, "last_seen": 123456}

    def test_lookup_pub_hits_ram_cache(self, server):
        addr = make_valid_address()
        server.chat_presence_pub[addr] = "pubkey_cached"
        server.chat_presence_ts[addr] = 999888
        message = {"address": addr}
        result = chat_lookup_pub(server, message, {}, "id", client_ip="ip")
        assert result == {"type": "CHAT_PUBKEY", "address": addr, "pubkey": "pubkey_cached", "found": True, "last_seen": 999888}
        # get_prekey_bundle should NOT be called when presence ts is in RAM
        server.get_prekey_bundle.assert_not_called()

    def test_not_found(self, server):
        addr = make_valid_address()
        message = {"address": addr}
        result = chat_lookup_pub(server, message, {}, "id", client_ip="ip")
        assert result["found"] is False
        assert result["pubkey"] is None

    def test_missing_address(self, server):
        result = chat_lookup_pub(server, {}, {}, "id", client_ip="ip")
        assert result == {"error": "missing address"}

    def test_rate_limited(self, server, mock_common):
        mock_common.allow_rpc_with_pow.side_effect = [(False, {"error": "ip_limit"}), (True, {})]
        result = chat_lookup_pub(server, {"address": make_valid_address()}, {}, "id", client_ip="ip")
        assert result == {"error": "ip_limit"}


class TestChatPresence:
    def test_success(self, server, mock_time):
        addr = make_valid_address()
        pubhex = make_valid_pubkey()
        spend_pk = make_valid_spend_pub()
        presence_sig = make_valid_sig()
        ts = int(mock_time.time.return_value)
        message = {
            "address": addr,
            "pubkey": pubhex,
            "spend_pub": spend_pk,
            "presence_sig": presence_sig,
            "hops": 0,
            "ts": ts,
        }
        result = chat_presence(server, message, {}, "id", addr, client_ip="ip")
        assert result == {"type": "CHAT_PRESENCE_OK"}
        assert server.chat_presence_pub[addr] == pubhex
        assert server.chat_spend_pub[addr] == spend_pk
        assert len(server.chat_presence_seen) == 1
        assert server.chat_prekeys[addr]["ik"] == pubhex
        server.relay_presence_async.assert_called_once()

    def test_stale_ts(self, server, mock_time):
        mock_time.time.return_value = 1000
        message = {
            "address": make_valid_address(),
            "pubkey": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "hops": 0,
            "ts": 100,
        }
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_stale"}

    def test_missing_fields(self, server):
        message = {}
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_missing_fields"}

    def test_bad_pub(self, server, mock_time):
        message = {
            "address": make_valid_address(),
            "pubkey": "invalid",
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "hops": 0,
            "ts": int(mock_time.time.return_value),
        }
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_bad_pub"}

    def test_bad_spend_pub(self, server, mock_time):
        message = {
            "address": make_valid_address(),
            "pubkey": make_valid_pubkey(),
            "spend_pub": "invalid",
            "presence_sig": make_valid_sig(),
            "hops": 0,
            "ts": int(mock_time.time.return_value),
        }
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_bad_spend_pub"}

    def test_address_mismatch(self, server, mock_hash160, mock_time):
        # Make hash160 return different than prog
        mock_hash160.return_value = b"different" + b"\x00"*13  # 20 bytes
        message = {
            "address": make_valid_address(),
            "pubkey": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "hops": 0,
            "ts": int(mock_time.time.return_value),
        }
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_addr_mismatch"}

    def test_bad_sig(self, server, mock_common, mock_time):
        frm = make_valid_address()
        server.chat_presence_pub[frm] = "f"*64
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"chat_send": False}
        message = {
            "from": frm,
            "to": make_valid_address(),
            "enc": {"nonce": "a"*24, "ct": "c"*100},          # valid hex
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),           # use mocked time
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": "f"*64,
        }
        result = chat_send(server, message, {}, "id", client_ip="ip",
                           choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

    def test_max_hops(self, server, mock_time):
        message = {
            "address": make_valid_address(),
            "pubkey": make_valid_pubkey(),
            "spend_pub": make_valid_spend_pub(),
            "presence_sig": make_valid_sig(),
            "hops": 10,  # > max
            "ts": int(mock_time.time.return_value),  # use mocked time
        }
        result = chat_presence(server, message, {}, "id", "addr", client_ip="ip")
        assert result == {"error": "presence_hops"}


class TestChatPublishPrekeys:
    def test_success(self, server):
        addr = make_valid_address()
        server.chat_spend_pub[addr] = make_valid_spend_pub()
        ik = make_valid_pubkey()
        spk = make_valid_pubkey()  # same length
        sig = make_valid_sig()
        message = {
            "address": addr,
            "ik": ik,
            "spk": spk,
            "sig": sig,
        }
        result = chat_publish_prekeys(server, message, {}, "id", client_ip="ip")
        assert result == {"type": "CHAT_PUBLISH_PREKEYS"}
        rec = server.chat_prekeys[addr]
        assert rec["ik"] == ik
        assert rec["spk"] == spk
        assert rec["sig"] == sig
        assert "ts" in rec

    def test_missing_fields(self, server):
        message = {"address": make_valid_address()}
        result = chat_publish_prekeys(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "missing fields"}

    def test_unknown_address(self, server):
        addr = make_valid_address()
        # No spend_pub set
        message = {
            "address": addr,
            "ik": make_valid_pubkey(),
            "spk": make_valid_pubkey(),
            "sig": make_valid_sig(),
        }
        result = chat_publish_prekeys(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "unknown_address"}

    def test_bad_spk_sig(self, server, mock_common):
        addr = make_valid_address()
        server.chat_spend_pub[addr] = make_valid_spend_pub()
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"spk": False}
        message = {
            "address": addr,
            "ik": make_valid_pubkey(),
            "spk": make_valid_pubkey(),
            "sig": make_valid_sig(),
        }
        result = chat_publish_prekeys(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "bad_spk_sig"}

    def test_opk_storage(self, server):
        addr = make_valid_address()
        server.chat_spend_pub[addr] = make_valid_spend_pub()
        opk = make_valid_pubkey()
        message = {
            "address": addr,
            "ik": make_valid_pubkey(),
            "spk": make_valid_pubkey(),
            "sig": make_valid_sig(),
            "opk": opk,
        }
        result = chat_publish_prekeys(server, message, {}, "id", client_ip="ip")
        assert result == {"type": "CHAT_PUBLISH_PREKEYS"}
        assert server.chat_prekeys[addr]["opk_list"] == [opk]


class TestChatGetPrekey:
    def test_success_with_opk(self, server):
        addr = make_valid_address()
        server.chat_prekeys[addr] = {
            "ik": "a"*64,
            "spk": "b"*64,
            "sig": "c"*128,
            "opk_list": ["d"*64, "e"*64],
        }
        server.chat_spend_pub[addr] = make_valid_spend_pub()
        message = {"address": addr}
        result = chat_get_prekey(server, message, client_ip="ip", is_miner_sender=False)
        assert result["type"] == "CHAT_PREKEY_BUNDLE"
        bundle = result["bundle"]
        assert bundle["ik"] == "a"*64
        assert bundle["spk"] == "b"*64
        assert bundle["sig"] == "c"*128
        assert bundle["opk"] == "d"*64  # popped first
        assert bundle["spend_pub"] == server.chat_spend_pub[addr]
        # Check opk_list now has only "e"*64
        assert server.chat_prekeys[addr]["opk_list"] == ["e"*64]

    def test_no_bundle(self, server):
        addr = make_valid_address()
        message = {"address": addr}
        result = chat_get_prekey(server, message, client_ip="ip", is_miner_sender=False)
        assert result == {"error": "no_bundle"}

    def test_no_opk(self, server):
        addr = make_valid_address()
        server.chat_prekeys[addr] = {
            "ik": "a"*64,
            "spk": "b"*64,
            "sig": "c"*128,
        }
        server.chat_spend_pub[addr] = make_valid_spend_pub()
        message = {"address": addr}
        result = chat_get_prekey(server, message, client_ip="ip", is_miner_sender=False)
        assert result["bundle"]["opk"] is None


class TestChatSend:
    def test_success_direct(self, server, mock_time):
        frm = make_valid_address()
        to = make_valid_address()
        server.chat_presence_pub[frm] = "f" * 64  # from_static
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        # Set up message
        enc = {"nonce": "a"*24, "ct": "c"*100}  # nonce hex
        fp_hex = make_valid_pubkey()
        fs_hex = "f" * 64
        chat_sig = make_valid_sig()
        message = {
            "from": frm,
            "to": to,
            "enc": enc,
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),
            "chat_sig": chat_sig,
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": fp_hex,
            "from_static": fs_hex,
        }
        result = chat_send(
            server, message, {}, "id",
            client_ip="ip",
            choose_relay_route=Mock(return_value=None),
            relay_chain=Mock()
        )
        assert result == {"type": "CHAT_ACK", "status": "queued"}
        server.mailbox_put.assert_called_once()
        server.enqueue_rcpt.assert_called_once()

    def test_missing_fields(self, server):
        message = {"from": "a"}
        result = chat_send(server, message, {}, "id", client_ip="ip", choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_fields"}

    def test_no_presence(self, server, mock_time):
        frm = make_valid_address()
        message = {
            "from": frm,
            "to": make_valid_address(),
            "enc": {"nonce": "a"*24, "ct": "c"*100},
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": make_valid_pubkey(),
        }
        # No presence for frm
        result = chat_send(server, message, {}, "id", client_ip="ip", choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "rejected", "reason": "no_presence"}

    def test_bad_from_static(self, server, mock_time):
        frm = make_valid_address()
        server.chat_presence_pub[frm] = "expected_static"
        message = {
            "from": frm,
            "to": make_valid_address(),
            "enc": {"nonce": "a"*24, "ct": "c"*100},
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": "wrong_static",
        }
        result = chat_send(server, message, {}, "id", client_ip="ip", choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}

    def test_bad_sig(self, server, mock_common, mock_time):
        frm = make_valid_address()
        server.chat_presence_pub[frm] = "f"*64
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"chat_send": False}
        message = {
            "from": frm,
            "to": make_valid_address(),
            "enc": {"nonce": "a"*24, "ct": "c"*100},
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": "f"*64,
        }
        result = chat_send(server, message, {}, "id", client_ip="ip", choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

    def test_relay_mode(self, server, mock_time):
        frm = make_valid_address()
        to = make_valid_address()
        server.chat_presence_pub[frm] = "f"*64
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        server.peers = {("peer1", 1): {}, ("peer2", 2): {}}
        with patch("tsarchain.network.rpc.user_rpc.category.chat.CFG.CHAT_FORCE_RELAY", True):
            route = [("peer1", 1), ("peer2", 2)]
            choose_relay_route = Mock(return_value=route)
            relay_chain = Mock()
            message = {
                "from": frm,
                "to": to,
                "enc": {"nonce": "a"*24, "ct": "c"*100},      # valid hex
                "msg_id": 123,
                "ts": int(mock_time.time.return_value),
                "chat_sig": make_valid_sig(),
                "ratchet_pn": 0,
                "ratchet_n": 0,
                "from_pub": make_valid_pubkey(),
                "from_static": "f"*64,
            }
            result = chat_send(server, message, {}, "id", client_ip="ip",
                               choose_relay_route=choose_relay_route, relay_chain=relay_chain)
            assert result == {"type": "CHAT_ACK", "status": "relayed", "hops": len(route)}

    def test_dedup(self, server, mock_time):
        frm = make_valid_address()
        server.chat_presence_pub[frm] = "f"*64
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        server.dedup_mid.return_value = True  # duplicate
        message = {
            "from": frm,
            "to": make_valid_address(),
            "enc": {"nonce": "a"*24, "ct": "c"*100},          # valid hex
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),           # use mocked time
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": "f"*64,
        }
        result = chat_send(server, message, {}, "id", client_ip="ip",
                           choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "duplicate"}


class TestChatRead:
    def test_success(self, server, mock_time):
        sender = make_valid_address()
        reader = make_valid_address()
        server.chat_spend_pub[reader] = make_valid_spend_pub()
        message = {
            "sender": sender,
            "reader": reader,
            "msg_id": 456,
            "ts": int(mock_time.time.return_value),
            "read_sig": make_valid_sig(),
        }
        result = chat_read(server, message, {}, "id", client_ip="ip")
        assert result == {"type": "CHAT_READ_OK"}
        server.enqueue_rcpt.assert_called_once_with(sender, "read", 456, sender, reader, int(mock_time.time.return_value))

    def test_bad_fields(self, server):
        message = {"sender": "a"}
        result = chat_read(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "bad_fields"}

    def test_no_sig(self, server, mock_time):
        message = {
            "sender": make_valid_address(),
            "reader": make_valid_address(),
            "msg_id": 456,
            "ts": int(mock_time.time.return_value),
        }
        result = chat_read(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "sig_required"}

    def test_bad_sig(self, server, mock_common, mock_time):
        server.chat_spend_pub[make_valid_address()] = make_valid_spend_pub()
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"read": False}
        message = {
            "sender": make_valid_address(),
            "reader": make_valid_address(),
            "msg_id": 456,
            "ts": int(mock_time.time.return_value),
            "read_sig": make_valid_sig(),
        }
        result = chat_read(server, message, {}, "id", client_ip="ip")
        assert result == {"error": "bad_sig"}


class TestChatPull:
    def test_success(self, server, mock_time):
        me = make_valid_address()
        server.chat_spend_pub[me] = make_valid_spend_pub()
        server.mailbox_pull.return_value = [{"msg": "hello"}]
        message = {
            "address": me,
            "n": 5,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_ITEMS", "items": [{"msg": "hello"}]}
        server.mailbox_pull.assert_called_once_with(me, 5)

    def test_rehydrate_spend_pub_from_storage(self, server, mock_time):
        me = make_valid_address()
        spend_pk = make_valid_spend_pub()
        # Not in RAM: server.chat_spend_pub is empty for `me`
        assert me not in server.chat_spend_pub
        # But exists in prekey bundle in storage
        server.chat_prekeys[me] = {"spend_pub": spend_pk}
        server.mailbox_pull.return_value = [{"msg": "rehydrated"}]
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_ITEMS", "items": [{"msg": "rehydrated"}]}
        assert server.chat_spend_pub[me] == spend_pk

    def test_bad_address(self, server):
        result = chat_pull(server, {"address": ""}, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "bad_address"}

    def test_not_registered(self, server, mock_time):
        me = make_valid_address()
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "not_registered"}

    def test_bad_sig(self, server, mock_common, mock_time):
        me = make_valid_address()
        server.chat_spend_pub[me] = make_valid_spend_pub()
        mock_common.verify_chat_signatures.side_effect = lambda sigs: {"pull": False}
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "bad_sig"}

    def test_ts_drift(self, server, mock_time):
        mock_time.time.return_value = 1000
        me = make_valid_address()
        server.chat_spend_pub[me] = make_valid_spend_pub()
        message = {
            "address": me,
            "ts": 100,  # old
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "ts_drift"}

    def test_replay_detected(self, server, mock_time):
        me = make_valid_address()
        server.chat_spend_pub[me] = make_valid_spend_pub()
        server.dedup_pull.return_value = True
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "replay_detected"}

    def test_not_registered_skips_dedup_check(self, server, mock_time):
        me = make_valid_address()
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "not_registered"}
        server.dedup_pull.assert_not_called()


class TestChatRelay:
    def test_success_last_hop(self, server, mock_config):
        # Route empty: deliver to mailbox
        inner = {
            "type": "CHAT_SEND_INNER",
            "to": make_valid_address(),
            "msg": {
                "from": make_valid_address(),
                "msg_id": 123,
                "ts": 1000,
                "from_static": "f"*64,
                "from_pub": make_valid_pubkey(),
                "enc": {"nonce": "a"*24, "ct": "c"*100},
                "used_opk": None,
                "ratchet_pn": 0,
                "ratchet_n": 0,
            }
        }
        message = {"route": [], "inner": inner}
        result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=Mock())
        assert result == {"type": "CHAT_RELAY_ACK", "status": "queued"}
        server.mailbox_put.assert_called_once()

    def test_forward_hop(self, server):
        # Route with hops
        server.peers = {("peer1", 1): {}, ("peer2", 2): {}}
        route = [["peer1", 1], ["peer2", 2]]
        inner = {"type": "CHAT_SEND_INNER", "to": "to_addr", "msg": {"from": "from_addr"}}
        message = {"route": route, "inner": inner}
        send_chat_relay = Mock(return_value={"ok": True})
        result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=send_chat_relay)
        # Should forward to next hop
        assert result is None or result == {"ok": True}  # send_chat_relay returns whatever
        send_chat_relay.assert_called_once()
        # mailbox not called
        server.mailbox_put.assert_not_called()

    def test_unknown_hop(self, server):
        server.peers = {}
        route = [["unknown", 1]]
        message = {"route": route, "inner": {"type": "CHAT_SEND_INNER"}}
        result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=Mock())
        assert result == {"error": "unknown_hop"}

    def test_route_too_long(self, server, mock_config):
        server.peers = {("p", i): {} for i in range(10)}
        route = [["p", i] for i in range(10)]  # > max 5
        with patch("tsarchain.network.rpc.user_rpc.category.chat.CFG.CHAT_RELAY_MAX_HOPS", 5):
            message = {"route": route, "inner": {"type": "CHAT_SEND_INNER"}}
            result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=Mock())
            assert result == {"error": "route_too_long"}

    def test_bad_inner_type(self, server):
        message = {"route": [], "inner": {"type": "WRONG"}}
        result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=Mock())
        assert result == {"error": "bad_inner_type"}

    def test_payload_too_large(self, server):
        # Buat inner yang valid tetapi besar
        inner = {
            "type": "CHAT_SEND_INNER",
            "to": make_valid_address(),
            "msg": {
                "from": make_valid_address(),
                "msg_id": 123,
                "ts": 1000,
                "from_static": "f" * 64,
                "from_pub": make_valid_pubkey(),
                "enc": {"nonce": "a" * 24, "ct": "c" * 200},   # panjang 200
                "used_opk": None,
                "ratchet_pn": 0,
                "ratchet_n": 0,
            }
        }
        message = {"route": [], "inner": inner}
        with patch("tsarchain.network.rpc.user_rpc.category.chat.CFG.CHAT_RELAY_MAX_INNER_BYTES", 100):
            result = chat_relay(server, message, {}, "id", client_ip="ip", send_chat_relay=Mock())
            assert result == {"error": "payload_too_large"}

    def test_rate_limited(self, server, mock_common):
        mock_common.allow_rpc_with_pow.side_effect = [(False, {"error": "limit"}), (True, {})]
        result = chat_relay(server, {}, {}, "id", client_ip="ip", send_chat_relay=Mock())
        assert result == {"error": "limit"}

    def test_chat_pull_replay_rejection(self, server, mock_time):
        me = make_valid_address()
        server.chat_spend_pub[me] = make_valid_spend_pub()
        server.dedup_pull = Mock(return_value=True)  # Replay detected
        message = {
            "address": me,
            "ts": int(mock_time.time.return_value),
            "pull_sig": make_valid_sig(),
        }
        result = chat_pull(server, message, client_ip="ip")
        assert result == {"type": "CHAT_NONE", "items": [], "error": "replay_detected"}

    def test_chat_send_verifies_used_opk_signature(self, server, mock_common, mock_time):
        frm = make_valid_address()
        to = make_valid_address()
        server.chat_presence_pub[frm] = "f"*64
        server.chat_spend_pub[frm] = make_valid_spend_pub()
        
        signatures_checked = []
        def check_sigs(sig_list):
            for item in sig_list:
                signatures_checked.append(item)
            return {"chat_send": True}
        mock_common.verify_chat_signatures.side_effect = check_sigs

        message = {
            "from": frm,
            "to": to,
            "enc": {"nonce": "a"*24, "ct": "c"*100},
            "msg_id": 123,
            "ts": int(mock_time.time.return_value),
            "chat_sig": make_valid_sig(),
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "from_pub": make_valid_pubkey(),
            "from_static": "f"*64,
            "used_opk": "k"*64,
        }
        result = chat_send(server, message, {}, "id", client_ip="ip",
                           choose_relay_route=Mock(), relay_chain=Mock())
        assert result == {"type": "CHAT_ACK", "status": "queued"}
        assert len(signatures_checked) == 1
        signed_bytes = signatures_checked[0][2]
        assert ("k"*64).encode() in signed_bytes