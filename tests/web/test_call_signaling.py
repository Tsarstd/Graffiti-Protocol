# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import base64
import hashlib
import json
import socket
import struct
import threading
import time
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import pytest
from ecdsa import SigningKey, SECP256k1

from bech32 import bech32_encode, convertbits
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160
from web.Backend.src.server import create_handler_class
from web.Backend.src.services.call_signaling_service import CallSignalingService, _OPCODE_TEXT, _OPCODE_CLOSE


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


from bech32 import encode as bech32_segwit_encode

def _real_hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(bytes(b)).digest()).digest()

def _generate_test_wallet():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    pub_bytes = vk.to_string("compressed")
    h160 = _real_hash160(pub_bytes)
    prefix = getattr(CFG, "ADDRESS_PREFIX", "tsar") or "tsar"
    addr = bech32_segwit_encode(prefix, 0, list(h160))
    if addr is None:
        raise RuntimeError(f"Address encoding failed: prefix={prefix!r}, h160={h160!r}")
    return sk, pub_bytes.hex(), addr


def _sign_challenge(sk: SigningKey, addr: str, nonce: str) -> str:
    payload = b"|".join([b"CALL_AUTH", addr.encode("utf-8"), nonce.encode("utf-8")])
    digest = hashlib.sha256(payload).digest()
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=lambda r, s, order: _encode_der(r, s, order))
    return sig.hex()


def _encode_der(r: int, s: int, order: int) -> bytes:
    # Enforce low S
    if s > order // 2:
        s = order - s
    rb = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
    sb = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
    if rb[0] & 0x80:
        rb = b"\x00" + rb
    if sb[0] & 0x80:
        sb = b"\x00" + sb
    return b"\x30" + bytes([len(rb) + len(sb) + 4, 0x02, len(rb)]) + rb + bytes([0x02, len(sb)]) + sb


class SimpleWSClient:
    """Minimal test WebSocket client using standard socket."""
    def __init__(self, host: str, port: int):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        # Perform WebSocket Upgrade handshake
        self.key = base64.b64encode(b"1234567890123456").decode("ascii")
        req = (
            f"GET /api/call/ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode("ascii"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        assert b"101 Switching Protocols" in resp

    def send_json(self, data: dict):
        payload = json.dumps(data).encode("utf-8")
        length = len(payload)
        header = bytearray()
        header.append(0x80 | _OPCODE_TEXT)
        mask = b"\x11\x22\x33\x44"

        if length <= 125:
            header.append(0x80 | length)
        elif length <= 65535:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))

        header.extend(mask)
        masked = bytearray(length)
        for i in range(length):
            masked[i] = payload[i] ^ mask[i % 4]

        self.sock.sendall(bytes(header) + bytes(masked))

    def recv_json(self, timeout=2.0) -> dict:
        self.sock.settimeout(timeout)
        head = self._recv_exact(2)
        if not head:
            raise TimeoutError("No data")
        b1, b2 = head[0], head[1]
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        payload = self._recv_exact(length)
        return json.loads(payload.decode("utf-8"))

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def test_call_signaling_full_lifecycle():
    port = _find_free_port()
    signaling_svc = CallSignalingService("127.0.0.1", 38169)
    handler_cls = create_handler_class(routes=None, signaling=signaling_svc)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    alice_sk, alice_pk, alice_addr = _generate_test_wallet()
    bob_sk, bob_pk, bob_addr = _generate_test_wallet()

    # Mock node chat status: both registered
    with patch.object(signaling_svc, "_check_node_chat_status", return_value=True):
        # 1. Connect Alice
        alice_client = SimpleWSClient("127.0.0.1", port)
        challenge_alice = alice_client.recv_json()
        assert challenge_alice["type"] == "AUTH_CHALLENGE"

        sig_alice = _sign_challenge(alice_sk, alice_addr, challenge_alice["nonce"])
        alice_client.send_json({
            "type": "AUTH_RESPONSE",
            "address": alice_addr,
            "pubkey": alice_pk,
            "sig": sig_alice,
        })
        auth_ok_alice = alice_client.recv_json()
        assert auth_ok_alice["type"] == "AUTH_OK"
        assert auth_ok_alice["address"] == alice_addr

        # 2. Connect Bob
        bob_client = SimpleWSClient("127.0.0.1", port)
        challenge_bob = bob_client.recv_json()
        assert challenge_bob["type"] == "AUTH_CHALLENGE"

        sig_bob = _sign_challenge(bob_sk, bob_addr, challenge_bob["nonce"])
        bob_client.send_json({
            "type": "AUTH_RESPONSE",
            "address": bob_addr,
            "pubkey": bob_pk,
            "sig": sig_bob,
        })
        auth_ok_bob = bob_client.recv_json()
        assert auth_ok_bob["type"] == "AUTH_OK"

        # 3. Alice initiates Call Offer
        call_id = "call_test_123"
        alice_client.send_json({
            "type": "CALL_OFFER",
            "call_id": call_id,
            "to": bob_addr,
            "media_type": "video",
            "sdp": "v=0\r\ntest_sdp_offer",
        })

        # Bob receives incoming call
        incoming = bob_client.recv_json()
        assert incoming["type"] == "CALL_INCOMING"
        assert incoming["call_id"] == call_id
        assert incoming["from"] == alice_addr
        assert incoming["media_type"] == "video"
        assert incoming["sdp"] == "v=0\r\ntest_sdp_offer"

        # 4. Bob sends Ringing
        bob_client.send_json({
            "type": "CALL_RINGING",
            "call_id": call_id,
        })
        ringing = alice_client.recv_json()
        assert ringing["type"] == "CALL_RINGING"
        assert ringing["call_id"] == call_id

        # 5. Bob Answers
        bob_client.send_json({
            "type": "CALL_ANSWER",
            "call_id": call_id,
            "sdp": "v=0\r\ntest_sdp_answer",
        })
        answer = alice_client.recv_json()
        assert answer["type"] == "CALL_ANSWER"
        assert answer["call_id"] == call_id
        assert answer["sdp"] == "v=0\r\ntest_sdp_answer"

        # 6. Exchange ICE Candidates
        alice_client.send_json({
            "type": "CALL_ICE_CANDIDATE",
            "call_id": call_id,
            "candidate": {"candidate": "cand_alice_1", "sdpMid": "0"},
        })
        cand_for_bob = bob_client.recv_json()
        assert cand_for_bob["type"] == "CALL_ICE_CANDIDATE"
        assert cand_for_bob["candidate"]["candidate"] == "cand_alice_1"

        # 7. Hangup
        alice_client.send_json({
            "type": "CALL_HANGUP",
            "call_id": call_id,
        })
        hangup = bob_client.recv_json()
        assert hangup["type"] == "CALL_HANGUP"
        assert hangup["call_id"] == call_id

        alice_client.close()
        bob_client.close()

    signaling_svc.shutdown()
    httpd.shutdown()
    httpd.server_close()


def test_call_signaling_dual_guard_deactivated():
    port = _find_free_port()
    signaling_svc = CallSignalingService("127.0.0.1", 38169)
    handler_cls = create_handler_class(routes=None, signaling=signaling_svc)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    alice_sk, alice_pk, alice_addr = _generate_test_wallet()
    charlie_sk, charlie_pk, charlie_addr = _generate_test_wallet()

    # Charlie is DEACTIVATED on Node RPC
    def mock_node_status(addr):
        return addr == alice_addr  # Alice is True, Charlie is False

    with patch.object(signaling_svc, "_check_node_chat_status", side_effect=mock_node_status):
        alice_client = SimpleWSClient("127.0.0.1", port)
        challenge_alice = alice_client.recv_json()
        sig_alice = _sign_challenge(alice_sk, alice_addr, challenge_alice["nonce"])
        alice_client.send_json({
            "type": "AUTH_RESPONSE",
            "address": alice_addr,
            "pubkey": alice_pk,
            "sig": sig_alice,
        })
        assert alice_client.recv_json()["type"] == "AUTH_OK"

        # Alice attempts to call Charlie who has DEACTIVATED chat
        alice_client.send_json({
            "type": "CALL_OFFER",
            "call_id": "call_rejected_1",
            "to": charlie_addr,
            "media_type": "audio",
            "sdp": "dummy_sdp",
        })
        rejected = alice_client.recv_json()
        assert rejected["type"] == "CALL_REJECTED"
        assert rejected["reason"] == "recipient_deactivated"

        alice_client.close()

    signaling_svc.shutdown()
    httpd.shutdown()
    httpd.server_close()
