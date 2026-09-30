# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import time
import json
import socket
import hashlib
import tempfile
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import pytest
from ecdsa import SigningKey, SECP256k1
from bech32 import encode as bech32_segwit_encode

from tsarchain.utils import config as CFG
from web.Backend.src.server import create_handler_class
from tsarchain.utils.fcm_service import FCMService
from web.Backend.src.services.call_signaling_service import CallSignalingService


def _real_hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(bytes(b)).digest()).digest()


def _encode_der(r: int, s: int, order: int) -> bytes:
    if s > order // 2:
        s = order - s
    rb = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
    sb = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
    if rb[0] & 0x80:
        rb = b"\x00" + rb
    if sb[0] & 0x80:
        sb = b"\x00" + sb
    return bytes([0x30, len(rb) + len(sb) + 4, 0x02, len(rb)]) + rb + bytes([0x02, len(sb)]) + sb


def _generate_test_wallet():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    pub_bytes = vk.to_string("compressed")
    h160 = _real_hash160(pub_bytes)
    prefix = CFG.ADDRESS_PREFIX or "tsar"
    addr = bech32_segwit_encode(prefix, 0, list(h160))
    return sk, pub_bytes.hex(), addr


def _sign_fcm_register(sk: SigningKey, addr: str, token: str, ts: int) -> str:
    payload = b"|".join([b"FCM_REGISTER", addr.encode("utf-8"), token.encode("utf-8"), str(ts).encode("utf-8")])
    digest = hashlib.sha256(payload).digest()
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=lambda r, s, order: _encode_der(r, s, order))
    return sig.hex()


def _sign_fcm_unregister(sk: SigningKey, addr: str, ts: int) -> str:
    payload = b"|".join([b"FCM_UNREGISTER", addr.encode("utf-8"), str(ts).encode("utf-8")])
    digest = hashlib.sha256(payload).digest()
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=lambda r, s, order: _encode_der(r, s, order))
    return sig.hex()


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_fcm_service_token_registration():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        db_path = tmp.name

    try:
        svc = FCMService(db_path=db_path)
        sk, pubkey, addr = _generate_test_wallet()
        token = "fcm_token_test_1234567890"
        ts = int(time.time())
        sig = _sign_fcm_register(sk, addr, token, ts)

        # 1. Valid registration
        ok, reason = svc.register_token(address=addr, token=token, pubkey=pubkey, sig=sig, ts=ts)
        assert ok is True
        assert reason == "ok"
        assert svc.get_token(addr) == token

        # 2. Re-load from disk
        svc2 = FCMService(db_path=db_path)
        assert svc2.get_token(addr) == token

        # 3. Bad signature test
        bad_sig = "00" * 64
        ok_bad, reason_bad = svc.register_token(address=addr, token="other", pubkey=pubkey, sig=bad_sig, ts=ts)
        assert ok_bad is False
        assert reason_bad == "bad_signature"

        # 4. Timestamp drift test
        stale_ts = ts - 1000
        stale_sig = _sign_fcm_register(sk, addr, token, stale_ts)
        ok_stale, reason_stale = svc.register_token(address=addr, token=token, pubkey=pubkey, sig=stale_sig, ts=stale_ts)
        assert ok_stale is False
        assert reason_stale == "timestamp_drift"

        # 5. Unregister
        unreg_ts = int(time.time())
        unreg_sig = _sign_fcm_unregister(sk, addr, unreg_ts)
        ok_unreg, reason_unreg = svc.unregister_token(address=addr, pubkey=pubkey, sig=unreg_sig, ts=unreg_ts)
        assert ok_unreg is True
        assert svc.get_token(addr) is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_fcm_http_endpoints():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        db_path = tmp.name

    port = _find_free_port()
    fcm_svc = FCMService(db_path=db_path)
    handler_cls = create_handler_class(fcm=fcm_svc)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        sk, pubkey, addr = _generate_test_wallet()
        token = "fcm_mobile_app_device_token_xyz"
        ts = int(time.time())
        sig = _sign_fcm_register(sk, addr, token, ts)

        reg_url = f"http://127.0.0.1:{port}/api/fcm/register"
        req_data = json.dumps({
            "address": addr,
            "token": token,
            "pubkey": pubkey,
            "sig": sig,
            "ts": ts,
        }).encode("utf-8")

        req = urllib.request.Request(reg_url, data=req_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body.get("status") == "ok"

        assert fcm_svc.get_token(addr) == token

        # Unregister endpoint
        unreg_url = f"http://127.0.0.1:{port}/api/fcm/unregister"
        unreg_ts = int(time.time())
        unreg_sig = _sign_fcm_unregister(sk, addr, unreg_ts)
        unreg_data = json.dumps({
            "address": addr,
            "pubkey": pubkey,
            "sig": unreg_sig,
            "ts": unreg_ts,
        }).encode("utf-8")

        req_unreg = urllib.request.Request(unreg_url, data=unreg_data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_unreg) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body.get("status") == "ok"

        assert fcm_svc.get_token(addr) is None

        # Chunked Transfer-Encoding registration test
        sk_ch, pk_ch, addr_ch = _generate_test_wallet()
        tok_ch = "fcm_token_chunked_12345"
        ts_ch = int(time.time())
        sig_ch = _sign_fcm_register(sk_ch, addr_ch, tok_ch, ts_ch)
        payload_ch = json.dumps({
            "address": addr_ch,
            "token": tok_ch,
            "pubkey": pk_ch,
            "sig": sig_ch,
            "ts": ts_ch,
        }).encode("utf-8")

        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.putrequest("POST", "/api/fcm/register")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        mid = len(payload_ch) // 2
        p1 = payload_ch[:mid]
        p2 = payload_ch[mid:]
        conn.send(f"{len(p1):x}\r\n".encode("ascii") + p1 + b"\r\n")
        conn.send(f"{len(p2):x}\r\n".encode("ascii") + p2 + b"\r\n")
        conn.send(b"0\r\n\r\n")
        resp_ch = conn.getresponse()
        assert resp_ch.status == 200
        assert fcm_svc.get_token(addr_ch) == tok_ch
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        if os.path.exists(db_path):
            os.remove(db_path)
