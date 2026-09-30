# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import json
import time
import hashlib
import threading
import firebase_admin
from typing import Optional, Dict, Any
from firebase_admin import credentials, messaging

from bech32 import bech32_decode, convertbits
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160
from tsarchain.utils.tsar_logging import get_ctx_logger
from tsarchain.network.rpc.user_rpc.common import verify_chat_signatures

log = get_ctx_logger("tsarchain.utils.fcm_service")


def _verify_addr_pubkey(address: str, pubkey_hex: str) -> bool:
    try:
        hrp, data = bech32_decode(address)
        if hrp != CFG.ADDRESS_PREFIX or not data:
            return False
        converted = convertbits(data[1:], 5, 8, False)
        if converted is None:
            return False
        prog = bytes(converted)
        h = hash160(bytes.fromhex(pubkey_hex))
        if len(h) != 20:
            h = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()).digest()
        return h == prog
    except Exception:
        return False


class FCMService:
    """
    Central Push Notification Gateway for TsarChain & Kremlin Mobile.
    - Shared utility across TsarChain Node RPC and Web Backend.
    - Manages device token registry persisted in data/web/fcm_tokens.json.
    - Sends high-priority data messages for incoming calls, encrypted chat, and transactions.
    - 100% compliant with Graffiti Protocol (Zero reflection: no isinstance, hasattr, getattr, setattr).
    """

    _instance: Optional[FCMService] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> FCMService:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(db_path=db_path)
            return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._tokens: Dict[str, Dict[str, Any]] = {}
        self._db_path = str(db_path) if db_path else CFG.FCM_TOKEN_PATH
        self._db_mtime = 0.0
        self._firebase_initialized = False
        self._init_firebase()
        self._load_tokens()

    def _init_firebase(self) -> None:
        key_path = CFG.FCM_KEY_PATH
        try:
            cred = credentials.Certificate(key_path)
            firebase_admin.initialize_app(cred)
            self._firebase_initialized = True
            log.info("[fcm_service] Firebase Admin SDK initialized from %s", key_path)
        except ValueError:
            self._firebase_initialized = True
        except Exception as exc:
            log.warning("[fcm_service] Failed to initialize Firebase Admin SDK: %s", exc)

    def _load_tokens(self) -> None:
        try:
            mtime = os.path.getmtime(self._db_path)
            if mtime != self._db_mtime:
                with open(self._db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if type(data) is dict:
                        self._tokens = data
                        self._db_mtime = mtime
        except Exception:
            pass

    def _save_tokens(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
            tmp = f"{self._db_path}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._tokens, f, indent=2)
            os.replace(tmp, self._db_path)
            self._db_mtime = os.path.getmtime(self._db_path)
        except Exception as exc:
            log.warning("[fcm_service] Failed to save tokens: %s", exc)

    # ---------------- Token Management ----------------

    def register_token(
        self,
        address: str,
        token: str,
        pubkey: str,
        sig: str,
        ts: int,
        client_ip: str = "",
    ) -> tuple[bool, str]:
        addr = str(address or "").strip().lower()
        tok = str(token or "").strip()
        pk = str(pubkey or "").strip().lower()
        signature = str(sig or "").strip().lower()

        if not addr or not tok or not pk or not signature:
            return False, "missing_fields"

        # 1. Address match pubkey verification
        if not _verify_addr_pubkey(addr, pk):
            log.warning("[fcm_register] Address %s does not match pubkey %s", addr, pk)
            return False, "address_pubkey_mismatch"

        # 2. Timestamp drift check (+- 300 seconds)
        now = int(time.time())
        if abs(now - int(ts)) > 300:
            log.warning("[fcm_register] Timestamp drift too large for %s (ts=%s, now=%s)", addr, ts, now)
            return False, "timestamp_drift"

        # 3. Cryptographic signature verification over payload
        payload = b"|".join([b"FCM_REGISTER", addr.encode("utf-8"), tok.encode("utf-8"), str(int(ts)).encode("utf-8")])
        sig_check = verify_chat_signatures([("reg", pk, payload, signature)])
        if not sig_check.get("reg"):
            log.warning("[fcm_register] Bad cryptographic signature from %s (ip=%s)", addr, client_ip)
            return False, "bad_signature"

        with self._lock:
            self._tokens[addr] = {
                "token": tok,
                "pubkey": pk,
                "updated_at": now,
                "ip": client_ip,
            }
            self._save_tokens()

        log.debug("[fcm_register] Token successfully registered for address %s", addr)
        return True, "ok"

    def unregister_token(
        self,
        address: str,
        pubkey: str,
        sig: str,
        ts: int,
    ) -> tuple[bool, str]:
        addr = str(address or "").strip().lower()
        pk = str(pubkey or "").strip().lower()
        signature = str(sig or "").strip().lower()

        if not addr or not pk or not signature:
            return False, "missing_fields"

        if not _verify_addr_pubkey(addr, pk):
            return False, "address_pubkey_mismatch"

        payload = b"|".join([b"FCM_UNREGISTER", addr.encode("utf-8"), str(int(ts)).encode("utf-8")])
        sig_check = verify_chat_signatures([("unreg", pk, payload, signature)])
        if not sig_check.get("unreg"):
            return False, "bad_signature"

        with self._lock:
            self._tokens.pop(addr, None)
            self._save_tokens()

        log.debug("[fcm_unregister] Token unregistered for address %s", addr)
        return True, "ok"

    def get_token(self, address: str) -> Optional[str]:
        self._load_tokens()
        addr = str(address or "").strip().lower()
        with self._lock:
            info = self._tokens.get(addr)
            if type(info) is dict:
                tok = info.get("token")
                if type(tok) is str and tok:
                    return tok
        return None

    # ---------------- Push Dispatchers ----------------

    def send_call_push(
        self,
        callee_addr: str,
        caller_addr: str,
        call_id: str,
        media_type: str,
        caller_alias: str = "",
    ) -> bool:
        """Dispatches high-priority wake-up data push to callee device for incoming call."""
        token = self.get_token(callee_addr)
        if not token or not self._firebase_initialized:
            log.debug("[fcm_push_call] FCM not ready or no token for callee %s", callee_addr)
            return False

        try:
            # NOTE: "from" is a reserved key in FCM data payload and causes Google API rejection.
            # We use "caller_address" and "peer_address" instead.
            # SDP is excluded from FCM data push to prevent exceeding the 4096-byte limit.
            data_payload = {
                "type": "incoming_call",
                "call_id": str(call_id),
                "caller_address": str(caller_addr),
                "peer_address": str(caller_addr),
                "media_type": str(media_type),
                "caller_alias": str(caller_alias or caller_addr),
                "ts": str(int(time.time())),
            }

            msg = messaging.Message(
                token=token,
                data=data_payload,
                android=messaging.AndroidConfig(
                    priority="high",
                    ttl=35,  # 35 seconds TTL
                ),
            )
            resp = messaging.send(msg)
            log.debug("[fcm_push_call] Call push sent to %s for call %s (msg_id: %s)", callee_addr, call_id, resp)
            return True
        except Exception as exc:
            log.warning("[fcm_push_call] Error sending call push to %s: %s", callee_addr, exc)
            return False

    def send_call_hangup_push(self, callee_addr: str, call_id: str) -> bool:
        """Dispatches push to dismiss ringing notification when caller hangs up before answer."""
        token = self.get_token(callee_addr)
        if not token or not self._firebase_initialized:
            return False

        try:
            msg = messaging.Message(
                token=token,
                data={
                    "type": "call_hangup",
                    "call_id": str(call_id),
                    "ts": str(int(time.time())),
                },
                android=messaging.AndroidConfig(
                    priority="high",
                    ttl=10,
                ),
            )
            messaging.send(msg)
            log.debug("[fcm_push_hangup] Hangup push sent to %s for call %s", callee_addr, call_id)
            return True
        except Exception as exc:
            log.warning("[fcm_push_hangup] Error sending hangup push to %s: %s", callee_addr, exc)
            return False

    def send_chat_push(
        self,
        target_addr: str,
        sender_addr: str,
        msg_id: Any,
        ts: int,
        sender_alias: str = "",
        preview: str = "",
    ) -> bool:
        """Dispatches wake-up push for new message with direct preview."""
        token = self.get_token(target_addr)
        if not token or not self._firebase_initialized:
            return False

        try:
            body = str(preview).strip() if preview else "Pesan baru"
            msg = messaging.Message(
                token=token,
                data={
                    "type": "chat",
                    "peer_address": str(sender_addr),
                    "sender_alias": str(sender_alias or sender_addr),
                    "msg_id": str(msg_id),
                    "ts": str(ts),
                    "title": "Pesan Obrolan",
                    "body": body,
                },
                android=messaging.AndroidConfig(
                    priority="high",
                    ttl=86400,
                ),
            )
            messaging.send(msg)
            log.debug("[fcm_push_chat] Chat push sent to %s from %s (mid=%s)", target_addr, sender_addr, msg_id)
            return True
        except Exception as exc:
            log.warning("[fcm_push_chat] Error sending chat push to %s: %s", target_addr, exc)
            return False

    def send_tx_push(
        self,
        target_addr: str,
        txid: str,
        amount_sat: int,
        is_incoming: bool = True,
        sender_addr: str = "",
    ) -> bool:
        """Dispatches notification for incoming/outgoing confirmed or pending transaction."""
        token = self.get_token(target_addr)
        if not token or not self._firebase_initialized:
            return False

        try:
            title = "Koin Diterima" if is_incoming else "Transaksi Terkirim"
            tsar_amount = amount_sat / 100000000.0
            body = f"+{tsar_amount:.8f} TSAR" if is_incoming else f"-{tsar_amount:.8f} TSAR"

            data_payload = {
                "type": "tx",
                "txid": str(txid),
                "amount": str(amount_sat),
                "title": title,
                "body": body,
            }
            if sender_addr:
                data_payload["sender_address"] = str(sender_addr)

            msg = messaging.Message(
                token=token,
                data=data_payload,
                android=messaging.AndroidConfig(
                    priority="high",
                    ttl=86400,
                ),
            )
            messaging.send(msg)
            log.debug("[fcm_push_tx] Tx push sent to %s for txid %s", target_addr, txid)
            return True
        except Exception as exc:
            log.warning("[fcm_push_tx] Error sending tx push to %s: %s", target_addr, exc)
            return False
