# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import threading
import time
from typing import Optional, Dict, Any

from bech32 import bech32_decode, convertbits
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160
from tsarchain.utils.tsar_logging import get_ctx_logger
from tsarchain.network.rpc.user_rpc.common import verify_chat_signatures
from web.Backend.src.core.logic_web.rpc_client import get_client, rpc_send

log = get_ctx_logger("tsarchain.web.Backend.call_signaling_service")

# WebSocket constants
WS_RFC6455_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_OPCODE_TEXT = 0x1
_OPCODE_CLOSE = 0x8
_OPCODE_PING = 0x9
_OPCODE_PONG = 0xA

CALL_OFFER_TIMEOUT_S = 35.0


class CallSession:
    def __init__(self, call_id: str, caller: str, callee: str, media_type: str):
        self.call_id: str = call_id
        self.caller: str = caller
        self.callee: str = callee
        self.media_type: str = media_type
        self.state: str = "offering"  # offering, ringing, connected, ended
        self.created_at: float = time.time()
        self.started_at: float = 0.0


class WebSocketConnection:
    """Lightweight RFC 6455 WebSocket framing wrapper around a standard socket."""

    def __init__(self, sock: Any, client_ip: str):
        self.sock = sock
        self.client_ip = client_ip
        self.address: Optional[str] = None
        self.nonce: str = secrets.token_hex(16)
        self.authenticated: bool = False
        self._send_lock = threading.Lock()
        self.closed: bool = False

    def send_raw_frame(self, opcode: int, payload: bytes) -> bool:
        if self.closed:
            return False
        length = len(payload)
        header = bytearray()
        header.append(0x80 | (opcode & 0x0F))

        if length <= 125:
            header.append(length)
        elif length <= 65535:
            header.append(126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(127)
            header.extend(struct.pack("!Q", length))

        try:
            with self._send_lock:
                self.sock.sendall(bytes(header) + payload)
            return True
        except Exception:
            self.closed = True
            return False

    def send_json(self, data: dict) -> bool:
        try:
            payload = json.dumps(data).encode("utf-8")
            return self.send_raw_frame(_OPCODE_TEXT, payload)
        except Exception as exc:
            log.warning("[ws_send_json_error] ip=%s addr=%s: %s", self.client_ip, self.address, exc)
            return False

    def recv_frame(self) -> Optional[tuple[int, bytes]]:
        """Reads a single WebSocket frame. Returns (opcode, payload) or None if closed."""
        try:
            head = self._recv_exact(2)
            if not head or len(head) < 2:
                return None
            b1, b2 = head[0], head[1]
            opcode = b1 & 0x0F
            is_masked = bool(b2 & 0x80)
            payload_len = b2 & 0x7F

            if payload_len == 126:
                ext = self._recv_exact(2)
                if not ext:
                    return None
                payload_len = struct.unpack("!H", ext)[0]
            elif payload_len == 127:
                ext = self._recv_exact(8)
                if not ext:
                    return None
                payload_len = struct.unpack("!Q", ext)[0]

            mask_key = None
            if is_masked:
                mask_key = self._recv_exact(4)
                if not mask_key:
                    return None

            data = self._recv_exact(payload_len)
            if data is None:
                return None

            if is_masked and mask_key:
                unmasked = bytearray(payload_len)
                for i in range(payload_len):
                    unmasked[i] = data[i] ^ mask_key[i % 4]
                return (opcode, bytes(unmasked))
            return (opcode, data)
        except Exception:
            return None

    def _recv_exact(self, num_bytes: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = self.sock.recv(num_bytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.send_raw_frame(_OPCODE_CLOSE, b"")
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass


class CallSignalingService:
    """
    Real-time WebSocket signaling service for P2P Voice & Video Calls.
    - Zero persistent storage (RAM-only ephemeral call registry).
    - Enforces DEACTIVATE_CHAT / CHAT_REGISTER on Node RPC.
    - Zero dynamic reflection (100% Graffiti Protocol compliant).
    """

    def __init__(self, node_host: str = "127.0.0.1", node_port: int = 38169):
        self.node_host: str = str(node_host)
        self.node_port: int = int(node_port)
        self.connected_clients: Dict[str, WebSocketConnection] = {}
        self.active_calls: Dict[str, CallSession] = {}
        self._lock = threading.Lock()
        self._running: bool = True

        # Background timeout watchdog
        self._watchdog_thread = threading.Thread(
            target=self._timeout_watchdog_loop,
            name="CallTimeoutWatchdog",
            daemon=True,
        )
        self._watchdog_thread.start()
        log.debug("[call_signaling] Service initialized (node=%s:%s)", self.node_host, self.node_port)

    def shutdown(self) -> None:
        self._running = False
        with self._lock:
            for conn in self.connected_clients.values():
                conn.send_json({"type": "SERVER_SHUTDOWN"})
                conn.close()
            self.connected_clients.clear()
            self.active_calls.clear()
        log.debug("[call_signaling] Service shut down successfully")

    def handle_connection(self, sock: Any, client_ip: str) -> None:
        """Entry point for an upgraded WebSocket client socket."""
        conn = WebSocketConnection(sock, client_ip)
        # 1. Send authentication challenge
        conn.send_json({"type": "AUTH_CHALLENGE", "nonce": conn.nonce})
        log.debug("[call_signaling] New connection from %s; sent AUTH_CHALLENGE", client_ip)

        try:
            while self._running and not conn.closed:
                frame = conn.recv_frame()
                if frame is None:
                    break
                opcode, payload = frame
                if opcode == _OPCODE_CLOSE:
                    break
                if opcode == _OPCODE_PING:
                    conn.send_raw_frame(_OPCODE_PONG, payload)
                    continue
                if opcode == _OPCODE_PONG:
                    continue
                if opcode == _OPCODE_TEXT:
                    try:
                        text = payload.decode("utf-8")
                        msg = json.loads(text)
                        if type(msg) is dict:
                            self._process_message(conn, msg)
                    except Exception as err:
                        log.warning("[call_signaling] Error parsing message from %s: %s", client_ip, err)
        finally:
            self._cleanup_client(conn)

    # ---------------- Message Dispatching ----------------

    def _process_message(self, conn: WebSocketConnection, msg: dict) -> None:
        msg_type = (msg.get("type") or "").strip().upper()

        # Phase 1: Authentication
        if not conn.authenticated:
            if msg_type == "AUTH_RESPONSE":
                self._handle_auth_response(conn, msg)
            else:
                log.warning("[call_signaling] Unauthenticated packet '%s' from %s", msg_type, conn.client_ip)
                conn.send_json({"type": "AUTH_FAILED", "reason": "unauthenticated"})
            return

        sender = conn.address
        if not sender:
            return

        # Phase 2: Call Signaling Messages
        if msg_type == "CALL_OFFER":
            self._handle_call_offer(conn, sender, msg)
        elif msg_type == "CALL_RINGING":
            self._handle_call_ringing(sender, msg)
        elif msg_type == "CALL_ANSWER":
            self._handle_call_answer(sender, msg)
        elif msg_type in ("CALL_ICE_CANDIDATE", "ICE_CANDIDATE"):
            self._handle_ice_candidate(sender, msg)
        elif msg_type in ("CALL_HANGUP", "CALL_REJECT"):
            self._handle_call_hangup(sender, msg, reason=msg.get("reason", "user_hangup"))
        elif msg_type == "PING":
            conn.send_json({"type": "PONG"})
        else:
            log.warning("[call_signaling] Unknown message type '%s' from %s", msg_type, sender)

    # ---------------- Handlers ----------------

    def _handle_auth_response(self, conn: WebSocketConnection, msg: dict) -> None:
        addr = (msg.get("address") or "").strip().lower()
        pubkey = (msg.get("pubkey") or "").strip().lower()
        sig = (msg.get("sig") or "").strip().lower()

        if not addr or not pubkey or not sig:
            log.warning("[call_signaling] Auth failed: missing fields from %s", conn.client_ip)
            conn.send_json({"type": "AUTH_FAILED", "reason": "missing_fields"})
            return

        # 1. Verify address matches spend public key
        if not self._verify_address_pubkey(addr, pubkey):
            log.warning("[call_signaling] Auth failed: address %s does not match pubkey %s", addr, pubkey)
            conn.send_json({"type": "AUTH_FAILED", "reason": "address_mismatch"})
            return

        # 2. Verify cryptographic signature over challenge nonce
        payload = b"|".join([b"CALL_AUTH", addr.encode("utf-8"), conn.nonce.encode("utf-8")])
        sig_check = verify_chat_signatures([("auth", pubkey, payload, sig)])
        if not sig_check.get("auth"):
            log.warning("[call_signaling] Auth failed: bad signature from %s (ip=%s)", addr, conn.client_ip)
            conn.send_json({"type": "AUTH_FAILED", "reason": "bad_signature"})
            return

        # 3. Check DEACTIVATE_CHAT status on Node RPC
        is_registered = self._check_node_chat_status(addr)
        if not is_registered:
            log.warning("[call_signaling] Auth failed: address %s has DEACTIVATED chat/calls", addr)
            conn.send_json({
                "type": "AUTH_FAILED",
                "reason": "chat_deactivated",
                "message": "Chat/Call feature is deactivated on your wallet.",
            })
            return

        conn.address = addr
        conn.authenticated = True

        with self._lock:
            # If previous connection exists for this address, close it cleanly
            old_conn = self.connected_clients.get(addr)
            if old_conn and old_conn != conn:
                old_conn.send_json({"type": "SUPERSEDED", "reason": "new_session_connected"})
                old_conn.close()
            self.connected_clients[addr] = conn

        conn.send_json({"type": "AUTH_OK", "address": addr})
        log.debug("[call_signaling] Client authenticated: addr=%s (ip=%s)", addr, conn.client_ip)

    def _handle_call_offer(self, conn: WebSocketConnection, sender: str, msg: dict) -> None:
        target = (msg.get("to") or "").strip().lower()
        call_id = (msg.get("call_id") or "").strip()
        media_type = (msg.get("media_type") or "audio").strip().lower()
        sdp = msg.get("sdp")

        if not target or not call_id or not sdp:
            log.warning("[call_signaling] Invalid CALL_OFFER from %s: missing required fields", sender)
            conn.send_json({"type": "CALL_REJECTED", "call_id": call_id, "reason": "bad_fields"})
            return

        if target == sender:
            log.warning("[call_signaling] Self-call attempt rejected from %s", sender)
            conn.send_json({"type": "CALL_REJECTED", "call_id": call_id, "reason": "cannot_call_self"})
            return

        # Dual-Guard Check: Check if target has DEACTIVATED chat on Node RPC
        if not self._check_node_chat_status(target):
            log.warning("[call_signaling] Call rejected: target %s has DEACTIVATED chat/calls (caller=%s)", target, sender)
            conn.send_json({
                "type": "CALL_REJECTED",
                "call_id": call_id,
                "reason": "recipient_deactivated",
                "message": "Kontak ini menonaktifkan fitur panggilan.",
            })
            return

        with self._lock:
            callee_conn = self.connected_clients.get(target)
            if not callee_conn or callee_conn.closed:
                log.warning("[call_signaling] Call failed: target %s is offline (caller=%s)", target, sender)
                conn.send_json({"type": "CALL_REJECTED", "call_id": call_id, "reason": "recipient_offline"})
                return

            # Check if either party is currently in an active call
            if self._is_party_in_call(sender):
                conn.send_json({"type": "CALL_REJECTED", "call_id": call_id, "reason": "already_in_call"})
                return

            if self._is_party_in_call(target):
                log.debug("[call_signaling] Call busy: target %s is in another call", target)
                conn.send_json({"type": "CALL_BUSY", "call_id": call_id, "reason": "user_busy"})
                return

            session = CallSession(call_id, sender, target, media_type)
            self.active_calls[call_id] = session

        callee_conn.send_json({
            "type": "CALL_INCOMING",
            "call_id": call_id,
            "from": sender,
            "media_type": media_type,
            "sdp": sdp,
            "ts": int(time.time()),
        })
        sdp_content = sdp.get("sdp", "") if type(sdp) is dict else str(sdp or "")
        has_audio = ("m=audio " in sdp_content and "m=audio 0" not in sdp_content)
        has_video = ("m=video " in sdp_content and "m=video 0" not in sdp_content)
        log.debug(
            "[call_signaling] Call offer forwarded: call_id=%s from=%s to=%s (type=%s, audio_in_sdp=%s, video_in_sdp=%s)",
            call_id, sender, target, media_type, has_audio, has_video
        )

    def _handle_call_ringing(self, sender: str, msg: dict) -> None:
        call_id = (msg.get("call_id") or "").strip()
        with self._lock:
            session = self.active_calls.get(call_id)
            if not session or session.callee != sender:
                return
            session.state = "ringing"
            caller_conn = self.connected_clients.get(session.caller)

        if caller_conn and not caller_conn.closed:
            caller_conn.send_json({"type": "CALL_RINGING", "call_id": call_id})

    def _handle_call_answer(self, sender: str, msg: dict) -> None:
        call_id = (msg.get("call_id") or "").strip()
        sdp = msg.get("sdp")

        with self._lock:
            session = self.active_calls.get(call_id)
            if not session or session.callee != sender:
                log.warning("[call_signaling] CALL_ANSWER for invalid session: %s from %s", call_id, sender)
                return
            session.state = "connected"
            session.started_at = time.time()
            caller_conn = self.connected_clients.get(session.caller)

        if caller_conn and not caller_conn.closed:
            caller_conn.send_json({
                "type": "CALL_ANSWER",
                "call_id": call_id,
                "sdp": sdp,
            })
            sdp_content = sdp.get("sdp", "") if type(sdp) is dict else str(sdp or "")
            has_audio = ("m=audio " in sdp_content and "m=audio 0" not in sdp_content)
            has_video = ("m=video " in sdp_content and "m=video 0" not in sdp_content)
            log.debug(
                "[call_signaling] Call answered and connected: call_id=%s (caller=%s, callee=%s, audio_in_sdp=%s, video_in_sdp=%s)",
                call_id, session.caller, sender, has_audio, has_video
            )

    def _handle_ice_candidate(self, sender: str, msg: dict) -> None:
        call_id = (msg.get("call_id") or "").strip()
        candidate = msg.get("candidate")
        if not call_id or not candidate:
            log.warning("[call_signaling] Ignored malformed/empty ICE candidate from %s (call_id=%s)", sender, call_id)
            return

        target_conn = None
        peer_addr = None
        with self._lock:
            session = self.active_calls.get(call_id)
            if not session:
                log.warning("[call_signaling] Dropped ICE candidate for inactive call_id=%s from %s", call_id, sender)
                return
            peer_addr = session.callee if session.caller == sender else session.caller
            target_conn = self.connected_clients.get(peer_addr)

        if not target_conn or target_conn.closed:
            log.warning("[call_signaling] Cannot forward ICE candidate: peer %s offline (call_id=%s)", peer_addr, call_id)
            return

        out_msg: Dict[str, Any] = {
            "type": "CALL_ICE_CANDIDATE",
            "call_id": call_id,
            "candidate": candidate,
        }
        # Forward sdpMid and sdpMLineIndex whether they are top-level in msg or inside candidate dict
        sdp_mid = msg.get("sdpMid")
        sdp_mline_index = msg.get("sdpMLineIndex")
        if type(candidate) is dict:
            if sdp_mid is None:
                sdp_mid = candidate.get("sdpMid")
            if sdp_mline_index is None:
                sdp_mline_index = candidate.get("sdpMLineIndex")

        if sdp_mid is not None:
            out_msg["sdpMid"] = sdp_mid
        if sdp_mline_index is not None:
            out_msg["sdpMLineIndex"] = sdp_mline_index

        target_conn.send_json(out_msg)

        if type(candidate) is str:
            cand_str = candidate
        elif type(candidate) is dict:
            cand_str = str(candidate.get("candidate", ""))
        else:
            cand_str = str(candidate or "")

        cand_type = "unknown"
        if " typ " in cand_str:
            cand_type = cand_str.split(" typ ")[1].split()[0]
        log.debug(
            "[call_signaling] ICE candidate forwarded: call_id=%s from=%s to=%s (type=%s, mid=%s, mline=%s)",
            call_id, sender, peer_addr, cand_type, sdp_mid, sdp_mline_index
        )

    def _handle_call_hangup(self, sender: str, msg: dict, reason: str) -> None:
        call_id = (msg.get("call_id") or "").strip()
        session = None
        peer_conn = None
        duration = 0.0

        with self._lock:
            session = self.active_calls.pop(call_id, None)
            if session:
                peer_addr = session.callee if session.caller == sender else session.caller
                peer_conn = self.connected_clients.get(peer_addr)
                if session.started_at > 0:
                    duration = time.time() - session.started_at

        if peer_conn and not peer_conn.closed:
            peer_conn.send_json({
                "type": "CALL_HANGUP",
                "call_id": call_id,
                "reason": reason,
                "duration_s": round(duration, 1),
            })

        if session:
            log.debug("[call_signaling] Call terminated: call_id=%s reason=%s duration=%.1fs", call_id, reason, duration)

    # ---------------- Helpers & Watchdog ----------------

    def _cleanup_client(self, conn: WebSocketConnection) -> None:
        addr = conn.address
        with self._lock:
            if addr and self.connected_clients.get(addr) == conn:
                self.connected_clients.pop(addr, None)
            # Find and terminate any calls involving this client
            to_remove = [
                cid for cid, sess in self.active_calls.items()
                if sess.caller == addr or sess.callee == addr
            ]
            terminated_calls = [self.active_calls.pop(cid) for cid in to_remove]

        for sess in terminated_calls:
            other = sess.callee if sess.caller == addr else sess.caller
            with self._lock:
                other_conn = self.connected_clients.get(other)
            if other_conn and not other_conn.closed:
                other_conn.send_json({
                    "type": "CALL_HANGUP",
                    "call_id": sess.call_id,
                    "reason": "peer_disconnected",
                })
            log.debug("[call_signaling] Terminated call %s due to peer disconnect (%s)", sess.call_id, addr)

        if addr:
            log.debug("[call_signaling] Client session cleaned up: addr=%s (ip=%s)", addr, conn.client_ip)
        conn.close()

    def _timeout_watchdog_loop(self) -> None:
        """Periodically checks and auto-cancels unresponded calls exceeding timeout."""
        while self._running:
            time.sleep(5.0)
            now = time.time()
            with self._lock:
                timed_out_ids = [
                    cid for cid, sess in self.active_calls.items()
                    if sess.state in ("offering", "ringing") and (now - sess.created_at) > CALL_OFFER_TIMEOUT_S
                ]
                timed_out = [self.active_calls.pop(cid) for cid in timed_out_ids]

            for sess in timed_out:
                log.warning("[call_signaling] Call timeout: call_id=%s not answered after %ds", sess.call_id, int(CALL_OFFER_TIMEOUT_S))
                with self._lock:
                    caller_conn = self.connected_clients.get(sess.caller)
                    callee_conn = self.connected_clients.get(sess.callee)

                if caller_conn and not caller_conn.closed:
                    caller_conn.send_json({"type": "CALL_TIMEOUT", "call_id": sess.call_id, "reason": "timeout"})
                if callee_conn and not callee_conn.closed:
                    callee_conn.send_json({"type": "CALL_TIMEOUT", "call_id": sess.call_id, "reason": "timeout"})

    def _is_party_in_call(self, addr: str) -> bool:
        for sess in self.active_calls.values():
            if sess.caller == addr or sess.callee == addr:
                return True
        return False

    def _check_node_chat_status(self, addr: str) -> bool:
        """Queries Node RPC CHAT_CHECK_PREKEYS to enforce sovereign DEACTIVATE_CHAT status."""
        try:
            client = get_client(self.node_host, self.node_port)
            resp = rpc_send(client, {"type": "CHAT_CHECK_PREKEYS", "address": addr})
            if type(resp) is dict and resp.get("registered") is True:
                return True
            return False
        except Exception as exc:
            log.warning("[call_signaling] Failed to verify chat status for %s from node: %s", addr, exc)
            # Default to False for privacy security
            return False

    def _verify_address_pubkey(self, address: str, pubkey_hex: str) -> bool:
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
