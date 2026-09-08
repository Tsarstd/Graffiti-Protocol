# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: libsecp256k1; Signal-X3DH; Signal-DoubleRatchet; RFC7748-X25519; RFC5869-HKDF; NIST-800-38D-AES-GCM

"""
Triple X3DH handshake and Double Ratchet session management.

This module have 11 categories helper functions for:
1. Initialization & Configuration
2. Key Management (Caching & Password)
3. Session Management (Load/Save/Delete)
4. Key Management (Unlocking & Key Retrieval)
5. Pubkey Directory
6. Session Bootstrapping (X3DH)
7. Registration & Publishing
8. Message Sending
9. Message Polling
10. Chat DH Cache
11. Utility Methods

All cryptographic primitives follow the Signal protocol specifications.
"""

import os
import time
import secrets
import hashlib
from typing import Callable, Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec, x25519

# ---------------- Local Project (With Node) ----------------
from tsarchain.utils import config as CFG

# ---------------- Local Project (Wallet Only) ----------------
from ..data_security import Wallet
from ..chat import chat_common as COM
from tsarchain.utils.benchmarks import benchmark
from ..chat.double_ratchet import RatchetSession

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.security.chat.triple_xdh")


class ChatManager:
    # ----------------------------------------------------------------------
    # Initialization & Configuration
    # ----------------------------------------------------------------------
    def __init__(self,
        rpc_send: Callable[[Dict[str, Any], Callable[[Optional[Dict[str, Any]]], None]], None],
        password_prompt_cb: Callable[[str], Optional[str]],
        key_ttl_sec: Optional[int] = None,):
        
        self.rpc_send = rpc_send
        self.password_prompt_cb = password_prompt_cb
        self.key_ttl_sec = int(key_ttl_sec if key_ttl_sec is not None else CFG.CHAT_KEY_TTL_SEC)

        # caches (exposed to the GUI when needed)
        self.priv_cache: Dict[str, tuple[str, float]] = {}
        self.pub_cache: Dict[str, str] = {}
        self.read_sent: set[int] = set()
        self._chat_dh_cache: Dict[str, tuple[str, str, float]] = {}
        self._pwd_cache: Dict[str, tuple[str, float]] = {}
        self._last_prekey_publish: Dict[str, float] = {}
        self._last_inventory_check: Dict[str, float] = {}
        self._prekey_bundle_cache: Dict[str, tuple[Dict[str, str], float]] = {}
        self._prekey_check_interval = max(float(CFG.CHAT_PUBLISH_MIN_INTERVAL_S or 0), 5.0)

        self._sessions: Dict[tuple[str, str], "RatchetSession"] = {}
        self._pending_used_opk: Dict[tuple[str, str], str] = {}
        self._registered_addrs: set[str] = set()
        self.on_partner_key_changed: Optional[Callable[[str, str, str], None]] = None
        self.on_partner_presence: Optional[Callable[[str, Optional[int]], None]] = None
        self.presence_ts: Dict[str, int] = {}

    # ----------------------------------------------------------------------
    # Key Management (Caching & Password)
    # ----------------------------------------------------------------------
    def _now(self) -> float:
        return time.time()

    def _pwd_cache_put(self, addr: str, pwd: str, ttl_sec: Optional[int] = None) -> None:
        ttl = ttl_sec if ttl_sec is not None else CFG.CHAT_PWD_CACHE_TTL_SEC
        self._pwd_cache[COM.canon(addr)] = (pwd, self._now() + int(ttl))

    def _pwd_cache_get(self, addr: str) -> Optional[str]:
        rec = self._pwd_cache.get(COM.canon(addr))
        return rec[0] if rec and self._now() < rec[1] else None

    def clear_pwd_cache(self, addr: Optional[str] = None) -> None:
        if addr:
            self._pwd_cache.pop(COM.canon(addr), None)
            self.priv_cache.pop(COM.canon(addr), None)
        else:
            self._pwd_cache.clear()
            self.priv_cache.clear()

    def _pwd_provider_for(self, addr: str):
        a = COM.canon(addr)
        def _provider(_prompt: str = "") -> Optional[str]:
            pwd = self._pwd_cache_get(a)
            if pwd:
                return pwd
            pwd = self.password_prompt_cb(a)
            if pwd: self._pwd_cache_put(a, pwd)
            return pwd
        return _provider

    def _ensure_prekey_inventory(self, addr: str, force: bool = False) -> None:
        now = self._now()
        if not force:
            last = self._last_inventory_check.get(addr)
            if last and now - last < self._prekey_check_interval:
                return
        self._last_inventory_check[addr] = now

        provider = self._pwd_provider_for(addr)
        inv = COM.get_prekey_inventory(addr, provider)
        rotated = False
        rotate_after = CFG.CHAT_SPK_ROTATE_INTERVAL_S
        created = int(inv.get("created") or 0)
        if rotate_after and created and now - created >= rotate_after:
            COM.rotate_signed_prekey(addr, provider)
            COM.add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
            rotated = True
            self._prekey_bundle_cache.pop(addr, None)
            inv = COM.get_prekey_inventory(addr, provider)
        if int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD:
            COM.add_one_time_prekeys(addr, CFG.CHAT_OPK_REFILL_COUNT, provider)
            self._prekey_bundle_cache.pop(addr, None)
        needs_publish = rotated or int(inv.get("opk_queue") or 0) < CFG.CHAT_OPK_MIN_THRESHOLD
        if needs_publish and self._can_publish_prekeys(addr):
            self.publish_prekeys(addr, on_done=lambda _resp: None, force_refresh_bundle=True)

    def _can_publish_prekeys(self, addr: str) -> bool:
        interval = float(CFG.CHAT_PUBLISH_MIN_INTERVAL_S or 0)
        if interval <= 0:
            return True
        last = self._last_prekey_publish.get(addr)
        if last is None:
            return True
        if self._now() - last >= interval:
            return True
        return False

    # ----------------------------------------------------------------------
    # Session Management (Load/Save/Delete)
    # ----------------------------------------------------------------------
    def _session_key(self, me: str, peer: str) -> Tuple[str, str]:
        return (COM.canon(me), COM.canon(peer))

    def _load_session_from_disk(self, me: str, peer: str) -> Optional["RatchetSession"]:
        provider = self._pwd_provider_for(me)
        data = COM.load_chat_session(me, peer, provider)
        if not data:
            return None
        return RatchetSession.from_dict(data)

    def _persist_session(self, me: str, peer: str, sess: "RatchetSession") -> None:
        provider = self._pwd_provider_for(me)
        COM.store_chat_session(me, peer, sess.to_dict(), provider)

    def _delete_session(self, me: str, peer: str) -> None:
        COM.delete_chat_session(me, peer)

    def _get_session(self, me: str, peer: str) -> Optional["RatchetSession"]:
        key = self._session_key(me, peer)
        sess = self._sessions.get(key)
        if sess is not None:
            return sess
        sess = self._load_session_from_disk(me, peer)
        if sess is not None:
            self._sessions[key] = sess
        return sess

    # ----------------------------------------------------------------------
    # Key Management (Unlocking & Key Retrieval)
    # ----------------------------------------------------------------------
    def try_unlock(self, address: str) -> tuple[Optional[str], Optional[str]]:
        addr = COM.canon(address)
        pwd = self.password_prompt_cb(addr)
        if pwd:
            self._pwd_cache_put(addr, pwd)
        if not pwd:
            return None, "cancelled"
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
            self._pwd_cache_put(addr, pwd)
            return priv_hex, None
        except Exception as e:
            return None, str(e)

    def get_priv_for_chat(self, address: str) -> Optional[str]:
        addr = COM.canon(address)
        cached = self.priv_cache.get(addr)
        if cached and self._now() < cached[1]:
            return cached[0]

        # try short-lived pwd cache first (avoid extra prompt)
        pwd = self._pwd_cache_get(addr)
        if not pwd:
            pwd = self._pwd_cache_get(addr) or self.password_prompt_cb(addr)

        if not pwd:
            return None
        try:
            w = Wallet.unlock(pwd, addr)
            priv_hex = w["private_key"]
            self.priv_cache[addr] = (priv_hex, self._now() + self.key_ttl_sec)
            self._pwd_cache_put(addr, pwd)
            return priv_hex
        except Exception:
            return None

    # ----------------------------------------------------------------------
    # Pubkey Directory
    # ----------------------------------------------------------------------
    def lookup_pub(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        a = COM.canon(addr)
        if a in self.pub_cache:
            cb(self.pub_cache[a])
            return
        
        self.rpc_send({"type": "CHAT_LOOKUP_PUB", "address": a}, lambda resp: self._handle_lookup_response(a, resp, cb))

    def _handle_lookup_response(self, addr: str, resp: Optional[Dict[str, Any]], cb: Callable[[Optional[str]], None]) -> None:
        pub = None
        if resp and resp.get("type") in ("CHAT_PUBKEY", "CHAT_PUB"):
            pub = resp.get("pubkey") or resp.get("chat_pub")
            self._update_presence_from_lookup(addr, resp)
            
        if pub:
            old = self.pub_cache.get(addr)
            self.pub_cache[addr] = pub
            if old and old != pub and callable(self.on_partner_key_changed):
                self.on_partner_key_changed(addr, old, pub)
        cb(pub)

    def _update_presence_from_lookup(self, addr: str, resp: Dict[str, Any]) -> None:
        ts_val = resp.get("last_seen")
        if type(ts_val) in (int, float):
            last_seen = int(ts_val)
            self.presence_ts[addr] = last_seen
            if callable(self.on_partner_presence):
                try:
                    self.on_partner_presence(addr, last_seen)
                except Exception:
                    log.exception("Unhandled exception")

    def expected_pub_or_lookup(self, addr: str) -> Optional[str]:
        a = COM.canon(addr)
        pub = self.pub_cache.get(a)
        if pub is None:
            self.lookup_pub(a, lambda _p: None)
        return pub

    # ----------------------------------------------------------------------
    # Session Bootstrapping (X3DH)
    # ----------------------------------------------------------------------
    def ensure_session(self, me_addr: str, peer_addr: str, cb: Callable[[Optional[str]],None]) -> None:
        me = COM.canon(me_addr)
        peer = COM.canon(peer_addr)
        if self._get_session(me, peer):
            cb(None)
            return

        self._ensure_prekey_inventory(me)
        my_sk_hex, my_pk_hex = self._get_chat_dh(me)   # identity (IK)

        def _on_bundle(resp: Optional[Dict[str, Any]]):
            self._process_prekey_bundle(resp, me, peer, my_sk_hex, my_pk_hex, cb)

        self.rpc_send({"type":"CHAT_GET_PREKEY","address": peer}, _on_bundle)

    def _process_prekey_bundle(self, resp: Optional[Dict[str, Any]], me: str, peer: str, my_sk_hex: str, my_pk_hex: str, cb: Callable[[Optional[str]],None]) -> None:
        if not resp or resp.get("type") != "CHAT_PREKEY_BUNDLE":
            cb("no_bundle")
            return

        b = resp.get("bundle") or {}
        err = self._validate_prekey_bundle(peer, b)
        if err:
            cb(err)
            return

        self._derive_x3dh_session(me, peer, b, my_sk_hex, my_pk_hex)
        cb(None)

    def _validate_prekey_bundle(self, peer: str, b: Dict[str, Any]) -> Optional[str]:
        spend_pub = (b.get("spend_pub") or "").lower()
        sig_hex = (b.get("sig") or "").lower()
        spk = (b.get("spk") or "").lower()

        if not spend_pub:
            log.warning("[ensure_session] bundle missing spend_pub for %s", peer)
            return "bundle_missing_spend_pub"

        if len(spend_pub) != 66 or any(c not in "0123456789abcdef" for c in spend_pub):
            log.warning("[ensure_session] spend_pub invalid format for %s", peer)
            return "bundle_invalid_spend_pub"

        if not sig_hex:
            log.warning("[ensure_session] bundle missing SPK signature for %s", peer)
            return "bundle_missing_spk_sig"

        if peer and peer.lower().startswith(CFG.ADDRESS_PREFIX):
            try:
                from tsarchain.utils.helpers import hash160
                from bech32 import bech32_encode, convertbits
                pkh = hash160(bytes.fromhex(spend_pub))
                data = [0] + convertbits(list(pkh), 8, 5, True)
                derived_addr = bech32_encode(CFG.ADDRESS_PREFIX, data)
                if derived_addr and derived_addr.lower() != peer.lower():
                    log.warning("[ensure_session] spend_pub does not match peer address %s (got %s)", peer, derived_addr)
                    return "bundle_spend_pub_mismatch"
            except Exception as e:
                log.warning("[ensure_session] failed to verify peer address binding for %s: %s", peer, e)
                return "bundle_address_binding_failed"

        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(spend_pub))
            payload = CFG.CHAT_SPK + bytes.fromhex(spk) + b"|" + bytes.fromhex(spend_pub)
            vk.verify(bytes.fromhex(sig_hex), payload, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            log.warning("[ensure_session] SPK signature verify failed for %s: %s", peer, e)
            return "bundle_spk_verify_failed"
        return None

    def _derive_x3dh_session(self, me: str, peer: str, b: Dict[str, Any], my_sk_hex: str, my_pk_hex: str) -> None:
        rik = (b.get("ik") or "").lower()
        spk = (b.get("spk") or "").lower()
        opk = (b.get("opk") or "").lower()

        eph = x25519.X25519PrivateKey.generate()
        iks = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_sk_hex))
        ikr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(rik))
        spkr= x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(spk))
        dh1 = iks.exchange(spkr)
        dh2 = eph.exchange(ikr)
        dh3 = eph.exchange(spkr)
        secret = dh1 + dh2 + dh3

        if opk:
            opkr = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(opk))
            secret += eph.exchange(opkr)

        rk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:x3dh:v1").derive(secret)
        sess = RatchetSession.init_as_initiator(
            root_key=rk,
            my_identity=my_pk_hex,
            their_identity=rik,
            my_ratchet_priv=eph,
            their_ratchet_pub_hex=spk,
            my_static_hex=my_pk_hex,
        )

        key = self._session_key(me, peer)
        self._sessions[key] = sess
        self._persist_session(me, peer, sess)

        if opk:
            self._pending_used_opk[key] = opk

    # ----------------------------------------------------------------------
    # Registration & Publishing
    # ----------------------------------------------------------------------
    @benchmark(label="register", threshold_ms=5.0)
    def register(self, address: str, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        addr = COM.canon(address)
        priv_hex = self.get_priv_for_chat(addr)
        if not priv_hex:
            on_done({"error": "unlock_failed"})
            return

        spend_pub = COM.pub_hex_from_priv(COM.ec_priv_from_hex(priv_hex))
        _, chat_pk_hex = self._get_chat_dh(addr)
        ts_now = int(time.time())
        
        payload = self._build_register_payload(addr, priv_hex, spend_pub, chat_pk_hex, ts_now)
        
        def _on(resp: Optional[Dict[str, Any]]):
            self._handle_register_response(addr, resp, chat_pk_hex, on_done)
            
        self.rpc_send(payload, _on)

    def _build_register_payload(self, addr: str, priv_hex: str, spend_pub: str, chat_pk_hex: str, ts_now: int) -> Dict[str, Any]:
        reg_bytes = b"|".join([b"CHAT_REG", addr.encode(), bytes.fromhex(spend_pub), bytes.fromhex(chat_pk_hex), str(ts_now).encode()])
        reg_sig = COM.sign(priv_hex, reg_bytes).lower()

        pres_bytes = b"|".join([b"CHAT_PRESENCE", addr.encode(), bytes.fromhex(chat_pk_hex), bytes.fromhex(spend_pub), str(ts_now).encode()])
        presence_sig = COM.sign(priv_hex, pres_bytes).lower()

        bundle = {}
        COM.ensure_signed_prekey(addr, self._pwd_provider_for(addr))
        bundle = COM.get_prekey_bundle_local(addr, self._pwd_provider_for(addr)) or {}
        spk_hex = (bundle.get("spk") or "").lower()
        if spk_hex:
            payload_spk = CFG.CHAT_SPK + bytes.fromhex(spk_hex) + b"|" + bytes.fromhex(spend_pub)
            bundle["sig"] = COM.sign(priv_hex, payload_spk)

        payload = {
            "type": "CHAT_REGISTER", "address": addr, "spend_pub": spend_pub,
            "chat_pub": chat_pk_hex, "ts": ts_now, "reg_sig": reg_sig, "presence_sig": presence_sig,
        }
        if bundle:
            if bundle.get("spk") and bundle.get("sig"):
                payload["spk"] = (bundle.get("spk") or "").lower()
                payload["sig"] = (bundle.get("sig") or "").lower()
            if bundle.get("opk"):
                payload["opk"] = (bundle.get("opk") or "").lower()
        return payload

    def _handle_register_response(self, addr: str, resp: Optional[Dict[str, Any]], chat_pk_hex: str, on_done: Callable[[Optional[Dict[str, Any]]], None]) -> None:
        if not resp:
            on_done(resp)
            return

        if resp.get("error"):
            err = str(resp.get("error"))
            rtype = resp.get("type")
            if err == "bad reg_sig":
                log.warning("[register] reg_sig refuse for %s ", addr)
            elif err == "rate_limited":
                log.warning("[register] rate limited for %s (type=%s)", addr, rtype)
            else:
                log.warning("[register] failed for %s error=%s type=%s", addr, err, rtype)
            on_done(resp)
            return

        if resp.get("type") == "CHAT_REGISTERED":
            self.pub_cache[addr] = chat_pk_hex
            self._registered_addrs.add(addr)
            self.publish_prekeys(addr, on_done=lambda _r: None)
        on_done(resp)

    def _ensure_registered(self, addr: str, cb: Callable[[Optional[str]], None]) -> None:
        regset = self._registered_addrs
        if addr in regset:
            cb(None); return

        def _on(resp):
            if resp and resp.get("type") == "CHAT_REGISTERED":
                self._registered_addrs.add(addr)
                log.info("[register] registered ok untuk %s", addr)
                cb(None)
            else:
                if resp and resp.get("error"):
                    log.warning("[register] auto-register gagal untuk %s error=%s type=%s", addr, resp.get("error"), resp.get("type"))
                cb("register_failed")

        log.debug("[send_message] auto-register for %s", addr)
        self.register(addr, _on)

    @benchmark(label="publish_prekeys", threshold_ms=5.0)
    def publish_prekeys(self, address: str, on_done=None, force_refresh_bundle: bool = False) -> None:
        addr = COM.canon(address)
        if not self._can_publish_prekeys(addr):
            (on_done or (lambda _r: None))({"skipped": "cooldown"})
            return
        now = self._now()
        bundle: Optional[Dict[str, str]] = None

        if not force_refresh_bundle:
            cached = self._prekey_bundle_cache.get(addr)
            if cached and now - cached[1] < self._prekey_check_interval:
                bundle = cached[0]

        if bundle is None:
            COM.ensure_signed_prekey(addr, self._pwd_provider_for(addr))
            bundle = COM.get_prekey_bundle_local(addr, self._pwd_provider_for(addr))  # {"ik","spk","sig","opk"}
            self._prekey_bundle_cache[addr] = (bundle, now)

        priv_hex_for_sign = self.get_priv_for_chat(addr)
        if priv_hex_for_sign and bundle.get("spk"):
            spend_pub = COM.pub_hex_from_priv(COM.ec_priv_from_hex(priv_hex_for_sign))
            payload_spk = CFG.CHAT_SPK + bytes.fromhex(bundle["spk"]) + b"|" + bytes.fromhex(spend_pub)
            bundle["sig"] = COM.sign(priv_hex_for_sign, payload_spk)

        payload = {
            "type": "CHAT_PUBLISH_PREKEYS",
            "address": addr,
            "ik":  (bundle.get("ik")  or "").lower(),
            "spk": (bundle.get("spk") or "").lower(),
            "sig": (bundle.get("sig") or "").lower(),
        }
        if bundle.get("opk"):
            payload["opk"] = (bundle["opk"] or "").lower()
        self._last_prekey_publish[addr] = now

        def _after(resp):
            try:
                if not resp or resp.get("error"):
                    self._last_prekey_publish.pop(addr, None)
                    self._prekey_bundle_cache.pop(addr, None)
            finally:
                (on_done or (lambda _r: None))(resp)

        self.rpc_send(payload, _after)

    # ----------------------------------------------------------------------
    # Message Sending
    # ----------------------------------------------------------------------
    def send_message(self, from_addr: str, to_addr: str, text: str,
                    on_queued, on_result) -> None:
        frm = COM.canon(from_addr)
        to  = COM.canon(to_addr)

        priv_hex = self.get_priv_for_chat(frm)
        if not priv_hex:
            on_result({"status": "unlock_failed"})
            return

        self._ensure_prekey_inventory(frm)

        def _do_send_after_session(err: Optional[str]):
            if err:
                on_result({"status": "sess_error", "reason": err})
                return
            sess = self._get_session(frm, to)
            if not sess:
                on_result({"status": "sess_missing"})
                return
            mid = secrets.randbelow(2**31)
            ts = int(time.time())
            pt = COM.pack(text)
            try:
                msg = sess.encrypt(pt, frm, to, mid, ts)
            except Exception as exc:
                log.exception("[send_message] encrypt failed for %s -> %s", frm, to)
                on_result({"status": "encrypt_failed", "reason": str(exc)})
                return

            header = msg.get("ratchet", {})
            eph_hex = (header.get("eph_pub") or "").lower()
            static_hex = (header.get("static_pub") or "").lower()
            pn_val = int(header.get("pn", 0))
            n_val = int(header.get("n", 0))

            key = self._session_key(frm, to)
            used = self._pending_used_opk.pop(key, None)
            used_opk_hex = (used or "").lower()

            try:
                sig_parts = [
                    b"CHAT_SEND",
                    frm.encode(), to.encode(),
                    str(mid).encode(), str(ts).encode(),
                    bytes.fromhex(eph_hex), bytes.fromhex(static_hex),
                    str(pn_val).encode(), str(n_val).encode(),
                    bytes.fromhex(msg["enc"]["nonce"]),
                    bytes.fromhex(msg["enc"]["ct"]),
                    used_opk_hex.encode(),
                ]
            except Exception:
                log.exception("Unhandled exception")
                on_result({"status": "ratchet_header_invalid"})
                return

            chat_sig = COM.sign(priv_hex, b"|".join(sig_parts)).lower()
            payload = {
                "type": "CHAT_SEND",
                "from": frm,
                "to": to,
                "msg_id": mid,
                "ts": ts,
                "from_static": static_hex,
                "from_pub": eph_hex,
                "ratchet_pn": pn_val,
                "ratchet_n": n_val,
                "enc": msg["enc"],
                "chat_sig": chat_sig,
            }

            if used:
                payload["used_opk"] = used

            self._persist_session(frm, to, sess)
            on_queued(mid, ts)

            def _wrapped(resp):
                r = dict(resp or {})
                r.setdefault("msg_id", mid)
                r.setdefault("to", to)
                r.setdefault("from", frm)
                on_result(r)

            self.rpc_send(payload, _wrapped)

        def _after_registered(err: Optional[str]):
            if err:
                on_result({"status": "register_failed", "reason": err})
                return
            sess = self._get_session(frm, to)
            if sess is None:
                self.ensure_session(frm, to, _do_send_after_session)
            else:
                _do_send_after_session(None)

        self._ensure_registered(frm, _after_registered)

    def send_read_receipt(self, sender: str, reader: str, msg_id: int, on_result) -> None:
        priv_hex = self.get_priv_for_chat(reader)
        if not priv_hex:
            on_result({"error": "unlock_failed"})
            return
        ts = int(time.time())
        rr = b"|".join([b"CHAT_READ", sender.encode(), reader.encode(), str(msg_id).encode(), str(ts).encode()])
        read_sig = COM.sign(priv_hex, rr).lower()
        self.rpc_send({"type": "CHAT_READ", "sender": sender, "reader": reader, "msg_id": int(msg_id), "ts": ts, "read_sig": read_sig}, on_result)

    # ----------------------------------------------------------------------
    # Message Polling
    # ----------------------------------------------------------------------
    @benchmark(label="poll", threshold_ms=5.0)
    def poll(self, address: str, n: int, on_items, on_done=None) -> None:
        me = COM.canon(address)
        priv_hex = self.get_priv_for_chat(me)
        if not priv_hex:
            if on_done: on_done({"error": "unlock_failed"})
            return

        self._ensure_prekey_inventory(me)
        ts_now = int(time.time())
        pull_sig = COM.sign(priv_hex, b"|".join([b"CHAT_PULL", me.encode(), str(ts_now).encode()]))

        def _on(resp):
            self._handle_poll_response(resp, me, n, ts_now, pull_sig, _on, on_items, on_done)

        self.rpc_send({"type": "CHAT_PULL", "address": me, "n": int(n), "ts": ts_now, "pull_sig": pull_sig}, _on)

    def _handle_poll_response(self, resp, me, n, ts_now, pull_sig, _on, on_items, on_done) -> None:
        if resp and resp.get("type") == "CHAT_NONE" and str(resp.get("error")) == "not_registered":
            log.info("[poll] %s belum terdaftar, mencoba auto-register", me)
            return self._ensure_registered(me, lambda err: (
                self.poll(me, n, on_items, on_done) if not err else (on_done and on_done({"error": "register_failed"}))
            ))

        try:
            if not resp or resp.get("type") not in ("CHAT_ITEMS", "CHAT_NONE"):
                on_items([])
                return
            items = resp.get("items") or []
            out = self._process_chat_items(me, items)
            on_items(out)
        finally:
            if on_done: on_done(resp)

    def _process_chat_items(self, me: str, items: list) -> list:
        out = []
        my_sk_hex, _ = self._get_chat_dh(me)
        for it in items:
            if it.get("type") != "CHAT_ITEM":
                if it.get("type") == "CHAT_RCPT":
                    out.append({
                        "type": "rcpt", "rcpt": it.get("rcpt"), "msg_id": it.get("msg_id"),
                        "from": it.get("from"), "to": it.get("to"), "ts": it.get("ts"),
                    })
                continue

            frm = (it.get("from") or "").lower()
            mid = int(it.get("msg_id") or 0)
            ts = int(it.get("ts") or 0)
            enc = it.get("enc") or {}
            
            header = {
                "eph_pub": (it.get("from_pub") or "").lower(),
                "static_pub": (it.get("from_static") or "").lower(),
                "pn": int(it.get("ratchet_pn") or 0),
                "n": int(it.get("ratchet_n") or 0),
            }

            sess = self._get_session(me, frm)
            if not sess:
                sess = self._init_responder_session(me, frm, my_sk_hex, header, (it.get("used_opk") or "").lower())
                if not sess:
                    continue

            msg_text = self._decrypt_chat_message(me, frm, sess, enc, mid, ts, header)
            # Self-healing: if decryption fails and message appears to be a new handshake (has used_opk or pn=0, n=0)
            if msg_text is None and (it.get("used_opk") or (header.get("pn") == 0 and header.get("n") == 0)):
                log.info("[poll] Attempting responder session recovery for %s -> %s", frm, me)
                sess = self._init_responder_session(me, frm, my_sk_hex, header, (it.get("used_opk") or "").lower())
                if sess:
                    msg_text = self._decrypt_chat_message(me, frm, sess, enc, mid, ts, header)

            if msg_text is not None:
                out.append({"type": "chat", "from": frm, "text": msg_text, "msg_id": mid, "ts": ts, "to": me})
            else:
                log.warning("[poll] decrypt failed for %s mid=%s", frm, mid)

        return out

    def _init_responder_session(self, me: str, frm: str, my_sk_hex: str, header: dict, used_opk: str):
        try:
            provider_me = self._pwd_provider_for(me)
            pkinfo = COM.get_local_prekeys_for_recv(me, provider_me)
            spk_sk = (pkinfo.get("spk_sk") or "")
            if not spk_sk:
                log.warning("[_init_responder_session] missing spk_sk for %s", me)
                return None
            
            from_static = header.get("static_pub", "")
            from_pub = header.get("eph_pub", "")
            if not from_static or not from_pub:
                return None

            exp_static = self.expected_pub_or_lookup(frm)
            if exp_static and exp_static != from_static:
                log.warning("[poll] static pub mismatch for %s expected=%s got=%s", frm, exp_static, from_static)
                if callable(self.on_partner_key_changed):
                    try:
                        self.on_partner_key_changed(frm, exp_static, from_static)
                    except Exception:
                        log.exception("partner key error")
                return None

            ikr = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_sk_hex))
            spks = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(spk_sk))
            iks_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(from_static))
            eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(from_pub))
            dh1 = spks.exchange(iks_pub)
            dh2 = ikr.exchange(eph_pub)
            dh3 = spks.exchange(eph_pub)
            secret = dh1 + dh2 + dh3

            if used_opk:
                opk_sk = COM.consume_opk_priv(me, used_opk, provider_me)
                if opk_sk:
                    opks = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(opk_sk))
                    secret += opks.exchange(eph_pub)

            rk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tsar:x3dh:v1").derive(secret)
            _, my_pk_hex = self._get_chat_dh(me)
            sess = RatchetSession.init_as_responder(
                root_key=rk,
                my_identity=my_pk_hex,
                their_identity=from_static,
                their_first_eph=from_pub,
                my_ratchet_priv=spks,
                my_static_hex=my_pk_hex,
            )
            key = self._session_key(me, frm)
            self._sessions[key] = sess
            self._persist_session(me, frm, sess)
            return sess
        except Exception as e:
            log.warning("[_init_responder_session] failed to initialize responder session for %s: %s", frm, e)
            return None

    def _decrypt_chat_message(self, me: str, frm: str, sess, enc, mid, ts, header):
        pt = sess.decrypt(enc, frm, me, mid, ts, header)
        if pt is not None:
            msg_text = COM.unpack(pt)
            self._persist_session(me, frm, sess)
            return msg_text
        return None

    # ----------------------------------------------------------------------
    # Chat DH Cache
    # ----------------------------------------------------------------------
    def _get_chat_dh(self, address: str) -> tuple[str, str]:
        a = COM.canon(address)
        now = self._now()
        cached = self._chat_dh_cache.get(a)
        if cached and now < cached[2]:
            return cached[0], cached[1]
        sk_hex, pk_hex = COM.load_or_create_chat_dh_key(a, self._pwd_provider_for(a))
        self._chat_dh_cache[a] = (sk_hex, pk_hex, now + self.key_ttl_sec)
        return sk_hex, pk_hex

    # ----------------------------------------------------------------------
    # Utility Methods
    # ----------------------------------------------------------------------
    def sas(self, addr_a: str, addr_b: str) -> str:
        pa = (self.expected_pub_or_lookup(addr_a) or "").lower()
        pb = (self.expected_pub_or_lookup(addr_b) or "").lower()
        keys = sorted([pa, pb])
        data = ("SAS|" + keys[0] + "|" + keys[1]).encode()
        digest = hashlib.sha256(data).digest()
        emojis = ["🐙","🦊","🐼","🐧","🐯","🐸","🦁","🐵","🦄","🐺","🐤","🦉","🐢","🐬","🦒","🐳"]
        return "".join(emojis[digest[i] % len(emojis)] for i in range(6))