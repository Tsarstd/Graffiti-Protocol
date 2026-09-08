# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
import json
import secrets

from bech32 import convertbits, bech32_decode
from .....utils.helpers import hash160

from .....utils import config as CFG
from ...user_rpc import common as CM
from .....utils.benchmarks import benchmark

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.chat")


@benchmark(label="CHAT_REGISTER", threshold_ms=15.0)
def chat_register(self, message, pow_obj, base_identity, addr, *,
                     client_ip, **kwargs):
    try:
        addr_s   = (message.get("address")  or "").strip().lower()
        ok, pow_resp = CM.allow_rpc_with_pow(
            self,
            scope="rpc:chat_reg",
            table=self.rl_ip,
            ip=client_ip,
            identity=addr_s or base_identity,
            key_label="chatreg",
            burst=CFG.CHAT_REG_RL_IP_BURST,
            window_s=CFG.CHAT_REG_RL_WINDOW_S,
            backoff_s=CFG.CHAT_REG_RL_BACKOFF_S,
            pow_obj=pow_obj,
            difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
        )
        if not ok:
            log.warning("[chat_register] Rate limit/PoW failed for ip=%s (addr=%s)", client_ip, addr_s)
            return pow_resp
        addr_key = f"chatreg_addr:{addr_s}" if addr_s else None
        if addr_key:
            ok, pow_resp = CM.allow_rpc_with_pow(
                self,
                scope="rpc:chat_reg_addr",
                table=self.rl_addr,
                ip=client_ip,
                identity=addr_s or base_identity,
                key_label=addr_key,
                burst=CFG.CHAT_REG_RL_ADDR_BURST,
                window_s=CFG.CHAT_REG_RL_ADDR_WINDOW_S,
                backoff_s=CFG.CHAT_REG_RL_ADDR_BACKOFF_S,
                pow_obj=pow_obj,
                difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
            )
            if not ok:
                log.warning("[chat_register] Addr rate limit/PoW failed for %s", addr_s)
                return pow_resp
        chat_pub = ((message.get("chat_pub") or message.get("pubkey") or "").strip().lower())

        presence_sig = (message.get("presence_sig") or "").strip().lower()

        spend_pk = (message.get("spend_pub") or "").strip().lower()
        reg_sig  = (message.get("reg_sig")  or "")
        ts_val   = int(message.get("ts", 0))
        spk_reg  = (message.get("spk") or "").strip().lower()
        sig_reg  = (message.get("sig") or "").strip().lower()
        opk_reg  = (message.get("opk") or "").strip().lower()

        err = _validate_register_fields_and_address(addr_s, chat_pub, spend_pk, reg_sig, ts_val, presence_sig)
        if err:
            log.warning("[chat_register] Validation error for %s from %s: %s", addr_s, client_ip, err)
            return err
        
        pres_bytes = b"|".join([
            b"CHAT_PRESENCE",
            addr_s.encode(),
            bytes.fromhex(chat_pub),
            bytes.fromhex(spend_pk),
            str(ts_val).encode()
        ])
        reg_bytes = b"|".join([
            b"CHAT_REG",
            addr_s.encode(),
            bytes.fromhex(spend_pk),
            bytes.fromhex(chat_pub),
            str(int(ts_val)).encode()
        ])

        sig_check = CM.verify_chat_signatures([
            ("presence", spend_pk, pres_bytes, presence_sig),
            ("register", spend_pk, reg_bytes, reg_sig),
        ])
        if not sig_check.get("presence"):
            log.warning("[chat_register] Bad presence signature for %s from %s", addr_s, client_ip)
            return {"error": "bad_presence_sig"}
        if not sig_check.get("register"):
            log.warning("[chat_register] Bad reg_sig from %s (ip=%s)", addr_s, client_ip)
            return {"error": "bad reg_sig"}

        spk_valid, spk_err = _validate_spk_registration(spend_pk, spk_reg, sig_reg)
        if spk_err:
            log.warning("[chat_register] SPK validation failed for %s: %s", addr_s, spk_err)
            return spk_err

        now = time.time()
        now_int = int(now)
        pid = secrets.token_hex(16)
        with self.chat_lock:
            self.chat_spend_pub[addr_s] = spend_pk
            self.chat_presence_pub[addr_s] = chat_pub
            try:
                self.chat_presence_ts[addr_s] = now_int
            except (AttributeError, TypeError):
                pass
            try:
                rec_seen = self.record_presence_seen
            except AttributeError:
                rec_seen = None
            if callable(rec_seen):
                rec_seen(pid)
            else:
                self.chat_presence_seen.add(pid)
            b = self.get_prekey_bundle(addr_s)
            b["spend_pub"] = spend_pk
            if "ik" not in b: 
                b["ik"] = chat_pub
                b["ts"] = now_int
            b["ts"] = now_int
            if spk_valid:
                b["spk"] = spk_reg
                b["sig"] = sig_reg
                b["spend_pub"] = spend_pk
            if opk_reg and len(opk_reg) == 64:
                lst = b.setdefault("opk_list", [])
                if opk_reg not in lst and len(lst) < 10:
                    lst.append(opk_reg)
            self.put_prekey_bundle(addr_s, b)

        pres = {"pid": pid, "address": addr_s, "pubkey": chat_pub, "spend_pub": spend_pk, "presence_sig": presence_sig, "ts": now_int, "hops": 0}
        self.relay_presence_async(pres, exclude=addr)
        return {"type": "CHAT_REGISTERED", "address": addr_s, "pubkey": chat_pub}
    except Exception as exc:
        log.exception("[chat_register] Unexpected error for %s: %s", message.get("address"), exc)
        return {"error": str(exc)}


@benchmark(label="CHAT_LOOKUP_PUB", threshold_ms=10.0)
def chat_lookup_pub(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    addr_s = (message.get("address") or "").strip().lower()
    if not addr_s:
        return {"error": "missing address"}
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_lookup",
        table=self.rl_ip,
        ip=client_ip,
        identity=addr_s or base_identity,
        key_label="chatlook",
        burst=CFG.CHAT_LOOKUP_RL_IP_BURST,
        window_s=CFG.CHAT_LOOKUP_RL_IP_WINDOW_S,
        backoff_s=CFG.CHAT_LOOKUP_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_lookup_pub] Rate limit/PoW failed for %s", addr_s)
        return pow_resp
    
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_lookup_addr",
        table=self.rl_addr,
        ip=client_ip,
        identity=addr_s or base_identity,
        key_label=f"chatlook:{addr_s}",
        burst=CFG.CHAT_LOOKUP_RL_ADDR_BURST,
        window_s=CFG.CHAT_LOOKUP_RL_ADDR_WINDOW_S,
        backoff_s=CFG.CHAT_LOOKUP_RL_ADDR_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_lookup_pub] Addr rate limit/PoW failed for %s", addr_s)
        return pow_resp
    pubhex = self.chat_presence_pub.get(addr_s)
    last_seen = self.chat_presence_ts.get(addr_s)
    if last_seen is None:
        b = self.get_prekey_bundle(addr_s)
        ts_field = b.get("ts")
        if ts_field is not None:
            last_seen = int(ts_field)
            self.chat_presence_ts[addr_s] = last_seen

    return {"type": "CHAT_PUBKEY", "address": addr_s, "pubkey": pubhex, "found": bool(pubhex), "last_seen": last_seen}


@benchmark(label="CHAT_PRESENCE", threshold_ms=10.0)
def chat_presence(self, message, pow_obj, base_identity, addr, *,
                  client_ip, **kwargs):
    addr_s = (message.get("address") or "").strip().lower()
    pubhex = (message.get("pubkey")  or "").strip().lower()
    spend_pk = (message.get("spend_pub") or "").strip().lower()
    presence_sig = (message.get("presence_sig") or "").strip().lower()
    hops   = int(message.get("hops") or 0)
    ts_val = int(message.get("ts")   or 0)

    err = _validate_presence_signature_and_fields(addr_s, pubhex, spend_pk, presence_sig, ts_val)
    if err:
        log.warning("[chat_presence] Validation failed for %s from %s: %s", addr_s, client_ip, err)
        return err

    if hops >= CFG.PRESENCE_MAX_HOPS:
        log.warning("[chat_presence] Max hops reached for %s from %s", addr_s, addr)
        return {"error": "presence_hops"}

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_presence",
        table=self.rl_ip,
        ip=client_ip,
        identity=addr_s or base_identity,
        key_label="chat_presence",
        burst=CFG.CHAT_RL_IP_BURST,
        window_s=CFG.CHAT_RL_IP_WINDOWS,
        backoff_s=CFG.CHAT_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_presence] IP rate limit/PoW failed for %s from %s", addr_s, client_ip)
        return pow_resp

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_presence_addr",
        table=self.rl_addr,
        ip=client_ip,
        identity=addr_s or base_identity,
        key_label=f"presence:{addr_s}",
        burst=CFG.PRESENCE_RL_ADDR_BURST,
        window_s=CFG.PRESENCE_RL_ADDR_WINDOWS,
        backoff_s=CFG.CHAT_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_presence] Addr rate limit/PoW failed for %s", addr_s)
        return pow_resp

    pid = message.get("pid") or secrets.token_hex(16)
    now_int = int(time.time())
    with self.chat_lock:
        self.chat_presence_pub[addr_s] = pubhex
        self.chat_spend_pub[addr_s] = spend_pk
        self.chat_presence_ts[addr_s] = now_int
        rec_seen = self.record_presence_seen
        if callable(rec_seen):
            rec_seen(pid)
        else:
            self.chat_presence_seen.add(pid)
        b = self.get_prekey_bundle(addr_s)
        if "ik" not in b:
            b["ik"] = pubhex
        b["ts"] = now_int
        self.put_prekey_bundle(addr_s, b)

    message["hops"] = hops + 1
    self.relay_presence_async(message, exclude=addr)
    return {"type": "CHAT_PRESENCE_OK"}


# ====== PREKEY BUNDLE ======


@benchmark(label="CHAT_PUBLISH_PREKEYS", threshold_ms=15.0)
def chat_publish_prekeys(self, message, pow_obj, base_identity, *,
                         client_ip, **kwargs):
    addr_s = (message.get("address") or "").strip().lower()
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_reg",
        table=self.rl_ip,
        ip=client_ip,
        identity=addr_s or base_identity,
        key_label="chatreg",
        burst=CFG.CHAT_REG_RL_IP_BURST,
        window_s=CFG.CHAT_REG_RL_WINDOW_S,
        backoff_s=CFG.CHAT_REG_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_publish_prekeys] Rate limit/PoW failed for %s", addr_s)
        return pow_resp

    ik  = (message.get("ik")  or "").strip().lower()
    spk = (message.get("spk") or "").strip().lower()
    sig = (message.get("sig") or "").strip().lower()
    opk = (message.get("opk") or None)
    if not addr_s or not ik or not spk or not sig:
        return {"error":"missing fields"}
    # validation: addr -> spend_pub exists? and SPK signature is signed by spend key
    get_sp = self.get_spend_pub
    sp = (get_sp(addr_s) or "").strip().lower() if callable(get_sp) else (self.chat_spend_pub.get(addr_s) or "").strip().lower()
    if not sp:
        log.warning("[chat_publish_prekeys] Unknown address %s (spend_pub missing)", addr_s)
        return {"error":"unknown_address"}
    payload = CFG.CHAT_SPK + bytes.fromhex(spk) + b"|" + bytes.fromhex(sp)
    sig_ok = CM.verify_chat_signatures([("spk", sp, payload, sig)])
    if not sig_ok.get("spk"):
        log.warning("[chat_publish_prekeys] Bad SPK signature for %s", addr_s)
        return {"error":"bad_spk_sig"}
    now_int = int(time.time())
    with self.chat_lock:
        self.chat_presence_ts[addr_s] = now_int
        rec = self.get_prekey_bundle(addr_s)
        rec.update({"ik": ik, "spk": spk, "sig": sig, "spend_pub": sp, "ts": now_int})
        if type(opk) is str and len(opk) == 64:
            lst = rec.setdefault("opk_list", [])
            if opk not in lst and len(lst) < 10:
                lst.append(opk)
        self.put_prekey_bundle(addr_s, rec)

    return {"type":"CHAT_PUBLISH_PREKEYS"}


@benchmark(label="CHAT_GET_PREKEY", threshold_ms=10.0)
def chat_get_prekey(self, message, *,
                    client_ip, is_miner_sender, **kwargs):
    addr_s = (message.get("address") or "").strip().lower()
    with self.chat_lock:
        b = self.get_prekey_bundle(addr_s)
        if not b or ("ik" not in b or "spk" not in b or "sig" not in b):
            return {"error":"no_bundle"}
        lst = b.get("opk_list") or []
        opk = lst.pop(0) if lst else None
        if lst:
            b["opk_list"] = lst
        else:
            b.pop("opk_list", None)
        self.put_prekey_bundle(addr_s, b)
        sp = self.chat_spend_pub.get(addr_s)
    
    return {"type":"CHAT_PREKEY_BUNDLE","bundle":{"ik": b["ik"], "spk": b["spk"], "sig": b["sig"], "opk": opk, "spend_pub": sp}}


# ====== END OF PREKEY BUNDLE ======


@benchmark(label="CHAT_SEND", threshold_ms=15.0)
def chat_send(self, message, pow_obj, base_identity, *,
              client_ip, choose_relay_route, relay_chain, **kwargs):
    frm = (message.get("from") or "").strip().lower()
    to  = (message.get("to")   or "").strip().lower()
    enc = message.get("enc")
    mid = message.get("msg_id")
    ts  = int(message.get("ts") or 0)
    chat_sig = (message.get("chat_sig") or "").strip().lower()
    ratchet_pn = int(message.get("ratchet_pn") or 0)
    ratchet_n = int(message.get("ratchet_n") or 0)

    err = _validate_send_fields(frm, to, enc, mid, ts, ratchet_pn, ratchet_n)
    if err:
        log.warning("[chat_send] Field validation failed from %s (ip=%s): %s", frm, client_ip, err)
        return err

    for scope, table, key_label, burst, window_s in [
        ("rpc:chat_send", self.rl_ip, "chat_send", CFG.CHAT_RL_IP_BURST, CFG.CHAT_RL_IP_WINDOWS),
        ("rpc:chat_send_addr", self.rl_addr, f"chat_send:{frm}", CFG.CHAT_RL_ADDR_BURST, CFG.CHAT_RL_ADDR_WINDOWS),
    ]:
        ok, pow_resp = CM.allow_rpc_with_pow(
            self,
            scope=scope,
            table=table,
            ip=client_ip,
            identity=frm or base_identity,
            key_label=key_label,
            burst=burst,
            window_s=window_s,
            backoff_s=CFG.CHAT_BACKOFF_S,
            pow_obj=pow_obj,
            difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
        )
        if not ok:
            log.warning("[chat_send] %s rate limit/PoW failed for %s", key_label, frm or client_ip)
            return {"type": "CHAT_ACK", **(pow_resp or {})}

    if self.dedup_mid(frm, mid):
        return {"type": "CHAT_ACK", "status": "duplicate"}

    # ---- Encrypted only ----
    nonce_hex = str((enc or {}).get("nonce") or "")
    ct_hex    = str((enc or {}).get("ct")    or "")
    fp_hex    = (message.get("from_pub")    or "").strip().lower()     # eph X25519
    fs_hex = (message.get("from_static") or "").strip().lower()

    enc_err = _validate_send_encryption(self, frm, ct_hex, nonce_hex, fp_hex, fs_hex)
    if enc_err:
        log.warning("[chat_send] Encryption validation failed %s -> %s: %s", frm, to, enc_err)
        return enc_err

    # routing authenticity signature verification (without decryption)
    if not chat_sig:
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "sig_required"}
    get_sp = self.get_spend_pub
    sp = (get_sp(frm) or "").strip().lower() if callable(get_sp) else (self.chat_spend_pub.get(frm) or "").strip().lower()
    if not sp:
        log.warning("[chat_send] Missing spend_pub for sender %s", frm)
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_spend_pub"}
    
    used_opk = message.get("used_opk")
    used_opk_hex = (used_opk or "").strip().lower()
    chat_bytes = b"|".join([
        b"CHAT_SEND",
        frm.encode(), to.encode(),
        str(mid).encode(), str(ts).encode(),
        bytes.fromhex(fp_hex), bytes.fromhex(fs_hex),
        str(ratchet_pn).encode(), str(ratchet_n).encode(),
        bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex),
        used_opk_hex.encode()
    ])
    chat_verify = CM.verify_chat_signatures([("chat_send", sp, chat_bytes, chat_sig)])
    if not chat_verify.get("chat_send"):
        log.warning("[chat_send] Bad chat_sig from %s (ip=%s)", frm, client_ip)
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_sig"}

    msg_payload = {
        "from": frm,
        "msg_id": mid,
        "ts": ts,
        "from_static": fs_hex,
        "from_pub": fp_hex,
        "enc": {"nonce": enc.get("nonce"), "ct": enc.get("ct")},
        "used_opk": used_opk,
        "ratchet_pn": ratchet_pn,
        "ratchet_n": ratchet_n,
    }

    # === Onion-lite relay (opsional) ===
    relay_hops = int(CFG.CHAT_NUM_HOPS)
    if CFG.CHAT_FORCE_RELAY and len(self.peers) >= max(1, relay_hops):
        route = choose_relay_route(self, relay_hops)
        if not route:
            log.warning("[chat_send] CHAT_SEND relay requested but no peers available; falling back to direct queue")
        else:
            relay_chain(self, route, {"type": "CHAT_SEND_INNER", "to": to, "msg": msg_payload})
            return {"type": "CHAT_ACK", "status": "relayed", "hops": len(route)}

    ok = self.mailbox_put(to, {"type": "CHAT_ITEM", "to": to, **msg_payload},
                          CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)

    if not ok:
        log.warning("[chat_send] Mailbox full for %s (dropped mid=%s)", to, mid)
        return {"type": "CHAT_ACK", "status": "mailbox_full"}
    self.enqueue_rcpt(frm, "delivered", mid, frm, to, ts)
    return {"type": "CHAT_ACK", "status": "queued"}


@benchmark(label="CHAT_READ", threshold_ms=15.0)
def chat_read(self, message, pow_obj, base_identity, *,
              client_ip, **kwargs):
    sender = (message.get("sender") or "").strip().lower()
    reader = (message.get("reader") or "").strip().lower()
    mid    = message.get("msg_id")
    ts_val = int(message.get("ts") or 0)
    read_sig = (message.get("read_sig") or "").strip().lower()

    if not sender or not reader or mid is None or ts_val <= 0:
        return {"error": "bad_fields"}
    if not read_sig:
        return {"error": "sig_required"}

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_read",
        table=self.rl_ip,
        ip=client_ip,
        identity=reader or base_identity,
        key_label="chat_read",
        burst=8,
        window_s=10,
        backoff_s=CFG.CHAT_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_read] Rate limit/PoW failed for %s", reader)
        return pow_resp

    # read receipt verification
    get_sp = self.get_spend_pub
    sp = (get_sp(reader) or "").strip().lower() if callable(get_sp) else (self.chat_spend_pub.get(reader) or "").strip().lower()
    if not sp:
        log.warning("[chat_read] Spend pub missing for reader %s", reader)
        return {"error": "no_spend_pub"}
    rr = b"|".join([
        b"CHAT_READ",
        sender.encode(), reader.encode(),
        str(mid).encode(), str(ts_val).encode()
    ])
    read_check = CM.verify_chat_signatures([("read", sp, rr, read_sig)])
    if not read_check.get("read"):
        log.warning("[chat_read] Bad read signature from %s (ip=%s)", reader, client_ip)
        return {"error": "bad_sig"}

    self.enqueue_rcpt(sender, "read", mid, sender, reader, int(time.time()))
    return {"type": "CHAT_READ_OK"}


@benchmark(label="CHAT_PULL", threshold_ms=10.0)
def chat_pull(self, message, *,
              client_ip, **kwargs):
    me = (message.get("address") or "").strip().lower()
    if not me:
        return {"type": "CHAT_NONE", "items": [], "error": "bad_address"}
    n_raw = message.get("n", message.get("max", 20))
    n = int(n_raw)
    if n > CFG.CHAT_PULL_MAX_ITEMS:
        n = CFG.CHAT_PULL_MAX_ITEMS
    if n < 0:
        n = 0
    ts = int(message.get("ts", 0))
    pull_sig = (message.get("pull_sig") or "").strip().lower()

    now = int(time.time())
    if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
        log.warning("[chat_pull] Timestamp drift error for %s (now=%d, ts=%d, ip=%s)", me, now, ts, client_ip)
        return {"type": "CHAT_NONE", "items": [], "error": "ts_drift"}

    get_sp = self.get_spend_pub
    spend_pk = get_sp(me) if callable(get_sp) else self.chat_spend_pub.get(me)
    if not spend_pk:
        return {"type": "CHAT_NONE", "items": [], "error": "not_registered"}

    msg_bytes = b"|".join([b"CHAT_PULL", me.encode(), str(ts).encode()])
    pull_check = CM.verify_chat_signatures([("pull", spend_pk, msg_bytes, pull_sig)])
    if not pull_check.get("pull"):
        log.warning("[chat_pull] Bad pull signature for %s (ip=%s)", me, client_ip)
        return {"type": "CHAT_NONE", "items": [], "error": "bad_sig"}

    dedup = self.dedup_pull
    if callable(dedup) and dedup(me, pull_sig):
        log.warning("[chat_pull] Replay detected for %s from %s", me, client_ip)
        return {"type": "CHAT_NONE", "items": [], "error": "replay_detected"}

    items = self.mailbox_pull(me, n)
    return {"type": "CHAT_ITEMS", "items": items}


@benchmark(label="CHAT_RELAY", threshold_ms=15.0)
def chat_relay(self, message, pow_obj, base_identity, *,
               client_ip, send_chat_relay, **kwargs):
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:chat_relay",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="chatrelay",
        burst=CFG.CHAT_RELAY_RL_IP_BURST,
        window_s=CFG.CHAT_RELAY_RL_WINDOW_S,
        backoff_s=CFG.CHAT_RELAY_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_CHAT),
    )
    if not ok:
        log.warning("[chat_relay] Rate limit/PoW failed for relay request from %s", client_ip)
        return pow_resp

    # payload: {"route": [peer1, peer2, ...], "inner": {...}}
    route_raw = list(message.get("route") or [])
    route, err = _validate_relay_route(self, route_raw, client_ip)
    if err:
        log.warning("[chat_relay] Relay route validation failed from %s: %s", client_ip, err)
        return err

    inner = message.get("inner") or {}
    inner_err = _validate_relay_inner(inner)
    if inner_err:
        log.warning("[chat_relay] Relay inner validation failed from %s: %s", client_ip, inner_err)
        return inner_err

    if route:
        nxt = route.pop(0)
        return send_chat_relay(self, nxt, {"type": "CHAT_RELAY", "route": route, "inner": inner})
    # last hop: deliver inner ke mailbox
    if (inner or {}).get("type") == "CHAT_SEND_INNER":
        to  = (inner.get("to") or "").strip().lower()
        msg = inner.get("msg") or {}
        ok = self.mailbox_put(to, {
            "type": "CHAT_ITEM",
            "from": msg.get("from"),
            "to": to,
            "enc": msg.get("enc"),
            "from_pub": msg.get("from_pub"),
            "from_static": msg.get("from_static"),
            "used_opk": msg.get("used_opk"),
            "ratchet_pn": msg.get("ratchet_pn"),
            "ratchet_n": msg.get("ratchet_n"),
            "msg_id": msg.get("msg_id"),
            "ts": msg.get("ts"),
        }, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)
        if not ok:
            log.warning("[chat_relay] Mailbox full for %s on final relay delivery", to)
        return {"type": "CHAT_RELAY_ACK", "status": ("queued" if ok else "rejected")}
    return {"error": "bad_inner"}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _validate_send_fields(frm, to, enc, mid, ts, ratchet_pn, ratchet_n) -> dict | None:
    max_idx = CFG.CHAT_RATCHET_INDEX_MAX
    if not (0 <= ratchet_pn <= max_idx and 0 <= ratchet_n <= max_idx):
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "ratchet_index_out_of_range"}
    if not (frm and to and enc and (mid is not None) and ts):
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_fields"}
    now = int(time.time())
    if abs(now - ts) > CFG.CHAT_TS_DRIFT_S:
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "ts_drift"}
    return None


def _validate_send_encryption(self, frm, ct_hex, nonce_hex, fp_hex, fs_hex) -> dict | None:
    exp = self.chat_presence_pub.get(frm)
    if not exp:
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "no_presence"}
    if fs_hex != exp:
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_static"}
    if len(ct_hex) // 2 > CFG.CHAT_MAX_CT_BYTES:
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "too_large"}
    if not (len(nonce_hex) == 24 and all(c in "0123456789abcdef" for c in nonce_hex)):
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_nonce"}
    if not (len(fp_hex) == 64 and all(c in "0123456789abcdef" for c in fp_hex)):
        return {"type": "CHAT_ACK", "status": "rejected", "reason": "bad_from_pub"}
    return None


def _validate_presence_signature_and_fields(addr_s, pubhex, spend_pk, presence_sig, ts_val) -> dict | None:
    if not (pubhex and spend_pk and presence_sig):
        return {"error": "presence_missing_fields"}
    if abs(time.time() - ts_val) > CFG.PRESENCE_TTL_S:
        return {"error": "presence_stale"}
    if not (len(pubhex) == 64 and all(c in "0123456789abcdef" for c in pubhex)):
        return {"error": "presence_bad_pub"}
    if not (len(spend_pk) == 66 and all(c in "0123456789abcdef" for c in spend_pk)):
        return {"error": "presence_bad_spend_pub"}
    hrp, data = bech32_decode(addr_s)
    if hrp != CFG.ADDRESS_PREFIX or not data:
        return {"error": "presence_bad_hrp"}
    prog = bytes(convertbits(data[1:], 5, 8, False))
    if len(prog) != 20:
        return {"error": "presence_bad_prog"}
    if hash160(bytes.fromhex(spend_pk)) != prog:
        return {"error": "presence_addr_mismatch"}
    
    pres_bytes = b"|".join([b"CHAT_PRESENCE", addr_s.encode(), bytes.fromhex(pubhex), bytes.fromhex(spend_pk), str(ts_val).encode()])
    sig_ok = CM.verify_chat_signatures([("presence", spend_pk, pres_bytes, presence_sig)])
    if not sig_ok.get("presence"):
        return {"error": "presence_bad_sig"}
    return None


def _validate_register_fields_and_address(addr_s, chat_pub, spend_pk, reg_sig, ts_val, presence_sig) -> dict | None:
    if not addr_s or not chat_pub or not spend_pk or not reg_sig or not ts_val or not presence_sig:
        return {"error": "missing fields"}

    if not addr_s.startswith(CFG.ADDRESS_PREFIX):
        return {"error": "bad address format"}

    if not (len(chat_pub) == 64 and all(c in "0123456789abcdef" for c in chat_pub)):
        return {"error": "bad chat_pub"}

    if not (len(spend_pk) == 66 and all(c in "0123456789abcdef" for c in spend_pk)):
        return {"error": "bad spend_pub"}

    # Anti replay time window (±5 minutes)
    if abs(time.time() - ts_val) > 300:
        return {"error": "stale ts"}
    try:
        hrp, data = bech32_decode(addr_s)
        if hrp != CFG.ADDRESS_PREFIX or not data:
            return {"error": "bad address hrp"}
        witver = data[0]
        converted = convertbits(data[1:], 5, 8, False)
        if converted is None:
            return {"error": "bad convertbits"}
        prog = bytes(converted)
        if witver != 0 or len(prog) != 20:
            return {"error": "address not p2wpkh"}
        if hash160(bytes.fromhex(spend_pk)) != prog:
            return {"error": "register proof mismatch"}
    except Exception as e:
        return {"error": f"invalid address proof: {e}"}
    return None


def _validate_spk_registration(spend_pk, spk_reg, sig_reg) -> tuple[bool, dict | None]:
    if not spk_reg or not sig_reg:
        return False, None
    if not (len(spk_reg) == 64 and all(c in "0123456789abcdef" for c in spk_reg)):
        return False, {"error": "bad_spk"}
    
    payload = CFG.CHAT_SPK + bytes.fromhex(spk_reg) + b"|" + bytes.fromhex(spend_pk)
    sig_ok = CM.verify_chat_signatures([("spk", spend_pk, payload, sig_reg)])
    spk_valid = bool(sig_ok.get("spk"))
    if not spk_valid:
        return False, {"error": "bad_spk_sig"}
    return True, None


def _validate_relay_route(self, route_raw, client_ip) -> tuple[list[tuple], dict | None]:
    route = []
    for hop in route_raw:
        if len(hop) >= 2:
            hop_norm = (str(hop[0]), int(hop[1]))
        else:
            return [], {"error": "bad_route_entry"}
        if hop_norm not in self.peers:
            log.warning("[CHAT_RELAY] unknown hop=%s from=%s", hop_norm, client_ip)
            return [], {"error": "unknown_hop"}
        route.append(hop_norm)
    if len(route) > CFG.CHAT_RELAY_MAX_HOPS:
        return [], {"error": "route_too_long"}
    return route, None


def _validate_relay_inner(inner) -> dict | None:
    allowed_inner_types = {"CHAT_SEND_INNER"}
    if inner.get("type") not in allowed_inner_types:
        return {"error": "bad_inner_type"}
    if inner.get("type") == "CHAT_SEND_INNER":
        msg_obj = inner.get("msg")
        if not inner.get("to"):
            return {"error": "bad_inner"}
        msg_keys = msg_obj.keys()
        allowed_msg_keys = {"from", "msg_id", "ts", "from_static", "from_pub", "enc", "used_opk", "ratchet_pn", "ratchet_n"}
        for k in msg_keys:
            if k not in allowed_msg_keys:
                return {"error": "bad_inner_field"}
    try:
        inner_size = len(json.dumps(inner, separators=CFG.CANONICAL_SEP).encode("utf-8"))
    except Exception:
        inner_size = CFG.CHAT_RELAY_MAX_INNER_BYTES + 1
    if inner_size > CFG.CHAT_RELAY_MAX_INNER_BYTES:
        return {"error": "payload_too_large"}
    return None