# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP141; BIP173; Merkle; Signal-X3DH

import json
import time
import socket
import struct
import threading
import collections
from concurrent.futures import ThreadPoolExecutor

# ---------------- Local Project ----------------
from ...utils import config as CFG
from .base import NetworkHandlerProxy
from ..protocol import send_message, recv_message,build_envelope, SecureChannel
from ...storage.kv import get as kv_get, put as kv_put, delete as kv_delete

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.chat")

_presence_executor: ThreadPoolExecutor | None = None
_presence_executor_lock = threading.Lock()


def get_presence_executor() -> ThreadPoolExecutor:
    global _presence_executor
    if _presence_executor is None:
        with _presence_executor_lock:
            if _presence_executor is None:
                _presence_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="presence_relay")
    return _presence_executor


def encode_prekey_bundle(bundle: dict) -> bytes:
    if type(bundle) is not dict:
        return b""
    ts = int(bundle.get("ts", 0) or 0)
    ik = bundle.get("ik")
    spk = bundle.get("spk")
    sig = bundle.get("sig")
    spend_pub = bundle.get("spend_pub")
    opk_list = bundle.get("opk_list") or []

    flags = 0
    body = bytearray()
    if ik and type(ik) is str and len(ik) == 64:
        body.extend(bytes.fromhex(ik))
        flags |= 0x01
    if spk and type(spk) is str and len(spk) == 64:
        body.extend(bytes.fromhex(spk))
        flags |= 0x02
    if sig and type(sig) is str:
        sig_bytes = bytes.fromhex(sig)
        if len(sig_bytes) <= 65535:
            body.extend(struct.pack("<H", len(sig_bytes)))
            body.extend(sig_bytes)
            flags |= 0x04
    if spend_pub and type(spend_pub) is str and len(spend_pub) == 66:
        body.extend(bytes.fromhex(spend_pub))
        flags |= 0x08

    opk_bytes = bytearray()
    if type(opk_list) is list:
        for o in opk_list:
            if o and type(o) is str and len(o) == 64:
                opk_bytes.extend(bytes.fromhex(o))

    opk_count = len(opk_bytes) // 32
    opk_header = struct.pack("<I", opk_count)
    header = struct.pack("<QB", ts, flags)
    return bytes(header + body + opk_header + opk_bytes)


def decode_prekey_bundle(raw: bytes) -> dict:
    if not raw or len(raw) < 9:
        return {}
    try:
        ts, flags = struct.unpack_from("<QB", raw, 0)
        offset = 9
        ik = None
        spk = None
        sig = None
        spend_pub = None
        if flags & 0x01:
            if offset + 32 <= len(raw):
                ik = raw[offset:offset+32].hex()
                offset += 32
        if flags & 0x02:
            if offset + 32 <= len(raw):
                spk = raw[offset:offset+32].hex()
                offset += 32
        if flags & 0x04:
            if offset + 2 <= len(raw):
                sig_len = struct.unpack_from("<H", raw, offset)[0]
                offset += 2
                if offset + sig_len <= len(raw):
                    sig = raw[offset:offset+sig_len].hex()
                    offset += sig_len
        if flags & 0x08:
            if offset + 33 <= len(raw):
                spend_pub = raw[offset:offset+33].hex()
                offset += 33
        opk_list = []
        if offset + 4 <= len(raw):
            opk_count = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            for _ in range(opk_count):
                if offset + 32 <= len(raw):
                    opk_list.append(raw[offset:offset+32].hex())
                    offset += 32
        res: dict = {"ts": ts}
        if ik:
            res["ik"] = ik
        if spk:
            res["spk"] = spk
        if sig:
            res["sig"] = sig
        if spend_pub:
            res["spend_pub"] = spend_pub
        if opk_list:
            res["opk_list"] = opk_list
        return res
    except Exception:
        return {}


# ------------------------------ P2P Chat ------------------------------

class ChatHandler(NetworkHandlerProxy):
    def __init__(self, network):
        super().__init__(network)
        self.chat_presence_seen_order = collections.deque(maxlen=10000)
        self.chat_pull_seen = {}

    def get_spend_pub(self, addr: str) -> str | None:
        if not addr:
            return None
        spend_dict = self.chat_spend_pub
        if type(spend_dict) is dict:
            sp = str(spend_dict.get(addr, "")).strip().lower()
            if sp:
                return sp
        b = self.get_prekey_bundle(addr)
        sp = str(b.get("spend_pub", "")).strip().lower()
        if sp:
            with self.chat_lock:
                if type(self.chat_spend_pub) is dict:
                    self.chat_spend_pub[addr] = sp
            return sp
        return None

    def get_prekey_bundle(self, addr: str) -> dict:
        if not addr:
            return {}
        with self.chat_lock:
            raw = kv_get("chat_prekeys", addr.encode("utf-8"))
            return decode_prekey_bundle(raw) if raw else {}

    def put_prekey_bundle(self, addr: str, bundle: dict) -> None:
        if not addr:
            return
        with self.chat_lock:
            raw = encode_prekey_bundle(bundle)
            kv_put("chat_prekeys", addr.encode("utf-8"), raw)

    def delete_prekey_bundle(self, addr: str) -> None:
        if not addr:
            return
        with self.chat_lock:
            kv_delete("chat_prekeys", addr.encode("utf-8"))

    def send_to_peer(self, peer: tuple[str,int], payload: dict) -> None:
        if type(peer) is not tuple or len(peer) != 2:
            raise ValueError("bad peer")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            s.connect(peer)
            env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
            env["pubkey"] = self.pubkey
            raw = json.dumps(env).encode("utf-8")
            chan = SecureChannel(
                s, role="client",
                node_id=self.node_id, node_pub=self.pubkey, node_priv=self.privkey,
                get_pinned=self.get_pinned, set_pinned=self.set_pinned,
            )
            chan.handshake()
            chan.send(raw)
            _ = chan.recv(1)


    def relay_presence_async(self, pres: dict, exclude=None) -> None:
        get_presence_executor().submit(self._relay_presence, pres, exclude)


    def mailbox_put(self, addr, item, ttl_s, per_addr_max, global_max):
        now = time.time()
        exp = now + ttl_s
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if dq is None:
                dq = collections.deque()
                self.chat_mailbox[addr] = dq
            # lazy GC per addr
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            if len(dq) >= per_addr_max or self.chat_global_count >= global_max:
                return False  # mailbox full
            dq.append((exp, item))
            self.chat_global_count += 1
            return True


    def mailbox_pull(self, addr, nmax):
        now = time.time()
        out = []
        with self.chat_lock:
            dq = self.chat_mailbox.get(addr)
            if not dq:
                return out
            # prune expired entries first
            while dq and dq[0][0] <= now:
                dq.popleft(); self.chat_global_count -= 1
            while dq and len(out) < nmax:
                exp, it = dq.popleft()
                self.chat_global_count -= 1
                if exp > now:
                    out.append(it)
        return out


    def enqueue_rcpt(self, to_addr, kind, mid, frm, to, ts):
        item = {
            "type": "CHAT_RCPT",
            "rcpt": kind,
            "msg_id": mid,
            "from": frm,
            "to": to,
            "ts": int(ts),
        }
        self.mailbox_put(to_addr, item, CFG.CHAT_TTL_S, CFG.CHAT_MAILBOX_MAX, CFG.CHAT_GLOBAL_QUEUE_MAX)


    def record_presence_seen(self, pid: str) -> None:
        if not pid:
            return
        with self.chat_lock:
            if pid in self.chat_presence_seen:
                return
            if len(self.chat_presence_seen_order) == self.chat_presence_seen_order.maxlen:
                oldest = self.chat_presence_seen_order.popleft()
                self.chat_presence_seen.discard(oldest)
            self.chat_presence_seen_order.append(pid)
            self.chat_presence_seen.add(pid)


    def dedup_pull(self, addr: str, pull_sig: str) -> bool:
        if not pull_sig or not addr:
            return False
        with self.chat_lock:
            if len(self.chat_pull_seen) > 2000 and addr not in self.chat_pull_seen:
                oldest_addr = next(iter(self.chat_pull_seen))
                self.chat_pull_seen.pop(oldest_addr, None)
            rec = self.chat_pull_seen.get(addr)
            if rec is None:
                dq = collections.deque(maxlen=128)
                st = set()
                self.chat_pull_seen[addr] = (dq, st)
            else:
                dq, st = rec
            if pull_sig in st:
                return True
            if len(dq) == dq.maxlen:
                old = dq.popleft()
                st.discard(old)
            dq.append(pull_sig)
            st.add(pull_sig)
            return False


    def gc_mailboxes(self):
        now = time.time()
        if now - self.chat_gc_last < 30:
            return
        with self.chat_lock:
            empty_mailboxes = []
            for addr, dq in self.chat_mailbox.items():
                changed = False
                while dq and dq[0][0] <= now:
                    dq.popleft(); self.chat_global_count -= 1; changed = True
                if not dq and changed:
                    empty_mailboxes.append(addr)
            for addr in empty_mailboxes:
                self.chat_mailbox.pop(addr, None)

            # Clean expired backoffs
            expired_backoffs = [k for k, until in self.backoff_until.items() if until <= now]
            for k in expired_backoffs:
                self.backoff_until.pop(k, None)

            # Clean oversized seen structures if needed
            if len(self.chat_pull_seen) > 2000:
                self.chat_pull_seen.clear()
            if len(self.chat_seen_mid) > 2000:
                # prune half of oldest address keys
                keys_to_remove = list(self.chat_seen_mid.keys())[:1000]
                for k in keys_to_remove:
                    self.chat_seen_mid.pop(k, None)
        self.chat_gc_last = now


    def dedup_mid(self, from_addr, msg_id):
        if msg_id is None: 
            return False
        with self.chat_lock:
            if len(self.chat_seen_mid) > 2000 and from_addr not in self.chat_seen_mid:
                try:
                    oldest_addr = next(iter(self.chat_seen_mid))
                    self.chat_seen_mid.pop(oldest_addr, None)
                except StopIteration:
                    pass
            rec = self.chat_seen_mid.get(from_addr)
            if rec is None:
                dq = collections.deque(maxlen=self.chat_seen_max)
                st = set()
                self.chat_seen_mid[from_addr] = (dq, st)
            else:
                dq, st = rec
            if msg_id in st:
                return True
            # tambah
            if len(dq) == dq.maxlen:
                old = dq.popleft(); st.discard(old)
            dq.append(msg_id); st.add(msg_id)
            return False


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _relay_presence(self, pres: dict, exclude=None) -> None:
        hops = int(pres.get("hops", 0))
        if hops >= 2:
            return
        pres2 = dict(pres); pres2["hops"] = hops + 1
        msg = {"type": "CHAT_PRESENCE", **pres2}
        self.broadcast.send_gossip(self.peers, msg, exclude=exclude)