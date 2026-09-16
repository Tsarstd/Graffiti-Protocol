# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md


import time
import json
import struct
from typing import Any, Dict

from ..utils import config as CFG
from ..storage.kv import iter_prefix, batch, put

from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger('tsarchain.contracts.graffiti_registry')


# =============================================================================
# BINARY SERIALIZATION / DESERIALIZATION HELPERS
# =============================================================================

_POST_HEADER_STRUCT = "<QQQQIIiI"
_COMMENT_HEADER_STRUCT = "<IQQQQQI"
_PAYOUT_HEADER_STRUCT = "<IQiI"
_PROOF_HEADER_STRUCT = "<QQIIQI"


def serialize_post_binary(entry: dict) -> bytes:
    stats = entry.get("stats", {})
    pool_bal = int(stats.get("pool_balance", 0))
    creator_paid = int(stats.get("creator_paid", 0))
    storage_paid = int(stats.get("storage_paid", 0))
    comments = int(stats.get("comments", 0))
    last_paid_epoch = int(stats.get("last_paid_epoch", -1))
    height = int(entry.get("block_height", 0))
    amt_paid = int(entry.get("amount_paid", 0))
    
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack(_POST_HEADER_STRUCT, amt_paid, pool_bal, creator_paid, storage_paid, height, comments, last_paid_epoch, len(payload))
    return header + payload


def _deserialize_binary(raw: bytes, struct_fmt: str) -> dict:
    header_size = struct.calcsize(struct_fmt)
    *_, payload_len = struct.unpack_from(struct_fmt, raw, 0)
    return json.loads(raw[header_size:header_size + payload_len].decode("utf-8"))


def deserialize_post_binary(raw: bytes, art_id: str = "") -> dict:
    data = _deserialize_binary(raw, _POST_HEADER_STRUCT)
    if art_id and "art_id" not in data:
        data["art_id"] = art_id
    return data


def serialize_comment_binary(entry: dict) -> bytes:
    height = int(entry.get("block_height", 0))
    amount = int(entry.get("amount", 0))
    tip = int(entry.get("tip", 0))
    creator_paid = int(entry.get("creator_paid", 0))
    storage_paid = int(entry.get("storage_paid", 0))
    ts = int(entry.get("ts", 0))
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack(_COMMENT_HEADER_STRUCT, height, amount, tip, creator_paid, storage_paid, ts, len(payload))
    return header + payload


def deserialize_comment_binary(raw: bytes) -> dict:
    return _deserialize_binary(raw, _COMMENT_HEADER_STRUCT)


def serialize_payout_binary(entry: dict) -> bytes:
    height = int(entry.get("block_height", 0))
    amount = int(entry.get("amount", 0))
    raw_epoch = entry.get("epoch")
    epoch = -1 if raw_epoch is None else int(raw_epoch)
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack(_PAYOUT_HEADER_STRUCT, height, amount, epoch, len(payload))
    return header + payload


def deserialize_payout_binary(raw: bytes) -> dict:
    return _deserialize_binary(raw, _PAYOUT_HEADER_STRUCT)


def serialize_proof_binary(entry: dict) -> bytes:
    epoch = int(entry.get("epoch", 0))
    offset = int(entry.get("offset", 0))
    length = int(entry.get("length", 0))
    height = int(entry.get("height", 0))
    ts = int(entry.get("ts", 0))
    payload = json.dumps(entry, separators=CFG.CANONICAL_SEP).encode("utf-8")
    header = struct.pack(_PROOF_HEADER_STRUCT, epoch, offset, length, height, ts, len(payload))
    return header + payload


def deserialize_proof_binary(raw: bytes) -> dict:
    return _deserialize_binary(raw, _PROOF_HEADER_STRUCT)


class GraffitiRegistry:
    def __init__(self) -> None:
        self._kv_prefix = "graffiti:"
        self.store = None
        self._data_cache = None
        self._stored_counts = {"comments": {}, "payouts": {}, "proofs": {}}
        self._stored_posts = set()
        default = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
        self.data = self._load(default)
        self.data.setdefault("proofs", {})


    def record_post(self, art_id: str, meta: Dict[str, Any], txid: str, block_height: int, pool_addr: str, amount_paid: int, *, block_hash: str | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        existing = posts.get(art_id)
        if existing and existing.get("txid") == txid:
            return
        entry = dict(meta)
        entry.update({
            "art_id": art_id,
            "txid": txid,
            "block_height": int(block_height),
            "pool_address": pool_addr,
            "amount_paid": int(amount_paid),
            "block_hash": block_hash,
        })
        stats = entry.setdefault("stats", {})
        stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(amount_paid)
        stats.setdefault("creator_paid", 0)
        stats.setdefault("storage_paid", 0)
        stats.setdefault("comments", 0)
        posts[art_id] = entry
        self._flush()


    def get_post(self, art_id: str) -> Dict[str, Any] | None:
        return self.data.get("posts", {}).get(art_id)


    def record_comment(self, art_id: str, meta: Dict[str, Any], txid: str,
                       block_height: int, creator_paid: int, storage_paid: int) -> None:
        comments = self.data.setdefault("comments", {})
        thread = comments.setdefault(art_id, [])
        entry = {
            "txid": txid,
            "block_height": int(block_height),
            "comment": meta.get("comment"),
            "commenter": meta.get("commenter"),
            "amount": int(meta.get("amount", 0)),
            "tip": int(meta.get("tip", 0)),
            "creator_paid": int(creator_paid),
            "storage_paid": int(storage_paid),
            "ts": int(meta.get("ts", time.time())),
        }
        existing_txids = {item.get("txid") for item in thread}
        if txid in existing_txids:
            return
        thread.append(entry)
        post = self.get_post(art_id)
        if post:
            stats = post.setdefault("stats", {})
            stats["creator_paid"] = int(stats.get("creator_paid", 0)) + int(creator_paid)
            stats["storage_paid"] = int(stats.get("storage_paid", 0)) + int(storage_paid)
            stats["pool_balance"] = int(stats.get("pool_balance", 0)) + int(storage_paid)
            stats["comments"] = int(stats.get("comments", 0)) + 1
        self._flush()


    def record_payout(self, art_id: str, recipients: Dict[str, int], txid: str, block_height: int, epoch: int | None = None, pool_balance: int | None = None) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        total = sum(int(v) for v in recipients.values())
        payouts = self.data.setdefault("payouts", {})
        art_payouts = payouts.setdefault(art_id, [])
        # Idempotent replay: skip if already recorded
        for existing in art_payouts:
            if existing.get("txid") == txid:
                if pool_balance is not None:
                    stats["pool_balance"] = max(0, int(pool_balance))
                return
        if pool_balance is not None:
            stats["pool_balance"] = max(0, int(pool_balance))
        else:
            stats["pool_balance"] = max(0, int(stats.get("pool_balance", 0)) - total)
        if epoch is not None:
            stats["last_paid_epoch"] = max(int(stats.get("last_paid_epoch", -1)), int(epoch))
        art_payouts.append({
            "txid": txid,
            "block_height": int(block_height),
            "recipients": {addr: int(val) for addr, val in recipients.items()},
            "amount": int(total),
            "epoch": None if epoch is None else int(epoch),
        })
        self._flush()


    def set_pool_balance(self, art_id: str, pool_balance: int) -> None:
        posts = self.data.setdefault("posts", {})
        post = posts.get(art_id)
        if not post:
            return
        stats = post.setdefault("stats", {})
        stats["pool_balance"] = max(0, int(pool_balance))
        self._flush()


    def record_proof(self, art_id: str, storer: str, epoch: int, offset: int, length: int,
                     proof_hash: str, height: int = 0, seed: str = "") -> None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return
        proofs = self.data.setdefault("proofs", {})
        art_proofs = proofs.setdefault(art_id, [])
        entry = {
            "storer": storer,
            "epoch": int(epoch),
            "offset": int(offset),
            "length": int(length),
            "hash": proof_hash,
            "height": int(height),
            "seed": seed,
            "ts": int(time.time()),
        }
        # Replace existing entry for same storer+epoch
        target_idx = len(art_proofs)
        for idx, item in enumerate(art_proofs):
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                art_proofs[idx] = entry
                target_idx = idx
                break
        else:
            art_proofs.append(entry)
        self.data["proofs"][art_id] = art_proofs
        put("graffiti", f"r:{art_id}:{target_idx:08d}".encode("utf-8"), serialize_proof_binary(entry))
        self._stored_counts.setdefault("proofs", {})[art_id] = len(art_proofs)


    def get_proof(self, art_id: str, storer: str, epoch: int) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower()
        if not art_id or not storer:
            return None
        proofs = self.data.get("proofs", {}).get(art_id, [])
        for item in proofs:
            if item.get("storer") == storer and int(item.get("epoch", -1)) == int(epoch):
                return dict(item)
        return None


    def get_latest_proof(self, art_id: str, storer: str | None = None) -> Dict[str, Any] | None:
        art_id = (art_id or "").strip().lower()
        storer = (storer or "").strip().lower() if storer else None
        proofs = self.data.get("proofs", {}).get(art_id, [])
        if not proofs:
            return None
        filtered = [dict(p) for p in proofs if (not storer or p.get("storer") == storer)]
        if not filtered:
            return None
        filtered.sort(key=lambda r: (int(r.get("epoch", -1)), int(r.get("ts", 0))), reverse=True)
        return filtered[0]


    def get_latest_proof_epoch(self, art_id: str, storer: str | None = None) -> int:
        proof = self.get_latest_proof(art_id, storer)
        if not proof:
            return -1
        return int(proof.get("epoch", -1))


    def list_payouts(self, art_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        payouts = self.data.get("payouts", {}).get(art_id, [])
        items = [dict(entry) for entry in payouts]
        items.sort(key=lambda r: int(r.get("block_height", 0)), reverse=True)
        if type(limit) is int and limit > 0:
            return items[:limit]
        return items


    def list_posts(self, limit: int = 50, offset: int = 0) -> list[Dict[str, Any]]:
        posts = self.data.get("posts", {})
        items: list[Dict[str, Any]] = []
        for art_id, entry in posts.items():
            rec = dict(entry)
            rec["art_id"] = art_id
            stats = rec.get("stats", {})
            rec["stats"] = stats
            items.append(rec)
        items.sort(key=lambda r: (int(r.get("block_height", 0)), int(r.get("ts", 0))), reverse=True)
        off = max(0, int(offset or 0))
        if type(limit) is int and limit > 0:
            return items[off:off + limit]
        return items[off:]


    def list_comments(self, art_id: str, limit: int = 50) -> list[Dict[str, Any]]:
        art_id = (art_id or "").strip().lower()
        if not art_id:
            return []
        comments = self.data.get("comments", {}).get(art_id, [])
        items = [dict(entry) for entry in comments]
        items.sort(key=lambda r: (int(r.get("block_height", 0)), int(r.get("ts", 0))), reverse=True)
        if type(limit) is int and limit > 0:
            return items[:limit]
        return items


    def _load(self, default: dict) -> dict:
        data = {"posts": {}, "comments": {}, "payouts": {}, "proofs": {}}
        self._stored_counts = {"comments": {}, "payouts": {}, "proofs": {}}
        self._stored_posts = set()
        for k, v in iter_prefix("graffiti", b""):
            try:
                if k.startswith(b"p:"):
                    art_id = k[2:].decode("utf-8")
                    data["posts"][art_id] = deserialize_post_binary(v, art_id)
                    self._stored_posts.add(art_id)
                elif k.startswith(b"c:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["comments"].setdefault(art_id, []).append(deserialize_comment_binary(v))
                elif k.startswith(b"y:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["payouts"].setdefault(art_id, []).append(deserialize_payout_binary(v))
                elif k.startswith(b"r:"):
                    parts = k[2:].decode("utf-8").split(":")
                    if len(parts) >= 2:
                        art_id = parts[0]
                        data["proofs"].setdefault(art_id, []).append(deserialize_proof_binary(v))
            except Exception:
                log.exception("Error decoding graffiti key %s", k)
        
        for art_id, comments in data["comments"].items():
            self._stored_counts["comments"][art_id] = len(comments)
        for art_id, payouts in data["payouts"].items():
            self._stored_counts["payouts"][art_id] = len(payouts)
        for art_id, proofs in data["proofs"].items():
            self._stored_counts["proofs"][art_id] = len(proofs)

        return data or dict(default)


    def _flush(self) -> None:
        with batch("graffiti") as b:
            current_posts = self.data.get("posts", {})
            for art_id, post in current_posts.items():
                b.put(f"p:{art_id}".encode("utf-8"), serialize_post_binary(post))
            
            # Clean up deleted posts
            for deleted_art in (self._stored_posts - set(current_posts.keys())):
                b.delete(f"p:{deleted_art}".encode("utf-8"))
            self._stored_posts = set(current_posts.keys())

            current_comments = self.data.get("comments", {})
            all_comment_art_ids = set(self._stored_counts.get("comments", {}).keys()) | set(current_comments.keys())
            for art_id in all_comment_art_ids:
                comments = current_comments.get(art_id, [])
                for idx, c in enumerate(comments):
                    b.put(f"c:{art_id}:{idx:08d}".encode("utf-8"), serialize_comment_binary(c))
                prev_count = self._stored_counts.get("comments", {}).get(art_id, 0)
                for stale_idx in range(len(comments), prev_count):
                    b.delete(f"c:{art_id}:{stale_idx:08d}".encode("utf-8"))
                self._stored_counts.setdefault("comments", {})[art_id] = len(comments)

            current_payouts = self.data.get("payouts", {})
            all_payout_art_ids = set(self._stored_counts.get("payouts", {}).keys()) | set(current_payouts.keys())
            for art_id in all_payout_art_ids:
                payouts = current_payouts.get(art_id, [])
                for idx, y in enumerate(payouts):
                    b.put(f"y:{art_id}:{idx:08d}".encode("utf-8"), serialize_payout_binary(y))
                prev_count = self._stored_counts.get("payouts", {}).get(art_id, 0)
                for stale_idx in range(len(payouts), prev_count):
                    b.delete(f"y:{art_id}:{stale_idx:08d}".encode("utf-8"))
                self._stored_counts.setdefault("payouts", {})[art_id] = len(payouts)

            current_proofs = self.data.get("proofs", {})
            all_proof_art_ids = set(self._stored_counts.get("proofs", {}).keys()) | set(current_proofs.keys())
            for art_id in all_proof_art_ids:
                proofs = current_proofs.get(art_id, [])
                for idx, r in enumerate(proofs):
                    b.put(f"r:{art_id}:{idx:08d}".encode("utf-8"), serialize_proof_binary(r))
                prev_count = self._stored_counts.get("proofs", {}).get(art_id, 0)
                for stale_idx in range(len(proofs), prev_count):
                    b.delete(f"r:{art_id}:{stale_idx:08d}".encode("utf-8"))
                self._stored_counts.setdefault("proofs", {})[art_id] = len(proofs)


__all__ = ["GraffitiRegistry", "serialize_post_binary", "deserialize_post_binary", "serialize_comment_binary", "deserialize_comment_binary", "serialize_payout_binary", "deserialize_payout_binary", "serialize_proof_binary", "deserialize_proof_binary"]
