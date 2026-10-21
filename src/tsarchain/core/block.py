# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
import struct
import contextlib
import multiprocessing as mp
from typing import List, Optional
from multiprocessing.synchronize import Event as MpEvent


# ---------------- Local Project ----------------
from ..core.tx import Tx
from ..utils import config as CFG
from ..core.coinbase import CoinbaseTx
from ..utils.helpers import (
    bits_to_target,
    int_to_little_endian,
    merkle_root,
    native_randomx_mine,
    pow_hash_verify_light,
    pow_key_for_height,
    to_bytes,
)

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.core.block")

class BlockHeader:
    def __init__(self, version: int, prev_block_hash: bytes, merkle_root: bytes, timestamp: int, bits: int, nonce: int):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def serialize_block(self) -> bytes:
        return (
            int_to_little_endian(self.version, 4) +
            to_bytes(self.prev_block_hash) +
            to_bytes(self.merkle_root) +
            int_to_little_endian(self.timestamp, 4) +
            int_to_little_endian(self.bits, 4) +
            int_to_little_endian(self.nonce, 4)
        )


class Block:
    def __init__(
        self,
        height: int,
        prev_block_hash: bytes,
        transactions: List[Tx],
        version: int = 1,
        bits: int = CFG.INITIAL_BITS,
        timestamp: Optional[int] = None,
        nonce: int = 0,
        merkle_root_precomputed: bytes | None = None,
        difficulty=None,
        chainwork=None,
    ):
        self.height = height
        self.version = version
        self.prev_block_hash = to_bytes(prev_block_hash) if type(prev_block_hash) is str else prev_block_hash
        self.transactions = transactions
        self.difficulty = difficulty
        self.chainwork = chainwork
        self.size_bytes: Optional[int] = None
        self.vbytes: Optional[int] = None
        self.weight: Optional[int] = None
        self.merkle_root = bytes(merkle_root_precomputed) if merkle_root_precomputed is not None else merkle_root(transactions)
        self.timestamp = int(time.time()) if timestamp is None else timestamp
        self.bits = bits
        self.nonce = nonce
        self._cached_hash = None
        self._cached_hash_nonce = None
        self._cached_hash_bits = None
        self._cached_hash_mr = None
        self._cached_hash_prev = None

    @property
    def total_fee(self) -> int:
        return sum(int(tx.fee or 0) for tx in (self.transactions or []) if not tx.is_coinbase)

    def to_dict(self):
        return {
            "height": self.height,
            "version": self.version,
            "prev_block_hash": self.prev_block_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "chainwork": self.chainwork,
            "bits": int(self.bits),
            "nonce": self.nonce,
            "hash": self.hash().hex(),
            "total_fee": self.total_fee,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @staticmethod
    def _parse_bits(v):
        if v is None or type(v) is bool:
            return int(CFG.INITIAL_BITS) & 0xFFFFFFFF
        if type(v) is int or (type(v) is float and v.is_integer()):
            return int(v) & 0xFFFFFFFF
        if type(v) is str:
            return int(v, 0) & 0xFFFFFFFF
        raise TypeError(f"bits must be int/hexstr, got {type(v)}")

    @classmethod
    def from_dict(cls, data):
        tx_list = [
            CoinbaseTx.from_dict(tx_data) if tx_data.get("type") == "Coinbase" or tx_data.get("is_coinbase") else Tx.from_dict(tx_data)
            for tx_data in (data.get("transactions") or [])
        ]
        prev_hash = to_bytes(data.get("prev_block_hash")) or (b"\x00" * 32)
        mr_bytes = to_bytes(data.get("merkle_root")) or None

        obj = cls(
            height=data.get("height", 0),
            prev_block_hash=prev_hash,
            transactions=tx_list,
            timestamp=data.get("timestamp"),
            nonce=data.get("nonce"),
            bits=cls._parse_bits(data.get("bits")),
            version=data.get("version", 1),
            merkle_root_precomputed=mr_bytes,
        )
        obj.difficulty = data.get("difficulty")
        obj.chainwork = data.get("chainwork")

        h_str = data.get("hash")
        if type(h_str) is str and len(h_str) >= 64:
            with contextlib.suppress(ValueError, TypeError):
                obj._cached_hash = bytes.fromhex(h_str)
                obj._cached_hash_nonce = obj.nonce
                obj._cached_hash_bits = obj.bits
                obj._cached_hash_mr = obj.merkle_root
                obj._cached_hash_prev = obj.prev_block_hash

        meta = data.get("_meta")
        if type(meta) is dict:
            obj._meta = dict(meta)
            obj.chainwork = obj.chainwork if obj.chainwork is not None else meta.get("chainwork")
            obj.difficulty = obj.difficulty if obj.difficulty is not None else meta.get("difficulty")
            obj.size_bytes = obj.size_bytes if obj.size_bytes is not None else meta.get("size_bytes")
            obj.vbytes = obj.vbytes if obj.vbytes is not None else meta.get("vbytes")
            obj.weight = obj.weight if obj.weight is not None else meta.get("weight")
        return obj

    def header(self) -> bytes:
        return BlockHeader(self.version, self.prev_block_hash, self.merkle_root, self.timestamp, self.bits, self.nonce).serialize_block()

    def to_storage_bytes(self) -> bytes:
        header_bytes = self.header()
        tail = struct.pack("<QQQ", int(self.height or 0), int(self.difficulty or 0), int(self.chainwork or 0))
        txs = self.transactions or []
        tx_parts = [struct.pack("<I", len(txs))]
        for tx in txs:
            tx_raw = tx.to_storage_bytes()
            tx_parts.append(struct.pack("<I", len(tx_raw)) + tx_raw)
        return header_bytes + tail + b"".join(tx_parts)

    @classmethod
    def from_storage_bytes(cls, raw: bytes) -> "Block":
        if len(raw) < 108:
            raise ValueError(f"Raw block data too short: {len(raw)} bytes")
        version = int.from_bytes(raw[0:4], "little")
        prev_hash = raw[4:36]
        merkle = raw[36:68]
        timestamp = int.from_bytes(raw[68:72], "little")
        bits = int.from_bytes(raw[72:76], "little")
        nonce = int.from_bytes(raw[76:80], "little")

        h, diff, cw = struct.unpack_from("<QQQ", raw, 80)
        offset = 104

        (tx_count,) = struct.unpack_from("<I", raw, offset)
        offset += 4

        txs = []
        for _ in range(tx_count):
            (tx_len,) = struct.unpack_from("<I", raw, offset)
            offset += 4
            tx_raw = raw[offset:offset + tx_len]
            offset += tx_len
            txs.append(Tx.from_storage_bytes(tx_raw))

        return cls(
            height=h,
            prev_block_hash=prev_hash,
            transactions=txs,
            version=version,
            bits=bits,
            timestamp=timestamp,
            nonce=nonce,
            merkle_root_precomputed=merkle,
            difficulty=diff,
            chainwork=cw,
        )

    # -----------------------------
    # MINING
    # -----------------------------

    def hash(self) -> bytes:
        if (
            self._cached_hash is not None
            and self._cached_hash_nonce == self.nonce
            and self._cached_hash_bits == self.bits
            and self._cached_hash_mr == self.merkle_root
            and self._cached_hash_prev == self.prev_block_hash
        ):
            return self._cached_hash

        try:
            h = pow_hash_verify_light(self.header(), key_hint=pow_key_for_height(self.height))
        except Exception:
            h = pow_hash_verify_light(self.header(), height=self.height)
        self._cached_hash = h
        self._cached_hash_nonce = self.nonce
        self._cached_hash_bits = self.bits
        self._cached_hash_mr = self.merkle_root
        self._cached_hash_prev = self.prev_block_hash
        return h

    def mine(self, use_cores: int | None = None, stop_event: Optional[MpEvent] = None, progress_queue: Optional[mp.Queue] = None):
        self.nonce = 0
        if stop_event is not None and stop_event.is_set():
            return None

        total_cores = mp.cpu_count()
        num_cores = min(max(1, use_cores or 1), total_cores)

        target = bits_to_target(self.bits)
        if target <= 0:
            return None

        pow_key = pow_key_for_height(self.height)
        if not pow_key:
            raise RuntimeError("RandomX key derivation failed; check RANDOMX_* configuration.")

        header_prefix = self.header()[:-4]
        target_be = int(target).to_bytes(32, "big", signed=False)

        found = native_randomx_mine(
            header_prefix,
            target_be,
            pow_key,
            threads=num_cores,
            full_mem=bool(CFG.RANDOMX_FULL_MEM),
            large_pages=bool(CFG.RANDOMX_LARGE_PAGES),
            jit=bool(CFG.RANDOMX_JIT),
            hard_aes=bool(CFG.RANDOMX_HARD_AES),
            secure_jit=bool(CFG.RANDOMX_SECURE_JIT),
            progress_queue=progress_queue,
            progress_interval_ms=250,
            stop_event=stop_event,
        )

        if found:
            nonce, h = found
            self.nonce = int(nonce)
            if pow_hash_verify_light(self.header(), key_hint=pow_key) != h:
                log.error("[mine] native hash verification failed (nonce=%s)", self.nonce)
                return None
            return h
        return None

    def __repr__(self):
        return (
            f"--- Block {self.height} ---\n"
            f"PrevHash : {self.prev_block_hash.hex()}\n"
            f"Hash     : {self.hash().hex()}\n"
            f"Time     : {time.ctime(self.timestamp)}\n"
            f"Nonce    : {self.nonce}\n"
            f"Tx Count : {len(self.transactions)}\n"
        )