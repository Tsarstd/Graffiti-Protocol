# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP143; BIP141; BIP173; CompactSize; Merkle; libsecp256k1; LowS-Policy; Signal-X3DH

from __future__ import annotations

import os
import json
import string
import socket
import secrets
import hashlib
import contextlib
import unicodedata
from decimal import Decimal, InvalidOperation, ROUND_DOWN

from bech32 import bech32_decode, bech32_encode, convertbits
from ..utils import config as CFG

try:
    from tsarcore_native import (
        count_sigops as _native_count_sigops,
        hash160 as _native_hash160,
        hash256 as _native_hash256,
        merkle_root as _native_merkle_root,
        secp_verify_der_low_s_many as _native_verify_many,
        secp_sign_der_low_s as _native_sign_der_low_s,
        sighash_bip143 as _native_sighash_bip143,
        validate_block_txs_native as _native_validate_block_txs,
        validate_block_txs_compact as _native_validate_block_txs_compact,
        randomx_pow_hash as _native_randomx_hash,
        utxo_build_ops_compact as _native_utxo_build_ops_compact,
        serialize_tx_compact as _native_serialize_tx_compact,
        txid_from_compact as _native_txid_from_compact,
        wtxid_from_compact as _native_wtxid_from_compact,
        validate_tx_p2wpkh_compact as _native_validate_tx_p2wpkh_compact,
        randomx_mine as _native_randomx_mine,
)
except ImportError as exc:
    raise ImportError(
        "tsarcore_native is required: build/install the Rust extension to run TsarChain"
    ) from exc

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.utils.helpers")

SIGHASH_ALL = 1

# opcode constants
OP_0 = 0x00
OP_RETURN = 0x6a
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

OP_1 = 0x51
OP_16 = 0x60
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_EQUALVERIFY = 0x88
OP_CHECKMULTISIG = 0xAE
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIGVERIFY = 0xAF


# -----------------------------
# RANDOMX MINING ALGO
# -----------------------------


def _resolve_randomx_root() -> bytes:
    raw = (CFG.RANDOMX_STATIC_KEY or "").strip()
    if not raw:
        return b"tsar-randomx-dev"
    lowered = raw.lower()
    if lowered.startswith("0x"):
        lowered = lowered[2:]
    if lowered and len(lowered) % 2 == 0 and all(c in "0123456789abcdef" for c in lowered):
        return bytes.fromhex(lowered)
    return raw.encode("utf-8")


_RANDOMX_ROOT = _resolve_randomx_root()


def _pow_epoch(height: int | None) -> int:
    if height is None:
        return 0
    h = int(height)
    if h < 0:
        h = 0
    return h // CFG.RANDOMX_KEY_EPOCH_BLOCKS


def randomx_key_for_height(height: int | None = None) -> bytes:
    epoch = _pow_epoch(height)
    payload = _RANDOMX_ROOT + CFG.RANDOMX_KEY_SALT + epoch.to_bytes(8, "big", signed=False)
    return hashlib.sha256(payload).digest()


def pow_key_for_height(height: int | None = None) -> bytes:
    return randomx_key_for_height(height) if CFG.POW_ALGO == "randomx" else b""


def _randomx_hash_core(data: bytes, seed_bytes: bytes, *, full_mem: bool) -> bytes:
    cache_cap = max(1, int(CFG.RANDOMX_CACHE_MAX))
    return _native_randomx_hash(
        data,
        seed_bytes,
        bool(full_mem),
        bool(CFG.RANDOMX_LARGE_PAGES),
        bool(CFG.RANDOMX_JIT),
        bool(CFG.RANDOMX_HARD_AES),
        bool(CFG.RANDOMX_SECURE_JIT),
        cache_cap if cache_cap > 0 else 1,
    )


def _resolve_rx_full_mem(full_mem_override: bool | None) -> bool:
    """
    Resolution order:
      1) explicit function arg full_mem_override (if not None)
      2) CFG.RANDOMX_FULL_MEM
    """
    if full_mem_override is not None:
        return bool(full_mem_override)
    return bool(CFG.RANDOMX_FULL_MEM)


def pow_hash_miner(header: bytes, *, height: int | None = None, key_hint: bytes | None = None, full_mem_override: bool | None = None) -> bytes:
    """Hash for MINING. Can be full-mem according to override/CFG."""
    data = to_bytes(header)
    if CFG.POW_ALGO != "randomx":
        return hash256(data)
    seed = key_hint if key_hint is not None else randomx_key_for_height(height)
    fm = _resolve_rx_full_mem(full_mem_override)
    return _randomx_hash_core(data, bytes(seed), full_mem=fm)


def pow_hash_verify_light(header: bytes, *, height: int | None = None, key_hint: bytes | None = None) -> bytes:
    """Hash for VERIFICATION. Always LIGHT (no 2 GB dataset)."""
    data = to_bytes(header)
    if CFG.POW_ALGO != "randomx":
        return hash256(data)
    seed = key_hint if key_hint is not None else randomx_key_for_height(height)
    return _randomx_hash_core(data, bytes(seed), full_mem=False)


# -----------------------------
# SIGOPS UTIL
# -----------------------------


def extract_script_bytes(spk, _depth: int = 0) -> bytes | None:
    if spk is None or _depth > 3:
        return None
    if type(spk) in (bytes, bytearray):
        return bytes(spk)
    if type(spk) is str:
        try:
            return bytes.fromhex(spk)
        except ValueError:
            return None
    if type(spk) is dict:
        inner = spk.get("tx_out", spk.get("script_pubkey", spk.get("script")))
        return extract_script_bytes(inner, _depth + 1) if inner is not None else None

    try:
        spk_attr = spk.script_pubkey
        if spk_attr is not None:
            res = extract_script_bytes(spk_attr, _depth + 1)
            if res is not None:
                return res
    except AttributeError:
        pass

    try:
        tx_out_attr = spk.tx_out
        if tx_out_attr is not None:
            res = extract_script_bytes(tx_out_attr, _depth + 1)
            if res is not None:
                return res
    except AttributeError:
        pass

    try:
        ser = spk.serialize
        if callable(ser):
            res = ser()
            if type(res) in (bytes, bytearray):
                return bytes(res)
    except (AttributeError, TypeError):
        pass

    return None


def extract_utxo_amount(utxo_data) -> int | None:
    if utxo_data is None:
        return None
    if type(utxo_data) is dict:
        if "amount" in utxo_data:
            return int(utxo_data["amount"])
        if "tx_out" in utxo_data:
            txo = utxo_data["tx_out"]
            if type(txo) is dict:
                return int(txo.get("amount", 0))
            try:
                amt = txo.amount
                if amt is not None:
                    return int(amt)
            except AttributeError:
                pass
        return None
    try:
        amt = utxo_data.amount
        if amt is not None:
            return int(amt)
    except AttributeError:
        pass
    return None


def script_to_address(script) -> str | None:
    b = extract_script_bytes(script)
    if not b:
        return None
    if len(b) == 22 and b[0] == 0x00 and b[1] == 0x14:
        data = [0] + list(convertbits(b[2:], 8, 5, True))
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    if len(b) == 34 and b[0] == 0x00 and b[1] == 0x20:
        data = [0] + list(convertbits(b[2:], 8, 5, True))
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    return None


def to_bytes(x) -> bytes:
    try:
        return x.serialize()
    except (AttributeError, TypeError):
        pass
    if type(x) in (bytes, bytearray):
        return bytes(x)
    try:
        return bytes.fromhex(x)
    except (TypeError, ValueError):
        pass
    return b""


def read_push(script: bytes, i: int):
    if i >= len(script):
        return None, i
    op = script[i]; i += 1
    if op <= 0x4b:
        ln = op
    elif op == OP_PUSHDATA1:
        if i >= len(script): return None, i
        ln = script[i]; i += 1
    elif op == OP_PUSHDATA2:
        if i+1 >= len(script): return None, i
        ln = int.from_bytes(script[i:i+2], "little"); i += 2
    elif op == OP_PUSHDATA4:
        if i+3 >= len(script): return None, i
        ln = int.from_bytes(script[i:i+4], "little"); i += 4
    else:
        return (op, None), i-1
    data = script[i:i+ln]; i += ln
    return (None, data), i


def parse_ops(script: bytes):
    ops = []
    i = 0
    while i < len(script):
        b = script[i]
        if b <= 0x4b or b in (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4):
            item, i2 = read_push(script, i)
            if item is None:
                break
            ops.append(item); i = i2
        else:
            ops.append((b, None)); i += 1
    return ops


def is_p2wpkh(spk: bytes) -> bool:
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def is_p2wsh(spk: bytes) -> bool:
    return len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20


def last_pushdata(script_sig: bytes) -> bytes | None:
    ops = parse_ops(script_sig)
    for op, data in reversed(ops):
        if op is None and data is not None:
            return data
    return None


# -----------------------------
# ENDIANNESS
# -----------------------------


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'little')


# -----------------------------
# HASHING
# -----------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash160(b: bytes) -> bytes:
    return bytes(_native_hash160(bytes(b)))


def hash256(data: bytes) -> bytes:
    return bytes(_native_hash256(bytes(data)))


# -----------------------------
# DECODE SIG
# -----------------------------


def decode_address(address: str) -> bytes:
    hrp, data = bech32_decode(address)
    if hrp != CFG.ADDRESS_PREFIX:
        raise ValueError(f"Invalid address prefix: expected '{CFG.ADDRESS_PREFIX}', got '{hrp}'")
    if not data:
        raise ValueError("Invalid Bech32 address: no data")
    witver = data[0]
    if witver != 0:
        raise ValueError(f"Unsupported witness version: {witver}")
    decoded = convertbits(data[1:], 5, 8, False)
    if len(decoded) not in (20, 32):
        raise ValueError(f"Invalid witness program length: {len(decoded)} (expected 20 or 32)")
    return bytes(decoded)


def spkhex_to_address(spk_hex) -> str | None:
    if spk_hex is None:
        return None
    if type(spk_hex) in (bytes, bytearray):
        spk_hex = bytes(spk_hex).hex()
    elif type(spk_hex) is not str:
        try:
            spk_hex = spk_hex.hex()
        except (AttributeError, TypeError):
            spk_hex = str(spk_hex)
    spk_hex = str(spk_hex).lower()
    if spk_hex.startswith("0014") and len(spk_hex) == 44:
        prog = bytes.fromhex(spk_hex[4:])
        data = [0] + convertbits(list(prog), 8, 5, True)
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    if spk_hex.startswith("0020") and len(spk_hex) == 68:
        prog = bytes.fromhex(spk_hex[4:])
        data = [0] + convertbits(list(prog), 8, 5, True)
        return bech32_encode(CFG.ADDRESS_PREFIX, data)
    return None


# --- Compact bits <-> target (kanonik & unsigned) ---


def bits_to_target(bits: int) -> int:
    exp  = (bits >> 24) & 0xff
    mant = bits & 0x007fffff
    if exp >= 3:
        return mant << (8 * (exp - 3))
    else:
        return mant >> (8 * (3 - exp))


def target_to_bits(target: int) -> int:
    if target <= 0:
        target = 1
    exp = (target.bit_length() + 7) // 8
    if exp <= 3:
        mant = target << (8 * (3 - exp))
        exp = 3
    else:
        shift = 8 * (exp - 3)
        mant = target >> shift
        if mant & 0x00800000:
            mant >>= 8
            exp += 1
    mant &= 0x007fffff
    return (exp << 24) | mant


DIFFICULTY_CONST = (1 << 256) 


def target_to_difficulty(target: int) -> int:
    t = max(1, int(target))
    return DIFFICULTY_CONST // t


def difficulty_to_target(diff: int) -> int:
    d = max(1, int(diff))
    return max(1, DIFFICULTY_CONST // d)


# ========== Low-level serializers ===========

def serialize_tx(tx, include_witness: bool = True) -> bytes:
    compact = tx_to_compact_tuple(tx)
    return serialize_tx_compact(compact, include_witness)


def compute_tx_weight_vsize(tx) -> tuple[int, int, int, int]:
    """
    Returns (weight, vsize, base_size, total_size) using witness/non-witness serialization.
    weight = base*3 + total (BIP141); vsize = ceil(weight/4).
    """
    raw_base = serialize_tx(tx, include_witness=False)
    raw_full = serialize_tx(tx, include_witness=True)
    base_size = len(raw_base)
    total_size = len(raw_full)
    weight = (base_size * 3) + total_size
    vsize = (weight + 3) // 4
    return weight, vsize, base_size, total_size


def _estimate_tx_size_bytes(tx) -> int:
    to_storage = tx.to_storage_bytes
    if callable(to_storage):
        raw = to_storage()
        if type(raw) in (bytes, bytearray):
            return len(raw)
    size = 10
    inputs = tx.inputs or []
    for txin in inputs:
        size += 40
        script_sig = txin.script_sig
        if script_sig:
            size += len(script_sig.serialize())

        witness = txin.witness
        if witness:
            size += sum(len(w) for w in witness)

    outputs = tx.outputs or []
    for txout in outputs:
        size += 8
        spk = txout.script_pubkey
        if spk:
            size += len(spk.serialize())
    return int(size)


def estimate_block_size_bytes(block) -> int:
    to_storage_block = block.to_storage_bytes
    if callable(to_storage_block):
        raw = to_storage_block()
        if type(raw) in (bytes, bytearray):
            return len(raw)

    txs = block.transactions or []
    total = 108  # 80 bytes header + 24 bytes metadata + 4 bytes tx count
    for tx in txs:
        to_storage = tx.to_storage_bytes
        if callable(to_storage):
            raw = to_storage()
            if type(raw) in (bytes, bytearray):
                total += 4 + len(raw)
                continue

        if tx.inputs is not None and tx.outputs is not None:
            total += 4 + _estimate_tx_size_bytes(tx)
        else:
            total += 4 + len(json.dumps(tx))
    return int(total)


# ====== Block Id (Voice Sovereignty flavored) ======


def _ascii_slug(s: str, maxlen: int = 32) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    s = "".join(ch if ch.isalnum() else "_" for ch in s)
    while "__" in s:
        s = s.replace("__", "_")
    s = s.strip("_")
    if not s:
        s = "unnamed"
    return s[:maxlen] if maxlen else s


def block_id_generator(length: int = 9, with_year: bool = True) -> str:
    chars = string.ascii_letters + string.digits
    rand = "".join(secrets.choice(chars) for _ in range(length))

    name, year = secrets.choice(CFG.VOICE_SOVEREIGNTY_FIGURES)
    name_slug = _ascii_slug(name, 24)
    year_part = (f"{year}_" if (with_year and year) else "")

    patterns = [
        f"{name_slug}_{year_part}{rand}",
        f"{year_part}_{name_slug}{rand}",
    ]
    
    for p in patterns:
        if len(p) <= 48:
            return p
    return patterns[0][:48]


# ========== Script Class ==========

class Script:

    def __init__(self, cmds: list = None):
        self.cmds = list(cmds) if cmds else []


    @staticmethod
    def _encode_pushdata(b: bytes) -> bytes:
        n = len(b)
        if n <= 75:
            return bytes([n]) + b
        elif n <= 255:
            return b'\x4c' + bytes([n]) + b
        elif n <= 65535:
            return b'\x4d' + n.to_bytes(2, 'little') + b 
        else:
            return b'\x4e' + n.to_bytes(4, 'little') + b 


    @classmethod
    def _read_push_or_opcode(cls, first: int, data: bytes, i: int):
        
        if 1 <= first <= 75:
            n = first
            end = i + n
            if end > len(data):
                raise ValueError("script short read (small push)")
            return data[i:end], end

        if first == OP_0:
            return OP_0, i

        if first == OP_PUSHDATA1:
            if i + 1 > len(data):
                raise ValueError("script short read (PUSHDATA1 header)")
            n = data[i]
            i += 1
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA1 payload)")
            return data[i:end], end

        if first == OP_PUSHDATA2:
            if i + 2 > len(data):
                raise ValueError("script short read (PUSHDATA2 header)")
            n = int.from_bytes(data[i:i+2], 'little')
            i += 2
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA2 payload)")
            return data[i:end], end

        if first == OP_PUSHDATA4:
            if i + 4 > len(data):
                raise ValueError("script short read (PUSHDATA4 header)")
            n = int.from_bytes(data[i:i+4], 'little')
            i += 4
            end = i + n
            if end > len(data):
                raise ValueError("script short read (PUSHDATA4 payload)")
            return data[i:end], end

        return first, i
    
    
    @staticmethod
    def build_opreturn_script(data: bytes, max_bytes: int) -> str:
        if len(data) > max_bytes:
            raise ValueError("opreturn_too_large")
        b = bytearray([OP_RETURN])
        n = len(data)
        if n <= 75:
            b.append(n); b.extend(data)
        elif n <= 255:
            b.append(OP_PUSHDATA1); b.append(n); b.extend(data)
        elif n <= 520:
            b.append(OP_PUSHDATA2); b.extend(n.to_bytes(2, "little")); b.extend(data)
        else:
            raise ValueError("opreturn_exceeds_520_bytes")
        return b.hex()


    def to_hex(self) -> str:
        return self.serialize().hex()


    def serialize(self) -> bytes:
        out = bytearray()
        for cmd in self.cmds:
            try:
                out.append(cmd & 0xff)  # opcode (int)
            except TypeError:
                try:
                    out += self._encode_pushdata(bytes(cmd))
                except Exception:
                    raise TypeError(f"Unsupported script cmd type: {type(cmd)}")
        return bytes(out)


    @classmethod
    def deserialize(cls, data: bytes) -> 'Script':
        cmds = []
        i = 0
        n = len(data)
        while i < n:
            first = data[i]
            i += 1
            item, i = cls._read_push_or_opcode(first, data, i)
            cmds.append(item)
        return cls(cmds)


    @classmethod
    def parse(cls, raw_bytes: bytes) -> 'Script':
        return cls.deserialize(raw_bytes)


    def to_dict(self):
        cmds_serializable = []
        for cmd in self.cmds:
            try:
                cmds_serializable.append(cmd.hex())
            except AttributeError:
                cmds_serializable.append(cmd)
        return {'cmds': cmds_serializable}


    @classmethod
    def from_dict(cls, data: dict) -> 'Script':
        cmds = []
        for cmd in data.get('cmds', []):
            try:
                cmds.append(bytes.fromhex(cmd))
            except (TypeError, ValueError):
                cmds.append(cmd)
        return cls(cmds)

    # ---------------------------
    # Helpers
    # ---------------------------
    @staticmethod
    def p2wpkh_script(address: str):
        pubkey_hash = decode_address(address)
        return Script([OP_0, pubkey_hash])

    @staticmethod
    def p2wsh_script(address: str):
        prog = decode_address(address)
        return Script([OP_0, prog])


# ===========================================================================
# Native acceleration (Rust)
# ===========================================================================


def count_sigops_in_script(script: bytes) -> int:
    data = to_bytes(script)
    if not data:
        return 0
    return int(_native_count_sigops(data))


def batch_verify_der_low_s(items, enforce_low_s: bool = True, parallel: bool = True):
    return list(_native_verify_many(items, enforce_low_s, parallel))


def bip143_sig_hash(tx, input_index: int, script_code: bytes, value: int, sighash: int = SIGHASH_ALL) -> bytes:
    tx_bytes = serialize_tx(tx, include_witness=True)
    script = to_bytes(script_code)
    digest32 = _native_sighash_bip143(
        tx_bytes,
        int(input_index),
        script,
        int(value),
        int(sighash),
    )
    return bytes(digest32)


def sign_digest_der_low_s_native(priv_hex: str, digest32: bytes) -> bytes:
    try:
        d_bytes = bytes(digest32)
        if len(d_bytes) != 32:
            raise ValueError("digest32 must be 32-byte")
    except TypeError:
        raise ValueError("digest32 must be 32-byte")
    return bytes(_native_sign_der_low_s(priv_hex, d_bytes))


def merkle_root(transactions) -> bytes:
    if not transactions:
        return b"\x00" * 32
    txids = [tx if type(tx) in (bytes, bytearray) else tx.txid for tx in transactions]
    return bytes(_native_merkle_root(txids))


def native_validate_block_txs(block_dict: dict, utxo_snapshot: dict, spend_height: int, options: dict):
    return _native_validate_block_txs(block_dict, utxo_snapshot, int(spend_height), options)


def native_validate_block_txs_compact(block_txs, utxo_items, spend_height: int, options: dict):
    return _native_validate_block_txs_compact(block_txs, utxo_items, int(spend_height), options)


def native_validate_tx_p2wpkh_compact(tx_tuple, utxo_items, spend_height: int, options: dict):
    return _native_validate_tx_p2wpkh_compact(tx_tuple, utxo_items, int(spend_height), options)


def native_utxo_build_ops_compact(block_txs, spend_height: int):
    return _native_utxo_build_ops_compact(block_txs, int(spend_height))


# =======================
# Codec helpers (compact native tx serializer)
# =======================


def serialize_tx_compact(tx_tuple, include_witness: bool = True) -> bytes:
    return bytes(_native_serialize_tx_compact(tx_tuple, bool(include_witness)))


def txid_from_compact(tx_tuple) -> bytes:
    return bytes(_native_txid_from_compact(tx_tuple))


def wtxid_from_compact(tx_tuple) -> bytes:
    return bytes(_native_wtxid_from_compact(tx_tuple))


def parse_amount_sats(raw: str | int | float | Decimal, default: int = 0, *, min_sats: int = 0) -> int:
    """Parse TSAR amount into atomic satoshis safely and accurately."""
    if raw is None or raw == "":
        return int(default)
    if type(raw) is int:
        sats = int(raw)
    elif type(raw) is Decimal:
        sats = int((raw * Decimal(CFG.TSAR)).to_integral_value(rounding=ROUND_DOWN))
    else:
        txt = str(raw).strip().replace(" ", "").replace("_", "").replace(",", ".")
        if not txt:
            return int(default)
        if txt.startswith("."):
            txt = "0" + txt
        try:
            dec = Decimal(txt)
        except InvalidOperation as exc:
            raise ValueError(f"Format jumlah tidak valid: {raw}") from exc
        if dec <= 0:
            if dec == 0 and int(default) == 0:
                return 0
            raise ValueError("Amount must be > 0.")
        quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
        dec_q = dec.quantize(quant, rounding=ROUND_DOWN)
        sats = int(dec_q * Decimal(CFG.TSAR))
        if sats <= 0:
            raise ValueError("Jumlah terlalu kecil")

    if min_sats > 0 and sats < min_sats:
        raise ValueError(f"Amount terlalu kecil (< {min_sats} sat, dust).")
    return sats


def connect_tcp_socket(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    """Create and connect a TCP socket with a specified timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, int(port)))
    return s


def clean_remove_file(file_path: str | None) -> bool:
    """Safely remove a file ignoring missing file errors without swallowing other exceptions."""
    if not file_path:
        return False
    with contextlib.suppress(FileNotFoundError, OSError):
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
    return False


def tx_to_compact_tuple(tx) -> tuple:
    version = int(tx.version) if tx.version is not None else 1
    locktime = int(tx.locktime) if tx.locktime is not None else 0
    inputs_c = [
        (
            to_bytes(txin.txid if txin.txid is not None else txin.prev_tx) or b"",
            int(txin.vout if txin.vout is not None else txin.prev_index or 0),
            int(txin.sequence if txin.sequence is not None else 0xFFFFFFFF),
            extract_script_bytes(txin.script_sig) or b"",
            [to_bytes(w) for w in (txin.witness or []) if w is not None],
        )
        for txin in (tx.inputs or [])
    ]
    outputs_c = [
        (
            int(txout.amount or 0),
            extract_script_bytes(txout.script_pubkey) or extract_script_bytes(txout) or b"",
        )
        for txout in (tx.outputs or [])
    ]
    is_cb = bool(tx.is_coinbase)
    tx_tuple = (version, locktime, inputs_c, outputs_c, b"\x00" * 32, is_cb)
    txid = txid_from_compact(tx_tuple)
    return (version, locktime, inputs_c, outputs_c, txid, is_cb)


# =======================
# Mining (RandomX)
# =======================


def native_randomx_mine(
    header_prefix: bytes,
    target_be: bytes,
    key: bytes,
    threads: int = 0,
    *,
    full_mem: bool = False,
    large_pages: bool = False,
    jit: bool = True,
    hard_aes: bool = True,
    secure_jit: bool = False,
    progress_queue=None,
    progress_interval_ms: int | None = None,
    stop_event=None,
):
    """
    Native RandomX miner. header_prefix must be 76-byte header without nonce.
    target_be must be 32-byte big-endian target.
    Returns (nonce, hash) or None if not found.
    """
    return _native_randomx_mine(
        bytes(header_prefix),
        bytes(target_be),
        bytes(key),
        int(threads),
        bool(full_mem),
        bool(large_pages),
        bool(jit),
        bool(hard_aes),
        bool(secure_jit),
        progress_queue,
        progress_interval_ms if progress_interval_ms is None else int(progress_interval_ms),
        stop_event,
    )