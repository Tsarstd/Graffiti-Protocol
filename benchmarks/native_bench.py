# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP143; BIP141; Merkle; libsecp256k1; LowS-Policy

import time
import secrets
import argparse

import tsarchain.utils.helpers as H
from typing import List, Tuple
from ecdsa import SigningKey, VerifyingKey, SECP256k1, util as ecdsa_util

from tsarchain.core.block import Block
from tsarchain.utils.helpers import Script
from tsarchain.core.coinbase import CoinbaseTx
from tsarchain.core.tx import Tx, TxIn, TxOut
from tsarchain.utils import config as CFG
from kremlin.security.data_security import pubkey_from_privhex, pubkey_to_tsar_address


def _configure_randomx_pow(use_lite: bool, cache_cap: int):
    """Tune RandomX config for tests (default to lite mode)."""
    cache_cap = max(1, cache_cap)
    if use_lite:
        CFG.RANDOMX_FULL_MEM = False
        CFG.RANDOMX_LARGE_PAGES = False
        CFG.RANDOMX_CACHE_MAX = cache_cap
    else:
        CFG.RANDOMX_FULL_MEM = True
        CFG.RANDOMX_CACHE_MAX = cache_cap

    H._RANDOMX_EPOCH_BLOCKS = max(1, int(CFG.RANDOMX_KEY_EPOCH_BLOCKS))
    H._RANDOMX_SALT = (CFG.RANDOMX_KEY_SALT or "tsar-randomx").decode("utf-8")
    H._RANDOMX_ROOT = H._resolve_randomx_root()
    mode = "lite" if use_lite else "full"
    print(f"[randomx] configured {mode} mode (cache_max={CFG.RANDOMX_CACHE_MAX})")


# -----------------------------
# Utilities
# -----------------------------

def human(n):
    try:
        return f"{int(n):,}".replace(",", ".")
    except Exception:
        return str(n)

def hx(b: bytes, n: int = 64) -> str:
    if not isinstance(b, (bytes, bytearray)):
        try:
            b = bytes(b)
        except Exception:
            return str(b)
    s = b.hex()
    return s if len(s) <= n else s[:n] + "…"

def _make_low_s_der(sk: SigningKey, digest32: bytes) -> bytes:
    rb, sb = sk.sign_digest(digest32, sigencode=ecdsa_util.sigencode_strings)
    r = int.from_bytes(rb, "big")
    s = int.from_bytes(sb, "big")
    n = SECP256k1.order
    if s > n // 2:
        s = n - s
    return ecdsa_util.sigencode_der(r, s, n)

def _make_high_s_from_low_der(der_low: bytes) -> bytes:
    r, s = ecdsa_util.sigdecode_der(der_low, SECP256k1.order)
    n = SECP256k1.order
    if s <= n // 2:
        s = n - s
    return ecdsa_util.sigencode_der(r, s, n)

def is_signature_canonical_low_s(der_sig: bytes) -> bool:
    try:
        _, s = ecdsa_util.sigdecode_der(der_sig, SECP256k1.order)
        return 1 <= s <= SECP256k1.order // 2
    except Exception:
        return False

from tsarcore_native import secp_verify_der_low_s

def _vk_bytes_uncompressed(vk: VerifyingKey) -> bytes:
    return b"\x04" + vk.to_string()

def verify_der_strict_low_s(vk: VerifyingKey, digest32: bytes, der_sig: bytes) -> bool:
    pub = _vk_bytes_uncompressed(vk)
    return bool(secp_verify_der_low_s(pub, bytes(digest32), bytes(der_sig)))

HASH256_ABC = bytes.fromhex("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
HASH160_ABC = bytes.fromhex("bb1be98c142444d7a56aa3981c3942a978e4dc33")

MERKLE_SAMPLE_TXIDS = [bytes([i]) * 32 for i in range(3)]
MERKLE_SAMPLE_ROOT = bytes.fromhex("d6384640762f797ede7e7f13839222f9452272809932cc6089f701331df4552d")

BIP143_PREV_TXID = bytes.fromhex("11" * 32)
BIP143_SCRIPT_CODE = b"\x76\xa9\x14" + bytes.fromhex("44" * 20) + b"\x88\xac"
BIP143_EXPECTED_DIGEST = bytes.fromhex("ad701ad662d18e8ee1324071611ed61e4391d1dfb5596a8a86aecbf8e93ed924")

# -----------------------------
# Native block validation helpers/tests
# -----------------------------

def _make_test_address(priv_hex: str) -> Tuple[str, bytes]:
    pubkey = pubkey_from_privhex(priv_hex)
    address = pubkey_to_tsar_address(pubkey)
    return address, pubkey


def _build_p2wpkh_block():
    priv_hex = secrets.token_hex(32)
    address, pubkey = _make_test_address(priv_hex)

    prev_txid = secrets.token_bytes(32)
    prev_amount = 50_000_000
    fee = 1_000
    spend_amount = prev_amount - fee

    prev_output = TxOut(amount=prev_amount, script_pubkey=Script.p2wpkh_script(address))
    spend_input = TxIn(
        txid=prev_txid,
        vout=0,
        amount=prev_amount,
        script_sig=Script([]),
    )
    spend_tx = Tx(
        inputs=[spend_input],
        outputs=[TxOut(amount=spend_amount, script_pubkey=Script.p2wpkh_script(address))],
        locktime=0,
        is_coinbase=False,
    )
    spend_tx.sign_input(0, priv_hex, prev_output, prev_amount)

    reward = int(CFG.INITIAL_REWARD)
    coinbase = CoinbaseTx(
        to_address=address,
        reward=reward + fee,
        height=1,
    )
    prev_hash = CFG.ZERO_HASH
    if isinstance(prev_hash, str):
        prev_hash = bytes.fromhex(prev_hash)
    block = Block(
        height=1,
        prev_block_hash=prev_hash,
        transactions=[coinbase, spend_tx],
        bits=CFG.INITIAL_BITS,
        timestamp=int(time.time()),
    )
    snapshot = {
        f"{prev_txid.hex()}:0": {
            "tx_out": {
                "amount": prev_amount,
                "script_pubkey": prev_output.script_pubkey.serialize().hex(),
            },
            "is_coinbase": False,
            "block_height": 0,
        }
    }
    return block, snapshot, spend_tx, fee

def _native_opts():
    return {
        "coinbase_maturity": int(CFG.COINBASE_MATURITY),
        "max_sigops_per_tx": int(CFG.MAX_SIGOPS_PER_TX),
        "max_sigops_per_block": int(CFG.MAX_SIGOPS_PER_BLOCK),
        "max_block_bytes": int(CFG.MAX_BLOCK_BYTES),
        "max_tx_vsize": int(CFG.MAX_TX_VSIZE),
        "max_tx_weight": int(CFG.MAX_TX_WEIGHT),
        "max_tx_inputs": int(CFG.MAX_TX_INPUTS),
        "max_tx_outputs": int(CFG.MAX_TX_OUTPUTS),
        "min_tx_weight": int(CFG.MIN_TX_WEIGHT),
        "min_tx_vsize": int(CFG.MIN_TX_VSIZE),
        "enforce_low_s": True,
    }

def test_native_block_validator_accepts_valid_block():
    block, snapshot, _, fee = _build_p2wpkh_block()
    opts = _native_opts()
    ok, reason, fees = H.native_validate_block_txs(
        block.to_dict(),
        snapshot,
        block.height,
        opts,
    )
    assert ok, f"native validator rejected block: {reason}"
    assert fees == [fee], "fee projection mismatch"


def test_native_block_validator_detects_invalid_witness():
    block, snapshot, spend_tx, _ = _build_p2wpkh_block()
    # Corrupt witness pubkey so hash mismatch occurs
    spend_tx.inputs[0].witness[1] = b"\x02" + b"\x01" * 32
    opts = _native_opts()
    ok, reason, _ = H.native_validate_block_txs(
        block.to_dict(),
        snapshot,
        block.height,
        opts,
    )
    assert not ok, "tampered witness should fail native validation"
    assert reason, "failure should include reason"


def test_native_block_validator_detects_immature_coinbase():
    block, snapshot, _, _ = _build_p2wpkh_block()
    entry = next(iter(snapshot.values()))
    entry["is_coinbase"] = True
    entry["block_height"] = block.height
    ok, reason, _ = H.native_validate_block_txs(
        block.to_dict(),
        snapshot,
        block.height,
        _native_opts(),
    )
    assert not ok, "immature coinbase spend must be rejected"
    assert isinstance(reason, str) and reason.startswith("coinbase_immature"), f"unexpected reason: {reason}"


def test_native_block_validator_requires_witness():
    block, snapshot, spend_tx, _ = _build_p2wpkh_block()
    spend_tx.inputs[0].witness = []
    opts = _native_opts()
    opts['min_tx_vsize'] = 0
    opts['min_tx_weight'] = 0
    ok, reason, _ = H.native_validate_block_txs(
        block.to_dict(),
        snapshot,
        block.height,
        opts,
    )
    assert not ok
    assert reason and "witness" in reason.lower(), f"Expected witness-related error, got {reason}"


def test_native_block_validator_rejects_unsupported_script():
    block, snapshot, _, _ = _build_p2wpkh_block()
    entry = next(iter(snapshot.values()))
    entry["tx_out"]["script_pubkey"] = ("76a914" + "11" * 20 + "88ac").lower()
    ok, reason, _ = H.native_validate_block_txs(
        block.to_dict(),
        snapshot,
        block.height,
        _native_opts(),
    )
    assert not ok
    assert reason == "unsupported_script"


def run_block_validation_checks():
    scenarios = [
        ("valid block", test_native_block_validator_accepts_valid_block),
        ("invalid witness", test_native_block_validator_detects_invalid_witness),
        ("immature coinbase", test_native_block_validator_detects_immature_coinbase),
        ("missing witness", test_native_block_validator_requires_witness),
        ("unsupported script", test_native_block_validator_rejects_unsupported_script),
    ]
    for label, fn in scenarios:
        fn()
        print(f"[block] {label}: ok")


# -----------------------------
# Micro-bench functions
# -----------------------------

def bench_sigops(iters: int) -> float:
    scripts = [b"\xac", b"\x51\xae", b"\x60\xae"]  # CHECKSIG; 1 CHECKMULTISIG; 16 CHECKMULTISIG
    t0 = time.perf_counter()
    s = 0
    for i in range(iters):
        s += H.count_sigops_in_script(scripts[i % 3])
    dt = time.perf_counter() - t0
    assert s >= 0
    return dt

def bench_merkle(n_txids: int, reps: int) -> float:
    txids = [secrets.token_bytes(32) for _ in range(n_txids)]
    t0 = time.perf_counter()
    last = None
    for _ in range(reps):
        last = H.merkle_root(txids)
    dt = time.perf_counter() - t0
    assert isinstance(last, (bytes, bytearray)) and len(last) == 32
    return dt

def bench_verify_ecdsa(num_keys: int, iters: int) -> float:
    vectors = []
    for _ in range(num_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        assert is_signature_canonical_low_s(der)
        vectors.append((vk, d, der))

    # sanity
    for (vk, d, der) in vectors[:min(5, len(vectors))]:
        ok = verify_der_strict_low_s(vk, d, der)
        assert ok

    t0 = time.perf_counter()
    ok_count = 0
    for i in range(iters):
        vk, d, der = vectors[i % num_keys]
        if verify_der_strict_low_s(vk, d, der):
            ok_count += 1
    dt = time.perf_counter() - t0
    assert ok_count >= 0
    return dt

def bench_verify_batch(num_keys: int, iters: int) -> float:
    vecs = []
    for _ in range(num_keys):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        vecs.append((vk, d, der))

    items = [(_vk_bytes_uncompressed(vk), d, der) for (vk, d, der) in vecs]
    singles = [verify_der_strict_low_s(vk, d, der) for (vk, d, der) in vecs]
    batch_once = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
    assert list(map(bool, batch_once)) == list(map(bool, singles)), "batch != single result"

    t0 = time.perf_counter()
    cnt = 0
    for _ in range(max(1, iters // num_keys)):
        res = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
        cnt += sum(1 for x in res if x)
    dt = time.perf_counter() - t0
    assert cnt >= 0
    return dt

def bench_hashes(total_bytes: int = 2_000_000) -> Tuple[float, float]:
    blobs = []
    left = total_bytes
    while left > 0:
        n = min(left, secrets.randbelow(4096) + 1)
        blobs.append(secrets.token_bytes(n))
        left -= n

    t0 = time.perf_counter()
    for b in blobs:
        _ = H.hash256(b)
    dt256 = time.perf_counter() - t0

    t0 = time.perf_counter()
    for b in blobs:
        _ = H.hash160(b)
    dt160 = time.perf_counter() - t0

    return dt256, dt160


# -----------------------------
# Correctness tests
# -----------------------------

def check_hash_vectors():
    assert H.hash256(b"abc") == HASH256_ABC
    assert H.hash160(b"abc") == HASH160_ABC

def check_merkle_vector():
    root = H.merkle_root(MERKLE_SAMPLE_TXIDS)
    assert isinstance(root, (bytes, bytearray)) and len(root) == 32
    assert root == MERKLE_SAMPLE_ROOT
    empty_root = H.merkle_root([])
    assert isinstance(empty_root, (bytes, bytearray)) and len(empty_root) == 32 and set(empty_root) <= {0}

def check_verify_low_s():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    d = secrets.token_bytes(32)
    der_low = _make_low_s_der(sk, d)
    der_high = _make_high_s_from_low_der(der_low)
    assert verify_der_strict_low_s(vk, d, der_low) is True
    assert verify_der_strict_low_s(vk, d, der_high) is False

def check_batch_matches_single(num: int = 64):
    vecs = []
    for _ in range(num):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        d = secrets.token_bytes(32)
        der = _make_low_s_der(sk, d)
        vecs.append((vk, d, der))

    singles = [verify_der_strict_low_s(vk, d, der) for (vk, d, der) in vecs]

    items = [(_vk_bytes_uncompressed(vk), d, der) for (vk, d, der) in vecs]
    batch = H.batch_verify_der_low_s(items, enforce_low_s=True, parallel=True)
    assert list(map(bool, batch)) == list(map(bool, singles)), "batch != single result"

# ---- BIP143 SIGHASH (ALL) parity test ----

class _RawScript:
    def __init__(self, b: bytes): self.b = bytes(b)
    def serialize(self) -> bytes: return self.b

class _TxIn:
    def __init__(self, txid: bytes, vout: int, script_sig: _RawScript = None, sequence: int = 0xffffffff, witness=None):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig or _RawScript(b"")
        self.sequence = sequence
        self.witness = witness or []

class _TxOut:
    def __init__(self, amount: int, script_pubkey: _RawScript):
        self.amount = int(amount)
        self.script_pubkey = script_pubkey

class _Tx:
    def __init__(self, version: int, inputs: List[_TxIn], outputs: List[_TxOut], locktime: int = 0, is_coinbase: bool = False):
        self.version = int(version)
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = int(locktime)
        self.is_coinbase = bool(is_coinbase)

def check_bip143_vector():
    inp = _TxIn(txid=BIP143_PREV_TXID, vout=1, script_sig=_RawScript(b""))
    spk1 = _RawScript(b"\x00\x14" + bytes.fromhex("22" * 20))
    spk2 = _RawScript(b"\x00\x14" + bytes.fromhex("33" * 20))
    out1 = _TxOut(50_000, spk1)
    out2 = _TxOut(30_000, spk2)
    tx = _Tx(version=2, inputs=[inp], outputs=[out1, out2], locktime=0)

    digest_native = H.bip143_sig_hash(tx, 0, BIP143_SCRIPT_CODE, value=50_000, sighash=H.SIGHASH_ALL)
    assert isinstance(digest_native, (bytes, bytearray)) and len(digest_native) == 32
    assert digest_native == BIP143_EXPECTED_DIGEST, "BIP143 digest mismatch vs known vector"


# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="TsarChain native test (correctness + microbench)")
    ap.add_argument("--sigops-iters", type=int, default=250_000)
    ap.add_argument("--merkle-n", type=int, default=1_000)
    ap.add_argument("--merkle-reps", type=int, default=200)
    ap.add_argument("--ecdsa-keys", type=int, default=200)
    ap.add_argument("--ecdsa-iters", type=int, default=5_000)
    ap.add_argument("--batch-keys", type=int, default=256)
    ap.add_argument("--batch-iters", type=int, default=2_048)
    ap.add_argument("--hash-total", type=int, default=1_500_000, help="total bytes for hash benches")
    ap.add_argument("--no-bench-batch", action="store_true")
    ap.add_argument("--no-bench-hash", action="store_true")
    ap.add_argument("--randomx-cache", type=int, default=1, help="max RandomX VM cache entries during tests (default: 1)")
    gx = ap.add_mutually_exclusive_group()
    gx.add_argument("--randomx-lite", dest="randomx_lite", action="store_true", help="force RandomX light mode (default)")
    gx.add_argument("--randomx-full", dest="randomx_lite", action="store_false", help="use full-memory RandomX dataset (slow, ~2GB)")
    ap.set_defaults(randomx_lite=True)
    args = ap.parse_args()

    _configure_randomx_pow(args.randomx_lite, args.randomx_cache)

    print("Native backend is mandatory; helpers module imported tsarcore_native successfully.")
    print("Functions available:", [x for x in (
        "count_sigops_in_script", "bip143_sig_hash",
        "merkle_root", "hash256", "hash160", "batch_verify_der_low_s"
    ) if getattr(H, x, None) is not None])

    # -------- correctness --------
    print("\n== correctness checks ==")
    check_hash_vectors()
    print("[ok] hash256/hash160 vectors")

    check_merkle_vector()
    print("[ok] merkle root deterministic vector")

    check_verify_low_s()
    print("[ok] verify_der_strict_low_s (low-S true, high-S false)")

    check_batch_matches_single()
    print("[ok] batch_verify_der_low_s == single verify")

    check_bip143_vector()
    print("[ok] bip143_sig_hash known vector (SIGHASH_ALL)")

    print("\n== native block validation ==")
    run_block_validation_checks()

    # -------- microbenches --------
    print("\n== microbench ==")
    dt = bench_sigops(args.sigops_iters)
    rate = args.sigops_iters / dt
    print(f"[sigops] {human(args.sigops_iters)} loops in {dt:.3f}s -> {human(int(rate))} ops/s")

    dt = bench_merkle(args.merkle_n, args.merkle_reps)
    rate = args.merkle_reps / dt
    print(f"[merkle] {args.merkle_reps} trees (n={args.merkle_n}) in {dt:.3f}s -> {rate:.1f} trees/s")

    dt = bench_verify_ecdsa(args.ecdsa_keys, args.ecdsa_iters)
    rate = args.ecdsa_iters / dt
    print(f"[ecdsa-single] {human(args.ecdsa_iters)} verifications in {dt:.3f}s -> {human(int(rate))} verif/s")

    if not args.no_bench_batch:
        dt = bench_verify_batch(args.batch_keys, args.batch_iters)
        total_verifs = (args.batch_iters // max(1, args.batch_keys)) * args.batch_keys
        rate = max(1, total_verifs) / dt if dt > 0 else 0
        print(f"[ecdsa-batch] ~{human(total_verifs)} verifications in {dt:.3f}s -> ~{human(int(rate))} verif/s")

    if not args.no_bench_hash:
        dt256, dt160 = bench_hashes(args.hash_total)
        print(f"[hash256] {human(args.hash_total)}B in {dt256:.3f}s")
        print(f"[hash160] {human(args.hash_total)}B in {dt160:.3f}s")


if __name__ == "__main__":
    main()
