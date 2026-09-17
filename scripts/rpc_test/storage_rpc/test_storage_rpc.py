# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — Storage RPC Test Suite
==================================
Reference: src/tsarchain/network/rpc/docs/STORAGE_RPC.MD

This script tests TsarChain Storage RPC endpoints (STORAGE_RPC_TYPES):
1. HELLO (role: "NODE_STORAGE") : Archivist storage node registration & pubkey pinning
2. GRAFFITI_PROOF_SUBMIT        : Proof of Retention (PoR) submission & verification pipeline
3. GRAFFITI_BUILD_PAYOUT        : Payout transaction builder for verified storer proofs
4. Storage Anti-Replay Guard    : ts + nonce replay window validation
5. Storage Rate Limiting        : Token-bucket throttling (Cap: 30 requests / 60s)
6. Cooldown Recovery            : Token-bucket refill verification after backoff

Execution logs are saved automatically to 'logging/rpc_storage_test.log'.
"""

from __future__ import annotations

import sys
import time
import json
import socket
import argparse
from datetime import datetime
from bech32 import bech32_encode, convertbits
from rich.console import Console
from rich.panel import Panel

# ---------------- Local Project ----------------
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
from tsarchain.miner.cosmetic import interface as COL
from tsarchain.miner.cosmetic.tui import _enable_windows_vt100
from tsarchain.network.protocol import (
    SecureChannel,
    build_envelope,
    verify_and_unwrap,
    load_or_create_keypair_at,
    is_envelope,
)

# =============================================================================
# SCENARIO CONFIGURATION (EDIT HERE TO CUSTOMIZE TEST PARAMETERS)
# =============================================================================

# --- Target Node ---
TARGET_HOST = CFG.BOOTSTRAP_DEV[0][0] if CFG.BOOTSTRAP_DEV else "127.0.0.1"
TARGET_PORT = CFG.BOOTSTRAP_DEV[0][1] if CFG.BOOTSTRAP_DEV else 38169

# --- Archivist / Storer Parameters ---
STORER_PORT               = 39200  # Simulated storage node listen port
STORER_URL                = "http://127.0.0.1:39200"
SAMPLE_ART_ID             = "0" * 64  # Valid 64-character hex art_id for testing pipelines

# --- Burst & Throttling Parameters ---
# Default burst cap for STORAGE_RPC in config.py is 30 requests per 60 seconds.
BURST_COUNT_STORAGE       = 35     # Requests fired in rate-limit flood test (Cap: 30/60s)
BURST_DELAY_MS            = 0.0    # Milliseconds delay between requests (0.0 for immediate flood)
COOLDOWN_WAIT_SEC         = 4.5    # Seconds to wait for backoff cooldown (Backoff: 3s)

# --- Scenario Toggles ---
RUN_UNAUTHORIZED_TEST     = True   # Test calling storage RPC without NODE_STORAGE registration
RUN_REGISTRATION_TEST     = True   # Test HELLO registration with role: "NODE_STORAGE"
RUN_REPLAY_GUARD_TEST     = True   # Test anti-replay guard (missing ts & nonce)
RUN_PROOF_SUBMIT_TEST     = True   # Test GRAFFITI_PROOF_SUBMIT pipeline
RUN_BUILD_PAYOUT_TEST     = True   # Test GRAFFITI_BUILD_PAYOUT validation
RUN_RATE_LIMIT_TEST       = True   # Test storage token-bucket throttling (rate_limited)
RUN_COOLDOWN_TEST         = True   # Test token bucket recovery after cooldown

# --- Client Identity ---
CLIENT_KEY_NAME           = "rpc_storage_test_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.storage_rpc")


def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"{COL.BOLD}{COL.GREY} {d} {COL.RESET}{COL.BOLD}{COL.GREY} {t} {COL.RESET}"


def clog(message: str, color: str = COL.GREY):
    formatted = f"{_stamp()} : {color}{message}{COL.RESET}"
    print(formatted)
    log.info(message)


# =============================================================================
# STORAGE RPC CLIENT HELPER
# =============================================================================

class StorageRpcClient:
    def __init__(self, host: str, port: int, key_name: str = CLIENT_KEY_NAME):
        self.host = str(host)
        self.port = int(port)
        self.key_name = key_name
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at(key_name)
        
        # Derive canonical Bech32 storer payout address from pubkey
        pkh = hash160(bytes.fromhex(self.pubkey))
        data = [0] + list(convertbits(pkh, 8, 5, True))
        self.storer_addr = bech32_encode(CFG.ADDRESS_PREFIX, data)

        self.node_ctx = {
            "net_id": CFG.DEFAULT_NET_ID,
            "node_id": self.node_id,
            "pubkey": self.pubkey,
            "privkey": self.privkey,
        }
        self.sock: socket.socket | None = None
        self.chan: SecureChannel | None = None
        self.peer_node_id: str | None = None
        self.peer_pubkey: str | None = None

    def connect(self, timeout: float = 6.0) -> bool:
        clog(f"Connecting TCP to {self.host}:{self.port} (timeout={timeout}s)...", COL.CYAN)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        try:
            s.connect((self.host, self.port))
            self.sock = s
            clog("TCP connection established. Initializing SecureChannel handshake...", COL.CYAN)

            self.chan = SecureChannel(
                s,
                role="client",
                node_id=self.node_id,
                node_pub=self.pubkey,
                node_priv=self.privkey,
            )
            self.chan.handshake()
            self.peer_node_id = self.chan.peer_node_id
            self.peer_pubkey = self.chan.peer_node_pub
            clog(f"SecureChannel established! Remote node_id: {self.peer_node_id}", COL.GREEN)
            log.info(f"Handshake success: remote_id={self.peer_node_id}, remote_pub={self.peer_pubkey}")
            return True
        except Exception as e:
            clog(f"Failed to connect / handshake with {self.host}:{self.port}: {e}", COL.RED)
            log.exception("Connection or handshake error")
            if s:
                s.close()
            self.sock = None
            self.chan = None
            return False

    def send_rpc(self, payload: dict, timeout: float = 5.0) -> dict | None:
        if not self.chan:
            clog("Error: Channel is not connected!", COL.RED)
            return None

        env = build_envelope(payload, self.node_ctx, extra={"pubkey": self.pubkey})
        encoded_env = json.dumps(env).encode("utf-8")

        try:
            self.chan.send(encoded_env)
            raw = self.chan.recv(timeout=timeout)
            if not raw:
                log.warning("Received empty frame from peer")
                return None

            outer = json.loads(raw.decode("utf-8"))
            if is_envelope(outer):
                inner = verify_and_unwrap(outer, lambda qnid: self.peer_pubkey)
                return inner
            return outer
        except Exception as e:
            log.warning(f"Error during Storage RPC {payload.get('type')}: {e}")
            return None

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.chan = None


# =============================================================================
# TEST SUITE
# =============================================================================

def run_storage_test_suite(host: str, port: int, burst_count: int, delay_ms: float, cooldown_sec: float) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain Storage RPC Test Suite (STORAGE_RPC_TYPES)[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Burst Count : [bold magenta]{burst_count}[/bold magenta] requests (Cap: {CFG.STORAGE_RPC_RL_IP_BURST}/60s)\n"
        f"Log File    : [bold white]logging/rpc_storage_test.log[/bold white]",
        border_style="cyan"
    ))

    # -------------------------------------------------------------
    # 1. Unauthorized Storage RPC Rejection Test (Fresh Unregistered Client)
    # -------------------------------------------------------------
    if RUN_UNAUTHORIZED_TEST:
        clog("--- [Test 1] Testing Storage Authorization Guard (Unregistered Sender) ---", COL.YELLOW)
        unauth_client = StorageRpcClient(host, port, key_name="unregistered_storage_probe")
        if unauth_client.connect():
            try:
                unauth_payload = {
                    "type": "GRAFFITI_PROOF_SUBMIT",
                    "art_id": SAMPLE_ART_ID,
                    "epoch": 0,
                    "height": 0,
                    "storer": unauth_client.storer_addr,
                    "offset": 0,
                    "length": 1024,
                    "hash": "0" * 64,
                    "seed": "seed",
                    "chunk": "aGVsbG8=",
                    "port": STORER_PORT,
                    "ts": int(time.time()),
                    "nonce": f"nonce_unauth_{time.time()}",
                }
                t0 = time.time()
                resp = unauth_client.send_rpc(unauth_payload)
                dt = (time.time() - t0) * 1000

                if resp and resp.get("error") == "forbidden: storage-only endpoint":
                    clog(f"PASS: Unregistered storage RPC correctly rejected with forbidden error in {dt:.1f}ms!", COL.GREEN)
                    log.info(f"Unregistered storage access rejected: {resp}")
                    results["unauthorized_protection"] = True
                else:
                    clog(f"FAIL: Expected forbidden: storage-only endpoint, got {resp}", COL.RED)
                    results["unauthorized_protection"] = False
            finally:
                unauth_client.close()
        else:
            results["unauthorized_protection"] = False

    # -------------------------------------------------------------
    # Connect Primary Test Client
    # -------------------------------------------------------------
    client = StorageRpcClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not establish P2P connection to target.", COL.RED)
        return {"connection": False}

    results["connection"] = True

    try:
        # -------------------------------------------------------------
        # 2. Storage Node Registration (HELLO with role: "NODE_STORAGE")
        # -------------------------------------------------------------
        if RUN_REGISTRATION_TEST:
            clog("--- [Test 2] Testing Storage Node Registration via HELLO ---", COL.YELLOW)
            clog(f"Registering storer address: {client.storer_addr}", COL.CYAN)
            reg_payload = {
                "type": "HELLO",
                "role": "NODE_STORAGE",
                "port": STORER_PORT,
                "address": client.storer_addr,
                "url": STORER_URL,
                "height": 0,
                "peers": [],
            }
            t0 = time.time()
            resp = client.send_rpc(reg_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("type") == "HELLO_RESPONSE":
                tip_h = resp.get("height")
                clog(f"PASS: Storage node registered successfully in {dt:.1f}ms! Tip Height: {tip_h}", COL.GREEN)
                log.info(f"NODE_STORAGE registered: tip_height={tip_h}")
                results["storage_registration"] = True
            else:
                clog(f"FAIL: Storage registration failed: {resp}", COL.RED)
                results["storage_registration"] = False

        # -------------------------------------------------------------
        # 3. Anti-Replay Guard Test (ts & nonce validation)
        # -------------------------------------------------------------
        if RUN_REPLAY_GUARD_TEST:
            clog("--- [Test 3] Testing Anti-Replay Guard (Missing ts & nonce) ---", COL.YELLOW)
            t0 = time.time()
            resp_missing = client.send_rpc({
                "type": "GRAFFITI_PROOF_SUBMIT",
                "port": STORER_PORT,
            })
            dt = (time.time() - t0) * 1000

            if resp_missing and resp_missing.get("error") == "replay_guard":
                clog(f"PASS: Missing ts/nonce rejected with 'replay_guard' in {dt:.1f}ms!", COL.GREEN)
                log.info("Replay guard passed for missing parameters")
                results["replay_guard"] = True
            else:
                clog(f"FAIL: Expected replay_guard for missing nonce, got: {resp_missing}", COL.RED)
                results["replay_guard"] = False

        # -------------------------------------------------------------
        # 4. GRAFFITI_PROOF_SUBMIT Pipeline Test
        # -------------------------------------------------------------
        if RUN_PROOF_SUBMIT_TEST:
            clog(f"--- [Test 4] Testing GRAFFITI_PROOF_SUBMIT Pipeline (art_id: {SAMPLE_ART_ID[:16]}...) ---", COL.YELLOW)
            proof_payload = {
                "type": "GRAFFITI_PROOF_SUBMIT",
                "art_id": SAMPLE_ART_ID,
                "epoch": 0,
                "height": 0,
                "storer": client.storer_addr,
                "offset": 0,
                "length": 65536,
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "seed": "0" * 64,
                "chunk": "aGVsbG8=",
                "port": STORER_PORT,
                "ts": int(time.time()),
                "nonce": f"nonce_proof_{time.time()}",
            }
            t0 = time.time()
            resp = client.send_rpc(proof_payload)
            dt = (time.time() - t0) * 1000

            # Since the art_id doesn't exist on-chain, valid verification accurately returns 'unknown_art_id'
            if resp and resp.get("error") in ("unknown_art_id", "registry_unavailable"):
                clog(f"PASS: Proof verification pipeline executed in {dt:.1f}ms! Registry status: {resp.get('error')}", COL.GREEN)
                log.info(f"GRAFFITI_PROOF_SUBMIT pipeline response: {resp}")
                results["proof_submit"] = True
            elif resp and resp.get("status") == "ok":
                clog(f"PASS: Proof accepted in {dt:.1f}ms! Status: ok", COL.GREEN)
                results["proof_submit"] = True
            else:
                clog(f"UNEXPECTED: Response was {resp}", COL.YELLOW)
                results["proof_submit"] = False

        # -------------------------------------------------------------
        # 5. GRAFFITI_BUILD_PAYOUT Pipeline Test
        # -------------------------------------------------------------
        if RUN_BUILD_PAYOUT_TEST:
            clog(f"--- [Test 5] Testing GRAFFITI_BUILD_PAYOUT Pipeline (art_id: {SAMPLE_ART_ID[:16]}...) ---", COL.YELLOW)
            payout_payload = {
                "type": "GRAFFITI_BUILD_PAYOUT",
                "art_id": SAMPLE_ART_ID,
                "epoch": 0,
                "recipients": [{"addr": client.storer_addr, "amount": 5000}],
                "fee_rate": 2,
                "broadcast": False,
                "port": STORER_PORT,
                "ts": int(time.time()),
                "nonce": f"nonce_payout_{time.time()}",
            }
            t0 = time.time()
            resp = client.send_rpc(payout_payload)
            dt = (time.time() - t0) * 1000

            # Without verified proof on-chain for this art, valid check returns 'missing_proof'
            if resp and resp.get("error") in ("missing_proof", "epoch_in_future", "utxo_unavailable"):
                clog(f"PASS: Payout builder pipeline executed in {dt:.1f}ms! Status: {resp.get('error')}", COL.GREEN)
                log.info(f"GRAFFITI_BUILD_PAYOUT response: {resp}")
                results["build_payout"] = True
            elif resp and resp.get("status") == "ok":
                clog(f"PASS: Payout built successfully in {dt:.1f}ms! Status: ok", COL.GREEN)
                results["build_payout"] = True
            else:
                clog(f"UNEXPECTED: Response was {resp}", COL.YELLOW)
                results["build_payout"] = False

        # -------------------------------------------------------------
        # 6. Storage Rate Limiting Test (Cap: 30 requests / 60s)
        # -------------------------------------------------------------
        if RUN_RATE_LIMIT_TEST:
            clog(f"--- [Test 6] Testing Storage Token-Bucket Rate Limiting ({burst_count} rapid requests, Cap: 30/60s) ---", COL.YELLOW)
            rate_limited_hit = False

            for i in range(1, burst_count + 1):
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                t0 = time.time()
                resp = client.send_rpc({
                    "type": "GRAFFITI_BUILD_PAYOUT",
                    "art_id": SAMPLE_ART_ID,
                    "epoch": 0,
                    "recipients": [{"addr": client.storer_addr, "amount": 5000}],
                    "fee_rate": 2,
                    "broadcast": False,
                    "port": STORER_PORT,
                    "ts": int(time.time()),
                    "nonce": f"nonce_flood_{i}_{time.time()}",
                })
                dt = (time.time() - t0) * 1000
                err = resp.get("error") if resp else "NO_RESPONSE"

                if resp and resp.get("error") == "rate_limited":
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> RATE LIMITED! (error=rate_limited)", COL.CYAN)
                    rate_limited_hit = True
                    break
                else:
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> OK ({err})", COL.GREY)

            if rate_limited_hit:
                clog("PASS: Storage Token Bucket correctly triggered rate_limited rejection at cap threshold!", COL.GREEN)
                results["rate_limiting"] = True
            else:
                clog("WARN: Storage burst did not trigger rate limit (burst cap may be refilled or higher).", COL.YELLOW)
                results["rate_limiting"] = False

            # -------------------------------------------------------------
            # 7. Cooldown Recovery Test
            # -------------------------------------------------------------
            if RUN_COOLDOWN_TEST and rate_limited_hit:
                clog(f"--- [Test 7] Testing Cooldown Recovery (Waiting {cooldown_sec:.1f}s)... ---", COL.YELLOW)
                time.sleep(cooldown_sec)

                t0 = time.time()
                resp = client.send_rpc({
                    "type": "GRAFFITI_BUILD_PAYOUT",
                    "art_id": SAMPLE_ART_ID,
                    "epoch": 0,
                    "recipients": [{"addr": client.storer_addr, "amount": 5000}],
                    "fee_rate": 2,
                    "broadcast": False,
                    "port": STORER_PORT,
                    "ts": int(time.time()),
                    "nonce": f"nonce_recovery_{time.time()}",
                })
                dt = (time.time() - t0) * 1000

                if resp and resp.get("error") != "rate_limited":
                    clog(f"PASS: Node accepted requests again after cooldown in {dt:.1f}ms! Status: {resp.get('error')}", COL.GREEN)
                    results["cooldown_recovery"] = True
                else:
                    clog(f"FAIL: Still rate limited after cooldown: {resp}", COL.RED)
                    results["cooldown_recovery"] = False

    finally:
        client.close()

    # Summary
    clog("================================================================", COL.CYAN)
    clog("STORAGE RPC TEST SUMMARY RESULTS:", COL.BOLD)
    for test_name, status in results.items():
        tag = "PASS" if status else "FAIL"
        color = COL.GREEN if status else COL.RED
        clog(f"  - {test_name.ljust(25)} : {tag}", color)
    clog("================================================================", COL.CYAN)
    clog("Full execution logs saved to 'logging/rpc_storage_test.log'.", COL.GREY)
    return results


# =============================================================================
# ENTRY POINT
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain Storage RPC & Rate Limit Tester")
    parser.add_argument("--target", default=TARGET_HOST, help="Target node IP or hostname")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help="Target node P2P port")
    parser.add_argument("--burst", type=int, default=BURST_COUNT_STORAGE, help="Number of burst requests for rate limiting")
    parser.add_argument("--delay", type=float, default=BURST_DELAY_MS, help="Delay between burst requests in ms")
    parser.add_argument("--cooldown", type=float, default=COOLDOWN_WAIT_SEC, help="Cooldown duration in seconds")
    return parser.parse_args()


def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_storage_test.log", force=True)
    args = parse_args()

    run_storage_test_suite(
        host=args.target,
        port=args.port,
        burst_count=args.burst,
        delay_ms=args.delay,
        cooldown_sec=args.cooldown,
    )


if __name__ == "__main__":
    main()
