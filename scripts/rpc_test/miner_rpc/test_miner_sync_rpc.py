# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — Miner Sync & Propagation RPC Test Suite
===================================================
Reference: src/tsarchain/network/rpc/docs/MINER_RPC.MD

This script tests the 4 protected Miner RPC protocols:
1. GET_BLOCK_HASH : Retrieve block hash at a given height (Rate Limit: 8/3s)
2. GET_BLOCKS     : Download packed binary storage blocks by height list (Rate Limit: 50/5s)
3. NEW_BLOCK       : Broadcast and propagate newly mined block binary (Rate Limit: 16/5s)
4. MEMPOOL         : Push and synchronize unconfirmed transaction batch (Rate Limit: 6/10s)

All tests execute through authenticated P2P SecureChannel (AEAD AES-256-GCM).
Execution logs are saved automatically to 'logging/rpc_miner_sync_test.log'.
"""

from __future__ import annotations

import sys
import time
import json
import base64
import struct
import socket
import argparse
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

# ---------------- Local Project ----------------
from tsarchain.utils import config as CFG
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
from tsarchain.miner.cosmetic import interface as COL
from tsarchain.miner.cosmetic.tui import _enable_windows_vt100
from tsarchain.core.block import Block
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

# --- Test Heights & Payloads ---
SAMPLE_BLOCK_HEIGHT       = 0      # Height used for GET_BLOCK_HASH and GET_BLOCKS tests
CLIENT_ADVERTISED_PORT    = 38170  # Port advertised in NEW_BLOCK / MEMPOOL payloads

# --- Burst & Throttling Parameters ---
BURST_COUNT_HASH          = 10     # Burst requests for GET_BLOCK_HASH (Cap: 8/3s)
BURST_COUNT_MEMPOOL       = 8      # Burst requests for MEMPOOL (Cap: 6/10s)
BURST_DELAY_MS            = 0.0    # Milliseconds delay between burst requests (0.0 for immediate flood)
COOLDOWN_WAIT_SEC         = 5.0    # Seconds to wait for token bucket refill

# --- Scenario Toggles ---
RUN_GET_BLOCK_HASH_TEST   = True   # Test 1: GET_BLOCK_HASH endpoint
RUN_GET_BLOCKS_TEST       = True   # Test 2: GET_BLOCKS endpoint & block deserialization
RUN_NEW_BLOCK_TEST        = True   # Test 3: NEW_BLOCK endpoint
RUN_MEMPOOL_TEST          = True   # Test 4: MEMPOOL endpoint
RUN_BURST_RATE_LIMIT_TEST = True   # Test 5: Rate limit throttling on MEMPOOL or GET_BLOCK_HASH
RUN_COOLDOWN_TEST         = True   # Test 6: Recovery after rate-limit backoff

# --- Client Identity ---
CLIENT_KEY_NAME           = "rpc_miner_sync_test_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.miner_sync")


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
# P2P CLIENT HELPER
# =============================================================================

class MinerSyncClient:
    def __init__(self, host: str, port: int, key_name: str = CLIENT_KEY_NAME):
        self.host = str(host)
        self.port = int(port)
        self.key_name = key_name
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at(key_name)
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
            log.warning(f"Error during RPC {payload.get('type')}: {e}")
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

def run_sync_test_suite(host: str, port: int, height: int, burst_mempool: int, burst_hash: int) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain Miner Sync & Propagation RPC Test[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Sample Height: [bold magenta]{height}[/bold magenta]\n"
        f"Log File    : [bold white]logging/rpc_miner_sync_test.log[/bold white]",
        border_style="cyan"
    ))

    client = MinerSyncClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not establish P2P connection to target.", COL.RED)
        clog("Note: If the remote host recently banned your IP, please wait for cooldown.", COL.YELLOW)
        return {"connection": False}

    results["connection"] = True

    cached_block_bytes: bytes | None = None
    cached_block_hash: str | None = None

    try:
        # -------------------------------------------------------------
        # 1. GET_BLOCK_HASH RPC
        # -------------------------------------------------------------
        if RUN_GET_BLOCK_HASH_TEST:
            clog(f"--- [Test 1] Testing GET_BLOCK_HASH RPC (Height: {height}) ---", COL.YELLOW)
            hash_payload = {
                "type": "GET_BLOCK_HASH",
                "height": height,
            }
            t0 = time.time()
            resp = client.send_rpc(hash_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("type") == "BLOCK_HASH" and resp.get("hash"):
                h_val = resp.get("height")
                hx = resp.get("hash")
                cache_hit = resp.get("cache_hit", False)
                clog(f"PASS: BLOCK_HASH received in {dt:.1f}ms! Height: {h_val}, Hash: {hx} (cache_hit={cache_hit})", COL.GREEN)
                log.info(f"GET_BLOCK_HASH details: height={h_val}, hash={hx}, cache_hit={cache_hit}")
                cached_block_hash = hx
                results["get_block_hash"] = True
            else:
                clog(f"FAIL: Unexpected GET_BLOCK_HASH response: {resp}", COL.RED)
                results["get_block_hash"] = False

        # -------------------------------------------------------------
        # 2. GET_BLOCKS RPC
        # -------------------------------------------------------------
        if RUN_GET_BLOCKS_TEST:
            clog(f"--- [Test 2] Testing GET_BLOCKS RPC (Heights: [{height}]) ---", COL.YELLOW)
            blocks_payload = {
                "type": "GET_BLOCKS",
                "heights": [height],
            }
            t0 = time.time()
            resp = client.send_rpc(blocks_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("type") == "BLOCKS_BIN" and resp.get("data"):
                count = int(resp.get("count", 0))
                b64_data = resp.get("data", "")
                bin_data = base64.b64decode(b64_data)
                
                # Unpack [4-byte LE length] + [raw_storage_bytes]
                if len(bin_data) >= 4:
                    blen = struct.unpack("<I", bin_data[:4])[0]
                    raw_block = bin_data[4:4 + blen]
                    parsed_block = Block.from_storage_bytes(raw_block)
                    cached_block_bytes = raw_block
                    b_hx = parsed_block.hash().hex()
                    clog(f"PASS: BLOCKS_BIN received in {dt:.1f}ms! Unpacked {count} block(s). Block {height} Hash: {b_hx}", COL.GREEN)
                    log.info(f"GET_BLOCKS success: height={parsed_block.height}, hash={b_hx}, txs={len(parsed_block.transactions)}")
                    results["get_blocks"] = True
                else:
                    clog("FAIL: Empty or malformed block binary payload received", COL.RED)
                    results["get_blocks"] = False
            else:
                clog(f"FAIL: Unexpected GET_BLOCKS response: {resp}", COL.RED)
                results["get_blocks"] = False

        # -------------------------------------------------------------
        # 3. NEW_BLOCK RPC
        # -------------------------------------------------------------
        if RUN_NEW_BLOCK_TEST:
            clog("--- [Test 3] Testing NEW_BLOCK RPC (Broadcast Announcement) ---", COL.YELLOW)
            if not cached_block_bytes:
                clog("Retrieving Block 0 binary to use for NEW_BLOCK announcement...", COL.CYAN)
                res_b = client.send_rpc({"type": "GET_BLOCKS", "heights": [0]})
                if res_b and res_b.get("data"):
                    bin_raw = base64.b64decode(res_b["data"])
                    blen = struct.unpack("<I", bin_raw[:4])[0]
                    cached_block_bytes = bin_raw[4:4 + blen]
                    b_temp = Block.from_storage_bytes(cached_block_bytes)
                    cached_block_hash = b_temp.hash().hex()

            if cached_block_bytes and cached_block_hash:
                new_block_payload = {
                    "type": "NEW_BLOCK",
                    "data": base64.b64encode(cached_block_bytes).decode("ascii"),
                    "hash": cached_block_hash,
                    "port": CLIENT_ADVERTISED_PORT,
                }
                t0 = time.time()
                resp = client.send_rpc(new_block_payload)
                dt = (time.time() - t0) * 1000

                if resp and resp.get("status") == "ok":
                    clog(f"PASS: NEW_BLOCK announcement accepted in {dt:.1f}ms! Status: ok", COL.GREEN)
                    log.info(f"NEW_BLOCK accepted for hash={cached_block_hash}")
                    results["new_block"] = True
                else:
                    clog(f"FAIL: NEW_BLOCK rejected or unexpected response: {resp}", COL.RED)
                    results["new_block"] = False
            else:
                clog("SKIP: Could not obtain block binary for NEW_BLOCK test", COL.YELLOW)
                results["new_block"] = False

        # -------------------------------------------------------------
        # 4. MEMPOOL RPC
        # -------------------------------------------------------------
        if RUN_MEMPOOL_TEST:
            clog("--- [Test 4] Testing MEMPOOL RPC (Mempool Push Batch) ---", COL.YELLOW)
            mempool_payload = {
                "type": "MEMPOOL",
                "data": [],
                "port": CLIENT_ADVERTISED_PORT,
            }
            t0 = time.time()
            resp = client.send_rpc(mempool_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("status") == "mempool received":
                clog(f"PASS: MEMPOOL batch pushed in {dt:.1f}ms! Status: {resp.get('status')}", COL.GREEN)
                log.info("MEMPOOL push succeeded")
                results["mempool"] = True
            else:
                clog(f"FAIL: Unexpected MEMPOOL response: {resp}", COL.RED)
                results["mempool"] = False

        # -------------------------------------------------------------
        # 5. Rate Limit Throttling on MEMPOOL (Cap: 6/10s)
        # -------------------------------------------------------------
        if RUN_BURST_RATE_LIMIT_TEST:
            clog(f"--- [Test 5] Testing Rate Limit Throttling on MEMPOOL ({burst_mempool} rapid requests, Cap: 6/10s) ---", COL.YELLOW)
            burst_payload = {
                "type": "MEMPOOL",
                "data": [],
                "port": CLIENT_ADVERTISED_PORT,
            }
            rate_limited_hit = False
            retry_after_val = 6.0

            for i in range(1, burst_mempool + 1):
                t0 = time.time()
                resp = client.send_rpc(burst_payload)
                dt = (time.time() - t0) * 1000
                m_type = resp.get("type") if resp else "NO_RESPONSE"
                err = resp.get("error") if resp else None
                status = resp.get("status") if resp else None

                if resp and resp.get("type") == "SYNC_REJECT" and resp.get("error") == "rate_limited":
                    retry_after_val = float(resp.get("retry_after", 6.0))
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> RATE LIMITED! (type={m_type}, error={err}, retry_after={retry_after_val}s)", COL.CYAN)
                    rate_limited_hit = True
                    break
                else:
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> OK (status={status})", COL.GREY)

            if rate_limited_hit:
                clog("PASS: MEMPOOL Rate limit (Token Bucket) correctly triggered SYNC_REJECT!", COL.GREEN)
                results["mempool_rate_limiting"] = True
            else:
                clog("WARN: MEMPOOL burst did not trigger rate limit (burst cap may be refilled or higher).", COL.YELLOW)
                results["mempool_rate_limiting"] = False

            # -------------------------------------------------------------
            # 6. Cooldown Recovery Test
            # -------------------------------------------------------------
            if RUN_COOLDOWN_TEST and rate_limited_hit:
                wait_sec = retry_after_val + 1.0
                clog(f"--- [Test 6] Testing Cooldown Recovery (Waiting {wait_sec:.1f}s)... ---", COL.YELLOW)
                time.sleep(wait_sec)

                t0 = time.time()
                resp = client.send_rpc(burst_payload)
                dt = (time.time() - t0) * 1000

                if resp and resp.get("status") == "mempool received":
                    clog(f"PASS: Node accepted MEMPOOL push again after cooldown in {dt:.1f}ms!", COL.GREEN)
                    results["cooldown_recovery"] = True
                else:
                    clog(f"FAIL: Post-cooldown request failed: {resp}", COL.RED)
                    results["cooldown_recovery"] = False

    finally:
        client.close()

    # Summary
    clog("================================================================", COL.CYAN)
    clog("TEST SUMMARY RESULTS:", COL.BOLD)
    for test_name, status in results.items():
        tag = "PASS" if status else "FAIL"
        color = COL.GREEN if status else COL.RED
        clog(f"  - {test_name.ljust(25)} : {tag}", color)
    clog("================================================================", COL.CYAN)
    clog("Full execution logs saved to 'logging/rpc_miner_sync_test.log'.", COL.GREY)
    return results


# =============================================================================
# ENTRY POINT
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain Miner Sync & Propagation Tester")
    parser.add_argument("--target", default=TARGET_HOST, help="Target node IP or hostname")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help="Target node P2P port")
    parser.add_argument("--height", type=int, default=SAMPLE_BLOCK_HEIGHT, help="Sample block height for GET_BLOCKS / GET_BLOCK_HASH")
    parser.add_argument("--burst-mempool", type=int, default=BURST_COUNT_MEMPOOL, help="Burst requests for MEMPOOL rate limit test")
    parser.add_argument("--burst-hash", type=int, default=BURST_COUNT_HASH, help="Burst requests for GET_BLOCK_HASH rate limit test")
    return parser.parse_args()


def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_miner_sync_test.log", force=True)
    args = parse_args()

    run_sync_test_suite(
        host=args.target,
        port=args.port,
        height=args.height,
        burst_mempool=args.burst_mempool,
        burst_hash=args.burst_hash,
    )


if __name__ == "__main__":
    main()
