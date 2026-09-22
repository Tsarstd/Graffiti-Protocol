# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — Miner RPC & Rate Limit Test Suite
=============================================
Reference: src/tsarchain/network/rpc/docs/MINER_RPC.MD

This script tests TsarChain miner RPC endpoints, P2P channel encryption (SecureChannel),
bootstrap authorization exceptions, and token-bucket rate limiting against a live node
(VPS target or local node runner).

Logs are saved automatically to 'logging/rpc_miner_test.log'.
"""

from __future__ import annotations

import time
import json
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
# Default to BOOTSTRAP_DEV configured in src/tsarchain/utils/config.py
TARGET_HOST = CFG.BOOTSTRAP_DEV[0][0] if CFG.BOOTSTRAP_DEV else "127.0.0.1"
TARGET_PORT = CFG.BOOTSTRAP_DEV[0][1] if CFG.BOOTSTRAP_DEV else 38169

# --- Burst & Throttling Parameters ---
# Default burst cap for MINER_INFO (HELLO) in config.py is 8 requests per 3 seconds.
BURST_COUNT_HELLO       = 12     # Number of rapid HELLO requests to fire (threshold: 8)
BURST_DELAY_MS          = 0.0    # Milliseconds delay between requests (0.0 for immediate flood)
COOLDOWN_WAIT_SEC       = 5.0    # Seconds to wait for token bucket refill after hitting rate limit

# --- Scenario Toggles ---
RUN_HANDSHAKE_TEST      = True   # Test P2P SecureChannel handshake (P2P_HS1 -> P2P_HS2)
RUN_HELLO_TEST          = True   # Test basic HELLO RPC handshake
RUN_GET_HEADERS_TEST    = True   # Test GET_HEADERS sync request
RUN_HELLO_BURST_TEST    = True   # Test rapid HELLO burst to verify SYNC_REJECT rate limiting
RUN_COOLDOWN_TEST       = True   # Test recovery after retry_after cooldown
RUN_UNAUTHORIZED_TEST   = False  # [WARNING] Tests protected RPC (GET_INFO) without miner key.
                                 # Setting True will cause the target to TEMP-BAN your IP for 180s!

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_miner_test_client"
CLIENT_ADVERTISED_PORT  = 38170

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.miner_rpc")


def _stamp() -> str:
    now = datetime.now()
    d = f"{now.year:04d}.{now.month:02d}.{now.day:02d}"
    t = f"{now.hour:02d}.{now.minute:02d}.{now.second:02d}"
    return f"{COL.BOLD}{COL.GREY} {d} {COL.RESET}{COL.BOLD}{COL.GREY} {t} {COL.RESET}"


def clog(message: str, color: str = COL.GREY):
    formatted = f"{_stamp()} : {color}{message}{COL.RESET}"
    print(formatted)
    # Strip ANSI escapes for file logging
    log.info(message)


# =============================================================================
# P2P CLIENT HELPER
# =============================================================================

class MinerRpcClient:
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
# TEST CASES
# =============================================================================

def run_test_suite(host: str, port: int, burst_count: int, delay_ms: float, cooldown_sec: float) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain Miner RPC & Rate Limit Test[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Burst Count : [bold magenta]{burst_count}[/bold magenta] requests (Cap: {CFG.MINER_INFO_RL_IP_BURST}/3s)\n"
        f"Log File    : [bold white]logging/rpc_miner_test.log[/bold white]",
        border_style="cyan"
    ))

    client = MinerRpcClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not establish P2P connection to target.", COL.RED)
        clog("Note: If the remote host recently banned your IP (180s), please wait for cooldown.", COL.YELLOW)
        return {"connection": False}

    results["connection"] = True

    try:
        # -------------------------------------------------------------
        # 1. HELLO RPC (Bootstrap Allowed)
        # -------------------------------------------------------------
        if RUN_HELLO_TEST:
            clog("--- [Test 1] Testing HELLO RPC (Bootstrap Allowed) ---", COL.YELLOW)
            hello_payload = {
                "type": "HELLO",
                "ip": "0.0.0.0",
                "port": CLIENT_ADVERTISED_PORT,
                "height": 0,
                "role": "NODE",
                "peers": [],
            }
            t0 = time.time()
            resp = client.send_rpc(hello_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("type") == "HELLO_RESPONSE":
                height = resp.get("height")
                peers = resp.get("peers", [])
                clog(f"PASS: HELLO_RESPONSE received in {dt:.1f}ms! Tip Height: {height}, Active Peers: {len(peers)}", COL.GREEN)
                log.info(f"HELLO response details: height={height}, peers_count={len(peers)}")
                results["hello"] = True
            else:
                clog(f"FAIL: Unexpected HELLO response: {resp}", COL.RED)
                results["hello"] = False

        # -------------------------------------------------------------
        # 2. GET_HEADERS RPC (Bootstrap Allowed)
        # -------------------------------------------------------------
        if RUN_GET_HEADERS_TEST:
            clog("--- [Test 2] Testing GET_HEADERS RPC (Bootstrap Allowed) ---", COL.YELLOW)
            headers_payload = {
                "type": "GET_HEADERS",
                "locator": [],
                "limit": 10,
            }
            t0 = time.time()
            resp = client.send_rpc(headers_payload)
            dt = (time.time() - t0) * 1000

            if resp and resp.get("type") == "HEADERS":
                headers = resp.get("headers", [])
                more = resp.get("more", False)
                best_h = resp.get("best_height", 0)
                clog(f"PASS: HEADERS received in {dt:.1f}ms! Returned {len(headers)} headers (best_height={best_h}, more={more})", COL.GREEN)
                log.info(f"HEADERS response: count={len(headers)}, best_height={best_h}, more={more}")
                results["get_headers"] = True
            else:
                clog(f"FAIL: Unexpected GET_HEADERS response: {resp}", COL.RED)
                results["get_headers"] = False

        # -------------------------------------------------------------
        # 3. HELLO Burst Rate Limiting Test
        # -------------------------------------------------------------
        if RUN_HELLO_BURST_TEST:
            clog(f"--- [Test 3] Testing Rate Limit Throttling on HELLO ({burst_count} rapid requests) ---", COL.YELLOW)
            burst_payload = {
                "type": "HELLO",
                "ip": "0.0.0.0",
                "port": CLIENT_ADVERTISED_PORT,
                "height": 0,
                "role": "NODE",
                "peers": [],
            }
            
            rate_limited_hit = False
            retry_after_val = 4.0

            for i in range(1, burst_count + 1):
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                t0 = time.time()
                resp = client.send_rpc(burst_payload)
                dt = (time.time() - t0) * 1000
                m_type = resp.get("type") if resp else "NO_RESPONSE"
                err = resp.get("error") if resp else None

                if resp and resp.get("type") == "SYNC_REJECT" and resp.get("error") == "rate_limited":
                    retry_after_val = float(resp.get("retry_after", 4.0))
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> RATE LIMITED! (type={m_type}, error={err}, retry_after={retry_after_val}s)", COL.CYAN)
                    rate_limited_hit = True
                    break
                else:
                    clog(f"  Req #{i:02d} [{dt:5.1f}ms] -> OK (type={m_type})", COL.GREY)

            if rate_limited_hit:
                clog("PASS: Rate limit (Token Bucket) correctly triggered SYNC_REJECT!", COL.GREEN)
                results["rate_limiting"] = True
            else:
                clog("WARN: Burst did not trigger rate limit (rate may have refilled or burst cap is higher).", COL.YELLOW)
                results["rate_limiting"] = False

            # -------------------------------------------------------------
            # 4. Backoff Cooldown & Recovery Test
            # -------------------------------------------------------------
            if RUN_COOLDOWN_TEST and rate_limited_hit:
                wait_sec = retry_after_val + 1.0
                clog(f"--- [Test 4] Testing Cooldown Recovery (Waiting {wait_sec:.1f}s)... ---", COL.YELLOW)
                time.sleep(wait_sec)

                t0 = time.time()
                resp = client.send_rpc(burst_payload)
                dt = (time.time() - t0) * 1000

                if resp and resp.get("type") == "HELLO_RESPONSE":
                    clog(f"PASS: Node accepted requests again after cooldown in {dt:.1f}ms!", COL.GREEN)
                    results["cooldown_recovery"] = True
                else:
                    clog(f"FAIL: Post-cooldown request failed: {resp}", COL.RED)
                    results["cooldown_recovery"] = False

        # -------------------------------------------------------------
        # 5. Unauthorized Miner Endpoint Test (Optional)
        # -------------------------------------------------------------
        if RUN_UNAUTHORIZED_TEST:
            clog("--- [Test 5] Testing Unauthorized Miner RPC Rejection (GET_INFO) ---", COL.YELLOW)
            clog("CAUTION: This will trigger a temporary 180s IP ban on the target node!", COL.RED)
            t0 = time.time()
            resp = client.send_rpc({"type": "GET_INFO"})
            dt = (time.time() - t0) * 1000
            
            if resp and resp.get("error") == "forbidden: miners-only endpoint":
                clog(f"PASS: Unauthorized miner endpoint correctly blocked with forbidden error in {dt:.1f}ms!", COL.GREEN)
                results["unauthorized_protection"] = True
            else:
                clog(f"UNEXPECTED: Response was {resp}", COL.YELLOW)
                results["unauthorized_protection"] = False

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
    clog(f"Full execution logs saved to 'logging/rpc_miner_test.log'.", COL.GREY)
    return results


# =============================================================================
# ENTRY POINT
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="TsarChain Miner RPC & Rate Limit Tester")
    parser.add_argument("--target", default=TARGET_HOST, help="Target node IP or hostname")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help="Target node P2P port")
    parser.add_argument("--burst", type=int, default=BURST_COUNT_HELLO, help="Number of burst requests for rate limiting")
    parser.add_argument("--delay", type=float, default=BURST_DELAY_MS, help="Delay between burst requests in ms")
    parser.add_argument("--cooldown", type=float, default=COOLDOWN_WAIT_SEC, help="Cooldown duration in seconds")
    parser.add_argument("--unauthorized", action="store_true", help="Include test for unauthorized protected endpoint (causes 180s temp ban)")
    return parser.parse_args()


def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_miner_test.log", force=True)
    args = parse_args()

    global RUN_UNAUTHORIZED_TEST
    if args.unauthorized:
        RUN_UNAUTHORIZED_TEST = True

    run_test_suite(
        host=args.target,
        port=args.port,
        burst_count=args.burst,
        delay_ms=args.delay,
        cooldown_sec=args.cooldown,
    )


if __name__ == "__main__":
    main()
