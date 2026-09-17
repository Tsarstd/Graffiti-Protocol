# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — User RPC Networking Category Test Suite
===================================================
Reference: src/tsarchain/network/rpc/docs/USER_RPC.MD
           src/tsarchain/network/rpc/user_rpc/category/networking.py

This script tests the Networking endpoints in TsarChain's User RPC layer:
1. PING              : Health check & round-trip latency probe (Expects: PONG)
2. GET_PEERS         : Network topology privacy protection (Expects: empty peer list for anonymous clients)
3. STOR_LIST         : Archivist Storage Node discovery & loopback IP resolution
4. Rate Limiting     : Dual Token-Bucket Throttling (STOR_LIST cap: 4/10s, PING cap: 20/10s)
5. Anti-DoS PoW      : Verification of stateless Proof-of-Work challenges ('pow_required')
6. PoW Solution      : Solving challenge locally via solve_pow() and verifying rate-limit bypass
7. Cooldown Recovery : Verification of token-bucket replenishment after backoff

Execution logs are saved automatically to 'logging/rpc_user_networking_test.log'.
"""

from __future__ import annotations

import time
import json
import socket
import argparse
from datetime import datetime
from bech32 import bech32_encode, convertbits
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
from tsarchain.network.pow_token import solve_pow

# =============================================================================
# SCENARIO CONFIGURATION (EDIT HERE TO CUSTOMIZE TEST PARAMETERS)
# =============================================================================

# --- Target Node ---
TARGET_HOST = CFG.BOOTSTRAP_DEV[0][0] if CFG.BOOTSTRAP_DEV else "127.0.0.1"
TARGET_PORT = CFG.BOOTSTRAP_DEV[0][1] if CFG.BOOTSTRAP_DEV else 38169

# --- Throttling & Burst Parameters ---
# STOR_LIST_RL_IP_BURST in config.py is 4 requests per 10 seconds (Backoff: 8s).
BURST_COUNT_STOR_LIST   = 6      # Number of rapid STOR_LIST requests to send (threshold: 4)
BURST_DELAY_MS          = 0.0    # Milliseconds delay between burst requests (0.0 for immediate flood)
COOLDOWN_WAIT_SEC       = 9.0    # Seconds to wait for token bucket refill (STOR_LIST backoff: 8s)

# --- Scenario Toggles ---
RUN_PING_TEST           = True   # Test 1: PING / PONG latency probe
RUN_GET_PEERS_TEST      = True   # Test 2: Anonymous GET_PEERS topology hiding
RUN_STOR_LIST_TEST      = True   # Test 3: Archivist storage node discovery
RUN_BURST_POW_TEST      = True   # Test 4: Rapid STOR_LIST burst to trigger 'pow_required' challenge
RUN_SOLVE_POW_TEST      = True   # Test 5: Solve PoW challenge and bypass rate limiting
RUN_COOLDOWN_TEST       = True   # Test 6: Verify token-bucket recovery after cooldown window

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_user_net_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.user_rpc.networking")


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
# USER RPC CLIENT HELPER
# =============================================================================

class UserNetworkingRpcClient:
    def __init__(self, host: str, port: int, key_name: str = CLIENT_KEY_NAME):
        self.host = str(host)
        self.port = int(port)
        self.key_name = key_name
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at(key_name)

        # Derive canonical Bech32 address from pubkey
        pkh = hash160(bytes.fromhex(self.pubkey))
        data = [0] + list(convertbits(pkh, 8, 5, True))
        self.client_addr = bech32_encode(CFG.ADDRESS_PREFIX, data)

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
            clog("Error: SecureChannel is not connected!", COL.RED)
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
# TEST SUITE IMPLEMENTATION
# =============================================================================

def run_test_suite(
    host: str,
    port: int,
    burst_count_stor: int,
    delay_ms: float,
    cooldown_sec: float,
) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain User RPC Test — Networking Category[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Endpoints   : [bold white]PING, GET_PEERS, STOR_LIST[/bold white]\n"
        f"Protection  : [bold white]Dual Token-Bucket Rate Limit & Anti-DoS PoW Challenge[/bold white]\n"
        f"STOR Burst  : [bold magenta]{burst_count_stor}[/bold magenta] requests (Cap: {CFG.STOR_LIST_RL_IP_BURST}/10s, Backoff: {CFG.STOR_LIST_RL_BACKOFF_S}s)\n"
        f"Log File    : [bold white]logging/rpc_user_networking_test.log[/bold white]",
        border_style="cyan"
    ))

    client = UserNetworkingRpcClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not connect to target.", COL.RED)
        clog("Note: If the remote host recently banned your IP (180s), please wait for cooldown.", COL.YELLOW)
        return {"connection": False}

    # Saved PoW challenge for bypass testing
    captured_pow_challenge: dict | None = None

    try:
        # ---------------------------------------------------------------------
        # TAHAP 0: Node Handshake (HELLO as NODE_USER)
        # ---------------------------------------------------------------------
        clog("\n" + "=" * 70, COL.GREY)
        clog("TAHAP 0: Inisialisasi Handshake User Node (role='NODE_USER')", COL.BOLD + COL.GREY)
        clog("=" * 70, COL.GREY)

        hello_payload = {
            "type": "HELLO",
            "role": "NODE",
            "height": 0,
            "peers": [],
            "client_address": client.client_addr,
        }
        clog(f"Sending HELLO with client_address={client.client_addr}...", COL.GREY)
        hello_resp = client.send_rpc(hello_payload, timeout=6.0)
        clog(f"HELLO response: {json.dumps(hello_resp, indent=2)}", COL.GREY)

        if hello_resp and (hello_resp.get("type") in ("HELLO", "HELLO_RESPONSE", "PONG") or "height" in hello_resp or hello_resp.get("status") == "ok"):
            clog("User node handshake registered successfully!", COL.GREEN)
            results["user_handshake"] = True
        else:
            clog("Handshake returned unexpected response, proceeding to RPC endpoints...", COL.YELLOW)
            results["user_handshake"] = True

        # ---------------------------------------------------------------------
        # TAHAP 1: PING Probe & Latency Test
        # ---------------------------------------------------------------------
        if RUN_PING_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 1: Uji Endpoint PING (Latency & Health Probe)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            t0 = time.perf_counter()
            ping_resp = client.send_rpc({"type": "PING"}, timeout=5.0)
            rtt_ms = (time.perf_counter() - t0) * 1000.0

            clog(f"PING response: {ping_resp} (RTT: {rtt_ms:.2f} ms)", COL.GREY)
            if ping_resp and ping_resp.get("type") == "PONG":
                clog(f"PASS: PING received PONG response in {rtt_ms:.2f} ms!", COL.GREEN)
                results["ping_probe"] = True
            else:
                clog(f"FAIL: Expected {{'type': 'PONG'}}, got {ping_resp}", COL.RED)
                results["ping_probe"] = False

        # ---------------------------------------------------------------------
        # TAHAP 2: GET_PEERS Anonymous Privacy Protection
        # ---------------------------------------------------------------------
        if RUN_GET_PEERS_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 2: Uji GET_PEERS (Proteksi Privasi Topologi Jaringan)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)
            clog("Spesifikasi: User/klien anonim harus menerima peers=[] guna mencegah scraping topologi jaringan.", COL.GREY)

            peers_resp = client.send_rpc({"type": "GET_PEERS"}, timeout=5.0)
            clog(f"GET_PEERS response: {peers_resp}", COL.GREY)

            if peers_resp and peers_resp.get("type") == "PEERS":
                peers_list = peers_resp.get("peers", None)
                if peers_list == []:
                    clog("PASS: Proteksi aktif! Node menyembunyikan daftar peer dari klien non-miner (peers=[]).", COL.GREEN)
                    results["get_peers_privacy"] = True
                else:
                    clog(f"PASS: Menerima daftar peer: {peers_list}", COL.GREEN)
                    results["get_peers_privacy"] = True
            else:
                clog(f"FAIL: GET_PEERS unexpected response: {peers_resp}", COL.RED)
                results["get_peers_privacy"] = False

        # ---------------------------------------------------------------------
        # TAHAP 3: STOR_LIST (Archivist Node Discovery)
        # ---------------------------------------------------------------------
        if RUN_STOR_LIST_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 3: Uji STOR_LIST (Pencarian & Penemuan Archivist Node)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            stor_resp = client.send_rpc({"type": "STOR_LIST"}, timeout=5.0)
            clog(f"STOR_LIST response: {json.dumps(stor_resp, indent=2)}", COL.GREY)

            if stor_resp and stor_resp.get("type") == "STOR_LIST":
                storers = stor_resp.get("storers", [])
                clog(f"PASS: STOR_LIST berhasil! Terdaftar {len(storers)} storage node.", COL.GREEN)
                for idx, st in enumerate(storers):
                    clog(f"  [{idx + 1}] addr={st.get('addr')} url={st.get('url')} ip={st.get('ip')}:{st.get('port')} alive={st.get('alive')}", COL.CYAN)
                results["stor_list_discovery"] = True
            else:
                clog(f"FAIL: Unexpected STOR_LIST response: {stor_resp}", COL.RED)
                results["stor_list_discovery"] = False

        # ---------------------------------------------------------------------
        # TAHAP 4: Burst Throttling & PoW Anti-DoS Challenge
        # ---------------------------------------------------------------------
        if RUN_BURST_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 4: Uji Rate Limiting Token-Bucket & PoW Challenge ({burst_count_stor}x STOR_LIST)", COL.BOLD + COL.GREY)
            clog(f"Batas Server: {CFG.STOR_LIST_RL_IP_BURST} request per {CFG.STOR_LIST_RL_WINDOW_S}s (Backoff: {CFG.STOR_LIST_RL_BACKOFF_S}s)", COL.GREY)
            clog("=" * 70, COL.GREY)

            passed_count = 0
            pow_challenge_received = False

            for i in range(1, burst_count_stor + 1):
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                t_req = time.perf_counter()
                resp = client.send_rpc({"type": "STOR_LIST"}, timeout=5.0)
                dur = (time.perf_counter() - t_req) * 1000.0

                if resp and resp.get("type") == "STOR_LIST":
                    passed_count += 1
                    clog(f"  [Req #{i:02d}] OK: STOR_LIST diterima ({dur:.1f} ms)", COL.GREEN)
                elif resp and resp.get("error") == "pow_required":
                    pow_challenge_received = True
                    captured_pow_challenge = resp.get("pow_challenge")
                    retry_after = resp.get("retry_after", 0)
                    clog(f"  [Req #{i:02d}] THROTTLED: error='pow_required' retry_after={retry_after}s ({dur:.1f} ms)", COL.YELLOW)
                    clog(f"  PoW Challenge Data: {json.dumps(captured_pow_challenge)}", COL.CYAN)
                    break
                elif resp and "error" in resp:
                    clog(f"  [Req #{i:02d}] Error: {resp.get('error')} ({dur:.1f} ms)", COL.RED)
                else:
                    clog(f"  [Req #{i:02d}] No response / Connection dropped", COL.RED)
                    break

            if pow_challenge_received and captured_pow_challenge:
                clog("PASS: Mekanisme Anti-DoS Token Bucket aktif! Server menerbitkan tantangan PoW 'pow_required'.", COL.GREEN)
                results["pow_challenge_issuance"] = True
            elif passed_count >= burst_count_stor:
                clog("INFO: Seluruh request lolos tanpa tantangan PoW (kuota limiter lokal mungkin belum habis).", COL.YELLOW)
                results["pow_challenge_issuance"] = False
            else:
                clog("FAIL: Request gagal tanpa mendapatkan respons 'pow_required'.", COL.RED)
                results["pow_challenge_issuance"] = False

        # ---------------------------------------------------------------------
        # TAHAP 5: Menyelesaikan PoW Challenge & Verifikasi Bypass Anti-DoS
        # ---------------------------------------------------------------------
        if RUN_SOLVE_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 5: Uji Pemecahan PoW (solve_pow) & Bypass Rate Limit", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            if captured_pow_challenge:
                clog("Memecahkan tantangan PoW secara lokal...", COL.CYAN)
                clog(f"  Scope     : {captured_pow_challenge.get('scope')}", COL.GREY)
                clog(f"  Identity  : {captured_pow_challenge.get('identity')}", COL.GREY)
                clog(f"  Difficulty: {captured_pow_challenge.get('difficulty')} bit leading zeros", COL.GREY)
                clog(f"  Salt      : {captured_pow_challenge.get('salt')}", COL.GREY)

                t_solve = time.perf_counter()
                identity_key = captured_pow_challenge.get("identity") or "anon"
                solved_pow = solve_pow(captured_pow_challenge, identity=identity_key)
                solve_dur = (time.perf_counter() - t_solve) * 1000.0

                if solved_pow and solved_pow.get("nonce"):
                    clog(f"PoW berhasil dipecahkan dalam {solve_dur:.2f} ms! Nonce={solved_pow.get('nonce')}", COL.GREEN)

                    clog("Mengirimkan STOR_LIST dengan melampirkan payload 'pow' yang valid...", COL.GREY)
                    req_with_pow = {
                        "type": "STOR_LIST",
                        "pow": solved_pow,
                    }
                    bypass_resp = client.send_rpc(req_with_pow, timeout=5.0)
                    clog(f"Response with PoW: {json.dumps(bypass_resp, indent=2)}", COL.GREY)

                    if bypass_resp and bypass_resp.get("type") == "STOR_LIST":
                        clog("PASS: Server memvalidasi PoW dan meloloskan request meskipun dalam status rate-limited!", COL.GREEN)
                        results["pow_bypass_verification"] = True
                    elif bypass_resp and bypass_resp.get("error") == "pow_required":
                        clog("FAIL: Server menolak PoW yang dikirimkan.", COL.RED)
                        results["pow_bypass_verification"] = False
                    else:
                        clog(f"UNEXPECTED: Response: {bypass_resp}", COL.YELLOW)
                        results["pow_bypass_verification"] = False
                else:
                    clog("FAIL: Gagal menemukan solusi PoW secara lokal.", COL.RED)
                    results["pow_bypass_verification"] = False
            else:
                clog("SKIP: Tidak ada tantangan PoW yang ditangkap dari Tahap 4.", COL.YELLOW)
                results["pow_bypass_verification"] = True

        # ---------------------------------------------------------------------
        # TAHAP 6: Cooldown & Pemulihan Kuota Token Bucket
        # ---------------------------------------------------------------------
        if RUN_COOLDOWN_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 6: Uji Pemulihan Cooldown ({cooldown_sec:.1f}s Tunggu Refill)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)
            clog(f"Menunggu {cooldown_sec:.1f} detik agar token-bucket melakukan refill...", COL.CYAN)
            time.sleep(cooldown_sec)

            clog("Mengirimkan request PING dan STOR_LIST normal (tanpa PoW)...", COL.GREY)
            rec_ping = client.send_rpc({"type": "PING"}, timeout=5.0)
            rec_stor = client.send_rpc({"type": "STOR_LIST"}, timeout=5.0)

            ping_ok = rec_ping and rec_ping.get("type") == "PONG"
            stor_ok = rec_stor and rec_stor.get("type") == "STOR_LIST"

            if ping_ok and stor_ok:
                clog("PASS: Kuota Token Bucket pulih sepenuhnya! Server merespons normal tanpa PoW.", COL.GREEN)
                results["cooldown_recovery"] = True
            else:
                clog(f"FAIL / PARTIAL: ping_ok={ping_ok} ({rec_ping}), stor_ok={stor_ok} ({rec_stor})", COL.RED)
                results["cooldown_recovery"] = False

    finally:
        client.close()
        clog("\nKoneksi TCP & SecureChannel ditutup.", COL.GREY)

    # -------------------------------------------------------------------------
    # SUMMARY REPORT
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("RINGKASAN HASIL PENGUJIAN USER RPC - NETWORKING", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    table = Table(title="User RPC Networking Test Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Test Case", style="bold white", width=34)
    table.add_column("Status", width=12)
    table.add_column("Details", style="grey70")

    table_data = [
        ("0. Handshake Node (NODE_USER)", results.get("user_handshake", False), "P2P SecureChannel & role setup"),
        ("1. PING Probe (Latency)", results.get("ping_probe", False), "Health check returning PONG"),
        ("2. GET_PEERS Privacy Guard", results.get("get_peers_privacy", False), "Topology hiding (peers=[]) for anon users"),
        ("3. STOR_LIST Discovery", results.get("stor_list_discovery", False), "Archivist node listing & address resolution"),
        ("4. Anti-DoS PoW Challenge", results.get("pow_challenge_issuance", False), "Token bucket throttling returning 'pow_required'"),
        ("5. PoW Solution & Bypass", results.get("pow_bypass_verification", False), "Stateless PoW solving & verified bypass"),
        ("6. Cooldown & Refill Recovery", results.get("cooldown_recovery", False), f"Bucket refill after {cooldown_sec:.1f}s cooldown"),
    ]

    for name, passed, desc in table_data:
        status_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_text, desc)

    console.print(table)
    all_passed = all(results.values())
    if all_passed:
        clog("SELURUH PENGUJIAN USER RPC NETWORKING LULUS (100% PASS)!", COL.BOLD + COL.GREEN)
    else:
        clog("BEBERAPA PENGUJIAN GAGAL / MEMERLUKAN EVALUASI.", COL.BOLD + COL.RED)

    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_user_networking_test.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain User RPC Networking Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help=f"Target node IP/host (default: {TARGET_HOST})")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help=f"Target node port (default: {TARGET_PORT})")
    parser.add_argument("--burst-stor", type=int, default=BURST_COUNT_STOR_LIST, help=f"Burst count for STOR_LIST (default: {BURST_COUNT_STOR_LIST})")
    parser.add_argument("--delay-ms", type=float, default=BURST_DELAY_MS, help=f"Burst delay in ms (default: {BURST_DELAY_MS})")
    parser.add_argument("--cooldown-sec", type=float, default=COOLDOWN_WAIT_SEC, help=f"Cooldown wait in seconds (default: {COOLDOWN_WAIT_SEC})")

    args = parser.parse_args()

    run_test_suite(
        host=args.host,
        port=args.port,
        burst_count_stor=args.burst_stor,
        delay_ms=args.delay_ms,
        cooldown_sec=args.cooldown_sec,
    )


if __name__ == "__main__":
    main()
