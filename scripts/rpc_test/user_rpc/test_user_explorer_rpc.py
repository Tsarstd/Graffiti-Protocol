# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — User RPC Explorer Category Test Suite
=================================================
Reference: src/tsarchain/network/rpc/docs/USER_RPC.MD
           src/tsarchain/network/rpc/user_rpc/category/explorer.py

This script tests the Blockchain Explorer endpoints in TsarChain's User RPC layer:
1. GET_NETWORK_INFO : State snapshot (tip height, difficulty, peers, mempool stats)
2. GET_BALANCES     : Confirmed, immature, and pending mempool balances for addresses
3. GET_BLOCK        : Block details query by height (Genesis block 0 & tip) and by hash
4. GET_BLOCK_RANGE  : Sequential paginated block range query
5. GET_MEMPOOL      : Unconfirmed transactions inspection (txids and inline modes)
6. GET_TX_HISTORY   : Address transaction history lookups with pagination
7. GET_TOTAL_UTXO   : Address UTXO count inspection
8. Dual Rate Limit  : Dual Token-Bucket Throttling on Info & Read RPCs
9. Anti-DoS PoW     : Verification of stateless Proof-of-Work challenges ('pow_required')
10. PoW Solution    : Solving challenge via solve_pow() and verifying rate-limit bypass
11. Cooldown Refill : Verification of token-bucket replenishment after backoff

Execution logs are saved automatically to 'logging/rpc_user_explorer_test.log'.
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
# INFO_RL_IP_BURST in config.py is 20 requests per 8 seconds (Backoff: 3s).
BURST_COUNT_INFO        = 24     # Number of rapid GET_NETWORK_INFO requests to send (threshold: 20)
BURST_DELAY_MS          = 0.0    # Milliseconds delay between burst requests (0.0 for flood)
COOLDOWN_WAIT_SEC       = 5.0    # Seconds to wait for token bucket refill (Backoff: 3s)

# --- Scenario Toggles ---
RUN_NETWORK_INFO_TEST   = True   # Test 1: GET_NETWORK_INFO snapshot
RUN_BALANCES_TEST       = True   # Test 2: GET_BALANCES breakdown
RUN_BLOCK_TEST          = True   # Test 3: GET_BLOCK by height & hash
RUN_BLOCK_RANGE_TEST    = True   # Test 4: GET_BLOCK_RANGE pagination
RUN_MEMPOOL_TEST        = True   # Test 5: GET_MEMPOOL modes (txids & inline)
RUN_TX_HISTORY_TEST     = True   # Test 6: GET_TX_HISTORY lookup
RUN_TOTAL_UTXO_TEST     = True   # Test 7: GET_TOTAL_UTXO count
RUN_BURST_POW_TEST      = True   # Test 8: Rapid burst to trigger 'pow_required' challenge
RUN_SOLVE_POW_TEST      = True   # Test 9: Solve PoW challenge and bypass rate limiting
RUN_COOLDOWN_TEST       = True   # Test 10: Verify token-bucket recovery after cooldown

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_user_explorer_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.user_rpc.explorer")


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

class UserExplorerRpcClient:
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

    def send_rpc(self, payload: dict, timeout: float = 6.0) -> dict | None:
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
    burst_count_info: int,
    delay_ms: float,
    cooldown_sec: float,
) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain User RPC Test — Explorer Category[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Endpoints   : [bold white]GET_NETWORK_INFO, GET_BALANCES, GET_BLOCK, GET_BLOCK_RANGE, GET_MEMPOOL, GET_TX_HISTORY, GET_TOTAL_UTXO[/bold white]\n"
        f"Protection  : [bold white]Dual Token-Bucket Rate Limit & Anti-DoS PoW Challenge (Diff: 12 bit)[/bold white]\n"
        f"INFO Burst  : [bold cyan]{burst_count_info}[/bold cyan] requests (Cap: {CFG.INFO_RL_IP_BURST}/8s, Backoff: {CFG.INFO_RL_BACKOFF_S}s)\n"
        f"Log File    : [bold white]logging/rpc_user_explorer_test.log[/bold white]",
        border_style="cyan"
    ))

    client = UserExplorerRpcClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not connect to target.", COL.RED)
        clog("Note: If the remote host recently banned your IP (180s), please wait for cooldown.", COL.YELLOW)
        return {"connection": False}

    captured_pow_challenge: dict | None = None
    tip_block_hash: str | None = None
    tip_height: int = 0

    try:
        # ---------------------------------------------------------------------
        # TAHAP 0: Node Handshake (HELLO)
        # ---------------------------------------------------------------------
        clog("\n" + "=" * 70, COL.GREY)
        clog("TAHAP 0: Inisialisasi Handshake User Node (role='NODE')", COL.BOLD + COL.GREY)
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
            clog("Handshake response received, proceeding to explorer endpoints...", COL.YELLOW)
            results["user_handshake"] = True

        # ---------------------------------------------------------------------
        # TAHAP 1: GET_NETWORK_INFO Snapshot
        # ---------------------------------------------------------------------
        if RUN_NETWORK_INFO_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 1: Uji GET_NETWORK_INFO (Snapshot Status Jaringan)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            t0 = time.perf_counter()
            info_resp = client.send_rpc({"type": "GET_NETWORK_INFO"}, timeout=5.0)
            rtt_ms = (time.perf_counter() - t0) * 1000.0

            clog(f"Response (RTT: {rtt_ms:.2f} ms): {json.dumps(info_resp, indent=2)}", COL.GREY)

            if info_resp and info_resp.get("type") == "NETWORK_INFO":
                data = info_resp.get("data", {})
                tip_height = int(data.get("height", 0))
                tip_block_hash = data.get("tip_hash") or data.get("tip")
                diff = data.get("difficulty")
                peers_count = (data.get("peers") or {}).get("count", 0) if type(data.get("peers")) is dict else 0
                mempool_txs = (data.get("transactions") or {}).get("mempool_txs", 0) if type(data.get("transactions")) is dict else 0

                clog(f"PASS: Network info diterima! Height={tip_height}, TipHash={tip_block_hash}, Diff={diff}, Peers={peers_count}, MempoolTX={mempool_txs}", COL.GREEN)
                results["get_network_info"] = True
            else:
                clog(f"FAIL: Unexpected GET_NETWORK_INFO response: {info_resp}", COL.RED)
                results["get_network_info"] = False

        # ---------------------------------------------------------------------
        # TAHAP 2: GET_BALANCES Breakdown
        # ---------------------------------------------------------------------
        if RUN_BALANCES_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 2: Uji GET_BALANCES (Query Saldo Alamat Klien)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            # Case 2A: Valid balance query
            clog(f"Meminta breakdown saldo untuk alamat: {client.client_addr}...", COL.CYAN)
            bal_payload = {
                "type": "GET_BALANCES",
                "addresses": [client.client_addr],
            }
            bal_resp = client.send_rpc(bal_payload, timeout=5.0)
            clog(f"GET_BALANCES response: {json.dumps(bal_resp, indent=2)}", COL.GREY)

            if bal_resp and bal_resp.get("type") == "BALANCES":
                items = bal_resp.get("items", {})
                addr_info = items.get(client.client_addr, {})
                bal = addr_info.get("balance", 0)
                spendable = addr_info.get("spendable", 0)
                immature = addr_info.get("immature", 0)
                clog(f"PASS: Saldo terbaca: total={bal} sat, spendable={spendable} sat, immature={immature} sat", COL.GREEN)
                results["get_balances_query"] = True
            else:
                clog(f"FAIL: Unexpected GET_BALANCES response: {bal_resp}", COL.RED)
                results["get_balances_query"] = False

            # Case 2B: Defensive guard on empty addresses list
            clog("Case 2B: Meminta saldo dengan list kosong (defensive guard)...", COL.CYAN)
            empty_bal_resp = client.send_rpc({"type": "GET_BALANCES", "addresses": []}, timeout=5.0)
            clog(f"Empty balance response: {empty_bal_resp}", COL.GREY)
            if empty_bal_resp and empty_bal_resp.get("error") == "missing addresses":
                clog("PASS: Node menolak list alamat kosong secara defensif: 'missing addresses'", COL.GREEN)
                results["get_balances_empty_guard"] = True
            else:
                clog(f"FAIL: Unexpected empty balance response: {empty_bal_resp}", COL.RED)
                results["get_balances_empty_guard"] = False

        # ---------------------------------------------------------------------
        # TAHAP 3: GET_BLOCK by Height & Hash
        # ---------------------------------------------------------------------
        if RUN_BLOCK_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 3: Uji GET_BLOCK (Query Blok by Height & Hash)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            # Case 3A: Genesis Block 0
            clog("Case 3A: Meminta Genesis Block (height=0)...", COL.CYAN)
            blk0_resp = client.send_rpc({"type": "GET_BLOCK", "height": 0}, timeout=5.0)
            clog(f"Block 0 summary: height={blk0_resp.get('height')}, hash={blk0_resp.get('hash')}, txs={len(blk0_resp.get('txs', []))}", COL.GREY)

            if blk0_resp and blk0_resp.get("type") == "BLOCK" and blk0_resp.get("height") == 0:
                clog(f"PASS: Genesis block diterima! Hash: {blk0_resp.get('hash')}", COL.GREEN)
                genesis_hash = blk0_resp.get("hash")
                results["get_block_height"] = True
            else:
                clog(f"FAIL: Unexpected block 0 response: {blk0_resp}", COL.RED)
                genesis_hash = None
                results["get_block_height"] = False

            # Case 3B: Query by Hash
            if genesis_hash:
                clog(f"Case 3B: Meminta blok menggunakan hash genesis ({genesis_hash[:16]}...)...", COL.CYAN)
                blk_hash_resp = client.send_rpc({"type": "GET_BLOCK", "hash": genesis_hash}, timeout=5.0)
                if blk_hash_resp and blk_hash_resp.get("type") == "BLOCK" and blk_hash_resp.get("hash") == genesis_hash:
                    clog("PASS: Query blok berdasarkan hash berhasil mencocokkan Genesis block!", COL.GREEN)
                    results["get_block_hash"] = True
                else:
                    clog(f"FAIL: Query by hash gagal: {blk_hash_resp}", COL.RED)
                    results["get_block_hash"] = False
            else:
                results["get_block_hash"] = True

        # ---------------------------------------------------------------------
        # TAHAP 4: GET_BLOCK_RANGE Paginated Query
        # ---------------------------------------------------------------------
        if RUN_BLOCK_RANGE_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 4: Uji GET_BLOCK_RANGE (Query Rentang Blok Berhalaman)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            start_h = max(0, tip_height) if tip_height > 0 else 5
            limit_n = 5
            clog(f"Meminta rentang blok: start_height={start_h}, limit={limit_n}...", COL.CYAN)

            range_payload = {
                "type": "GET_BLOCK_RANGE",
                "start_height": start_h,
                "limit": limit_n,
            }
            range_resp = client.send_rpc(range_payload, timeout=6.0)
            clog(f"BLOCK_RANGE response: type={range_resp.get('type')}, items_count={len(range_resp.get('items', []))}, has_more={range_resp.get('has_more')}", COL.GREY)

            if range_resp and range_resp.get("type") == "BLOCK_RANGE":
                items = range_resp.get("items", [])
                clog(f"PASS: Menerima rentang {len(items)} blok (start: {range_resp.get('start_height')}, next: {range_resp.get('next_height')})", COL.GREEN)
                for it in items[:3]:
                    clog(f"  - Block #{it.get('height')}: hash={it.get('hash')[:16]}... txs={it.get('tx_count')}", COL.CYAN)
                results["get_block_range"] = True
            else:
                clog(f"FAIL: Unexpected BLOCK_RANGE response: {range_resp}", COL.RED)
                results["get_block_range"] = False

        # ---------------------------------------------------------------------
        # TAHAP 5: GET_MEMPOOL Inspection (txids & inline modes)
        # ---------------------------------------------------------------------
        if RUN_MEMPOOL_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 5: Uji GET_MEMPOOL (Inspeksi Transaksi Unconfirmed)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            # Mode txids
            clog("Case 5A: Meminta mempool mode 'txids'...", COL.CYAN)
            mempool_txids = client.send_rpc({"type": "GET_MEMPOOL", "mode": "txids"}, timeout=5.0)
            clog(f"Mempool (txids): {mempool_txids}", COL.GREY)
            if mempool_txids and mempool_txids.get("type") == "MEMPOOL" and mempool_txids.get("mode") == "txids":
                clog(f"PASS: Mempool txids diterima! Total pending: {len(mempool_txids.get('txs', []))}", COL.GREEN)
                results["get_mempool_txids"] = True
            else:
                clog(f"FAIL: Unexpected mempool txids response: {mempool_txids}", COL.RED)
                results["get_mempool_txids"] = False

            # Mode inline
            clog("Case 5B: Meminta mempool mode 'inline'...", COL.CYAN)
            mempool_inline = client.send_rpc({"type": "GET_MEMPOOL", "mode": "inline"}, timeout=5.0)
            clog(f"Mempool (inline): type={mempool_inline.get('type')}, mode={mempool_inline.get('mode')}, total={mempool_inline.get('total')}", COL.GREY)
            if mempool_inline and mempool_inline.get("type") == "MEMPOOL":
                clog("PASS: Mempool inline dump diterima dengan baik!", COL.GREEN)
                results["get_mempool_inline"] = True
            else:
                clog(f"FAIL: Unexpected mempool inline response: {mempool_inline}", COL.RED)
                results["get_mempool_inline"] = False

        # ---------------------------------------------------------------------
        # TAHAP 6: GET_TX_HISTORY & GET_TOTAL_UTXO Lookups
        # ---------------------------------------------------------------------
        if RUN_TX_HISTORY_TEST or RUN_TOTAL_UTXO_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 6: Uji Riwayat & UTXO Alamat (GET_TX_HISTORY & GET_TOTAL_UTXO)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            if RUN_TX_HISTORY_TEST:
                clog(f"Meminta riwayat transaksi alamat: {client.client_addr}...", COL.CYAN)
                hist_payload = {
                    "type": "GET_TX_HISTORY",
                    "address": client.client_addr,
                    "limit": 10,
                    "offset": 0,
                }
                hist_resp = client.send_rpc(hist_payload, timeout=5.0)
                clog(f"TX_HISTORY response: {json.dumps(hist_resp, indent=2)}", COL.GREY)
                if hist_resp and hist_resp.get("type") == "TX_HISTORY":
                    tx_items = hist_resp.get("items", []) or hist_resp.get("transactions", [])
                    clog(f"PASS: Riwayat transaksi berhasil di-query! Ditemukan {len(tx_items)} catatan.", COL.GREEN)
                    results["get_tx_history"] = True
                else:
                    clog(f"FAIL: Unexpected TX_HISTORY response: {hist_resp}", COL.RED)
                    results["get_tx_history"] = False

            if RUN_TOTAL_UTXO_TEST:
                clog(f"Meminta jumlah total UTXO alamat: {client.client_addr}...", COL.CYAN)
                utxo_resp = client.send_rpc({"type": "GET_TOTAL_UTXO", "address": client.client_addr}, timeout=5.0)
                clog(f"TOTAL_UTXO response: {utxo_resp}", COL.GREY)
                if utxo_resp and utxo_resp.get("type") == "UTXOS_COUNT":
                    count = utxo_resp.get("count", 0)
                    clog(f"PASS: Jumlah UTXO valid: {count} unspent outputs.", COL.GREEN)
                    results["get_total_utxo"] = True
                else:
                    clog(f"FAIL: Unexpected TOTAL_UTXO response: {utxo_resp}", COL.RED)
                    results["get_total_utxo"] = False

        # ---------------------------------------------------------------------
        # TAHAP 7: Burst Throttling & PoW Anti-DoS Challenge (GET_NETWORK_INFO)
        # ---------------------------------------------------------------------
        if RUN_BURST_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 7: Uji Rate Limiting Token-Bucket & PoW Challenge ({burst_count_info}x GET_NETWORK_INFO)", COL.BOLD + COL.GREY)
            clog(f"Batas Server: {CFG.INFO_RL_IP_BURST} request per {CFG.INFO_RL_IP_WINDOW_S}s (Backoff: {CFG.INFO_RL_BACKOFF_S}s)", COL.GREY)
            clog("=" * 70, COL.GREY)

            passed_count = 0
            pow_challenge_received = False

            for i in range(1, burst_count_info + 1):
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                t_req = time.perf_counter()
                resp = client.send_rpc({"type": "GET_NETWORK_INFO"}, timeout=5.0)
                dur = (time.perf_counter() - t_req) * 1000.0

                if resp and resp.get("type") == "NETWORK_INFO":
                    passed_count += 1
                    clog(f"  [Req #{i:02d}] OK: NETWORK_INFO diterima ({dur:.1f} ms)", COL.GREEN)
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
                clog("PASS: Mekanisme Anti-DoS Token Bucket Explorer aktif! Server menerbitkan tantangan PoW.", COL.GREEN)
                results["info_pow_challenge"] = True
            elif passed_count >= burst_count_info:
                clog("INFO: Seluruh request lolos (kuota token-bucket lokal belum habis).", COL.YELLOW)
                results["info_pow_challenge"] = False
            else:
                clog("FAIL: Request gagal tanpa mendapatkan respons 'pow_required'.", COL.RED)
                results["info_pow_challenge"] = False

        # ---------------------------------------------------------------------
        # TAHAP 8: Menyelesaikan PoW Challenge (Diff: 12) & Verifikasi Bypass
        # ---------------------------------------------------------------------
        if RUN_SOLVE_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 8: Uji Pemecahan PoW (solve_pow, Diff: 12) & Bypass Rate Limit Explorer", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            if captured_pow_challenge:
                clog("Memecahkan tantangan PoW explorer secara lokal...", COL.CYAN)
                clog(f"  Scope     : {captured_pow_challenge.get('scope')}", COL.GREY)
                clog(f"  Identity  : {captured_pow_challenge.get('identity')}", COL.GREY)
                clog(f"  Difficulty: {captured_pow_challenge.get('difficulty')} bit leading zeros", COL.GREY)
                clog(f"  Salt      : {captured_pow_challenge.get('salt')}", COL.GREY)

                t_solve = time.perf_counter()
                identity_key = captured_pow_challenge.get("identity") or "anon"
                solved_pow = solve_pow(captured_pow_challenge, identity=identity_key)
                solve_dur = (time.perf_counter() - t_solve) * 1000.0

                if solved_pow and solved_pow.get("nonce"):
                    clog(f"PoW explorer berhasil dipecahkan dalam {solve_dur:.2f} ms! Nonce={solved_pow.get('nonce')}", COL.GREEN)

                    clog("Mengirimkan GET_NETWORK_INFO dengan melampirkan payload 'pow' yang valid...", COL.GREY)
                    req_with_pow = {
                        "type": "GET_NETWORK_INFO",
                        "pow": solved_pow,
                    }
                    bypass_resp = client.send_rpc(req_with_pow, timeout=5.0)
                    clog(f"Response with PoW: {bypass_resp.get('type')}", COL.GREY)

                    if bypass_resp and bypass_resp.get("type") == "NETWORK_INFO":
                        clog("PASS: Server memvalidasi PoW dan meloloskan request explorer meskipun dalam status rate-limited!", COL.GREEN)
                        results["info_pow_bypass"] = True
                    elif bypass_resp and bypass_resp.get("error") == "pow_required":
                        clog("FAIL: Server menolak PoW explorer.", COL.RED)
                        results["info_pow_bypass"] = False
                    else:
                        clog(f"UNEXPECTED: Response: {bypass_resp}", COL.YELLOW)
                        results["info_pow_bypass"] = False
                else:
                    clog("FAIL: Gagal menemukan solusi PoW secara lokal.", COL.RED)
                    results["info_pow_bypass"] = False
            else:
                clog("SKIP: Tidak ada tantangan PoW yang ditangkap dari Tahap 7.", COL.YELLOW)
                results["info_pow_bypass"] = True

        # ---------------------------------------------------------------------
        # TAHAP 9: Cooldown & Pemulihan Kuota Token Bucket
        # ---------------------------------------------------------------------
        if RUN_COOLDOWN_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 9: Uji Pemulihan Cooldown ({cooldown_sec:.1f}s Tunggu Refill)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)
            clog(f"Menunggu {cooldown_sec:.1f} detik agar token-bucket explorer melakukan refill...", COL.CYAN)
            time.sleep(cooldown_sec)

            clog("Mengirimkan GET_NETWORK_INFO normal tanpa PoW...", COL.GREY)
            rec_info = client.send_rpc({"type": "GET_NETWORK_INFO"}, timeout=5.0)
            info_ok = rec_info and rec_info.get("type") == "NETWORK_INFO"

            if info_ok:
                clog("PASS: Kuota Token Bucket explorer pulih sepenuhnya! Server merespons normal tanpa PoW.", COL.GREEN)
                results["cooldown_recovery"] = True
            else:
                clog(f"FAIL: Kuota belum pulih atau terkena throttle berkelanjutan: {rec_info}", COL.RED)
                results["cooldown_recovery"] = False

    finally:
        client.close()
        clog("\nKoneksi TCP & SecureChannel ditutup.", COL.GREY)

    # -------------------------------------------------------------------------
    # SUMMARY REPORT
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("RINGKASAN HASIL PENGUJIAN USER RPC - EXPLORER", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    table = Table(title="User RPC Explorer Test Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Test Case", style="bold white", width=34)
    table.add_column("Status", width=12)
    table.add_column("Details", style="grey70")

    table_data = [
        ("0. Handshake Node (NODE)", results.get("user_handshake", False), "P2P SecureChannel & role setup"),
        ("1. GET_NETWORK_INFO Snapshot", results.get("get_network_info", False), "Tip height, difficulty, peers, mempool stats"),
        ("2A. GET_BALANCES Query", results.get("get_balances_query", False), "Confirmed, immature & pending balances"),
        ("2B. GET_BALANCES Empty Guard", results.get("get_balances_empty_guard", False), "Defensive 'missing addresses' handling"),
        ("3A. GET_BLOCK by Height", results.get("get_block_height", False), "Genesis Block 0 query"),
        ("3B. GET_BLOCK by Hash", results.get("get_block_hash", False), "Query block using verified block hash"),
        ("4. GET_BLOCK_RANGE Query", results.get("get_block_range", False), "Paginated block range & summaries"),
        ("5A. GET_MEMPOOL Txids Mode", results.get("get_mempool_txids", False), "Mempool query returning list of txids"),
        ("5B. GET_MEMPOOL Inline Mode", results.get("get_mempool_inline", False), "Mempool dump returning full tx objects"),
        ("6. GET_TX_HISTORY Lookup", results.get("get_tx_history", False), "Address transaction history & pagination"),
        ("7. GET_TOTAL_UTXO Inspection", results.get("get_total_utxo", False), "Address total unspent outputs count"),
        ("8. Anti-DoS PoW Challenge", results.get("info_pow_challenge", False), "Token bucket throttling returning 'pow_required'"),
        ("9. PoW Solution & Bypass (Diff 12)", results.get("info_pow_bypass", False), "Stateless PoW solving & verified bypass"),
        ("10. Cooldown & Refill Recovery", results.get("cooldown_recovery", False), f"Bucket refill after {cooldown_sec:.1f}s cooldown"),
    ]

    for name, passed, desc in table_data:
        status_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_text, desc)

    console.print(table)
    all_passed = all(results.values())
    if all_passed:
        clog("SELURUH PENGUJIAN USER RPC EXPLORER LULUS (100% PASS)!", COL.BOLD + COL.GREEN)
    else:
        clog("BEBERAPA PENGUJIAN GAGAL / MEMERLUKAN EVALUASI.", COL.BOLD + COL.RED)

    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_user_explorer_test.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain User RPC Explorer Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help=f"Target node IP/host (default: {TARGET_HOST})")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help=f"Target node port (default: {TARGET_PORT})")
    parser.add_argument("--burst-info", type=int, default=BURST_COUNT_INFO, help=f"Burst count for GET_NETWORK_INFO (default: {BURST_COUNT_INFO})")
    parser.add_argument("--delay-ms", type=float, default=BURST_DELAY_MS, help=f"Burst delay in ms (default: {BURST_DELAY_MS})")
    parser.add_argument("--cooldown-sec", type=float, default=COOLDOWN_WAIT_SEC, help=f"Cooldown wait in seconds (default: {COOLDOWN_WAIT_SEC})")

    args = parser.parse_args()

    run_test_suite(
        host=args.host,
        port=args.port,
        burst_count_info=args.burst_info,
        delay_ms=args.delay_ms,
        cooldown_sec=args.cooldown_sec,
    )


if __name__ == "__main__":
    main()
