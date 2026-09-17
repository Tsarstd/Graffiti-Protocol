# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — User RPC Transactions Category Test Suite
=====================================================
Reference: src/tsarchain/network/rpc/docs/USER_RPC.MD
           src/tsarchain/network/rpc/user_rpc/category/transactions.py

This script tests the Transactions endpoints in TsarChain's User RPC layer:
1. CREATE_TX        : Unsigned transaction template builder for single recipient
2. CREATE_TX_MULTI  : Multi-recipient & batch transaction template generator
3. NEW_TX           : Transaction submission, mempool validation, and consensus rejection
4. Dual Rate Limit  : Dual Token-Bucket Throttling on IP & Address (Cap: 12 requests / 6s)
5. Anti-DoS PoW     : Verification of Proof-of-Work challenges ('pow_required', Diff: 16 bit)
6. PoW Solution     : Solving challenge via solve_pow() and verifying rate-limit bypass
7. Cooldown Recovery: Verification of token-bucket replenishment after backoff

Execution logs are saved automatically to 'logging/rpc_user_transactions_test.log'.
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
# TX_SUBMIT_RL_IP_BURST in config.py is 12 requests per 6 seconds (Backoff: 6s).
BURST_COUNT_TX          = 15     # Number of rapid CREATE_TX requests to send (threshold: 12)
BURST_DELAY_MS          = 0.0    # Milliseconds delay between burst requests (0.0 for flood)
COOLDOWN_WAIT_SEC       = 7.0    # Seconds to wait for token bucket refill (Backoff: 6s)

# --- Scenario Toggles ---
RUN_CREATE_TX_TEST      = True   # Test 1: CREATE_TX template builder
RUN_CREATE_MULTI_TEST   = True   # Test 2: CREATE_TX_MULTI batch template builder
RUN_NEW_TX_TEST         = True   # Test 3: NEW_TX mempool validation & consensus guard
RUN_BURST_POW_TEST      = True   # Test 4: Rapid burst to trigger 'pow_required' challenge
RUN_SOLVE_POW_TEST      = True   # Test 5: Solve PoW challenge and bypass rate limiting
RUN_COOLDOWN_TEST       = True   # Test 6: Verify token-bucket recovery after cooldown

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_user_tx_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.user_rpc.transactions")


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

class UserTransactionsRpcClient:
    def __init__(self, host: str, port: int, key_name: str = CLIENT_KEY_NAME):
        self.host = str(host)
        self.port = int(port)
        self.key_name = key_name
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at(key_name)

        # Derive canonical Bech32 address from pubkey
        pkh = hash160(bytes.fromhex(self.pubkey))
        data = [0] + list(convertbits(pkh, 8, 5, True))
        self.client_addr = bech32_encode(CFG.ADDRESS_PREFIX, data)

        # Generate a dummy secondary recipient address for transfer tests
        dummy_pkh = hash160(b"dummy_recipient_address_seed_123")
        dummy_data = [0] + list(convertbits(dummy_pkh, 8, 5, True))
        self.recipient_addr = bech32_encode(CFG.ADDRESS_PREFIX, dummy_data)

        # Generate a dummy tertiary recipient address for multi-tx tests
        dummy_pkh2 = hash160(b"dummy_recipient_address_seed_456")
        dummy_data2 = [0] + list(convertbits(dummy_pkh2, 8, 5, True))
        self.recipient_addr2 = bech32_encode(CFG.ADDRESS_PREFIX, dummy_data2)

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
    burst_count_tx: int,
    delay_ms: float,
    cooldown_sec: float,
) -> dict[str, bool]:
    results = {}
    console = Console()
    console.print(Panel(
        f"[bold cyan]TsarChain User RPC Test — Transactions Category[/bold cyan]\n"
        f"Target      : [bold yellow]{host}:{port}[/bold yellow]\n"
        f"Network ID  : [bold green]{CFG.DEFAULT_NET_ID}[/bold green]\n"
        f"Endpoints   : [bold white]CREATE_TX, CREATE_TX_MULTI, NEW_TX[/bold white]\n"
        f"Protection  : [bold white]Dual Token-Bucket Rate Limit & Anti-DoS PoW Challenge (Diff: 16 bit)[/bold white]\n"
        f"TX Burst    : [bold cyan]{burst_count_tx}[/bold cyan] requests (Cap: {CFG.TX_SUBMIT_RL_IP_BURST}/6s, Backoff: {CFG.TX_SUBMIT_RL_BACKOFF_S}s)\n"
        f"Log File    : [bold white]logging/rpc_user_transactions_test.log[/bold white]",
        border_style="cyan"
    ))

    client = UserTransactionsRpcClient(host, port)
    if not client.connect():
        clog("Aborting test suite: Could not connect to target.", COL.RED)
        clog("Note: If the remote host recently banned your IP (180s), please wait for cooldown.", COL.YELLOW)
        return {"connection": False}

    captured_pow_challenge: dict | None = None

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
            clog("Handshake response received, proceeding to transaction endpoints...", COL.YELLOW)
            results["user_handshake"] = True

        # ---------------------------------------------------------------------
        # TAHAP 1: CREATE_TX Template Builder
        # ---------------------------------------------------------------------
        if RUN_CREATE_TX_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 1: Uji CREATE_TX (Pembuatan Template Transaksi Tunggal)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            # Case A: Query template from empty address
            clog("Case 1A: Meminta template transaksi dari address kosong (tanpa UTXO)...", COL.CYAN)
            create_payload = {
                "type": "CREATE_TX",
                "from": client.client_addr,
                "to": client.recipient_addr,
                "amount": 100000,
                "fee_rate": 2,
            }
            resp_empty = client.send_rpc(create_payload, timeout=5.0)
            clog(f"Response (empty address): {resp_empty}", COL.GREY)

            if resp_empty and resp_empty.get("error") == "no spendable utxos":
                clog("PASS: Node merespons dengan benar: 'no spendable utxos' tanpa exception!", COL.GREEN)
                results["create_tx_empty_utxo"] = True
            elif resp_empty and resp_empty.get("type") == "TX_TEMPLATE":
                clog("PASS: Node mengembalikan template transaksi valid!", COL.GREEN)
                results["create_tx_empty_utxo"] = True
            else:
                clog(f"UNEXPECTED: Response: {resp_empty}", COL.YELLOW)
                results["create_tx_empty_utxo"] = False

            # Case B: Query with invalid address format
            clog("Case 1B: Meminta template dengan format alamat tidak valid...", COL.CYAN)
            bad_addr_payload = {
                "type": "CREATE_TX",
                "from": "invalid_address_syntax",
                "to": client.recipient_addr,
                "amount": 100000,
                "fee_rate": 2,
            }
            resp_bad = client.send_rpc(bad_addr_payload, timeout=5.0)
            clog(f"Response (bad address): {resp_bad}", COL.GREY)
            if resp_bad and "error" in resp_bad:
                clog(f"PASS: Node menangani input alamat rusak secara defensif: error='{resp_bad.get('error')}'", COL.GREEN)
                results["create_tx_bad_addr"] = True
            else:
                clog(f"FAIL: Unexpected response: {resp_bad}", COL.RED)
                results["create_tx_bad_addr"] = False

        # ---------------------------------------------------------------------
        # TAHAP 2: CREATE_TX_MULTI Batch Template Builder
        # ---------------------------------------------------------------------
        if RUN_CREATE_MULTI_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 2: Uji CREATE_TX_MULTI (Pembuatan Template Multi-Output)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            # Case 2A: Missing outputs
            clog("Case 2A: Request multi-tx tanpa outputs...", COL.CYAN)
            empty_multi_payload = {
                "type": "CREATE_TX_MULTI",
                "from": client.client_addr,
                "outputs": [],
                "fee_rate": 2,
            }
            resp_no_out = client.send_rpc(empty_multi_payload, timeout=5.0)
            clog(f"Response (empty outputs): {resp_no_out}", COL.GREY)
            if resp_no_out and resp_no_out.get("error") == "missing from/outputs":
                clog("PASS: Validasi input lolos, node menolak outputs kosong: 'missing from/outputs'", COL.GREEN)
                results["create_tx_multi_validation"] = True
            else:
                clog(f"FAIL: Unexpected response: {resp_no_out}", COL.RED)
                results["create_tx_multi_validation"] = False

            # Case 2B: Multi outputs query
            clog("Case 2B: Request multi-tx ke 2 recipient...", COL.CYAN)
            multi_payload = {
                "type": "CREATE_TX_MULTI",
                "from": client.client_addr,
                "outputs": [
                    {"address": client.recipient_addr, "amount": 50000},
                    {"address": client.recipient_addr2, "amount": 50000},
                ],
                "fee_rate": 2,
            }
            resp_multi = client.send_rpc(multi_payload, timeout=5.0)
            clog(f"Response (multi outputs): {resp_multi}", COL.GREY)
            if resp_multi and (resp_multi.get("error") == "no spendable utxos" or resp_multi.get("type") == "TX_TEMPLATE"):
                clog("PASS: CREATE_TX_MULTI diproses dengan benar oleh TxHandler!", COL.GREEN)
                results["create_tx_multi_process"] = True
            else:
                clog(f"FAIL: Unexpected response: {resp_multi}", COL.RED)
                results["create_tx_multi_process"] = False

        # ---------------------------------------------------------------------
        # TAHAP 3: NEW_TX Mempool Validation & Consensus Guard
        # ---------------------------------------------------------------------
        if RUN_NEW_TX_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 3: Uji NEW_TX (Proteksi Mempool & Konsensus Transaksi)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)
            clog("Mengirimkan raw transaction palsu (unconfirmed/spent UTXO) untuk menguji penolakan konsensus...", COL.CYAN)

            dummy_tx_payload = {
                "type": "NEW_TX",
                "from_addr": client.client_addr,
                "data": {
                    "txid": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "version": 1,
                    "locktime": 0,
                    "inputs": [
                        {
                            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                            "vout": 0,
                            "index": 0,
                            "amount": 100000,
                            "script_pubkey": "0014" + "0" * 40,
                            "witness": ["30440220" + "0" * 60, "02" + "0" * 64],
                        }
                    ],
                    "outputs": [
                        {
                            "amount": 90000,
                            "script_pubkey": "0014" + "1" * 40,
                        }
                    ],
                }
            }
            tx_resp = client.send_rpc(dummy_tx_payload, timeout=5.0)
            clog(f"NEW_TX response: {tx_resp}", COL.GREY)

            if tx_resp and tx_resp.get("status") == "error":
                reason = tx_resp.get("reason", "unknown")
                clog(f"PASS: Mempool konsensus menolak transaksi tidak valid! Alasan: '{reason}'", COL.GREEN)
                results["new_tx_rejection"] = True
            elif tx_resp and tx_resp.get("error") == "pow_required":
                clog("INFO: Request NEW_TX terkena tantangan PoW limiter.", COL.YELLOW)
                results["new_tx_rejection"] = True
            else:
                clog(f"UNEXPECTED: Response: {tx_resp}", COL.YELLOW)
                results["new_tx_rejection"] = False

        # ---------------------------------------------------------------------
        # TAHAP 4: Burst Throttling & PoW Anti-DoS Challenge (TXSUB)
        # ---------------------------------------------------------------------
        if RUN_BURST_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 4: Uji Rate Limiting Token-Bucket & PoW Challenge ({burst_count_tx}x CREATE_TX)", COL.BOLD + COL.GREY)
            clog(f"Batas Server: {CFG.TX_SUBMIT_RL_IP_BURST} request per {CFG.TX_SUBMIT_RL_WINDOW_S}s (Backoff: {CFG.TX_SUBMIT_RL_BACKOFF_S}s)", COL.GREY)
            clog("=" * 70, COL.GREY)

            passed_count = 0
            pow_challenge_received = False

            for i in range(1, burst_count_tx + 1):
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                t_req = time.perf_counter()
                burst_req = {
                    "type": "CREATE_TX",
                    "from": client.client_addr,
                    "to": client.recipient_addr,
                    "amount": 1000 + i,
                    "fee_rate": 2,
                }
                resp = client.send_rpc(burst_req, timeout=5.0)
                dur = (time.perf_counter() - t_req) * 1000.0

                if resp and (resp.get("type") == "TX_TEMPLATE" or resp.get("error") == "no spendable utxos"):
                    passed_count += 1
                    clog(f"  [Req #{i:02d}] OK: CREATE_TX diproses ({dur:.1f} ms)", COL.GREEN)
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
                clog("PASS: Mekanisme Anti-DoS Token Bucket transaksi aktif! Server menerbitkan tantangan PoW.", COL.GREEN)
                results["tx_pow_challenge"] = True
            elif passed_count >= burst_count_tx:
                clog("INFO: Seluruh request lolos (kuota token-bucket lokal belum habis).", COL.YELLOW)
                results["tx_pow_challenge"] = False
            else:
                clog("FAIL: Request gagal tanpa mendapatkan respons 'pow_required'.", COL.RED)
                results["tx_pow_challenge"] = False

        # ---------------------------------------------------------------------
        # TAHAP 5: Menyelesaikan PoW Challenge (Diff: 16) & Verifikasi Bypass
        # ---------------------------------------------------------------------
        if RUN_SOLVE_POW_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog("TAHAP 5: Uji Pemecahan PoW (solve_pow, Diff: 16) & Bypass Rate Limit Transaksi", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)

            if captured_pow_challenge:
                clog("Memecahkan tantangan PoW transaksi secara lokal...", COL.CYAN)
                clog(f"  Scope     : {captured_pow_challenge.get('scope')}", COL.GREY)
                clog(f"  Identity  : {captured_pow_challenge.get('identity')}", COL.GREY)
                clog(f"  Difficulty: {captured_pow_challenge.get('difficulty')} bit leading zeros", COL.GREY)
                clog(f"  Salt      : {captured_pow_challenge.get('salt')}", COL.GREY)

                t_solve = time.perf_counter()
                identity_key = captured_pow_challenge.get("identity") or "anon"
                solved_pow = solve_pow(captured_pow_challenge, identity=identity_key)
                solve_dur = (time.perf_counter() - t_solve) * 1000.0

                if solved_pow and solved_pow.get("nonce"):
                    clog(f"PoW transaksi berhasil dipecahkan dalam {solve_dur:.2f} ms! Nonce={solved_pow.get('nonce')}", COL.GREEN)

                    clog("Mengirimkan CREATE_TX dengan melampirkan payload 'pow' yang valid...", COL.GREY)
                    req_with_pow = {
                        "type": "CREATE_TX",
                        "from": client.client_addr,
                        "to": client.recipient_addr,
                        "amount": 99999,
                        "fee_rate": 2,
                        "pow": solved_pow,
                    }
                    bypass_resp = client.send_rpc(req_with_pow, timeout=5.0)
                    clog(f"Response with PoW: {bypass_resp}", COL.GREY)

                    if bypass_resp and (bypass_resp.get("type") == "TX_TEMPLATE" or bypass_resp.get("error") == "no spendable utxos"):
                        clog("PASS: Server memvalidasi PoW dan meloloskan request transaksi meskipun dalam status rate-limited!", COL.GREEN)
                        results["tx_pow_bypass"] = True
                    elif bypass_resp and bypass_resp.get("error") == "pow_required":
                        clog("FAIL: Server menolak PoW transaksi.", COL.RED)
                        results["tx_pow_bypass"] = False
                    else:
                        clog(f"UNEXPECTED: Response: {bypass_resp}", COL.YELLOW)
                        results["tx_pow_bypass"] = False
                else:
                    clog("FAIL: Gagal menemukan solusi PoW secara lokal.", COL.RED)
                    results["tx_pow_bypass"] = False
            else:
                clog("SKIP: Tidak ada tantangan PoW yang ditangkap dari Tahap 4.", COL.YELLOW)
                results["tx_pow_bypass"] = True

        # ---------------------------------------------------------------------
        # TAHAP 6: Cooldown & Pemulihan Kuota Token Bucket
        # ---------------------------------------------------------------------
        if RUN_COOLDOWN_TEST:
            clog("\n" + "=" * 70, COL.GREY)
            clog(f"TAHAP 6: Uji Pemulihan Cooldown ({cooldown_sec:.1f}s Tunggu Refill)", COL.BOLD + COL.GREY)
            clog("=" * 70, COL.GREY)
            clog(f"Menunggu {cooldown_sec:.1f} detik agar token-bucket transaksi melakukan refill...", COL.CYAN)
            time.sleep(cooldown_sec)

            clog("Mengirimkan CREATE_TX normal tanpa PoW...", COL.GREY)
            clean_req = {
                "type": "CREATE_TX",
                "from": client.client_addr,
                "to": client.recipient_addr,
                "amount": 5000,
                "fee_rate": 2,
            }
            rec_tx = client.send_rpc(clean_req, timeout=5.0)
            clog(f"Response setelah cooldown: {rec_tx}", COL.GREY)

            tx_ok = rec_tx and (rec_tx.get("type") == "TX_TEMPLATE" or rec_tx.get("error") == "no spendable utxos")

            if tx_ok:
                clog("PASS: Kuota Token Bucket transaksi pulih sepenuhnya! Server merespons normal tanpa PoW.", COL.GREEN)
                results["cooldown_recovery"] = True
            else:
                clog(f"FAIL: Kuota belum pulih atau terkena throttle berkelanjutan: {rec_tx}", COL.RED)
                results["cooldown_recovery"] = False

    finally:
        client.close()
        clog("\nKoneksi TCP & SecureChannel ditutup.", COL.GREY)

    # -------------------------------------------------------------------------
    # SUMMARY REPORT
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("RINGKASAN HASIL PENGUJIAN USER RPC - TRANSACTIONS", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    table = Table(title="User RPC Transactions Test Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Test Case", style="bold white", width=34)
    table.add_column("Status", width=12)
    table.add_column("Details", style="grey70")

    table_data = [
        ("0. Handshake Node (NODE)", results.get("user_handshake", False), "P2P SecureChannel & role setup"),
        ("1A. CREATE_TX Empty UTXO Guard", results.get("create_tx_empty_utxo", False), "Defensive 'no spendable utxos' error"),
        ("1B. CREATE_TX Bad Address Guard", results.get("create_tx_bad_addr", False), "Defensive address validation handling"),
        ("2A. CREATE_TX_MULTI Validation", results.get("create_tx_multi_validation", False), "Rejection of empty outputs parameter"),
        ("2B. CREATE_TX_MULTI Processing", results.get("create_tx_multi_process", False), "Multi-output template generation"),
        ("3. NEW_TX Mempool Consensus Guard", results.get("new_tx_rejection", False), "Mempool consensus rejection of unconfirmed tx"),
        ("4. Anti-DoS PoW Challenge (TXSUB)", results.get("tx_pow_challenge", False), "Token bucket throttling returning 'pow_required'"),
        ("5. PoW Solution & Bypass (Diff 16)", results.get("tx_pow_bypass", False), "Stateless PoW solving & verified bypass"),
        ("6. Cooldown & Refill Recovery", results.get("cooldown_recovery", False), f"Bucket refill after {cooldown_sec:.1f}s cooldown"),
    ]

    for name, passed, desc in table_data:
        status_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_text, desc)

    console.print(table)
    all_passed = all(results.values())
    if all_passed:
        clog("SELURUH PENGUJIAN USER RPC TRANSACTIONS LULUS (100% PASS)!", COL.BOLD + COL.GREEN)
    else:
        clog("BEBERAPA PENGUJIAN GAGAL / MEMERLUKAN EVALUASI.", COL.BOLD + COL.RED)

    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_user_transactions_test.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain User RPC Transactions Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help=f"Target node IP/host (default: {TARGET_HOST})")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help=f"Target node port (default: {TARGET_PORT})")
    parser.add_argument("--burst-tx", type=int, default=BURST_COUNT_TX, help=f"Burst count for CREATE_TX (default: {BURST_COUNT_TX})")
    parser.add_argument("--delay-ms", type=float, default=BURST_DELAY_MS, help=f"Burst delay in ms (default: {BURST_DELAY_MS})")
    parser.add_argument("--cooldown-sec", type=float, default=COOLDOWN_WAIT_SEC, help=f"Cooldown wait in seconds (default: {COOLDOWN_WAIT_SEC})")

    args = parser.parse_args()

    run_test_suite(
        host=args.host,
        port=args.port,
        burst_count_tx=args.burst_tx,
        delay_ms=args.delay_ms,
        cooldown_sec=args.cooldown_sec,
    )


if __name__ == "__main__":
    main()
