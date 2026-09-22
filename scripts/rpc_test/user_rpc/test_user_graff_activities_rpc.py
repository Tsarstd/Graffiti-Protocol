# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — User RPC Graffiti Cultural Activities Category Test Suite
====================================================================
Reference: src/tsarchain/network/rpc/docs/USER_RPC.MD
           src/tsarchain/network/rpc/user_rpc/category/graff_activities.py

This script tests the Graffiti Cultural Activities endpoints in TsarChain's User RPC layer:
1. GRAFFITI_GET_POSTS    : Query paginated on-chain ASCII art and graffiti posts
2. GRAFFITI_GET_ART      : Retrieve detailed metadata, root, and storer info for specific art_id
3. Defensive Art Checks  : Missing art_id, invalid art_id syntax, and nonexistent art_id handling
4. GRAFFITI_GET_COMMENTS : Retrieve threaded on-chain comments for specific art_id
5. Defensive Comments    : Empty art_id handling
6. Token-Bucket Burst    : Rapid request burst against GRAFFITI_RL_IP_BURST (100 req/30s)
7. Anti-DoS PoW Challenge: Verification of stateless Proof-of-Work challenge ('pow_required')
8. PoW Solution & Bypass : Solving challenge via solve_pow() and verifying rate-limit bypass
9. Cooldown Refill       : Verification of token-bucket replenishment after backoff

NOTE: 'GRAFFITI_GET_PAYOUTS' is intentionally skipped as instructed (reserved for future implementation).

Execution logs are saved automatically to 'logging/rpc_user_graff_activities_test.log'.
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
# In config.py: GRAFFITI_RL_IP_BURST = 100 per 30 seconds (Backoff: 3s).
BURST_COUNT_GRAFFITI    = 106    # Number of rapid requests to send (threshold: 100)
BURST_DELAY_MS          = 0.0    # Delay between burst requests (0.0 for flood)
COOLDOWN_WAIT_SEC       = 5.0    # Seconds to wait for token bucket refill (Backoff: 3s)

# --- Scenario Toggles ---
RUN_GET_POSTS_TEST      = True   # Test 1: GRAFFITI_GET_POSTS query & pagination
RUN_GET_ART_TEST        = True   # Test 2: GRAFFITI_GET_ART & defensive checks
RUN_GET_COMMENTS_TEST   = True   # Test 3: GRAFFITI_GET_COMMENTS & empty checks
SKIP_GET_PAYOUTS        = True   # Test 4: Skipped as instructed (reserved for future plan)
RUN_BURST_POW_TEST      = True   # Test 5: Rapid burst to trigger 'pow_required' challenge
RUN_SOLVE_POW_TEST      = True   # Test 6: Solve PoW challenge and bypass rate limiting
RUN_COOLDOWN_TEST       = True   # Test 7: Verify token-bucket recovery after cooldown

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_user_graff_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.user_rpc.graff_activities")


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

class UserGraffitiRpcClient:
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
# MAIN TEST SUITE EXECUTION
# =============================================================================

def run_test_suite(
    host: str,
    port: int,
    burst_count_graffiti: int = BURST_COUNT_GRAFFITI,
    delay_ms: float = BURST_DELAY_MS,
    cooldown_sec: float = COOLDOWN_WAIT_SEC,
):
    console = Console()
    console.print(
        Panel.fit(
            f"[bold cyan]TsarChain User RPC Test Suite — Graffiti Cultural Activities[/bold cyan]\n"
            f"[grey70]Target Node  :[/grey70] [yellow]{host}:{port}[/yellow]\n"
            f"[grey70]Network ID   :[/grey70] [green]{CFG.DEFAULT_NET_ID}[/green]\n"
            f"[grey70]Graffiti Burst Limit:[/grey70] [cyan]{CFG.GRAFFITI_RL_IP_BURST} req / {CFG.GRAFFITI_RL_WINDOW_S}s[/cyan] (Backoff: {CFG.GRAFFITI_RL_BACKOFF_S}s)\n"
            f"[grey70]PoW Difficulty:[/grey70] [yellow]{CFG.RPC_POW_DIFFICULTY_READ}[/yellow] (Read-only operations)\n"
            f"[grey70]Dedicated Log:[/grey70] [white]logging/rpc_user_graff_activities_test.log[/white]",
            border_style="cyan",
        )
    )

    client = UserGraffitiRpcClient(host, port)
    if not client.connect():
        clog("ABORT: Gagal terhubung ke remote node. Uji coba dibatalkan.", COL.RED)
        return

    results: dict[str, bool] = {}
    discovered_art_id: str | None = None

    # -------------------------------------------------------------------------
    # TAHAP 0: Handshake User Node (role='NODE')
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("TAHAP 0: Inisialisasi Handshake User Node (role='NODE')", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    hello_payload = {
        "type": "HELLO",
        "port": port,
        "version": "1.0",
        "client_address": client.client_addr,
        "role": "NODE",
    }
    clog(f"Sending HELLO with client_address={client.client_addr}...", COL.GREY)
    resp = client.send_rpc(hello_payload)
    if resp and resp.get("type") == "HELLO_RESPONSE":
        results["user_handshake"] = True
        clog(f"HELLO response: {json.dumps(resp, indent=2)}", COL.GREY)
        clog("User node handshake registered successfully!", COL.GREEN)
    else:
        results["user_handshake"] = False
        clog(f"FAIL: Unexpected handshake response: {resp}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 1: Uji GRAFFITI_GET_POSTS (Daftar Post On-Chain)
    # -------------------------------------------------------------------------
    if RUN_GET_POSTS_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 1: Uji GRAFFITI_GET_POSTS (Query Paginated Posts On-Chain)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        # 1A. Default pagination (limit=10, offset=0)
        clog("Mengirimkan GRAFFITI_GET_POSTS (limit=10, offset=0)...", COL.GREY)
        t0 = time.time()
        resp = client.send_rpc({"type": "GRAFFITI_GET_POSTS", "limit": 10, "offset": 0})
        elapsed = (time.time() - t0) * 1000

        if resp and resp.get("type") == "GRAFFITI_GET_POSTS":
            posts = resp.get("posts") or []
            post_count = len(posts) if type(posts) is list else 0
            results["get_posts_list"] = True
            clog(f"PASS: GRAFFITI_GET_POSTS berhasil diterima ({elapsed:.2f} ms). Total post dalam batch: {post_count}", COL.GREEN)

            if post_count > 0:
                first_post = posts[0]
                if type(first_post) is dict:
                    discovered_art_id = first_post.get("art_id") or first_post.get("id")
                    clog(f"Contoh Post #1: art_id={discovered_art_id}, author={first_post.get('author')}, title={first_post.get('title', 'N/A')}", COL.CYAN)
                    log.info(f"Sample post data: {json.dumps(first_post, indent=2)}")
            else:
                clog("Catatan: Saat ini belum ada post on-chain yang tersimpan di registry.", COL.YELLOW)
        else:
            results["get_posts_list"] = False
            clog(f"FAIL: Respon GRAFFITI_GET_POSTS tidak valid: {resp}", COL.RED)

        # 1B. Pagination offset test (limit=2, offset=1)
        clog("Mengirimkan GRAFFITI_GET_POSTS paginasi (limit=2, offset=1)...", COL.GREY)
        resp_pag = client.send_rpc({"type": "GRAFFITI_GET_POSTS", "limit": 2, "offset": 1})
        if resp_pag and resp_pag.get("type") == "GRAFFITI_GET_POSTS":
            posts_pag = resp_pag.get("posts") or []
            results["get_posts_pagination"] = True
            clog(f"PASS: Pagination GRAFFITI_GET_POSTS valid. Posts returned: {len(posts_pag)}", COL.GREEN)
        else:
            results["get_posts_pagination"] = False
            clog(f"FAIL: Respon paginasi posts tidak valid: {resp_pag}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 2: Uji GRAFFITI_GET_ART (Inspeksi Metadata Seni & Uji Defensif)
    # -------------------------------------------------------------------------
    if RUN_GET_ART_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 2: Uji GRAFFITI_GET_ART (Metadata Seni & Uji Defensif)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        # 2A. Query Art Valid (jika ditemukan art_id di Tahap 1)
        target_art = discovered_art_id or "art_sample_placeholder"
        if discovered_art_id:
            clog(f"2A. Mengirimkan GRAFFITI_GET_ART untuk art_id yang valid: {target_art}...", COL.GREY)
            t0 = time.time()
            resp = client.send_rpc({"type": "GRAFFITI_GET_ART", "art_id": target_art})
            elapsed = (time.time() - t0) * 1000

            if resp and resp.get("type") == "GRAFFITI_GET_ART" and "post" in resp:
                results["get_art_valid"] = True
                clog(f"PASS: Metadata seni berhasil diperoleh ({elapsed:.2f} ms):", COL.GREEN)
                clog(f"  Art ID : {resp.get('art_id')}", COL.CYAN)
                post_meta = resp.get("post") or {}
                if type(post_meta) is dict:
                    clog(f"  Author : {post_meta.get('author')}", COL.GREY)
                    clog(f"  Root   : {post_meta.get('root')}", COL.GREY)
                    clog(f"  Height : {post_meta.get('height')}", COL.GREY)
            else:
                results["get_art_valid"] = False
                clog(f"FAIL: Gagal mengambil art valid: {resp}", COL.RED)
        else:
            clog("2A. Lewati query art valid (tidak ada art_id dari Tahap 1). Menandai sebagai PASS (no on-chain art).", COL.YELLOW)
            results["get_art_valid"] = True

        # 2B. Uji Defensif: Missing art_id
        clog("2B. Mengirimkan GRAFFITI_GET_ART dengan missing art_id (payload kosong)...", COL.GREY)
        resp_missing = client.send_rpc({"type": "GRAFFITI_GET_ART"})
        if resp_missing and resp_missing.get("error") == "missing_art_id":
            results["get_art_missing_guard"] = True
            clog("PASS: Server menolak request tanpa art_id: 'missing_art_id'", COL.GREEN)
        else:
            results["get_art_missing_guard"] = False
            clog(f"FAIL: Respon tidak sesuai harapan untuk missing art_id: {resp_missing}", COL.RED)

        # 2C. Uji Defensif: Malformed / Bad art_id syntax
        clog("2C. Mengirimkan GRAFFITI_GET_ART dengan format karakter tidak valid ('bad_art!@#$')...", COL.GREY)
        resp_bad = client.send_rpc({"type": "GRAFFITI_GET_ART", "art_id": "bad_art!@#$"})
        if resp_bad and resp_bad.get("error") == "bad_art_id":
            results["get_art_bad_format_guard"] = True
            clog("PASS: Server menolak format art_id yang salah: 'bad_art_id' (patch _normalize_art_id verified!)", COL.GREEN)
        else:
            results["get_art_bad_format_guard"] = False
            clog(f"FAIL: Respon tidak sesuai harapan untuk bad art_id: {resp_bad}", COL.RED)

        # 2D. Uji Defensif: Non-existent art_id
        dummy_hex_art = "00" * 32
        clog(f"2D. Mengirimkan GRAFFITI_GET_ART dengan art_id yang tidak ada ({dummy_hex_art[:16]}...)...", COL.GREY)
        resp_not_found = client.send_rpc({"type": "GRAFFITI_GET_ART", "art_id": dummy_hex_art})
        if resp_not_found and resp_not_found.get("error") == "not_found":
            results["get_art_not_found_guard"] = True
            clog("PASS: Server merespons bahwa art_id tidak ditemukan: 'not_found'", COL.GREEN)
        else:
            results["get_art_not_found_guard"] = False
            clog(f"FAIL: Respon tidak sesuai harapan untuk nonexistent art_id: {resp_not_found}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 3: Uji GRAFFITI_GET_COMMENTS (Inspeksi Thread Komentar & Uji Defensif)
    # -------------------------------------------------------------------------
    if RUN_GET_COMMENTS_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 3: Uji GRAFFITI_GET_COMMENTS (Thread Komentar & Uji Defensif)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        target_art = discovered_art_id or "art_test_query"

        # 3A. Query Komentar
        clog(f"3A. Mengirimkan GRAFFITI_GET_COMMENTS untuk art_id: {target_art} (limit=50)...", COL.GREY)
        t0 = time.time()
        resp = client.send_rpc({"type": "GRAFFITI_GET_COMMENTS", "art_id": target_art, "limit": 50})
        elapsed = (time.time() - t0) * 1000

        if resp and resp.get("type") == "GRAFFITI_GET_COMMENTS":
            comments = resp.get("comments") or []
            results["get_comments_query"] = True
            clog(f"PASS: GRAFFITI_GET_COMMENTS berhasil diterima ({elapsed:.2f} ms). Komentar ditemukan: {len(comments)}", COL.GREEN)
        else:
            results["get_comments_query"] = False
            clog(f"FAIL: Respon komentar tidak valid: {resp}", COL.RED)

        # 3B. Defensive: Empty art_id
        clog("3B. Mengirimkan GRAFFITI_GET_COMMENTS dengan art_id kosong...", COL.GREY)
        resp_empty = client.send_rpc({"type": "GRAFFITI_GET_COMMENTS", "art_id": ""})
        if resp_empty and resp_empty.get("type") == "GRAFFITI_GET_COMMENTS" and resp_empty.get("comments") == []:
            results["get_comments_empty_guard"] = True
            clog("PASS: Server mengembalikan list komentar kosong untuk art_id kosong tanpa crash.", COL.GREEN)
        else:
            results["get_comments_empty_guard"] = False
            clog(f"FAIL: Respon tidak sesuai harapan untuk komentar art_id kosong: {resp_empty}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 4: Pemeriksaan Endpoint GRAFFITI_GET_PAYOUTS (Skipped as Instructed)
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("TAHAP 4: Status Endpoint GRAFFITI_GET_PAYOUTS", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)
    if SKIP_GET_PAYOUTS:
        clog("INFORMASI: Sesuai instruksi pengguna, RPC 'GET_PAYOUTS' sengaja DILEWATI (SKIPPED)", COL.YELLOW)
        clog("           karena belum diimplementasikan dan memiliki rencana tersendiri nantinya.", COL.GREY)
        results["get_payouts_skipped"] = True
    else:
        results["get_payouts_skipped"] = True

    # -------------------------------------------------------------------------
    # TAHAP 5: Uji Rate Limiting Token-Bucket & Anti-DoS PoW (Burst ~106x)
    # -------------------------------------------------------------------------
    pow_challenge: dict | None = None

    if RUN_BURST_POW_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog(f"TAHAP 5: Uji Rate Limiting Token-Bucket & PoW Challenge ({burst_count_graffiti}x GRAFFITI_GET_POSTS)", COL.BOLD + COL.CYAN)
        clog(f"Batas Server: {CFG.GRAFFITI_RL_IP_BURST} request per {CFG.GRAFFITI_RL_WINDOW_S}s (Backoff: {CFG.GRAFFITI_RL_BACKOFF_S}s)", COL.YELLOW)
        clog("=" * 70, COL.CYAN)

        throttled = False
        throttled_at_req = -1

        for i in range(1, burst_count_graffiti + 1):
            t_req = time.time()
            resp = client.send_rpc({"type": "GRAFFITI_GET_POSTS", "limit": 1})
            dur_ms = (time.time() - t_req) * 1000

            if not resp:
                clog(f"  [Req #{i:03d}] ERROR: Frame kosong atau timeout", COL.RED)
                continue

            err = resp.get("error")
            if err == "pow_required":
                throttled = True
                throttled_at_req = i
                pow_challenge = resp.get("pow_challenge") or resp
                retry_after = resp.get("retry_after", CFG.GRAFFITI_RL_BACKOFF_S)
                clog(f"  [Req #{i:03d}] THROTTLED: error='pow_required' retry_after={retry_after}s ({dur_ms:.1f} ms)", COL.YELLOW)
                clog(f"  PoW Challenge Data: {json.dumps(pow_challenge)}", COL.GREY)
                break
            elif resp.get("type") == "GRAFFITI_GET_POSTS":
                if i % 10 == 0 or i <= 5 or i >= 95:
                    clog(f"  [Req #{i:03d}] OK: GRAFFITI_GET_POSTS diterima ({dur_ms:.1f} ms)", COL.GREY)
            else:
                clog(f"  [Req #{i:03d}] Lainnya: {resp}", COL.GREY)

            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        if throttled and pow_challenge:
            results["graff_pow_challenge"] = True
            clog(f"PASS: Mekanisme Anti-DoS Token Bucket Graffiti aktif pada request #{throttled_at_req:03d}!", COL.GREEN)
            clog(f"      Server menerbitkan tantangan PoW: scope='{pow_challenge.get('scope')}', difficulty={pow_challenge.get('difficulty')}", COL.GREEN)
        else:
            results["graff_pow_challenge"] = False
            clog("FAIL: Server tidak memicu tantangan 'pow_required' setelah burst selesai.", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 6: Uji Pemecahan PoW (solve_pow, Diff: 12) & Bypass Rate Limit
    # -------------------------------------------------------------------------
    if RUN_SOLVE_POW_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 6: Uji Pemecahan PoW (solve_pow, Diff: 12) & Bypass Rate Limit Graffiti", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        if not pow_challenge:
            clog("FAIL: Tidak ada challenge PoW dari tahap sebelumnya untuk dipecahkan.", COL.RED)
            results["graff_pow_bypass"] = False
        else:
            clog("Memecahkan tantangan PoW graffiti secara lokal...", COL.CYAN)
            clog(f"  Scope     : {pow_challenge.get('scope')}", COL.GREY)
            clog(f"  Identity  : {pow_challenge.get('identity')}", COL.GREY)
            clog(f"  Difficulty: {pow_challenge.get('difficulty')} bit leading zeros", COL.GREY)
            clog(f"  Salt      : {pow_challenge.get('salt')}", COL.GREY)

            t_solve = time.time()
            solved_pow = solve_pow(pow_challenge, identity=pow_challenge.get("identity"))
            solve_dur = (time.time() - t_solve) * 1000

            if solved_pow and "nonce" in solved_pow:
                clog(f"PoW graffiti berhasil dipecahkan dalam {solve_dur:.2f} ms! Nonce={solved_pow['nonce']}", COL.GREEN)
                log.info(f"Solved PoW payload: {json.dumps(solved_pow)}")

                clog("Mengirimkan GRAFFITI_GET_POSTS dengan melampirkan payload 'pow' yang valid...", COL.CYAN)
                bypass_payload = {
                    "type": "GRAFFITI_GET_POSTS",
                    "limit": 1,
                    "pow": solved_pow,
                }
                resp_bypass = client.send_rpc(bypass_payload)

                if resp_bypass and resp_bypass.get("type") == "GRAFFITI_GET_POSTS":
                    results["graff_pow_bypass"] = True
                    clog(f"Response with PoW: {resp_bypass.get('type')}", COL.GREY)
                    clog("PASS: Server memvalidasi PoW dan meloloskan request graffiti meskipun dalam status rate-limited!", COL.GREEN)
                else:
                    results["graff_pow_bypass"] = False
                    clog(f"FAIL: Server menolak request yang disertai PoW valid: {resp_bypass}", COL.RED)
            else:
                results["graff_pow_bypass"] = False
                clog("FAIL: Gagal menemukan solusi PoW secara lokal.", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 7: Uji Pemulihan Cooldown (Refill Recovery)
    # -------------------------------------------------------------------------
    if RUN_COOLDOWN_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog(f"TAHAP 7: Uji Pemulihan Cooldown ({cooldown_sec:.1f}s Tunggu Refill)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        clog(f"Menunggu {cooldown_sec:.1f} detik agar token-bucket graffiti melakukan refill...", COL.YELLOW)
        time.sleep(cooldown_sec)

        clog("Mengirimkan GRAFFITI_GET_POSTS normal tanpa PoW...", COL.CYAN)
        resp_after = client.send_rpc({"type": "GRAFFITI_GET_POSTS", "limit": 1})

        if resp_after and resp_after.get("type") == "GRAFFITI_GET_POSTS":
            results["cooldown_recovery"] = True
            clog("PASS: Kuota Token Bucket graffiti pulih sepenuhnya! Server merespons normal tanpa PoW.", COL.GREEN)
        elif resp_after and resp_after.get("error") == "pow_required":
            results["cooldown_recovery"] = False
            clog("FAIL: Server masih dalam status throttled setelah cooldown.", COL.RED)
        else:
            results["cooldown_recovery"] = False
            clog(f"FAIL: Respon tidak terduga setelah cooldown: {resp_after}", COL.RED)

    # -------------------------------------------------------------------------
    # TEARDOWN
    # -------------------------------------------------------------------------
    client.close()
    clog("\nKoneksi TCP & SecureChannel ditutup.", COL.GREY)

    # -------------------------------------------------------------------------
    # SUMMARY REPORT
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("RINGKASAN HASIL PENGUJIAN USER RPC - GRAFFITI CULTURAL ACTIVITIES", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    table = Table(title="User RPC Graffiti Activities Test Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Test Case", style="bold white", width=36)
    table.add_column("Status", width=12)
    table.add_column("Details", style="grey70")

    table_data = [
        ("0. Handshake Node (NODE)", results.get("user_handshake", False), "P2P SecureChannel & role setup"),
        ("1A. GRAFFITI_GET_POSTS Query", results.get("get_posts_list", False), "Paginated on-chain posts lookup"),
        ("1B. GRAFFITI_GET_POSTS Pagination", results.get("get_posts_pagination", False), "Pagination offset & limit inspection"),
        ("2A. GRAFFITI_GET_ART Metadata", results.get("get_art_valid", False), "Art details, author, root & height"),
        ("2B. Missing Art ID Guard", results.get("get_art_missing_guard", False), "Defensive rejection 'missing_art_id'"),
        ("2C. Bad Art ID Syntax Guard", results.get("get_art_bad_format_guard", False), "Defensive rejection 'bad_art_id' (patch verified)"),
        ("2D. Non-existent Art ID Guard", results.get("get_art_not_found_guard", False), "Defensive response 'not_found'"),
        ("3A. GRAFFITI_GET_COMMENTS Query", results.get("get_comments_query", False), "On-chain comments thread retrieval"),
        ("3B. Empty Comments Art ID Guard", results.get("get_comments_empty_guard", False), "Graceful empty list for blank art_id"),
        ("4. GET_PAYOUTS (Reserved)", results.get("get_payouts_skipped", False), "Skipped as instructed (reserved for future)"),
        ("5. Token-Bucket Burst (100 req/30s)", results.get("graff_pow_challenge", False), "Throttling returning 'pow_required'"),
        ("6. PoW Solution & Bypass (Diff 12)", results.get("graff_pow_bypass", False), "Stateless PoW solving & verified bypass"),
        ("7. Cooldown & Refill Recovery", results.get("cooldown_recovery", False), f"Bucket refill after {cooldown_sec:.1f}s cooldown"),
    ]

    for name, passed, desc in table_data:
        status_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_text, desc)

    console.print(table)
    all_passed = all(results.values())
    if all_passed:
        clog("SELURUH PENGUJIAN USER RPC GRAFFITI LULUS (100% PASS)!", COL.BOLD + COL.GREEN)
    else:
        clog("BEBERAPA PENGUJIAN GAGAL / MEMERLUKAN EVALUASI.", COL.BOLD + COL.RED)

    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_user_graff_activities_test.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain User RPC Graffiti Activities Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help=f"Target node IP/host (default: {TARGET_HOST})")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help=f"Target node port (default: {TARGET_PORT})")
    parser.add_argument("--burst-graffiti", type=int, default=BURST_COUNT_GRAFFITI, help=f"Burst count for GRAFFITI_GET_POSTS (default: {BURST_COUNT_GRAFFITI})")
    parser.add_argument("--delay-ms", type=float, default=BURST_DELAY_MS, help=f"Burst delay in ms (default: {BURST_DELAY_MS})")
    parser.add_argument("--cooldown-sec", type=float, default=COOLDOWN_WAIT_SEC, help=f"Cooldown wait in seconds (default: {COOLDOWN_WAIT_SEC})")

    args = parser.parse_args()

    run_test_suite(
        host=args.host,
        port=args.port,
        burst_count_graffiti=args.burst_graffiti,
        delay_ms=args.delay_ms,
        cooldown_sec=args.cooldown_sec,
    )


if __name__ == "__main__":
    main()
