# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Tsar Studio
# Part of TsarChain — see LICENSE

"""
TsarChain — User RPC Encrypted Chat Category Test Suite
======================================================
Reference: src/tsarchain/network/rpc/docs/USER_RPC.MD
           src/tsarchain/network/rpc/user_rpc/category/chat.py
           src/kremlin/security/chat/chat_common.py

This script performs an exhaustive, end-to-end verification of TsarChain's
Decentralized End-to-End Encrypted (E2EE) Chat Subsystem:

1. Handshake & Setup        : P2P SecureChannel connection with role='NODE'
2. Cryptographic Identities : Dual Secp256k1 spend keys + X25519 DH keys (Alice & Bob)
3. Pre-Registration Lookups : CHAT_CHECK_PREKEYS and CHAT_LOOKUP_PUB on unregistered profiles
4. Chat Registration       : CHAT_REGISTER for Alice & Bob with cryptographic signatures
5. Defensive Registration   : Stale timestamps, signature mismatches, malformed payloads
6. Post-Registration Status : Verification of persistent LMDB bundles and in-memory presence
7. Presence Heartbeats      : CHAT_PRESENCE updates and stale timestamp rejection
8. X3DH Prekey Cycle        : CHAT_PUBLISH_PREKEYS and atomic FIFO OPK consumption in CHAT_GET_PREKEY
9. Encrypted E2EE Messaging : CHAT_SEND with blind relay envelope, routing signature & duplicate guards
10. Mailbox FIFO Drain      : CHAT_PULL with authenticated pull signature & RAM queue clearing
11. Read Receipts           : CHAT_READ delivery and read-state signaling
12. Profile Deactivation    : DEACTIVATE_CHAT, database prekey deletion & reactivate cooldown guard
13. Token-Bucket Throttling : Rapid burst against CHAT_LOOKUP_RL_IP_BURST (80 req/10s, backoff: 2s)
14. Anti-DoS PoW Challenge  : Stateless PoW challenge verification (scope='rpc:chat_lookup', diff: 8)
15. PoW Solution & Bypass   : Solving challenge via solve_pow() and verifying rate-limit bypass
16. Cooldown Refill         : Verification of token-bucket replenishment after backoff

Execution logs are saved automatically to 'logging/rpc_user_chat_test.log'.
"""

from __future__ import annotations

import time
import json
import socket
import hashlib
import argparse
from datetime import datetime
from bech32 import bech32_encode, convertbits
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Cryptographic libraries
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

# ---------------- Local Project ----------------
from tsarchain.utils import config as CFG
from tsarchain.utils.helpers import hash160, sign_digest_der_low_s_native
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
# In config.py: CHAT_LOOKUP_RL_IP_BURST = 80 per 10 seconds (Backoff: 2s).
BURST_COUNT_CHAT        = 86     # Number of rapid lookup requests to send (threshold: 80)
BURST_DELAY_MS          = 0.0    # Delay between burst requests (0.0 for flood)
COOLDOWN_WAIT_SEC       = 4.0    # Seconds to wait for token bucket refill (Backoff: 2s)

# --- Scenario Toggles ---
RUN_REGISTRATION_TEST   = True   # Stage 3: CHAT_REGISTER for Alice & Bob
RUN_PRESENCE_TEST       = True   # Stage 5: CHAT_PRESENCE updates
RUN_PREKEY_CYCLE_TEST   = True   # Stage 6: CHAT_PUBLISH_PREKEYS & CHAT_GET_PREKEY
RUN_SEND_MESSAGE_TEST   = True   # Stage 7: CHAT_SEND E2EE envelope
RUN_PULL_MAILBOX_TEST   = True   # Stage 8: CHAT_PULL & mailbox drain
RUN_READ_RECEIPT_TEST   = True   # Stage 9: CHAT_READ receipt
RUN_DEACTIVATE_TEST     = True   # Stage 10: DEACTIVATE_CHAT & cooldown guard
RUN_BURST_POW_TEST      = True   # Stage 11: Rapid burst to trigger 'pow_required' challenge
RUN_SOLVE_POW_TEST      = True   # Stage 12: Solve PoW challenge and bypass rate limiting
RUN_COOLDOWN_TEST       = True   # Stage 13: Verify token-bucket recovery after cooldown

# --- Client Identity ---
CLIENT_KEY_NAME         = "rpc_user_chat_node_client"

# =============================================================================
# LOGGER & FORMATTER
# =============================================================================

log = get_ctx_logger("scripts.rpc_test.user_rpc.chat")


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
# CRYPTOGRAPHIC IDENTITY GENERATOR & SIGNER
# =============================================================================

class ChatIdentity:
    """Manages full Secp256k1 spend wallet and X25519 key hierarchy for an actor."""

    def __init__(self, name: str):
        self.name = name

        # 1. Secp256k1 spend keypair & Bech32 address
        sk_ec = ec.generate_private_key(ec.SECP256K1())
        self.spend_priv_hex = sk_ec.private_numbers().private_value.to_bytes(32, "big").hex()
        nums = sk_ec.public_key().public_numbers()
        prefix = 0x02 | (nums.y & 1)
        self.spend_pub_hex = f"{prefix:02x}{nums.x:064x}"

        pkh = hash160(bytes.fromhex(self.spend_pub_hex))
        data = [0] + list(convertbits(pkh, 8, 5, True))
        self.address = bech32_encode(CFG.ADDRESS_PREFIX, data)

        # 2. X25519 Long-term Identity Key (IK)
        sk_ik = x25519.X25519PrivateKey.generate()
        self.ik_priv_hex = sk_ik.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.ik_pub_hex = sk_ik.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        # 3. X25519 Signed PreKey (SPK)
        sk_spk = x25519.X25519PrivateKey.generate()
        self.spk_priv_hex = sk_spk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.spk_pub_hex = sk_spk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        # 4. X25519 One-Time PreKey (OPK)
        sk_opk = x25519.X25519PrivateKey.generate()
        self.opk_priv_hex = sk_opk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.opk_pub_hex = sk_opk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, data: bytes) -> str:
        """Signs arbitrary payload bytes with Secp256k1 spend private key."""
        digest = hashlib.sha256(data).digest()
        sig = sign_digest_der_low_s_native(self.spend_priv_hex, digest)
        return sig.hex()

    def build_presence_sig(self, ts_val: int) -> str:
        pres_bytes = b"|".join([
            b"CHAT_PRESENCE",
            self.address.encode(),
            bytes.fromhex(self.ik_pub_hex),
            bytes.fromhex(self.spend_pub_hex),
            str(ts_val).encode(),
        ])
        return self.sign(pres_bytes)

    def build_reg_sig(self, ts_val: int) -> str:
        reg_bytes = b"|".join([
            b"CHAT_REG",
            self.address.encode(),
            bytes.fromhex(self.spend_pub_hex),
            bytes.fromhex(self.ik_pub_hex),
            str(int(ts_val)).encode(),
        ])
        return self.sign(reg_bytes)

    def build_spk_sig(self, spk_hex: str) -> str:
        spk_payload = CFG.CHAT_SPK + bytes.fromhex(spk_hex) + b"|" + bytes.fromhex(self.spend_pub_hex)
        return self.sign(spk_payload)

    def build_pull_sig(self, ts_val: int) -> str:
        pull_bytes = b"|".join([b"CHAT_PULL", self.address.encode(), str(ts_val).encode()])
        return self.sign(pull_bytes)

    def build_deactivate_sig(self, ts_val: int) -> str:
        deact_bytes = b"|".join([b"DEACTIVATE_CHAT", self.address.encode("utf-8"), str(ts_val).encode("utf-8")])
        return self.sign(deact_bytes)


# =============================================================================
# USER RPC CLIENT HELPER
# =============================================================================

class UserChatRpcClient:
    def __init__(self, host: str, port: int, key_name: str = CLIENT_KEY_NAME):
        self.host = str(host)
        self.port = int(port)
        self.key_name = key_name
        self.node_id, self.pubkey, self.privkey = load_or_create_keypair_at(key_name)

        # Derive canonical Bech32 address from transport pubkey
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
    burst_count_chat: int = BURST_COUNT_CHAT,
    delay_ms: float = BURST_DELAY_MS,
    cooldown_sec: float = COOLDOWN_WAIT_SEC,
):
    console = Console()
    console.print(
        Panel.fit(
            f"[bold cyan]TsarChain User RPC Test Suite — Encrypted P2P Chat[/bold cyan]\n"
            f"[grey70]Target Node  :[/grey70] [yellow]{host}:{port}[/yellow]\n"
            f"[grey70]Network ID   :[/grey70] [green]{CFG.DEFAULT_NET_ID}[/green]\n"
            f"[grey70]Chat Lookup Burst Limit:[/grey70] [cyan]{CFG.CHAT_LOOKUP_RL_IP_BURST} req / {CFG.CHAT_LOOKUP_RL_IP_WINDOW_S}s[/cyan] (Backoff: {CFG.CHAT_LOOKUP_RL_BACKOFF_S}s)\n"
            f"[grey70]PoW Difficulty Chat:[/grey70] [yellow]{CFG.RPC_POW_DIFFICULTY_CHAT}[/yellow] (Anti-spam protection)\n"
            f"[grey70]Dedicated Log:[/grey70] [white]logging/rpc_user_chat_test.log[/white]",
            border_style="cyan",
        )
    )

    client = UserChatRpcClient(host, port)
    if not client.connect():
        clog("ABORT: Gagal terhubung ke remote node. Uji coba dibatalkan.", COL.RED)
        return

    results: dict[str, bool] = {}

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
    # TAHAP 1: Inisialisasi Identitas Kriptografi Dual-Client (Alice & Bob)
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("TAHAP 1: Inisialisasi Identitas Kriptografi Dual-Client (Alice & Bob)", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    alice = ChatIdentity("Alice")
    bob = ChatIdentity("Bob")

    clog(f"Identitas Alice berhasil digenerate:", COL.CYAN)
    clog(f"  Address   : {alice.address}", COL.GREY)
    clog(f"  Spend Pub : {alice.spend_pub_hex}", COL.GREY)
    clog(f"  IK Pub    : {alice.ik_pub_hex}", COL.GREY)

    clog(f"Identitas Bob berhasil digenerate:", COL.CYAN)
    clog(f"  Address   : {bob.address}", COL.GREY)
    clog(f"  Spend Pub : {bob.spend_pub_hex}", COL.GREY)
    clog(f"  IK Pub    : {bob.ik_pub_hex}", COL.GREY)

    results["crypto_identities_init"] = True

    # -------------------------------------------------------------------------
    # TAHAP 2: Uji Pra-Registrasi (CHAT_CHECK_PREKEYS & CHAT_LOOKUP_PUB)
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("TAHAP 2: Uji Pra-Registrasi & Pencarian Profil Belum Terdaftar", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    # 2A. CHAT_CHECK_PREKEYS untuk Alice sebelum registrasi
    clog(f"2A. Memeriksa status prekeys Alice sebelum registrasi...", COL.GREY)
    resp_chk = client.send_rpc({"type": "CHAT_CHECK_PREKEYS", "address": alice.address})
    if resp_chk and resp_chk.get("registered") is False and resp_chk.get("has_ik") is False:
        results["pre_reg_check_prekeys"] = True
        clog(f"PASS: Server menyatakan Alice belum terdaftar: registered=False, has_ik=False", COL.GREEN)
    else:
        results["pre_reg_check_prekeys"] = False
        clog(f"FAIL: Respon status sebelum registrasi tidak sesuai: {resp_chk}", COL.RED)

    # 2B. CHAT_LOOKUP_PUB untuk Alice sebelum registrasi
    clog(f"2B. Mencari pubkey chat Alice sebelum registrasi...", COL.GREY)
    resp_look = client.send_rpc({"type": "CHAT_LOOKUP_PUB", "address": alice.address})
    if resp_look and resp_look.get("found") is False and resp_look.get("pubkey") is None:
        results["pre_reg_lookup_pub"] = True
        clog(f"PASS: Server menyatakan pubkey chat Alice belum ada: found=False", COL.GREEN)
    else:
        results["pre_reg_lookup_pub"] = False
        clog(f"FAIL: Respon pencarian sebelum registrasi tidak sesuai: {resp_look}", COL.RED)

    # 2C. Defensive check: missing address
    clog("2C. Defensive: Query CHAT_LOOKUP_PUB dengan missing address...", COL.GREY)
    resp_def_look = client.send_rpc({"type": "CHAT_LOOKUP_PUB"})
    if resp_def_look and resp_def_look.get("error") == "missing address":
        results["lookup_missing_addr_guard"] = True
        clog("PASS: Server menolak lookup tanpa address: 'missing address'", COL.GREEN)
    else:
        results["lookup_missing_addr_guard"] = False
        clog(f"FAIL: Respon missing address tidak sesuai: {resp_def_look}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 3: Uji Registrasi Profil Chat (CHAT_REGISTER)
    # -------------------------------------------------------------------------
    if RUN_REGISTRATION_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 3: Uji Registrasi Profil Chat (CHAT_REGISTER: Alice & Bob)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_now = int(time.time())

        # 3A. Registrasi Alice
        clog("3A. Melakukan registrasi profil chat untuk Alice...", COL.CYAN)
        alice_spk_sig = alice.build_spk_sig(alice.spk_pub_hex)
        alice_reg_payload = {
            "type": "CHAT_REGISTER",
            "address": alice.address,
            "chat_pub": alice.ik_pub_hex,
            "spend_pub": alice.spend_pub_hex,
            "presence_sig": alice.build_presence_sig(ts_now),
            "reg_sig": alice.build_reg_sig(ts_now),
            "ts": ts_now,
            "spk": alice.spk_pub_hex,
            "sig": alice_spk_sig,
            "opk": alice.opk_pub_hex,
        }
        resp_reg_a = client.send_rpc(alice_reg_payload)
        if resp_reg_a and resp_reg_a.get("type") == "CHAT_REGISTERED" and resp_reg_a.get("address") == alice.address:
            results["register_alice"] = True
            clog(f"PASS: Profil chat Alice berhasil terdaftar di node! pubkey={resp_reg_a.get('pubkey')}", COL.GREEN)
        else:
            results["register_alice"] = False
            clog(f"FAIL: Gagal mendaftarkan profil Alice: {resp_reg_a}", COL.RED)

        # 3B. Registrasi Bob
        clog("3B. Melakukan registrasi profil chat untuk Bob...", COL.CYAN)
        bob_spk_sig = bob.build_spk_sig(bob.spk_pub_hex)
        bob_reg_payload = {
            "type": "CHAT_REGISTER",
            "address": bob.address,
            "chat_pub": bob.ik_pub_hex,
            "spend_pub": bob.spend_pub_hex,
            "presence_sig": bob.build_presence_sig(ts_now),
            "reg_sig": bob.build_reg_sig(ts_now),
            "ts": ts_now,
            "spk": bob.spk_pub_hex,
            "sig": bob_spk_sig,
            "opk": bob.opk_pub_hex,
        }
        resp_reg_b = client.send_rpc(bob_reg_payload)
        if resp_reg_b and resp_reg_b.get("type") == "CHAT_REGISTERED" and resp_reg_b.get("address") == bob.address:
            results["register_bob"] = True
            clog(f"PASS: Profil chat Bob berhasil terdaftar di node! pubkey={resp_reg_b.get('pubkey')}", COL.GREEN)
        else:
            results["register_bob"] = False
            clog(f"FAIL: Gagal mendaftarkan profil Bob: {resp_reg_b}", COL.RED)

        # 3C. Defensive check: Stale timestamp (>300 detik yang lalu)
        clog("3C. Defensive: Registrasi dengan timestamp kadaluarsa (anti-replay guard)...", COL.GREY)
        stale_payload = dict(bob_reg_payload)
        stale_payload["ts"] = ts_now - 500
        resp_stale = client.send_rpc(stale_payload)
        if resp_stale and resp_stale.get("error") == "stale ts":
            results["register_stale_ts_guard"] = True
            clog("PASS: Server menolak registrasi timestamp kadaluarsa: 'stale ts'", COL.GREEN)
        else:
            results["register_stale_ts_guard"] = False
            clog(f"FAIL: Respon timestamp kadaluarsa tidak sesuai: {resp_stale}", COL.RED)

        # 3D. Defensive check: Signature mismatch
        clog("3D. Defensive: Registrasi dengan signature yang tidak valid...", COL.GREY)
        bad_sig_payload = dict(bob_reg_payload)
        bad_sig_payload["reg_sig"] = "00" * 32
        resp_bad_sig = client.send_rpc(bad_sig_payload)
        if resp_bad_sig and "error" in resp_bad_sig:
            results["register_bad_sig_guard"] = True
            clog(f"PASS: Server menolak registrasi signature palsu: {resp_bad_sig.get('error')}", COL.GREEN)
        else:
            results["register_bad_sig_guard"] = False
            clog(f"FAIL: Respon signature palsu tidak sesuai: {resp_bad_sig}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 4: Verifikasi Pasca-Registrasi (CHAT_CHECK_PREKEYS & CHAT_LOOKUP_PUB)
    # -------------------------------------------------------------------------
    clog("\n" + "=" * 70, COL.CYAN)
    clog("TAHAP 4: Verifikasi Pasca-Registrasi Profil Chat", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    # 4A. CHAT_CHECK_PREKEYS Alice
    clog(f"4A. Memeriksa status prekeys Alice setelah registrasi...", COL.GREY)
    resp_chk_post = client.send_rpc({"type": "CHAT_CHECK_PREKEYS", "address": alice.address})
    if (
        resp_chk_post
        and resp_chk_post.get("registered") is True
        and resp_chk_post.get("has_ik") is True
        and resp_chk_post.get("has_spk") is True
        and resp_chk_post.get("opk_count", 0) >= 1
    ):
        results["post_reg_check_prekeys"] = True
        clog(f"PASS: Status registrasi Alice aktif! registered=True, has_ik=True, opk_count={resp_chk_post.get('opk_count')}", COL.GREEN)
    else:
        results["post_reg_check_prekeys"] = False
        clog(f"FAIL: Verifikasi status prekeys gagal: {resp_chk_post}", COL.RED)

    # 4B. CHAT_LOOKUP_PUB Alice
    clog(f"4B. Mencari pubkey chat Alice...", COL.GREY)
    resp_look_a = client.send_rpc({"type": "CHAT_LOOKUP_PUB", "address": alice.address})
    if resp_look_a and resp_look_a.get("found") is True and resp_look_a.get("pubkey") == alice.ik_pub_hex:
        results["post_reg_lookup_alice"] = True
        clog(f"PASS: Pubkey Alice berhasil ditemukan: {resp_look_a.get('pubkey')[:16]}... (matches IK)", COL.GREEN)
    else:
        results["post_reg_lookup_alice"] = False
        clog(f"FAIL: Pencarian pubkey Alice tidak sesuai: {resp_look_a}", COL.RED)

    # 4C. CHAT_LOOKUP_PUB Bob
    clog(f"4C. Mencari pubkey chat Bob...", COL.GREY)
    resp_look_b = client.send_rpc({"type": "CHAT_LOOKUP_PUB", "address": bob.address})
    if resp_look_b and resp_look_b.get("found") is True and resp_look_b.get("pubkey") == bob.ik_pub_hex:
        results["post_reg_lookup_bob"] = True
        clog(f"PASS: Pubkey Bob berhasil ditemukan: {resp_look_b.get('pubkey')[:16]}... (matches IK)", COL.GREEN)
    else:
        results["post_reg_lookup_bob"] = False
        clog(f"FAIL: Pencarian pubkey Bob tidak sesuai: {resp_look_b}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 5: Uji Presence Denyut Jantung Online (CHAT_PRESENCE)
    # -------------------------------------------------------------------------
    if RUN_PRESENCE_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 5: Uji Presence Denyut Jantung Online (CHAT_PRESENCE)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_pres = int(time.time())
        pres_payload = {
            "type": "CHAT_PRESENCE",
            "address": alice.address,
            "pubkey": alice.ik_pub_hex,
            "spend_pub": alice.spend_pub_hex,
            "presence_sig": alice.build_presence_sig(ts_pres),
            "ts": ts_pres,
            "hops": 0,
        }
        clog("5A. Mengirimkan CHAT_PRESENCE denyut jantung untuk Alice...", COL.GREY)
        resp_pres = client.send_rpc(pres_payload)
        if resp_pres and resp_pres.get("type") == "CHAT_PRESENCE_OK":
            results["chat_presence_update"] = True
            clog("PASS: CHAT_PRESENCE_OK diterima! Status online Alice diperbarui.", COL.GREEN)
        else:
            results["chat_presence_update"] = False
            clog(f"FAIL: CHAT_PRESENCE gagal: {resp_pres}", COL.RED)

        # Defensive check: Presence with stale timestamp (>CFG.PRESENCE_TTL_S = 3600s)
        clog("5B. Defensive: Mengirimkan CHAT_PRESENCE dengan timestamp kadaluarsa (>3600s)...", COL.GREY)
        stale_pres = dict(pres_payload)
        stale_ts = ts_pres - (int(CFG.PRESENCE_TTL_S) + 200)
        stale_pres["ts"] = stale_ts
        stale_pres["presence_sig"] = alice.build_presence_sig(stale_ts)
        resp_pres_stale = client.send_rpc(stale_pres)
        if resp_pres_stale and resp_pres_stale.get("error") == "presence_stale":
            results["presence_stale_guard"] = True
            clog("PASS: Server menolak presence kadaluarsa: 'presence_stale'", COL.GREEN)
        else:
            results["presence_stale_guard"] = False
            clog(f"FAIL: Respon presence kadaluarsa tidak sesuai: {resp_pres_stale}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 6: Uji Siklus Prekey X3DH (CHAT_PUBLISH_PREKEYS & CHAT_GET_PREKEY)
    # -------------------------------------------------------------------------
    if RUN_PREKEY_CYCLE_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 6: Uji Siklus Prekey X3DH (Publish & Atomic Pop Consume)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        # 6A. Bob mempublikasikan prekeys baru
        clog("6A. Bob mempublikasikan prekey baru (SPK + OPK) via CHAT_PUBLISH_PREKEYS...", COL.GREY)
        new_spk_sk = x25519.X25519PrivateKey.generate()
        new_spk_pk = new_spk_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        new_spk_sig = bob.build_spk_sig(new_spk_pk)

        new_opk_sk = x25519.X25519PrivateKey.generate()
        new_opk_pk = new_opk_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        pub_prekey_payload = {
            "type": "CHAT_PUBLISH_PREKEYS",
            "address": bob.address,
            "ik": bob.ik_pub_hex,
            "spk": new_spk_pk,
            "sig": new_spk_sig,
            "opk": new_opk_pk,
        }
        resp_pub_pk = client.send_rpc(pub_prekey_payload)
        if resp_pub_pk and resp_pub_pk.get("type") == "CHAT_PUBLISH_PREKEYS":
            results["publish_prekeys"] = True
            clog("PASS: Prekeys baru Bob berhasil dipublikasikan ke node!", COL.GREEN)
        else:
            results["publish_prekeys"] = False
            clog(f"FAIL: Publikasi prekeys gagal: {resp_pub_pk}", COL.RED)

        # 6B. Alice meminta prekey bundle Bob (CHAT_GET_PREKEY)
        clog("6B. Alice meminta prekey bundle Bob via CHAT_GET_PREKEY (menguji atomic pop OPK)...", COL.CYAN)
        resp_get_pk = client.send_rpc({"type": "CHAT_GET_PREKEY", "address": bob.address})
        if resp_get_pk and resp_get_pk.get("type") == "CHAT_PREKEY_BUNDLE":
            bundle = resp_get_pk.get("bundle") or {}
            consumed_opk = bundle.get("opk")
            if bundle.get("ik") == bob.ik_pub_hex and bundle.get("spk") == new_spk_pk and consumed_opk:
                results["get_prekey_bundle"] = True
                clog("PASS: Prekey bundle Bob diterima lengkap:", COL.GREEN)
                clog(f"  IK        : {bundle.get('ik')[:16]}...", COL.GREY)
                clog(f"  SPK       : {bundle.get('spk')[:16]}...", COL.GREY)
                clog(f"  OPK (pop) : {consumed_opk[:16]}... (dikonsumsi secara atomik!)", COL.CYAN)
                clog(f"  Spend Pub : {bundle.get('spend_pub')[:16]}...", COL.GREY)
            else:
                results["get_prekey_bundle"] = False
                clog(f"FAIL: Elemen bundle tidak lengkap: {bundle}", COL.RED)
        else:
            results["get_prekey_bundle"] = False
            clog(f"FAIL: Respon CHAT_GET_PREKEY tidak sesuai: {resp_get_pk}", COL.RED)

        # 6C. Defensive check: Alamat yang tidak memiliki bundle
        clog("6C. Defensive: Meminta bundle untuk alamat yang tidak terdaftar...", COL.GREY)
        dummy_addr = bech32_encode(CFG.ADDRESS_PREFIX, [0] + [0] * 32)
        resp_no_bundle = client.send_rpc({"type": "CHAT_GET_PREKEY", "address": dummy_addr})
        if resp_no_bundle and resp_no_bundle.get("error") == "no_bundle":
            results["get_prekey_no_bundle_guard"] = True
            clog("PASS: Server menolak query alamat tanpa bundle: 'no_bundle'", COL.GREEN)
        else:
            results["get_prekey_no_bundle_guard"] = False
            clog(f"FAIL: Respon alamat dummy tidak sesuai: {resp_no_bundle}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 7: Uji Pengiriman Pesan Terenkripsi E2EE (CHAT_SEND)
    # -------------------------------------------------------------------------
    test_msg_id = int(time.time() * 1000) % 1_000_000_000
    if RUN_SEND_MESSAGE_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 7: Uji Pengiriman Pesan Terenkripsi E2EE (CHAT_SEND)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_send = int(time.time())
        # Ephemeral X25519 keypair for Alice's transmission
        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pk_hex = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

        # Simulated encrypted payload (AES-256-GCM 96-bit nonce + ciphertext)
        nonce_hex = "0102030405060708090a0b0c"  # 12 bytes = 24 hex
        ct_hex = "48656c6c6f2c207468697320697320616e20656e637279707465642063686174207465737421"  # "Hello, this is an encrypted chat test!"

        # Build CHAT_SEND signature
        chat_bytes = b"|".join([
            b"CHAT_SEND",
            alice.address.encode(),
            bob.address.encode(),
            str(test_msg_id).encode(),
            str(ts_send).encode(),
            bytes.fromhex(eph_pk_hex),
            bytes.fromhex(alice.ik_pub_hex),
            b"0", b"0",  # ratchet_pn=0, ratchet_n=0
            bytes.fromhex(nonce_hex),
            bytes.fromhex(ct_hex),
            b"",  # used_opk_hex
        ])
        chat_sig = alice.sign(chat_bytes)

        send_payload = {
            "type": "CHAT_SEND",
            "from": alice.address,
            "to": bob.address,
            "msg_id": test_msg_id,
            "ts": ts_send,
            "from_static": alice.ik_pub_hex,
            "from_pub": eph_pk_hex,
            "enc": {
                "nonce": nonce_hex,
                "ct": ct_hex,
            },
            "used_opk": "",
            "ratchet_pn": 0,
            "ratchet_n": 0,
            "chat_sig": chat_sig,
        }

        # 7A. Valid CHAT_SEND
        clog(f"7A. Alice mengirim pesan terenkripsi ke Bob (msg_id={test_msg_id})...", COL.CYAN)
        resp_send = client.send_rpc(send_payload)
        if resp_send and resp_send.get("type") == "CHAT_ACK" and resp_send.get("status") == "queued":
            results["send_message_valid"] = True
            clog(f"PASS: Pesan terenkripsi berhasil diterima & diantrekan di mailbox Bob! status='queued'", COL.GREEN)
        else:
            results["send_message_valid"] = False
            clog(f"FAIL: CHAT_SEND gagal: {resp_send}", COL.RED)

        # 7B. Defensive check: Kirim ke penerima yang belum terdaftar
        clog("7B. Defensive: Mengirim pesan ke alamat penerima yang belum terdaftar...", COL.GREY)
        bad_recip_payload = dict(send_payload)
        bad_recip_payload["to"] = bech32_encode(CFG.ADDRESS_PREFIX, [0] + [1] * 32)
        bad_recip_payload["msg_id"] = test_msg_id + 1
        bad_recip_payload["chat_sig"] = alice.sign(b"|".join([
            b"CHAT_SEND",
            alice.address.encode(),
            bad_recip_payload["to"].encode(),
            str(bad_recip_payload["msg_id"]).encode(),
            str(ts_send).encode(),
            bytes.fromhex(eph_pk_hex),
            bytes.fromhex(alice.ik_pub_hex),
            b"0", b"0",
            bytes.fromhex(nonce_hex),
            bytes.fromhex(ct_hex),
            b"",
        ]))
        resp_bad_recip = client.send_rpc(bad_recip_payload)
        if resp_bad_recip and resp_bad_recip.get("reason") == "recipient_not_registered":
            results["send_unregistered_recipient_guard"] = True
            clog("PASS: Server menolak kirim ke penerima yang belum terdaftar: 'recipient_not_registered'", COL.GREEN)
        else:
            results["send_unregistered_recipient_guard"] = False
            clog(f"FAIL: Respon penerima belum terdaftar tidak sesuai: {resp_bad_recip}", COL.RED)

        # 7C. Defensive check: Duplicate msg_id deduplication
        clog("7C. Defensive: Mengirim ulang pesan dengan msg_id yang sama (replay mid guard)...", COL.GREY)
        resp_dup = client.send_rpc(send_payload)
        if resp_dup and resp_dup.get("type") == "CHAT_ACK" and resp_dup.get("status") == "duplicate":
            results["send_duplicate_mid_guard"] = True
            clog("PASS: Server mendeteksi pesan duplikat dan menolaknya: status='duplicate'", COL.GREEN)
        else:
            results["send_duplicate_mid_guard"] = False
            clog(f"FAIL: Respon duplikasi msg_id tidak sesuai: {resp_dup}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 8: Uji Penarikan Mailbox Penerima (CHAT_PULL & FIFO Drain)
    # -------------------------------------------------------------------------
    if RUN_PULL_MAILBOX_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 8: Uji Penarikan Mailbox Penerima (CHAT_PULL & FIFO Drain)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_pull = int(time.time())
        pull_sig = bob.build_pull_sig(ts_pull)
        pull_payload = {
            "type": "CHAT_PULL",
            "address": bob.address,
            "n": 20,
            "ts": ts_pull,
            "pull_sig": pull_sig,
        }

        # 8A. Pull pesan pertama kali
        clog("8A. Bob menarik pesan dari mailbox (CHAT_PULL)...", COL.CYAN)
        resp_pull = client.send_rpc(pull_payload)
        if resp_pull and resp_pull.get("type") == "CHAT_ITEMS":
            items = resp_pull.get("items") or []
            found_msg = any(it.get("msg_id") == test_msg_id and it.get("from") == alice.address for it in items)
            if found_msg:
                results["pull_mailbox_valid"] = True
                clog(f"PASS: Bob berhasil mengambil pesan dari Alice! (Total pesan diambil: {len(items)})", COL.GREEN)
                clog(f"      Item msg_id: {test_msg_id}, sender: {alice.address}", COL.CYAN)
            else:
                results["pull_mailbox_valid"] = False
                clog(f"FAIL: Pesan Alice dengan msg_id {test_msg_id} tidak ditemukan di item: {items}", COL.RED)
        else:
            results["pull_mailbox_valid"] = False
            clog(f"FAIL: Respon CHAT_PULL tidak sesuai: {resp_pull}", COL.RED)

        # 8B. Verifikasi Mailbox FIFO Drain (Pesan harus sudah terhapus permanen dari RAM)
        clog("8B. Verifikasi Mailbox FIFO Drain: Bob menarik pesan lagi (harus kosong)...", COL.GREY)
        ts_pull_2 = ts_pull + 1
        pull_sig_2 = bob.build_pull_sig(ts_pull_2)
        resp_pull_empty = client.send_rpc({
            "type": "CHAT_PULL",
            "address": bob.address,
            "n": 20,
            "ts": ts_pull_2,
            "pull_sig": pull_sig_2,
        })
        if resp_pull_empty and resp_pull_empty.get("type") == "CHAT_ITEMS" and resp_pull_empty.get("items") == []:
            results["mailbox_fifo_drain_verified"] = True
            clog("PASS: Mailbox Bob kosong! Terbukti mailbox TsarChain membersihkan pesan dari RAM setelah diambil (Zero-Persistence Guarantee).", COL.GREEN)
        else:
            results["mailbox_fifo_drain_verified"] = False
            clog(f"FAIL: Mailbox tidak terkuras: {resp_pull_empty}", COL.RED)

        # 8C. Defensive check: Pull dengan signature palsu
        clog("8C. Defensive: CHAT_PULL dengan signature palsu...", COL.GREY)
        bad_pull = dict(pull_payload)
        bad_pull["ts"] = ts_pull + 2
        bad_pull["pull_sig"] = "00" * 32
        resp_bad_pull = client.send_rpc(bad_pull)
        if resp_bad_pull and resp_bad_pull.get("error") == "bad_sig":
            results["pull_bad_sig_guard"] = True
            clog("PASS: Server menolak CHAT_PULL signature palsu: 'bad_sig'", COL.GREEN)
        else:
            results["pull_bad_sig_guard"] = False
            clog(f"FAIL: Respon bad pull sig tidak sesuai: {resp_bad_pull}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 9: Uji Tanda Terima Baca (CHAT_READ)
    # -------------------------------------------------------------------------
    if RUN_READ_RECEIPT_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 9: Uji Tanda Terima Baca (CHAT_READ Receipt)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_read = int(time.time())
        read_payload_bytes = b"|".join([
            b"CHAT_READ",
            alice.address.encode(),
            bob.address.encode(),
            str(test_msg_id).encode(),
            str(ts_read).encode(),
        ])
        read_sig = bob.sign(read_payload_bytes)

        read_payload = {
            "type": "CHAT_READ",
            "sender": alice.address,
            "reader": bob.address,
            "msg_id": test_msg_id,
            "ts": ts_read,
            "read_sig": read_sig,
        }

        # 9A. Valid CHAT_READ
        clog(f"9A. Bob mengirim tanda terima baca untuk pesan Alice (msg_id={test_msg_id})...", COL.GREY)
        resp_read = client.send_rpc(read_payload)
        if resp_read and resp_read.get("type") == "CHAT_READ_OK":
            results["send_read_receipt"] = True
            clog("PASS: CHAT_READ_OK diterima! Status read receipt diteruskan ke antrean Alice.", COL.GREEN)
        else:
            results["send_read_receipt"] = False
            clog(f"FAIL: CHAT_READ gagal: {resp_read}", COL.RED)

        # 9B. Defensive: CHAT_READ dengan signature tidak valid
        clog("9B. Defensive: CHAT_READ dengan signature palsu...", COL.GREY)
        bad_read = dict(read_payload)
        bad_read["read_sig"] = "00" * 32
        resp_bad_read = client.send_rpc(bad_read)
        if resp_bad_read and resp_bad_read.get("error") == "bad_sig":
            results["read_bad_sig_guard"] = True
            clog("PASS: Server menolak read receipt signature palsu: 'bad_sig'", COL.GREEN)
        else:
            results["read_bad_sig_guard"] = False
            clog(f"FAIL: Respon bad read sig tidak sesuai: {resp_bad_read}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 10: Uji Deaktivasi Profil Chat (DEACTIVATE_CHAT)
    # -------------------------------------------------------------------------
    if RUN_DEACTIVATE_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 10: Uji Deaktivasi Profil Chat & Cooldown Reaktivasi", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        ts_deact = int(time.time())
        deact_sig = alice.build_deactivate_sig(ts_deact)
        deact_payload = {
            "type": "DEACTIVATE_CHAT",
            "address": alice.address,
            "spend_pub": alice.spend_pub_hex,
            "ts": ts_deact,
            "deactivate_sig": deact_sig,
        }

        # 10A. Deaktivasi profil Alice
        clog("10A. Alice mendeaktivasi profil chat miliknya...", COL.CYAN)
        resp_deact = client.send_rpc(deact_payload)
        if resp_deact and resp_deact.get("status") == "ok" and resp_deact.get("deactivated") is True:
            results["deactivate_chat_profile"] = True
            clog("PASS: Profil chat Alice berhasil dideaktivasi (prekeys dihapus dari LMDB & RAM).", COL.GREEN)
        else:
            results["deactivate_chat_profile"] = False
            clog(f"FAIL: Deaktivasi chat gagal: {resp_deact}", COL.RED)

        # 10B. Verifikasi pencarian pasca deaktivasi
        clog("10B. Memeriksa status Alice setelah deaktivasi (CHAT_CHECK_PREKEYS)...", COL.GREY)
        resp_post_deact_chk = client.send_rpc({"type": "CHAT_CHECK_PREKEYS", "address": alice.address})
        if resp_post_deact_chk and resp_post_deact_chk.get("registered") is False:
            results["post_deact_unregistered"] = True
            clog("PASS: Alice terkonfirmasi berstatus unregistered pasca deaktivasi.", COL.GREEN)
        else:
            results["post_deact_unregistered"] = False
            clog(f"FAIL: Status pasca deaktivasi masih aktif: {resp_post_deact_chk}", COL.RED)

        # 10C. Verifikasi Cooldown Reaktivasi (Upaya registrasi ulang langsung harus ditolak)
        clog("10C. Menguji Cooldown Reaktivasi: Alice mencoba mendaftar kembali seketika...", COL.GREY)
        ts_re_reg = int(time.time())
        re_reg_payload = {
            "type": "CHAT_REGISTER",
            "address": alice.address,
            "chat_pub": alice.ik_pub_hex,
            "spend_pub": alice.spend_pub_hex,
            "presence_sig": alice.build_presence_sig(ts_re_reg),
            "reg_sig": alice.build_reg_sig(ts_re_reg),
            "ts": ts_re_reg,
        }
        resp_re_reg = client.send_rpc(re_reg_payload)
        if resp_re_reg and (resp_re_reg.get("error") == "reactivate_cooldown" or resp_re_reg.get("status") == "rejected"):
            results["reactivate_cooldown_guard"] = True
            rem = resp_re_reg.get("remaining_s", 0)
            clog(f"PASS: Server menolak reaktivasi chat seketika: 'reactivate_cooldown' (sisa: {rem}s)", COL.GREEN)
        else:
            results["reactivate_cooldown_guard"] = False
            clog(f"FAIL: Reaktivasi cooldown tidak aktif: {resp_re_reg}", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 11: Uji Rate Limiting Token-Bucket & Anti-DoS PoW (CHAT_LOOKUP_PUB)
    # -------------------------------------------------------------------------
    pow_challenge: dict | None = None

    if RUN_BURST_POW_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog(f"TAHAP 11: Uji Rate Limiting Token-Bucket & PoW Challenge ({burst_count_chat}x CHAT_LOOKUP_PUB)", COL.BOLD + COL.CYAN)
        clog(f"Batas Server: {CFG.CHAT_LOOKUP_RL_IP_BURST} request per {CFG.CHAT_LOOKUP_RL_IP_WINDOW_S}s (Backoff: {CFG.CHAT_LOOKUP_RL_BACKOFF_S}s)", COL.YELLOW)
        clog("=" * 70, COL.CYAN)

        throttled = False
        throttled_at_req = -1

        for i in range(1, burst_count_chat + 1):
            t_req = time.time()
            resp = client.send_rpc({"type": "CHAT_LOOKUP_PUB", "address": bob.address})
            dur_ms = (time.time() - t_req) * 1000

            if not resp:
                clog(f"  [Req #{i:03d}] ERROR: Frame kosong atau timeout", COL.RED)
                continue

            err = resp.get("error")
            if err == "pow_required":
                throttled = True
                throttled_at_req = i
                pow_challenge = resp.get("pow_challenge") or resp
                retry_after = resp.get("retry_after", CFG.CHAT_LOOKUP_RL_BACKOFF_S)
                clog(f"  [Req #{i:03d}] THROTTLED: error='pow_required' retry_after={retry_after}s ({dur_ms:.1f} ms)", COL.YELLOW)
                clog(f"  PoW Challenge Data: {json.dumps(pow_challenge)}", COL.GREY)
                break
            elif resp.get("type") == "CHAT_PUBKEY":
                if i % 10 == 0 or i <= 5 or i >= 75:
                    clog(f"  [Req #{i:03d}] OK: CHAT_PUBKEY diterima ({dur_ms:.1f} ms)", COL.GREY)
            else:
                clog(f"  [Req #{i:03d}] Lainnya: {resp}", COL.GREY)

            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        if throttled and pow_challenge:
            results["chat_pow_challenge"] = True
            clog(f"PASS: Mekanisme Anti-DoS Token Bucket Chat aktif pada request #{throttled_at_req:03d}!", COL.GREEN)
            clog(f"      Server menerbitkan tantangan PoW: scope='{pow_challenge.get('scope')}', difficulty={pow_challenge.get('difficulty')}", COL.GREEN)
        else:
            results["chat_pow_challenge"] = False
            clog("FAIL: Server tidak memicu tantangan 'pow_required' setelah burst selesai.", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 12: Uji Pemecahan PoW (solve_pow, Diff: 8) & Bypass Rate Limit Chat
    # -------------------------------------------------------------------------
    if RUN_SOLVE_POW_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog("TAHAP 12: Uji Pemecahan PoW (solve_pow, Diff: 8) & Bypass Rate Limit Chat", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        if not pow_challenge:
            clog("FAIL: Tidak ada challenge PoW dari tahap sebelumnya untuk dipecahkan.", COL.RED)
            results["chat_pow_bypass"] = False
        else:
            clog("Memecahkan tantangan PoW chat secara lokal...", COL.CYAN)
            clog(f"  Scope     : {pow_challenge.get('scope')}", COL.GREY)
            clog(f"  Identity  : {pow_challenge.get('identity')}", COL.GREY)
            clog(f"  Difficulty: {pow_challenge.get('difficulty')} bit leading zeros", COL.GREY)
            clog(f"  Salt      : {pow_challenge.get('salt')}", COL.GREY)

            t_solve = time.time()
            solved_pow = solve_pow(pow_challenge, identity=pow_challenge.get("identity"))
            solve_dur = (time.time() - t_solve) * 1000

            if solved_pow and "nonce" in solved_pow:
                clog(f"PoW chat berhasil dipecahkan dalam {solve_dur:.2f} ms! Nonce={solved_pow['nonce']}", COL.GREEN)
                log.info(f"Solved PoW payload: {json.dumps(solved_pow)}")

                clog("Mengirimkan CHAT_LOOKUP_PUB dengan melampirkan payload 'pow' yang valid...", COL.CYAN)
                bypass_payload = {
                    "type": "CHAT_LOOKUP_PUB",
                    "address": bob.address,
                    "pow": solved_pow,
                }
                resp_bypass = client.send_rpc(bypass_payload)

                if resp_bypass and resp_bypass.get("type") == "CHAT_PUBKEY":
                    results["chat_pow_bypass"] = True
                    clog(f"Response with PoW: {resp_bypass.get('type')}", COL.GREY)
                    clog("PASS: Server memvalidasi PoW dan meloloskan request chat meskipun dalam status rate-limited!", COL.GREEN)
                else:
                    results["chat_pow_bypass"] = False
                    clog(f"FAIL: Server menolak request yang disertai PoW valid: {resp_bypass}", COL.RED)
            else:
                results["chat_pow_bypass"] = False
                clog("FAIL: Gagal menemukan solusi PoW secara lokal.", COL.RED)

    # -------------------------------------------------------------------------
    # TAHAP 13: Uji Pemulihan Cooldown (Refill Recovery)
    # -------------------------------------------------------------------------
    if RUN_COOLDOWN_TEST:
        clog("\n" + "=" * 70, COL.CYAN)
        clog(f"TAHAP 13: Uji Pemulihan Cooldown ({cooldown_sec:.1f}s Tunggu Refill)", COL.BOLD + COL.CYAN)
        clog("=" * 70, COL.CYAN)

        clog(f"Menunggu {cooldown_sec:.1f} detik agar token-bucket chat melakukan refill...", COL.YELLOW)
        time.sleep(cooldown_sec)

        clog("Mengirimkan CHAT_LOOKUP_PUB normal tanpa PoW...", COL.CYAN)
        resp_after = client.send_rpc({"type": "CHAT_LOOKUP_PUB", "address": bob.address})

        if resp_after and resp_after.get("type") == "CHAT_PUBKEY":
            results["cooldown_recovery"] = True
            clog("PASS: Kuota Token Bucket chat pulih sepenuhnya! Server merespons normal tanpa PoW.", COL.GREEN)
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
    clog("RINGKASAN HASIL PENGUJIAN USER RPC - ENCRYPTED CHAT", COL.BOLD + COL.CYAN)
    clog("=" * 70, COL.CYAN)

    table = Table(title="User RPC Encrypted Chat Test Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Test Case", style="bold white", width=38)
    table.add_column("Status", width=12)
    table.add_column("Details", style="grey70")

    table_data = [
        ("0. Handshake Node (NODE)", results.get("user_handshake", False), "P2P SecureChannel & role setup"),
        ("1. Dual Crypto Identity Init", results.get("crypto_identities_init", False), "Secp256k1 spend & X25519 DH keys (Alice/Bob)"),
        ("2A. Pre-Reg CHAT_CHECK_PREKEYS", results.get("pre_reg_check_prekeys", False), "Unregistered prekey bundle verification"),
        ("2B. Pre-Reg CHAT_LOOKUP_PUB", results.get("pre_reg_lookup_pub", False), "Unregistered identity search verification"),
        ("2C. Missing Address Lookup Guard", results.get("lookup_missing_addr_guard", False), "Defensive rejection 'missing address'"),
        ("3A. CHAT_REGISTER Alice", results.get("register_alice", False), "Alice registration with spend & presence sigs"),
        ("3B. CHAT_REGISTER Bob", results.get("register_bob", False), "Bob registration with SPK & OPK attachments"),
        ("3C. Stale Timestamp Reg Guard", results.get("register_stale_ts_guard", False), "Anti-replay window (>300s) rejection"),
        ("3D. Signature Mismatch Guard", results.get("register_bad_sig_guard", False), "Secp256k1 signature validation check"),
        ("4A. Post-Reg Status Verification", results.get("post_reg_check_prekeys", False), "Registered flag & prekey bundle existence"),
        ("4B. Post-Reg Lookup Alice", results.get("post_reg_lookup_alice", False), "Identity key discovery for Alice"),
        ("4C. Post-Reg Lookup Bob", results.get("post_reg_lookup_bob", False), "Identity key discovery for Bob"),
        ("5A. CHAT_PRESENCE Heartbeat", results.get("chat_presence_update", False), "Online status & presence broadcast"),
        ("5B. Stale Presence Guard", results.get("presence_stale_guard", False), "Defensive rejection 'presence_stale'"),
        ("6A. CHAT_PUBLISH_PREKEYS", results.get("publish_prekeys", False), "New SPK & OPK publication"),
        ("6B. CHAT_GET_PREKEY Atomic Pop", results.get("get_prekey_bundle", False), "X3DH prekey bundle fetch & OPK pop"),
        ("6C. Non-existent Prekey Guard", results.get("get_prekey_no_bundle_guard", False), "Defensive rejection 'no_bundle'"),
        ("7A. CHAT_SEND E2EE Envelope", results.get("send_message_valid", False), "Blind relay message queuing to Bob"),
        ("7B. Unregistered Recipient Guard", results.get("send_unregistered_recipient_guard", False), "Defensive rejection 'recipient_not_registered'"),
        ("7C. Duplicate Message ID Guard", results.get("send_duplicate_mid_guard", False), "Deduplication rejection 'duplicate'"),
        ("8A. CHAT_PULL Mailbox Delivery", results.get("pull_mailbox_valid", False), "Authenticated pull signature & delivery"),
        ("8B. Mailbox FIFO RAM Drain", results.get("mailbox_fifo_drain_verified", False), "Zero-persistence RAM deletion on delivery"),
        ("8C. Pull Bad Signature Guard", results.get("pull_bad_sig_guard", False), "Defensive rejection 'bad_sig'"),
        ("9A. CHAT_READ Read Receipt", results.get("send_read_receipt", False), "Read receipt delivery & verification"),
        ("9B. Read Bad Signature Guard", results.get("read_bad_sig_guard", False), "Defensive rejection 'bad_sig'"),
        ("10A. DEACTIVATE_CHAT Profile", results.get("deactivate_chat_profile", False), "Persistent LMDB deletion & RAM clearance"),
        ("10B. Post-Deactivation State", results.get("post_deact_unregistered", False), "Unregistered verification in state"),
        ("10C. Reactivate Cooldown Guard", results.get("reactivate_cooldown_guard", False), "Reactivate block 'reactivate_cooldown'"),
        ("11. Token-Bucket Burst (80 req/10s)", results.get("chat_pow_challenge", False), "Throttling returning 'pow_required'"),
        ("12. PoW Solution & Bypass (Diff 8)", results.get("chat_pow_bypass", False), "Stateless PoW solving & verified bypass"),
        ("13. Cooldown & Refill Recovery", results.get("cooldown_recovery", False), f"Bucket refill after {cooldown_sec:.1f}s cooldown"),
    ]

    for name, passed, desc in table_data:
        status_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        table.add_row(name, status_text, desc)

    console.print(table)
    all_passed = all(results.values())
    if all_passed:
        clog("SELURUH PENGUJIAN USER RPC ENCRYPTED CHAT LULUS (100% PASS)!", COL.BOLD + COL.GREEN)
    else:
        clog("BEBERAPA PENGUJIAN GAGAL / MEMERLUKAN EVALUASI.", COL.BOLD + COL.RED)

    return results


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    _enable_windows_vt100()
    setup_logging("logging/rpc_user_chat_test.log", force=True)

    parser = argparse.ArgumentParser(description="TsarChain User RPC Encrypted Chat Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help=f"Target node IP/host (default: {TARGET_HOST})")
    parser.add_argument("--port", type=int, default=TARGET_PORT, help=f"Target node port (default: {TARGET_PORT})")
    parser.add_argument("--burst-chat", type=int, default=BURST_COUNT_CHAT, help=f"Burst count for CHAT_LOOKUP_PUB (default: {BURST_COUNT_CHAT})")
    parser.add_argument("--delay-ms", type=float, default=BURST_DELAY_MS, help=f"Burst delay in ms (default: {BURST_DELAY_MS})")
    parser.add_argument("--cooldown-sec", type=float, default=COOLDOWN_WAIT_SEC, help=f"Cooldown wait in seconds (default: {COOLDOWN_WAIT_SEC})")

    args = parser.parse_args()

    run_test_suite(
        host=args.host,
        port=args.port,
        burst_count_chat=args.burst_chat,
        delay_ms=args.delay_ms,
        cooldown_sec=args.cooldown_sec,
    )


if __name__ == "__main__":
    main()
