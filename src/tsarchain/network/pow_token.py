# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import hmac
import hashlib
import secrets
from typing import Dict, Optional

# ---------------- Logger ----------------
from ..utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.pow_token")

_SECRET = secrets.token_bytes(32)


def issue_pow(scope: str, identity: str, difficulty: int, ttl_s: float) -> Dict[str, object]:
    """
    Create a stateless proof-of-work challenge bound to the provided identity string.
    """
    identity_key = (identity or "anon").strip().lower()
    salt = secrets.token_hex(16)
    exp = int(time.time() + max(1.0, float(ttl_s)))
    diff = max(1, int(difficulty))
    payload = f"{scope}|{identity_key}|{salt}|{exp}|{diff}"
    token = hmac.new(_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    log.debug("[issue_pow] token: %s , diff: %s, exp: %s, salt: %s, identity_key: %s, scope: %s", token, diff, exp, salt, identity_key, scope)
    return {
        "scope": scope,
        "identity": identity_key,
        "salt": salt,
        "exp": exp,
        "difficulty": diff,
        "token": token,
    }


def verify_pow(pow_obj: dict, nonce: str | None, *, expected_scope: str, identity: str) -> bool:
    """
    Verify a submitted PoW solution without storing state on the server.
    """
    if not pow_obj or type(pow_obj) is not dict or not nonce:
        return False
    now = time.time()
    scope = str(pow_obj.get("scope") or "")
    if scope != expected_scope:
        return False
    identity_key = (identity or "anon").strip().lower()
    if identity_key != str(pow_obj.get("identity") or "").strip().lower():
        return False
    salt = pow_obj.get("salt")
    exp = int(pow_obj.get("exp", 0))
    diff = int(pow_obj.get("difficulty", 0))
    token = str(pow_obj.get("token") or "")
    if not (salt and token and diff > 0):
        return False
    if exp <= now:
        return False
    payload = f"{scope}|{identity_key}|{salt}|{exp}|{diff}"
    expected = hmac.new(_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, token):
        return False
    digest = hashlib.sha256(f"{payload}|{nonce}".encode("utf-8")).digest()
    log.debug("[verify_pow] digest: %s", digest)
    return _leading_zero_bits(digest) >= diff


def solve_pow(pow_obj: dict, *, identity: str, max_iters: int = 1_000_000) -> Optional[Dict[str, object]]:
    """
    Attempt to solve a PoW challenge locally. Returns a payload ready to be sent back to the server.
    """
    if not pow_obj or not identity:
        return None
    identity_key = (identity or "anon").strip().lower()
    scope = pow_obj.get("scope") or ""
    salt = pow_obj.get("salt") or ""
    exp = pow_obj.get("exp") or 0
    diff = int(pow_obj.get("difficulty", 0))
    token = pow_obj.get("token") or ""
    if not (scope and salt and token and diff > 0):
        return None
    payload = f"{scope}|{identity_key}|{salt}|{exp}|{diff}"
    attempt = 0
    while attempt < max_iters:
        nonce = secrets.token_hex(8)
        digest = hashlib.sha256(f"{payload}|{nonce}".encode("utf-8")).digest()
        if _leading_zero_bits(digest) >= diff:
            solved = dict(pow_obj)
            solved["identity"] = identity_key
            solved["nonce"] = nonce
            return solved
        attempt += 1
    log.debug("[solve_pow] attempt: %s", attempt)
    return None


# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _leading_zero_bits(digest: bytes) -> int:
    total = 0
    for b in digest:
        if b == 0:
            total += 8
            continue
        total += 8 - b.bit_length()
        break
    return total


__all__ = ("issue_pow", "verify_pow", "solve_pow")
