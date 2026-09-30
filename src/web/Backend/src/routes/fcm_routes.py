# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import json
from typing import Dict, Any, Tuple

from tsarchain.utils.fcm_service import FCMService


def handle_fcm_register(
    body_bytes: bytes,
    client_ip: str,
    fcm: FCMService,
) -> Tuple[int, Dict[str, Any]]:
    """Handle POST /api/fcm/register."""
    if not body_bytes:
        return 400, {"error": "bad_request", "detail": "invalid_payload_length"}
    try:
        body_json = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return 400, {"error": "bad_request", "detail": "invalid_json"}
    if type(body_json) is not dict:
        return 400, {"error": "bad_request", "detail": "expected_json_object"}

    addr = str(body_json.get("address", "")).strip().lower()
    token = str(body_json.get("token", "")).strip()
    pubkey = str(body_json.get("pubkey", "")).strip().lower()
    sig = str(body_json.get("sig", "")).strip().lower()
    ts = int(body_json.get("ts", 0))

    ok, reason = fcm.register_token(
        address=addr,
        token=token,
        pubkey=pubkey,
        sig=sig,
        ts=ts,
        client_ip=client_ip,
    )
    if ok:
        return 200, {"status": "ok", "address": addr}
    return 400, {"error": "registration_failed", "reason": reason}


def handle_fcm_unregister(
    body_bytes: bytes,
    fcm: FCMService,
) -> Tuple[int, Dict[str, Any]]:
    """Handle POST /api/fcm/unregister."""
    if not body_bytes:
        return 400, {"error": "bad_request", "detail": "invalid_payload_length"}
    try:
        body_json = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return 400, {"error": "bad_request", "detail": "invalid_json"}
    if type(body_json) is not dict:
        return 400, {"error": "bad_request", "detail": "expected_json_object"}

    addr = str(body_json.get("address", "")).strip().lower()
    pubkey = str(body_json.get("pubkey", "")).strip().lower()
    sig = str(body_json.get("sig", "")).strip().lower()
    ts = int(body_json.get("ts", 0))

    ok, reason = fcm.unregister_token(
        address=addr,
        pubkey=pubkey,
        sig=sig,
        ts=ts,
    )
    if ok:
        return 200, {"status": "ok", "address": addr}
    return 400, {"error": "unregistration_failed", "reason": reason}
