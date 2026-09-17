# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

import time
from .....utils.benchmarks import benchmark

from .....utils import config as CFG
from ...user_rpc import common as CM
from .....contracts import graffiti as GRAFFITI

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.graff_activities")



@benchmark(label="GET_POSTS", threshold_ms=10.0)
def get_posts(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    
    ok, pow_resp = _check_graffiti_pow(self, client_ip, base_identity, pow_obj)
    if not ok:
        return pow_resp

    limit = int(message.get("limit", 50) or 50)
    offset = int(message.get("offset", 0) or 0)
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    reg = self.broadcast.utxodb._graffiti_registry
    posts = reg.list_posts(limit, offset) if reg else []
        
    return {"type": "GRAFFITI_GET_POSTS", "posts": posts}


@benchmark(label="GET_COMMENTS", threshold_ms=10.0)
def get_comments(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    ok, pow_resp = _check_graffiti_pow(self, client_ip, base_identity, pow_obj)
    if not ok:
        return pow_resp

    art_id = str(message.get("art_id") or "").strip().lower()
    if not art_id:
        return {"type": "GRAFFITI_GET_COMMENTS", "comments": []}
    limit = int(message.get("limit", 100) or 100)
    limit = max(1, min(limit, 500))
    reg = self.broadcast.utxodb._graffiti_registry
    comments = reg.list_comments(art_id, limit) if reg else []
    
    return {"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "comments": comments}


@benchmark(label="GET_ART", threshold_ms=10.0)
def get_art(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs):
    ok, pow_resp = _check_graffiti_pow(self, client_ip, base_identity, pow_obj)
    if not ok:
        return pow_resp

    art_id_raw = str(message.get("art_id") or "").strip()
    if not art_id_raw:
        return {"type": "GRAFFITI_GET_ART", "error": "missing_art_id"}
    try:
        art_id = GRAFFITI._normalize_art_id(art_id_raw, prefer_prefix=False)
    except (ValueError, TypeError):
        return {"type": "GRAFFITI_GET_ART", "art_id": art_id_raw, "error": "bad_art_id"}
    reg = self.broadcast.utxodb._graffiti_registry
    post = reg.get_post(art_id) if reg else None
    if not post:
        return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "error": "not_found"}
    
    return {"type": "GRAFFITI_GET_ART", "art_id": art_id, "post": post}


@benchmark(label="GET_PAYOUTS", threshold_ms=10.0)
def get_payouts(self, message, pow_obj, base_identity, *,
                     client_ip, **kwargs): #NOTE : not used yet

    # Temporary block to avoid unnecessary load until future activation
    return {"type": "GRAFFITI_GET_PAYOUTS", "error": "endpoint_temporarily_disabled"}

# =============================================================================
# INTERNAL METHOD
# =============================================================================


def _check_graffiti_pow(self, client_ip, base_identity, pow_obj):
    return CM.allow_rpc_with_pow(
        self,
        scope="rpc:graffiti",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="graf",
        burst=CFG.GRAFFITI_RL_IP_BURST,
        window_s=CFG.GRAFFITI_RL_WINDOW_S,
        backoff_s=CFG.GRAFFITI_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_READ),
    )