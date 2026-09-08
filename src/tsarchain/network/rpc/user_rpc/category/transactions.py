# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from .....utils.benchmarks import benchmark

from .....utils import config as CFG
from ...user_rpc import common as CM

# ---------------- Logger ----------------
from .....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.category.transactions")


@benchmark(label="NEW_TX", threshold_ms=100.0)
def new_tx(self, message, pow_obj, base_identity, addr, *, client_ip, **kwargs):
    sender_addr = str(message.get("from_addr") or message.get("from") or "").strip().lower()
    if not sender_addr:
        sender_addr = str((message.get("data") or {}).get("from_addr") or "").strip().lower()

    ident_tx = sender_addr or base_identity

    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:new_tx",
        table=self.rl_ip,
        ip=client_ip,
        identity=ident_tx,
        key_label="txsub",
        burst=CFG.TX_SUBMIT_RL_IP_BURST,
        window_s=CFG.TX_SUBMIT_RL_WINDOW_S,
        backoff_s=CFG.TX_SUBMIT_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_TX),
    )
    if not ok:
        return {"status": "error", **(pow_resp or {})}

    if sender_addr:
        addr_key = f"txaddr:{sender_addr}"
        ok, pow_resp = CM.allow_rpc_with_pow(
            self,
            scope="rpc:tx_addr",
            table=self.rl_addr,
            ip=client_ip,
            identity=sender_addr,
            key_label=addr_key,
            burst=CFG.TX_SUBMIT_RL_ADDR_BURST,
            window_s=CFG.TX_SUBMIT_RL_ADDR_WINDOW_S,
            backoff_s=CFG.TX_SUBMIT_RL_ADDR_BACKOFF_S,
            pow_obj=pow_obj,
            difficulty=int(CFG.RPC_POW_DIFFICULTY_TX),
        )
        if not ok:
            return {"status": "error", **(pow_resp or {})}

    if CFG.ENABLE_DANDELION_PP and "phase" not in message:
        message = dict(message)
        message["phase"] = "stem"

    success = self.broadcast.receive_tx(message, addr, self.peers)
    if success:
        txid = (message.get("data") or {}).get("txid")
        return {"status": "ok", "txid": txid}
    else:
        reason = self.broadcast.mempool.last_error_reason
        log.warning("[new_tx] Transaction rejected by mempool for %s: %s", sender_addr or "unknown", reason)
        return {"status": "error", "reason": (reason or "invalid tx")}


@benchmark(label="CREATE_TX", threshold_ms=100.0)
def create_tx(self, message, pow_obj, base_identity, addr, mtype, *,
                     client_ip, is_miner_sender, **kwargs):
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:tx",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="txsub",
        burst=CFG.TX_SUBMIT_RL_IP_BURST,
        window_s=CFG.TX_SUBMIT_RL_WINDOW_S,
        backoff_s=CFG.TX_SUBMIT_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_TX),
    )
    if not ok:
        return pow_resp
        
    from_addr = (message.get("from") or "").strip().lower()
    to_addr   = (message.get("to")   or "").strip().lower()
    amount    = message.get("amount")
    fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
    fee_rate = max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB))
    try:
        tpl = self.create_template_tx(from_addr, to_addr, amount, fee_rate)
    except Exception as exc:
        log.warning("[create_tx] Template rejected for %s: %s", from_addr, exc)
        return {"error": str(exc) or "create_tx_failed"}
    
    return {"type": "TX_TEMPLATE", "data": tpl}


@benchmark(label="CREATE_TX_MULTI", threshold_ms=150.0)
def create_tx_multi(self, message, pow_obj, base_identity, addr, mtype, *,
                     client_ip, is_miner_sender, **kwargs):
    ok, pow_resp = CM.allow_rpc_with_pow(
        self,
        scope="rpc:tx_multi",
        table=self.rl_ip,
        ip=client_ip,
        identity=base_identity,
        key_label="txsub",
        burst=CFG.TX_SUBMIT_RL_IP_BURST,
        window_s=CFG.TX_SUBMIT_RL_WINDOW_S,
        backoff_s=CFG.TX_SUBMIT_RL_BACKOFF_S,
        pow_obj=pow_obj,
        difficulty=int(CFG.RPC_POW_DIFFICULTY_TX),
    )
    if not ok:
        return pow_resp

    from_addr = (message.get("from") or "").strip().lower()
    outputs   = message.get("outputs") or []
    fee_rate = int(message.get("fee_rate", CFG.DEFAULT_FEE_RATE_SATVB))
    force_inputs = message.get("force_inputs") or None
    if not from_addr or not outputs:
        return {"error": "missing from/outputs"}
    
    try:
        tpl = self.create_template_tx_multi(from_addr, outputs, fee_rate, force_inputs)
    except Exception as exc:
        log.warning("[create_tx_multi] Template rejected for %s: %s", from_addr, exc)
        return {"error": str(exc) or "create_tx_multi_failed"}
    
    return {"type": "TX_TEMPLATE", "data": tpl}