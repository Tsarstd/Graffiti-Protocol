# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from bech32 import convertbits, bech32_decode

# ---------------- Local Project ----------------
from ...utils import config as CFG
from .base import NetworkHandlerProxy
from ...core.tx import Tx, TxIn, TxOut
from ...contracts import graffiti as GRAFF
from ...utils.helpers import Script, OP_RETURN, last_pushdata, compute_tx_weight_vsize, extract_script_bytes

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.tx")


class TxHandler(NetworkHandlerProxy):
    def create_template_tx(self, from_addr, to_addr, amount, fee_rate):
        if type(from_addr) is not str or type(to_addr) is not str:
            raise ValueError("from/to address must be string")

        amt_sat = int(amount * CFG.TSAR) if type(amount) is float else int(amount)
        utxos_map = self.broadcast.utxodb.get(from_addr) or {}
        tip_height = self.broadcast.blockchain.height
        utxos_list = self._build_utxos_list(utxos_map, tip_height)

        if not utxos_list:
            log.warning(
                "[create_template_tx] Rejected tx for %s: no spendable utxos (balance exhausted or pending in mempool)",
                from_addr,
            )
            raise ValueError("no spendable utxos")

        from_spk = self.addr_to_spk(from_addr)
        to_spk   = self.addr_to_spk(to_addr)

        selected, fee, change = self._select_utxos_for(utxos_list, amt_sat, fee_rate)

        ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
        outs = [TxOut(amt_sat, to_spk)]
        if change >= CFG.DUST_THRESHOLD_SAT:
            outs.append(TxOut(change, from_spk))
        tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)
        self._check_tx_limits(tx)

        input_meta = [{
            "txid": u["txid"],
            "index": u["index"],
            "amount": int(u["amount"]),
            "script_pubkey": u["scriptPubKey"].hex(),
        } for u in selected]
        return {
            "tx": tx.to_dict(),
            "inputs": input_meta,
            "fee": fee,
            "change": change,
            "from": from_addr,
            "to": to_addr,
            "amount_sat": amt_sat
        }


    def create_template_tx_multi(self, from_addr: str, outputs: list, fee_rate: int, force_inputs: list[str] | None = None):
        if type(from_addr) is not str:
            raise ValueError("from must be string")
        if type(outputs) is not list or not outputs:
            raise ValueError("outputs must be non-empty list")

        fee_rate = int(max(CFG.MIN_FEE_RATE_SATVB, min(fee_rate, CFG.MAX_FEE_RATE_SATVB)))
        utxos_map = self.broadcast.utxodb.get(from_addr) or {}
        utxos_list = self._build_utxos_list(utxos_map, self.broadcast.blockchain.height)
        
        fixed_outs, total_target = self._parse_outputs(outputs)

        preselected, pre_acc = [], 0
        utxo_by_key = {f"{u['txid']}:{u['index']}": u for u in utxos_list}
        if force_inputs:
            preselected, pre_acc = self._process_forced_inputs(force_inputs, utxos_list, utxo_by_key, from_addr)

        if not utxos_list and not preselected:
            log.warning(
                "[create_template_tx_multi] Rejected tx for %s: no spendable utxos",
                from_addr,
            )
            raise ValueError("no spendable utxos")
            
        forced_keys = set(force_inputs or [])
        candidates = sorted([u for u in utxos_list if f"{u['txid']}:{u['index']}" not in forced_keys], key=lambda x: x["amount"])
        selected = list(preselected)
        
        change, fee_est = self._accumulate_utxos_multi(candidates, selected, pre_acc, total_target, fixed_outs, fee_rate)

        ins  = [TxIn(bytes.fromhex(u["txid"]), u["index"], amount=int(u["amount"])) for u in selected]
        non_opret, opret_outs = [], []
        for amt, spk in fixed_outs:
            try:
                cmds = spk.cmds
                is_opret = bool(cmds) and cmds[0] == OP_RETURN
            except AttributeError:
                is_opret = False
            (opret_outs if is_opret else non_opret).append(TxOut(amt, spk))
            
        outs = non_opret
        if change >= CFG.DUST_THRESHOLD_SAT:
            outs.append(TxOut(change, self.addr_to_spk(from_addr)))
        outs.extend(opret_outs)

        tx = Tx(version=1, inputs=ins, outputs=outs, locktime=0, is_coinbase=False)
        self._check_tx_limits(tx)

        return {
            "tx": tx.to_dict(),
            "inputs": [{"txid": u["txid"], "index": u["index"], "amount": int(u["amount"]), "script_pubkey": u["scriptPubKey"].hex()} for u in selected],
            "fee": fee_est,
            "change": change,
            "from": from_addr,
            "outputs": [{"amount": int(amt), "script_pubkey": spk.serialize().hex()} for (amt, spk) in fixed_outs]
        }


    def addr_to_spk(self, addr: str) -> Script:
        addr = (addr or "").strip()
        hrp, data = bech32_decode(addr)
        if data is None:
            raise ValueError("invalid bech32 address")
        if (hrp or "").lower() != CFG.ADDRESS_PREFIX:
            raise ValueError(f"Address HRP must be {CFG.ADDRESS_PREFIX}, got '{hrp}'")
        decoded = convertbits(data[1:], 5, 8, False)
        if decoded is None:
            raise ValueError("decode bech32 failed")
        return Script([0, bytes(decoded)])


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _build_utxos_list(self, utxos_map, tip_height):
        utxos_list = []
        mp = self.broadcast.mempool if self.broadcast else None
        is_spent = mp.is_prevout_spent if mp else None
        for k, v in (utxos_map.items() if type(utxos_map) is dict else []):
            txid_hex, idx_str = k.split(":")
            idx_int = int(idx_str)
            if callable(is_spent) and is_spent(txid_hex, idx_int) is True:
                continue
            is_cb = bool(v.get("is_coinbase", False))
            born  = int(v.get("block_height", 0))
            if is_cb:
                confirmations = max(0, (int(tip_height) - born) + 1)
                if confirmations < CFG.COINBASE_MATURITY:
                    continue
            spk_val = v.get("script_pubkey")
            if type(spk_val) is bytes:
                spk_bytes = spk_val
            elif type(spk_val) is str:
                spk_bytes = bytes.fromhex(spk_val)
            else:
                spk_bytes = b""
            utxos_list.append({
                "txid": txid_hex,
                "index": int(idx_str),
                "amount": int(v.get("amount", 0)),
                "scriptPubKey": spk_bytes,
                "height": born,
                "is_coinbase": is_cb,
            })
        return utxos_list


    def _select_utxos_for(self, utxos: list[dict], target_amount_sat: int, fee_rate: int):
        utxos_dict = {}
        for u in utxos:
            k = f"{u['txid']}:{u['index']}"
            utxos_dict[k] = {
                "amount": int(u.get("amount", 0)),
                "script_pubkey": u.get("scriptPubKey", b"").hex(),
            }

        candidates = []
        for key, v in utxos_dict.items():
            txid_hex, idx = key.split(":")
            candidates.append({
                "txid": txid_hex,
                "index": int(idx),
                "amount": int(v["amount"]),
                "scriptPubKey": bytes.fromhex(v["script_pubkey"])
            })
        candidates.sort(key=lambda x: x["amount"])

        selected, acc = [], 0
        n_outputs = 2
        est_fee = 0
        for c in candidates:
            selected.append(c)
            acc += c["amount"]
            est_size = self._est_tx_size(len(selected), n_outputs)
            est_fee  = fee_rate * est_size
            if acc >= target_amount_sat + est_fee:
                change = acc - target_amount_sat - est_fee
                if change < CFG.DUST_THRESHOLD_SAT:
                    n_outputs = 1
                    est_fee  = fee_rate * self._est_tx_size(len(selected), n_outputs)
                    if acc < target_amount_sat + est_fee:
                        continue
                    change = 0
                return selected, est_fee, change

        log.warning(
            "[select_utxos] Insufficient funds: available=%d sats, needed=%d sats (target=%d, fee=%d)",
            acc,
            target_amount_sat + est_fee,
            target_amount_sat,
            est_fee,
        )
        raise ValueError(f"insufficient funds: have={acc}, need={target_amount_sat + est_fee}")


    def _check_tx_limits(self, tx_obj: Tx):
        weight, vsize, _, _ = compute_tx_weight_vsize(tx_obj)
        vin = len(tx_obj.inputs or [])
        vout = len(tx_obj.outputs or [])

        if vsize > int(CFG.MAX_TX_VSIZE):
            raise ValueError("tx_vsize_exceeds_limit")
        if vsize < int(CFG.MIN_TX_VSIZE):
            raise ValueError("tx_vsize_below_min")
        if weight > int(CFG.MAX_TX_WEIGHT):
            raise ValueError("tx_weight_exceeds_limit")
        if weight < int(CFG.MIN_TX_WEIGHT):
            raise ValueError("tx_weight_below_min")
        if vin > int(CFG.MAX_TX_INPUTS):
            raise ValueError("tx_inputs_exceed_limit")
        if vout > int(CFG.MAX_TX_OUTPUTS):
            raise ValueError("tx_outputs_exceed_limit")


    def _parse_outputs(self, outputs: list) -> tuple[list[tuple[int, Script]], int]:
        fixed_outs = []
        total_target = 0
        for item in outputs:
            if type(item) is not dict:
                raise ValueError("output item must be dict")
            amt = int(item.get("amount", 0))
            if "spk_hex" in item:
                spk = self._deserialize_spk_hex(item["spk_hex"])
            elif "opret_hex" in item:
                data = bytes.fromhex(item["opret_hex"])
                spk = Script([OP_RETURN, data])
            elif "address" in item:
                spk = self.addr_to_spk(str(item["address"]))
            else:
                raise ValueError("output item must have spk_hex/opret_hex/address")
            self._guard_graffiti_output(spk)
            fixed_outs.append((amt, spk))
            total_target += max(0, amt)
        return fixed_outs, total_target


    def _guard_graffiti_output(self, spk: Script) -> None:
        """
        Validate graffiti OP_RETURN payload against node-side limits.
        Only triggers when payload starts with GRAFFITI_MAGIC.
        """

        raw = spk.serialize()
        data = last_pushdata(raw)
        if not data:
            return
        if not data.startswith(CFG.GRAFFITI_MAGIC):
            return
        if len(data) > int(CFG.MAX_GRAFFITI_OPRET):
            raise ValueError("graffiti_opreturn_too_large")

        meta = GRAFF.parse_payload(data)
        if not meta:
            raise ValueError("graffiti_payload_invalid")

        event = str(meta.get("event", "")).upper()
        if event == "POST":
            size_val = int(meta.get("size", 0))
            if size_val <= 0:
                raise ValueError("graffiti_size_invalid")
            if size_val > int(CFG.GRAFFITI_MAX_SIZE_BYTES):
                raise ValueError("graffiti_size_exceeds_limit")
            
        elif event == "COMMENT":
            comment_len = int(meta.get("comment_len", 0))
            if comment_len <= 0:
                raise ValueError("graffiti_comment_empty")
            if comment_len > int(CFG.GRAFFITI_COMMENT_MAX_BYTES):
                raise ValueError("graffiti_comment_too_large")
            amount = int(meta.get("amount", 0))
            if amount < int(CFG.GRAFFITI_COMMENT_MIN_FEE):
                raise ValueError("graffiti_comment_fee_too_low")
            tip = int(meta.get("tip", 0))
            if tip < 0:
                raise ValueError("graffiti_comment_tip_negative")


    def _process_forced_inputs(self, force_inputs: list[str], utxos_list: list, utxo_by_key: dict, from_addr: str) -> tuple[list, int]:
        preselected = []
        pre_acc = 0
        forced_keys = set(force_inputs)
        
        for key in forced_keys:
            if u := utxo_by_key.get(key):
                preselected.append(u)
                pre_acc += int(u["amount"])
                
        missing = [k for k in forced_keys if k not in utxo_by_key]
        if missing:
            global_utxos = self.broadcast.utxodb.utxos or {}
            for key in list(missing):
                txid_hex, idx_str = key.split(":")
                if entry := global_utxos.get(key):
                    tx_out = entry.get("tx_out") or entry
                    amt = int((tx_out.get("amount", 0) if type(tx_out) is dict else (tx_out.amount or 0)) or 0)
                    spk_bytes = extract_script_bytes(tx_out) or b""
                        
                    is_cb = bool(entry.get("is_coinbase", False))
                    born  = int(entry.get("block_height", 0))
                    u = {
                        "txid": txid_hex,
                        "index": int(idx_str),
                        "amount": amt,
                        "scriptPubKey": spk_bytes,
                        "height": born,
                        "is_coinbase": is_cb,
                    }
                    utxos_list.append(u)
                    utxo_by_key[key] = u
                    preselected.append(u)
                    pre_acc += amt
                    missing.remove(key)
                    
        if missing:
            locks = {}
            sender_spk = self.addr_to_spk(from_addr)
            sender_spk_bytes = sender_spk.serialize()
            for key in list(missing):
                meta = locks.get(key)
                if type(meta) is not dict or str(meta.get("owner", "")).strip().lower() != str(from_addr).strip().lower():
                    continue
                amt = int(meta.get("amount", 0))
                if amt <= 0 or not sender_spk_bytes:
                    continue
                txid_hex, idx_str = key.split(":")
                u = {
                    "txid": txid_hex,
                    "index": int(idx_str),
                    "amount": amt,
                    "scriptPubKey": sender_spk_bytes,
                    "height": 0,
                    "is_coinbase": False,
                }
                utxos_list.append(u)
                utxo_by_key[key] = u
                preselected.append(u)
                pre_acc += amt
                missing.remove(key)
                
        if any(k not in utxo_by_key for k in forced_keys):
            raise ValueError("forced_input_missing")
            
        return preselected, pre_acc


    def _accumulate_utxos_multi(self, candidates: list, selected: list, acc: int, total_target: int, fixed_outs: list, fee_rate: int) -> tuple[int, int]:
        change = 0
        fee_est = 0
        def _est_fee(n_in: int, n_out: int) -> int:
            return fee_rate * self._est_tx_size(n_in, n_out)

        while True:
            fee_est = _est_fee(len(selected), len(fixed_outs) + 1)
            if acc >= total_target + fee_est:
                change = acc - total_target - fee_est
                if change < CFG.DUST_THRESHOLD_SAT:
                    fee_est2 = _est_fee(len(selected), len(fixed_outs))
                    if acc >= total_target + fee_est2:
                        change = 0
                        fee_est = fee_est2
                if acc >= total_target + fee_est:
                    break

            if not candidates:
                log.warning(
                    "[accumulate_utxos_multi] Insufficient funds: available=%d sats, needed=%d sats (target=%d, fee=%d)",
                    acc,
                    total_target + fee_est,
                    total_target,
                    fee_est,
                )
                raise ValueError(f"insufficient funds: have={acc}, need={total_target + fee_est}")
            selected.append(candidates.pop(0))
            acc += int(selected[-1]["amount"])
            
        return change, fee_est


    def _est_tx_size(self, n_inputs, n_outputs):
        return CFG.TX_BASE_VBYTES + n_inputs * CFG.SEGWIT_INPUT_VBYTES + n_outputs * CFG.SEGWIT_OUTPUT_VBYTES


    def _deserialize_spk_hex(self, spk_hex: str) -> Script:
        b = bytes.fromhex((spk_hex or "").strip())
        return Script.deserialize(b)