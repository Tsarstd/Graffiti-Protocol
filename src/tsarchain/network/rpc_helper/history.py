# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

import time
import threading
import collections


from ...utils import config as CFG
from .base import NetworkHandlerProxy
from ...contracts import graffiti as GRAFF
from ...utils.helpers import spkhex_to_address

# ---------------- Logger ----------------
from ...utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc_helper.history")


class HistoryHandler(NetworkHandlerProxy):
    def __init__(self, network):
        super().__init__(network)
        self._tx_history_cache = collections.OrderedDict()
        self._tx_history_cache_lock = threading.RLock()
        self._chain_opmap_cache = {"tip_hash": "", "map": {}}
        self._chain_opmap_lock = threading.RLock()
        self._addr_tx_index = collections.defaultdict(list)
        self._indexed_count = 0
        self._indexed_genesis_hash = ""
        self._index_lock = threading.RLock()

    def _sync_index_to_tip(self, chain, tip_height: int, opmap_chain: dict):
        with self._index_lock:
            if not chain:
                self._addr_tx_index.clear()
                self._indexed_count = 0
                self._indexed_genesis_hash = ""
                return

            gen_hash = self.bhash_hex(chain[0])
            if self._indexed_genesis_hash and self._indexed_genesis_hash != gen_hash:
                self._addr_tx_index.clear()
                self._indexed_count = 0
            self._indexed_genesis_hash = gen_hash

            if len(chain) < self._indexed_count:
                self._addr_tx_index.clear()
                self._indexed_count = 0

            start_idx = self._indexed_count
            if start_idx >= len(chain):
                return

            for b in chain[start_idx:]:
                block_h = int(b.height or 0)
                block_timestamp = int(b.timestamp or 0)
                txs = b.transactions or []
                for tx in txs:
                    affected_spks = set()
                    for o in (tx.outputs or []):
                        spk = self._txout_to_spk_hex(o)
                        if spk:
                            affected_spks.add(spk)

                    for tin in (tx.inputs or []):
                        prevkey = self.txin_prevkey(tin)
                        amt_spk = opmap_chain.get(prevkey)
                        if amt_spk:
                            _, prev_spk = amt_spk
                            if prev_spk:
                                affected_spks.add(prev_spk)

                    for spk_hex in affected_spks:
                        addr = spkhex_to_address(spk_hex)
                        item = self._extract_tx_history_item(
                            tx, "chain", block_h, block_timestamp,
                            spk_hex, addr, opmap_chain, {}, tip_height
                        )
                        if item:
                            self._addr_tx_index[spk_hex].append(item)

            self._indexed_count = len(chain)

    def process_history_lookup(self, address: str, limit: int = 50, offset: int = 0, direction: str | None = None, status: str | None = None, since_height: int | None = None) -> dict:
        addr, target_spk_hex, err_result = self._validate_history_params(address, limit, offset)
        if err_result:
            return err_result

        mempool = self.broadcast.mempool
        mem_seq = mempool.change_seq if mempool else 0

        with self.broadcast.lock:
            chain = self.broadcast.blockchain.chain
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs() if self.broadcast.mempool else []

        tip_hash = self.bhash_hex(chain[-1]) if chain else ""

        cached_items = self._get_history_from_cache(target_spk_hex, tip_height, tip_hash, mem_seq)
        if cached_items is not None:
            sliced = self._slice_items(cached_items, limit, offset, direction, status, since_height)
            for it in sliced.get("items", []):
                if it.get("status") == "confirmed" and it.get("height") is not None:
                    it["confirmations"] = max(0, tip_height - int(it["height"]) + 1)
                else:
                    it["confirmations"] = 0
            with self._index_lock:
                confirmed_len = len(self._addr_tx_index.get(target_spk_hex) or [])
            sliced["total_confirmed"] = confirmed_len
            return sliced

        opmap_chain, opmap_mem = self.build_outpoint_map(chain, mem)
        self._sync_index_to_tip(chain, tip_height, opmap_chain)

        with self._index_lock:
            confirmed_items = list(self._addr_tx_index.get(target_spk_hex) or [])

        items = []
        for tx in mem:
            item = self._extract_tx_history_item(
                tx, "mempool", None, int(time.time()),
                target_spk_hex, addr, opmap_chain, opmap_mem, tip_height
            )
            if item:
                items.append(item)

        items.extend(confirmed_items)
        items = self._deduplicate_and_sort_history_items(items)
        self._save_history_to_cache(target_spk_hex, items, tip_height, tip_hash, mem_seq)

        sliced = self._slice_items(items, limit, offset, direction, status, since_height)
        for it in sliced.get("items", []):
            if it.get("status") == "confirmed" and it.get("height") is not None:
                it["confirmations"] = max(0, tip_height - int(it["height"]) + 1)
            else:
                it["confirmations"] = 0
        with self._index_lock:
            confirmed_len = len(self._addr_tx_index.get(target_spk_hex) or [])
        sliced["total_confirmed"] = confirmed_len

        return sliced


    def _txid_hex_helper(self, tid) -> str:
        if type(tid) in (bytes, bytearray):
            return tid.hex().lower()
        if type(tid) is str:
            return tid.strip().lower()
        return ""


    def find_tx_and_meta(self, txid_hex: str):
        target = str(txid_hex or "").strip().lower()
        with self.broadcast.lock:
            chain = self.broadcast.blockchain.chain
            tip_height = int(self.broadcast.blockchain.height)
            mem = self.broadcast.mempool.get_all_txs()
        for tx in mem:
            txid_val = tx.txid
            txid = self._txid_hex_helper(txid_val)
            if txid == target:
                return ("mempool", tx, None, 0, None, chain, mem, tip_height)
        for b in reversed(chain):
            h = int(b.height or 0)
            timestamp = int(b.timestamp or 0)
            txs = b.transactions or []
            for tx in txs:
                txid_val = tx.txid
                txid = self._txid_hex_helper(txid_val)
                if txid == target:
                    conf = max(0, tip_height - h + 1)
                    return ("chain", tx, h, timestamp, conf, chain, mem, tip_height)

        return (None, None, None, 0, 0, chain, mem, tip_height)


    def txin_prevkey(self, tin) -> str:
        txid = tin.txid
        if type(txid) in (bytes, bytearray):
            ptx = txid.hex()
        elif type(txid) is str and len(txid) >= 64:
            ptx = txid
        else:
            p0 = tin.prev_tx
            if type(p0) in (bytes, bytearray):
                ptx = p0.hex()
            else:
                ptx = str(p0 or "")

        idx = tin.vout
        idx = int(idx or 0)
        return f"{ptx}:{idx}"


    def is_coinbase_tx(self, tx) -> bool:
        ins = tx.inputs or []
        if len(ins) == 0:
            return True
        first = ins[0]
        p0 = first.txid
        if type(p0) in (bytes, bytearray):
            b = p0
        elif type(p0) is str and len(p0) == 64:
            b = bytes.fromhex(p0)
        else:
            b = first.prev_tx
            if type(b) not in (bytes, bytearray):
                b = b""
        return b == b"\x00" * 32


    def txout_to_address(self, txout) -> str | None:
        spk_hex = self._txout_to_spk_hex(txout)
        if not spk_hex:
            return None
        return spkhex_to_address(spk_hex)


    def build_outpoint_map(self, chain, mem=None):
        tip_hash = ""
        if chain:
            tip_hash = self.bhash_hex(chain[-1])

        chain_map = None
        if tip_hash and self._chain_opmap_cache.get("tip_hash") == tip_hash:
            chain_map = self._chain_opmap_cache.get("map")

        if chain_map is None:
            with self._chain_opmap_lock:
                cached_map = self._chain_opmap_cache.get("map")
                cached_h = self._chain_opmap_cache.get("height", -1)
                cached_gen = self._chain_opmap_cache.get("gen", "")
                cur_gen = self.bhash_hex(chain[0]) if chain else ""

                if cached_map is not None and cached_h >= 0 and cached_h < len(chain) and cached_gen == cur_gen:
                    chain_map = cached_map
                    start_idx = cached_h + 1
                else:
                    chain_map = {}
                    start_idx = 0

                for b_idx in range(start_idx, len(chain)):
                    b = chain[b_idx]
                    txs = b.transactions or []
                    for tx in txs:
                        txid_val = tx.txid
                        txid = self._txid_hex_helper(txid_val)
                        outputs = tx.outputs or []
                        for idx, o in enumerate(outputs):
                            amount = int(o.amount or 0)
                            spk_hex = self._txout_to_spk_hex(o) or ""
                            chain_map[f"{txid}:{idx}"] = (amount, spk_hex)

                if tip_hash:
                    self._chain_opmap_cache = {
                        "tip_hash": tip_hash,
                        "map": chain_map,
                        "height": len(chain) - 1,
                        "gen": cur_gen,
                    }

        if mem is None:
            return chain_map
        mem_map: dict[str, tuple[int, str]] = {}
        for tx in mem:
            txid_val = tx.txid
            txid = self._txid_hex_helper(txid_val)
            outputs = tx.outputs or []
            for idx, o in enumerate(outputs):
                amount = int(o.amount or 0)
                spk_hex = self._txout_to_spk_hex(o) or ""
                mem_map[f"{txid}:{idx}"] = (amount, spk_hex)
        return chain_map, mem_map


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _validate_history_params(self, address: str, limit: int, offset: int) -> tuple[str, str | None, dict | None]:
        if type(address) is not str:
            return "", None, {"items": [], "total": 0, "limit": limit, "offset": offset}
        addr = (address or "").strip().lower()
        if not addr:
            return "", None, {"items": [], "total": 0, "limit": limit, "offset": offset}
        max_addr_len = int(CFG.MAX_UTXO_ADDR_LEN)
        if len(addr) > max_addr_len:
            return "", None, {"items": [], "total": 0, "limit": limit, "offset": offset, "error": "address too long"}
        target_spk_hex = self._normalize_spk_hex(addr)
        if not target_spk_hex:
            return "", None, {"items": [], "total": 0, "limit": limit, "offset": offset, "error": "invalid address"}
        return addr, target_spk_hex, None


    def _extract_tx_history_item(self, tx, where, h_or_none, timestamp, target_spk_hex, addr, opmap_chain, opmap_mem, tip_height):
        txid_val = tx.txid
        txid = self._txid_hex_helper(txid_val)
        is_cb = self.is_coinbase_tx(tx)
        conf = 0
        height = None
        if where == "chain":
            height = int(h_or_none or 0)
            conf = max(0, tip_height - height + 1)

        received_to_addr = 0
        main_recipient_spk, max_rec_amt = None, -1
        is_graffiti = False
        event_type = None

        outputs = tx.outputs or []
        for o in outputs:
            amt = int(o.amount or 0)
            spk_hex = self._txout_to_spk_hex(o) or ""
            if spk_hex == target_spk_hex:
                received_to_addr += amt
            else:
                if amt > max_rec_amt:
                    max_rec_amt = amt
                    main_recipient_spk = spk_hex

            spk = o.script_pubkey
            if spk is not None:
                try:
                    meta = GRAFF.parse_from_script(spk)
                    if meta:
                        ev = str(meta.get("event", "")).upper()
                        if ev in ("POST", "COMMENT", "PAYOUT"):
                            is_graffiti = True
                            event_type = ev
                except Exception:
                    log.exception("_extract_tx_history_item")

        spent_from_addr = 0
        sources = set()
        inputs = tx.inputs or []
        for tin in inputs:
            key = self.txin_prevkey(tin)
            amt_spk = opmap_chain.get(key)
            if where == "mempool":
                amt_spk = opmap_mem.get(key) or amt_spk
            if not amt_spk:
                continue
            amt_prev, spk_prev = amt_spk
            if spk_prev == target_spk_hex:
                spent_from_addr += int(amt_prev)
            elif spk_prev:
                sources.add(spk_prev)

        if spent_from_addr > 0:
            net_amt = spent_from_addr - received_to_addr
            if net_amt < 0:
                net_amt = 0
            dirn = "out"
            frm = addr
            to = spkhex_to_address(main_recipient_spk) if main_recipient_spk else None
            if to == addr:
                to = None
        elif received_to_addr > 0:
            dirn = "in"
            net_amt = received_to_addr
            frm = "coinbase"
            if not is_cb and sources:
                src_spk = next(iter(sources))
                frm = spkhex_to_address(src_spk)
            to = addr
        else:
            return None

        st = "unconfirmed" if where == "mempool" else "confirmed"
        return {
            "txid": txid,
            "direction": dirn,
            "amount": int(net_amt),
            "status": st,
            "confirmations": conf,
            "height": height,
            "from": frm,
            "to": to,
            "timestamp": timestamp,
            "is_graffiti": is_graffiti,
            "event": event_type,
        }


    def _deduplicate_and_sort_history_items(self, items: list[dict]) -> list[dict]:
        by_id = {}
        for it in items:
            tid = it.get("txid")
            if not tid:
                continue
            prev = by_id.get(tid)
            if prev is None:
                by_id[tid] = it
                continue
            rank_prev = (prev.get("status") == "confirmed", int(prev.get("height") or -1))
            rank_new  = (it.get("status") == "confirmed", int(it.get("height") or -1))
            if rank_new > rank_prev:
                by_id[tid] = it
                
        unique_items = list(by_id.values())
        
        def _key(it):
            st = 0 if it["status"] == "unconfirmed" else 1
            h  = it["height"] if it["height"] is not None else -1
            return (st, -h)
            
        unique_items.sort(key=_key)
        return unique_items


    def _save_history_to_cache(self, target_spk_hex, items, tip_height, tip_hash, mem_seq):
        max_cache_items = max(200, int(CFG.MAX_HISTORY_LIMIT) * 10)
        max_cache = max(16, int(CFG.MAX_HISTORY_LIMIT))
        if len(items) > max_cache_items:
            return
        cache, cache_lock = self._setup_tx_history_cache()
        now = time.time()
        with cache_lock:
            cache[target_spk_hex] = {
                "ts": now,
                "tip_height": tip_height,
                "tip_hash": tip_hash,
                "mem_seq": mem_seq,
                "items": items,
            }
            cache.move_to_end(target_spk_hex)
            while len(cache) > max_cache:
                cache.popitem(last=False)


    def _slice_items(self, items: list[dict], limit: int, offset: int, direction: str | None, status: str | None, since_height: int | None = None) -> dict:
        filtered = items
        if direction in ("in", "out"):
            filtered = [it for it in filtered if it["direction"] == direction]
        if status in ("confirmed", "unconfirmed"):
            filtered = [it for it in filtered if it["status"] == status]
        if since_height is not None:
            # ponytail: delta filter returns only txs mined strictly after since_height or unconfirmed mempool txs
            filtered = [it for it in filtered if it.get("height") is None or int(it["height"]) > int(since_height)]

        total = len(filtered)
        start_idx = max(0, int(offset))
        end_idx   = max(start_idx, int(start_idx + max(0, int(limit))))
        page = filtered[start_idx:end_idx]

        optimized_items = []
        for item in page:
            optimized = dict(item)
            if optimized["direction"] == "in":
                optimized.pop("to", None)
            elif optimized["direction"] == "out":
                optimized.pop("from", None)
            optimized_items.append(optimized)

        return {"items": optimized_items, "total": total, "limit": int(limit), "offset": int(offset)}


    def _txout_to_spk_hex(self, txout) -> str | None:
        spk = txout.script_pubkey
        if spk is None:
            return None

        if type(spk) in (bytes, bytearray):
            return bytes(spk).hex()
        if type(spk) is str:
            return spk.lower()

        try:
            ser = spk.serialize
            if callable(ser):
                return ser().hex()
        except AttributeError:
            pass
        return None


    def _is_valid_hex(self, s: str) -> bool:
        try:
            bytes.fromhex(s)
            return True
        except Exception:
            return False


    def _normalize_bech32_addr(self, addr: str) -> str | None:
        try:
            spk = self.addr_to_spk(addr)
            return spk.serialize().hex()
        except Exception:
            return None


    def _normalize_spk_hex(self, addr: str) -> str | None:
        addr = (addr or "").strip().lower()
        if not addr:
            return None
        if addr.startswith(CFG.ADDRESS_PREFIX + "1"):
            return self._normalize_bech32_addr(addr)
        if addr.startswith("0014") and len(addr) == 44 and self._is_valid_hex(addr):
            return addr
        if addr.startswith("0020") and len(addr) == 68 and self._is_valid_hex(addr):
            return addr
        if addr.startswith("00") and len(addr) in (42, 66) and self._is_valid_hex(addr):
            return "0014" + addr[2:] if len(addr) == 42 else "0020" + addr[2:]
        return None


    def _setup_tx_history_cache(self):
        cache = self._tx_history_cache
        cache_lock = self._tx_history_cache_lock
        if cache is None or cache_lock is None:
            cache = self._tx_history_cache = collections.OrderedDict()
            cache_lock = self._tx_history_cache_lock = threading.RLock()
        return cache, cache_lock


    def _get_history_from_cache(self, target_spk_hex, tip_height, tip_hash, mem_seq):
        cache, cache_lock = self._setup_tx_history_cache()
        with cache_lock:
            entry = cache.get(target_spk_hex)
            if entry:
                # ponytail: tip_height + tip_hash + mem_seq is an exact deterministic invariant; no arbitrary 10s expiration
                if entry.get("tip_height") == tip_height and entry.get("tip_hash") == tip_hash and entry.get("mem_seq") == mem_seq:
                    cache.move_to_end(target_spk_hex)
                    return entry.get("items") or []
                cache.pop(target_spk_hex, None)
        return None