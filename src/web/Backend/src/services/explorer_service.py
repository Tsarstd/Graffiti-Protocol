# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE

from typing import Dict, Any, List, Optional
from web.Backend.src.utils.search_kind import guess_kind
from web.Backend.src.core import main_web


class ExplorerService:
    def __init__(self, node_host: str = "127.0.0.1", node_port: int = 19000):
        self.node_host = str(node_host)
        self.node_port = int(node_port)


    def get_receipt(self, txid: str) -> Any:
        return main_web.dispatch_rpc("receipt", txid, self.node_host, self.node_port)


    def get_history_book(self, address: str) -> Any:
        return main_web.dispatch_rpc("history_book", address, self.node_host, self.node_port)


    def get_network(self) -> Any:
        return main_web.dispatch_rpc("network", None, self.node_host, self.node_port)


    def get_block(self, block_id: str) -> Optional[Dict[str, Any]]:
        blk = main_web.dispatch_rpc("block", block_id, self.node_host, self.node_port)
        return self._normalize_block(blk)


    def get_tx(self, txid: str) -> Optional[Dict[str, Any]]:
        tx = main_web.dispatch_rpc("tx", txid, self.node_host, self.node_port)
        return self._normalize_tx(tx, txid)


    def get_address(self, addr: str) -> Any:
        info = main_web.dispatch_rpc("address", addr, self.node_host, self.node_port)
        return self._normalize_address(info)


    def get_graffiti(self, art_id: str) -> Optional[Dict[str, Any]]:
        resp = main_web.dispatch_rpc("graffiti", art_id, self.node_host, self.node_port)
        if not resp:
            return None
        return self._normalize_graffiti_detail(resp)


    def get_graffiti_posts(self, limit: int = 24, offset: int = 0) -> Dict[str, Any]:
        payload = {"limit": limit, "offset": offset}
        resp = main_web.dispatch_rpc("graffiti_posts", payload, self.node_host, self.node_port)
        posts_raw = (resp.get("posts") if resp else None) or []
        items = [self._normalize_graffiti_post(p) for p in posts_raw if p and p.get("art_id")]
        resp_limit = resp.get("limit", limit) if resp else limit
        resp_offset = resp.get("offset", offset) if resp else offset
        total = resp.get("total") if resp else None
        return {
            "items": items,
            "limit": resp_limit,
            "offset": resp_offset,
            "total": total,
            "nextOffset": offset + len(items),
            "hasMore": len(items) >= resp_limit,
        }


    def get_graffiti_media_info(self, art_id: str) -> Any:
        return main_web.dispatch_rpc("graffiti_file", {"art_id": art_id}, self.node_host, self.node_port)


    def get_graffiti_media_meta(self, art_id: str) -> Any:
        return main_web.dispatch_rpc("graffiti_media_meta", {"art_id": art_id}, self.node_host, self.node_port)


    def get_graffiti_chunk(self, art_id: str, offset: int, length: int) -> Any:
        payload = {"art_id": art_id, "offset": offset, "length": length}
        return main_web.dispatch_rpc("graffiti_chunk", payload, self.node_host, self.node_port)


    def get_block_range(self, start_height: Optional[int] = None, limit: int = 10, source: str = "auto") -> Dict[str, Any]:
        payload: Dict[str, Any] = {"limit": int(limit or 10)}
        if start_height is not None:
            payload["start_height"] = int(start_height)
        if source == "database":
            payload["use_database"] = True
            payload["prefer_cache"] = True

        resp = main_web.dispatch_rpc("block_range", payload, self.node_host, self.node_port)
        items_raw = (resp.get("items") if resp else None) or []
        items = [self._normalize_block_summary(item) for item in items_raw if item]

        next_height = None
        has_more = False
        if resp:
            next_height = resp.get("next_height")
            has_more = bool(resp.get("has_more", False))

        return {
            "items": items,
            "limit": resp.get("limit", payload["limit"]) if resp else payload["limit"],
            "startHeight": resp.get("start_height", payload.get("start_height")) if resp else payload.get("start_height"),
            "tipHeight": resp.get("tip_height") if resp else None,
            "nextHeight": next_height,
            "hasMore": has_more,
        }


    def search(self, query: str) -> Dict[str, Any]:
        kind = guess_kind(query)
        if kind == "unknown":
            return {"kind": kind, "data": None}

        if kind == "hash64":
            try:
                tx_data = self.get_tx(query)
                if tx_data and tx_data.get("txid") and not tx_data.get("error"):
                    return {"kind": "tx", "data": tx_data}
            except Exception:
                pass
            try:
                block_data = self.get_block(query)
                if block_data and block_data.get("hash") and not block_data.get("error"):
                    return {"kind": "block", "data": block_data}
            except Exception:
                pass
            return {"kind": "unknown", "data": None}

        if kind == "block_height":
            return {"kind": "block", "data": self.get_block(query)}
        if kind == "address":
            return {"kind": "address", "data": self.get_address(query)}
        if kind == "art_id":
            return {"kind": "graffiti", "data": self.get_graffiti(query)}

        return {"kind": "unknown", "data": None}


# =============================================================================
# INTERNAL METHOD
# =============================================================================


    def _pick(self, obj: Any, *keys: str) -> Any:
        if not obj:
            return None
        meta = obj.get("_meta") if obj.get("_meta") else None
        for key in keys:
            val = obj.get(key)
            if val is not None and val != "":
                return val
            if meta:
                mval = meta.get(key)
                if mval is not None and mval != "":
                    return mval
        return None


    def _decode_comment_hex(self, hex_str: Any) -> str:
        if not hex_str:
            return ""
        try:
            return bytes.fromhex(str(hex_str)).decode("utf-8", errors="replace")
        except Exception:
            return ""


    def _normalize_block(self, blk: Any) -> Optional[Dict[str, Any]]:
        if not blk or blk.get("error") or blk.get("status") == "error" or blk.get("found") is False:
            return None
        obj = blk.get("block") or blk
        if obj.get("error") or obj.get("status") == "error" or obj.get("found") is False:
            return None

        height = self._pick(obj, "height", "index")
        hash_val = self._pick(obj, "hash")
        if height is None and not hash_val:
            return None

        block_id = self._pick(obj, "block_id")
        prev = self._pick(obj, "prev_block_hash", "prev_hash")
        timestamp = self._pick(obj, "timestamp", "time")
        difficulty = self._pick(obj, "difficulty")
        size_bytes = self._pick(obj, "size_bytes", "size")
        chainwork = self._pick(obj, "chainwork")
        bits = self._pick(obj, "bits")
        version = self._pick(obj, "version")
        merkle_root = self._pick(obj, "merkle_root")
        nonce = self._pick(obj, "nonce")
        total_fee = self._pick(obj, "total_fee", "fee")

        txs_raw = obj.get("transactions", obj.get("tx", []))
        if not block_id and txs_raw and txs_raw[0]:
            first = txs_raw[0]
            block_id = first.get("block_id") if first.get("block_id") else block_id

        txs: List[Dict[str, Any]] = []
        for tx in txs_raw:
            if not tx or type(tx) is str:
                txs.append({"txid": str(tx or ""), "inputs": [], "outputs": []})
            else:
                txid = tx.get("txid", tx.get("id", tx.get("hash", "-")))
                inputs = tx.get("inputs", tx.get("vin", []))
                outputs = tx.get("outputs", tx.get("vout", []))
                txs.append({
                    "txid": txid,
                    "inputs": inputs,
                    "outputs": outputs,
                })

        graffiti = blk.get("graffiti", [])
        comments_raw = blk.get("comments", [])
        comments: List[Dict[str, Any]] = []
        for c in comments_raw:
            if c:
                c_copy = dict(c)
                c_copy["comment_text"] = c.get("comment_text") or self._decode_comment_hex(c.get("comment", c.get("comment_hex", "")))
                comments.append(c_copy)

        try:
            total_fee_num = float(total_fee or 0)
        except (ValueError, TypeError):
            total_fee_num = 0.0

        res = dict(blk)
        res.update({
            "height": height,
            "hash": hash_val,
            "block_id": block_id,
            "prev_block_hash": prev,
            "timestamp": timestamp,
            "difficulty": difficulty,
            "size_bytes": size_bytes,
            "chainwork": chainwork,
            "bits": bits,
            "version": version,
            "merkle_root": merkle_root,
            "nonce": nonce,
            "total_fee": total_fee_num,
            "transactions": txs,
            "graffiti": graffiti,
            "comments": comments,
        })
        return res


    def _normalize_block_summary(self, blk: Any) -> Dict[str, Any]:
        if not blk:
            return blk
        height = self._pick(blk, "height", "index")
        hash_val = self._pick(blk, "hash")
        timestamp = self._pick(blk, "timestamp", "time")
        size_bytes = self._pick(blk, "size_bytes", "size")
        total_fee = self._pick(blk, "total_fee", "fee")
        tx_count_raw = blk.get("tx_count")
        if tx_count_raw is None:
            txs = blk.get("transactions", blk.get("tx", []))
            tx_count = len(txs)
        else:
            try:
                tx_count = int(tx_count_raw)
            except (ValueError, TypeError):
                tx_count = 0

        try:
            graffiti_posts = int(blk.get("graffiti_posts", 0))
        except (ValueError, TypeError):
            graffiti_posts = 0

        try:
            graffiti_comments = int(blk.get("graffiti_comments", 0))
        except (ValueError, TypeError):
            graffiti_comments = 0

        default_g_count = graffiti_posts + graffiti_comments
        try:
            graffiti_count = int(blk.get("graffiti_count", default_g_count))
        except (ValueError, TypeError):
            graffiti_count = default_g_count

        try:
            total_fee_num = float(total_fee or 0)
        except (ValueError, TypeError):
            total_fee_num = 0.0

        res = dict(blk)
        res.update({
            "height": height,
            "hash": hash_val,
            "timestamp": timestamp,
            "size_bytes": size_bytes,
            "total_fee": total_fee_num,
            "tx_count": tx_count,
            "graffiti_posts": graffiti_posts,
            "graffiti_comments": graffiti_comments,
            "graffiti_count": graffiti_count,
        })
        return res


    def _normalize_tx(self, tx: Any, fallback_txid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not tx or tx.get("error") or tx.get("status") == "error" or tx.get("found") is False:
            return None
        obj = tx.get("tx") or tx.get("transaction") or tx
        if obj.get("error") or obj.get("status") == "error" or obj.get("found") is False:
            return None

        inputs = obj.get("inputs", obj.get("vin", []))
        outputs = obj.get("outputs", obj.get("vout", []))
        txid = obj.get("txid", obj.get("id", obj.get("hash")))
        if not txid and (inputs or outputs):
            txid = fallback_txid

        if not txid:
            return None

        confirmations = obj.get("confirmations", obj.get("conf", 0))
        fee = obj.get("fee", obj.get("fees", 0))
        height = obj.get("block_height", obj.get("height", "-"))
        size = obj.get("size", obj.get("vsize", obj.get("vbytes", "-")))
        vsize = obj.get("vsize", obj.get("vbytes", "-"))
        weight = obj.get("weight", "-")
        timestamp = obj.get("timestamp", obj.get("time"))

        try:
            conf_num = int(confirmations or 0)
        except (ValueError, TypeError):
            conf_num = 0
        status = obj.get("status", "confirmed" if conf_num > 0 else "unconfirmed")
        is_coinbase = obj.get("is_coinbase")

        norm_inputs: List[Dict[str, Any]] = []
        for inp in inputs:
            if inp:
                vout_val = int(inp.get("vout", 0))
                norm_inputs.append({
                    "txid": inp.get("txid", ""),
                    "vout": vout_val,
                    "address": inp.get("address", ""),
                    "amount": inp.get("amount", 0),
                    "is_coinbase": bool(inp.get("is_coinbase", False)),
                })

        norm_outputs: List[Dict[str, Any]] = []
        for idx, out in enumerate(outputs):
            if out:
                vout_val = out.get("index") if out.get("index") is not None else out.get("vout", idx)
                address = out.get("address")
                event = None
                evt = out.get("event")
                if evt:
                    event = evt if type(evt) is str else evt.get("type")
                norm_outputs.append({
                    "vout": vout_val,
                    "amount": out.get("amount", 0),
                    "address": address,
                    "event": event,
                })

        if is_coinbase is None and norm_inputs:
            prev = str(norm_inputs[0].get("txid") or "")
            first_coinbase = bool(inputs[0].get("coinbase", False)) if inputs else False
            is_coinbase = prev == ("0" * 64) or first_coinbase

        res = dict(obj)
        res.update({
            "txid": txid,
            "confirmations": confirmations,
            "fee": fee,
            "block_height": height,
            "size": size,
            "vsize": vsize,
            "weight": weight,
            "timestamp": timestamp,
            "status": status,
            "is_coinbase": bool(is_coinbase),
            "inputs": norm_inputs,
            "outputs": norm_outputs,
        })
        return res


    def _normalize_address(self, addr: Any) -> Any:
        if not addr:
            return addr
        utxos = addr.get("utxos", [])
        balance = addr.get("balance")
        if balance is None:
            balance = 0
            for u in utxos:
                if u:
                    try:
                        balance += float(u.get("amount", 0))
                    except (ValueError, TypeError):
                        pass
        history = addr.get("history", [])
        res = dict(addr)
        res.update({
            "balance": balance,
            "utxos": utxos,
            "utxo_count": addr.get("utxo_count", len(utxos)),
            "total_txs": addr.get("total_txs", len(history)),
            "history": history,
        })
        return res


    def _normalize_graffiti_post(self, post: Any) -> Any:
        if not post:
            return post
        art_id = post.get("art_id", "")
        res = dict(post)
        res["art_id"] = art_id
        res["preview_url"] = f"/api/graffiti/{art_id}/media" if art_id else None
        return res


    def _normalize_graffiti_detail(self, payload: Any) -> Optional[Dict[str, Any]]:
        if not payload:
            return None
        post_source = payload.get("post") or payload
        if not post_source:
            return None
        post = self._normalize_graffiti_post(post_source)
        if not post or not post.get("art_id"):
            return None
        comments_raw = payload.get("comments", post.get("comments", []))
        comments: List[Dict[str, Any]] = []
        for c in comments_raw:
            if c:
                c_copy = dict(c)
                c_copy["comment_text"] = c.get("comment_text") or self._decode_comment_hex(c.get("comment", c.get("comment_hex", "")))
                comments.append(c_copy)
        res = dict(post)
        res["comments"] = comments
        return res
