# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain - see LICENSE

import re
from kremlin.services.graffiti_service import fetch_graffiti_file

def get_explorer_providers(rpc_client):
    """
    Returns a dictionary of data provider functions for the ExplorePanel,
    bound to the given rpc_client.
    """

    def _rpc(payload: dict):
        return rpc_client.send(payload)


    def _prov_get_info():
        r = _rpc({"type": "GET_NETWORK_INFO"})
        tip = r.get("tip") or r.get("tip_hash")
        return {
            "network": r.get("net_id") or r.get("network_id") or "tsar-devnet-1",
            "height": r.get("height") or r.get("tip_height"),
            "difficulty": r.get("difficulty") or r.get("target") or r.get("tip_target"),
            "hashrate": r.get("hashrate") or r.get("network_hashrate"),
            "genesis": r.get("genesis_hash") or r.get("genesis"),
            "tip": tip,
        }


    def _prov_get_block(x):
        s = str(x).strip()
        if re.fullmatch(r"\d+", s):
            h = int(s)
            blk = _rpc({"type": "GET_BLOCK", "height": h})
            if blk and not blk.get("error"):
                blk.setdefault("height", h)
            return blk

        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            r = _rpc({"type": "GET_BLOCK", "hash": s})
            if r and not r.get("error"):
                r.setdefault("hash", s)
                return r
        return {"error": "not_found"}


    def _prov_get_tx(txid: str):
        r = _rpc({"type": "GET_TX_DETAIL", "txid": str(txid).lower()})
        found = False
        if r and not r.get("error"):
            found = True
        if not found:
            for pay in ({"type": "GET_TX", "txid": str(txid).lower()},
                        {"type": "GET_TRANSACTION", "txid": str(txid).lower()},
                        {"type": "TX_GET", "txid": str(txid).lower()}):
                rr = _rpc(pay)
                if rr and not rr.get("error"):
                    r = rr
                    found = True
                    break
            if not found:
                return {"error": "not_found"}

        t = r.get("tx") or r.get("transaction") or r
        if "txid" not in t:
            t["txid"] = t.get("id") or t.get("hash") or str(txid).lower()
        if "inputs" not in t and "vin" in t:
            t["inputs"] = t.get("vin", [])
        if "outputs" not in t and "vout" in t:
            t["outputs"] = t.get("vout", [])

        if "is_coinbase" not in t:
            vin = t.get("inputs", [])
            if vin:
                prev = vin[0].get("txid", "")
                t["is_coinbase"] = (prev == "0"*64) or bool(vin[0].get("coinbase"))
            else:
                t["is_coinbase"] = False
        return t


    def _prov_get_address(addr: str):
        bals = _rpc({"type": "GET_BALANCES", "addresses": [addr]})
        utx  = _rpc({"type": "GET_TOTAL_UTXO",    "address": addr})
        his  = _rpc({"type": "GET_TX_HISTORY","address": addr})

        res = {"address": addr, "spendable": 0, "immature": 0, "pending": 0, "utxos": [], "history": []}

        def _pick_entry(d):
            if not d:
                return None

            if any(k in d for k in ("spendable","confirmed","pending","immature")):
                return d
            for key in ("balances", "items", "map"):
                m = d.get(key)
                if type(m) is dict:
                    return m.get(addr) or next(iter(m.values()), {})
            bal_inner = d.get("balance")
            if type(bal_inner) is dict:
                return bal_inner

            return None

        be = _pick_entry(bals) or {}

        res["spendable"] = int(be.get("spendable", 0))
        res["immature"]  = int(be.get("immature", 0))
        res["pending"]   = int(be.get("pending", 0))


        utxo_list = []
        if utx:
            raw = utx.get("utxos", {})

            for k, v in raw.items():
                txid, idx = k.rsplit(":", 1); idx = int(idx)
                utxo_list.append({
                    "txid": txid,
                    "index": idx,
                    "amount": v.get("amount", 0),
                    "height": v.get("block_height"),
                    "confirmations": v.get("confirmations"),
                })

        res["utxos"] = utxo_list

        if his:
            res["history"] = his.get("history", [])

        if (res["spendable"] == 0 and res["pending"] == 0 and res["immature"] == 0) and res["utxos"]:
            res["spendable"] = int(sum(int(u.get("amount", 0)) for u in res["utxos"]))
        return res


    def _prov_get_mempool():
        return _rpc({"type": "GET_MEMPOOL"})


    def _prov_get_graffiti(art_id: str):
        return _rpc({"type": "GRAFFITI_GET_ART", "art_id": art_id})


    def _prov_get_graffiti_comments(art_id: str):
        return _rpc({"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id})


    def _prov_fetch_graffiti_file(post: dict | None, art_id: str):
        aid = art_id or (post or {}).get("art_id", "")
        storer_addr = (post or {}).get("storer")
        return fetch_graffiti_file(_rpc, aid, storer_addr=storer_addr)


    return {
        "get_info": _prov_get_info,
        "get_block": _prov_get_block,
        "get_tx": _prov_get_tx,
        "get_address": _prov_get_address,
        "get_mempool": _prov_get_mempool,
        "get_graffiti": _prov_get_graffiti,
        "get_graffiti_comments": _prov_get_graffiti_comments,
        "fetch_graffiti_file": _prov_fetch_graffiti_file,
    }
