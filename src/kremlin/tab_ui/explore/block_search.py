# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .main_tab import ExplorePanel


class BlockSearch:
    """Handler for fetch and render data blocks in Explorer."""

    def __init__(
        self,
        panel: "ExplorePanel",
        fmt_ts: Callable[[Optional[int | float]], str],
        fmt_tsar_amount: Callable[[Any], str],
    ) -> None:
        self.panel = panel
        self._fmt_ts = fmt_ts
        self._fmt_tsar_amount = fmt_tsar_amount

    # ---------- entrypoints ----------
    def open_block(self, idx: str) -> None:
        get_block = self.panel.providers.get("get_block")
        if not callable(get_block):
            self.panel._render_error("Provider get_block not available")
            self.panel._finish_search(False)
            return

        def worker():
            done = False
            try:
                b = get_block(idx)
                if not b or b.get("error"):
                    self.panel._ui(self.panel._render_error, "Block not found")
                else:
                    done = True
                    self.panel._ui(self.render_block, b)
            finally:
                self.panel._ui(self.panel._finish_search, done)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- renderers ----------
    def render_block(self, b: Dict) -> None:
        p = self.panel
        p._clear_text()
        meta = b.get("_meta") or {}

        def _pick(*keys):
            for k in keys:
                v = b.get(k)
                if v is None:
                    v = meta.get(k)
                if v not in (None, ""):
                    return v
            return None

        def _fmt_bytes(num):
            try:
                val = float(num)
            except Exception:
                return str(num)
            units = ["bytes", "KB", "MB", "GB", "TB"]
            size = val
            idx = 0
            while size >= 1024 and idx < len(units) - 1:
                size /= 1024
                idx += 1
            if idx == 0:
                return f"{int(size)} bytes"
            return f"{size:.2f} {units[idx]}"

        def _fmt_chainwork(val):
            if val in (None, ""):
                return "-"
            try:
                n = int(val)
                hexstr = hex(n)[2:]
                short = f"0x{hexstr}" if len(hexstr) <= 14 else f"0x{hexstr[:6]}...{hexstr[-6:]}"
                human = f"{n:,}"
                return f"{short} ({human})"
            except Exception:
                s = str(val)
                return s if len(s) <= 14 else f"{s[:6]}...{s[-6:]}"

        h = _pick("height", "index") or "Genesis"
        hh = _pick("hash")
        blkid = _pick("block_id")
        ts = self._fmt_ts(_pick("timestamp", "time"))
        prev = _pick("prev_block_hash", "prev_hash")
        nn = _pick("nonce")
        dif = _pick("difficulty")
        size_b = _pick("size_bytes", "size")
        weight = _pick("weight")
        chainwork = _pick("chainwork")
        bits = _pick("bits")
        ver = _pick("version")
        mroot = _pick("merkle_root")
        txs = b.get("transactions") or b.get("tx", [])

        p._section(f"Block #{h}")
        if not blkid:
            cb = (txs[0] if txs else {}) or {}
            blkid = cb.get("block_id")
        p._kv("Block ID", (blkid if blkid else "-"), mono=True, vtag="val_id")
        p._kv("Hash", str(hh), mono=True, vtag="val_hex")
        p._kv("Previous", str(prev), mono=True, vtag="val_hex")
        p._kv("Time", str(ts), mono=True)
        p._kv("Nonce", str(nn), mono=True, vtag="val_num")
        if dif is not None:
            p._kv("Difficulty", str(dif), mono=True)
        if size_b is not None:
            p._kv("Size", _fmt_bytes(size_b), mono=True)
        if weight is not None:
            p._kv("Weight", str(weight), mono=True)
        if chainwork is not None:
            p._kv("Chainwork", _fmt_chainwork(chainwork), mono=True)
        if bits is not None:
            p._kv("Bits", str(bits), mono=True, vtag="val_num")
        if ver is not None:
            p._kv("Version", str(ver), mono=True, vtag="val_num")
        if mroot is not None:
            p._kv("Merkle Root", str(mroot), mono=True, vtag="val_hex")
        tot_fee = _pick("total_fee")
        if tot_fee is not None:
            p._kv("Total Fee", self._fmt_tsar_amount(tot_fee), mono=True, vtag="val_num")

        # Graffiti / comments
        graff = b.get("graffiti")
        comments = b.get("comments")
        meta_payouts = meta.get("payouts")
        payouts = b.get("payouts") or meta_payouts or []
        if graff or comments or payouts:
            p._section("Graffiti Activity")
            if graff:
                for g in graff:
                    sha = g.get("sha256") or "-"
                    p._kv("SHA256", str(sha), mono=True, vtag="val_hex")
                    p._kv("TxID", str(g.get("txid") or "-"), mono=True, vtag="val_hex")
                    mime = g.get("mime") or "-"
                    sz = g.get("size")
                    p._kv("Meta", f"{mime} | {_fmt_bytes(sz)}", mono=True)
            if comments:
                for c in comments:
                    art = c.get("art_id") or "-"
                    comment_len = c.get("comment_len")
                    p._kv("Art ID", str(art), mono=True, vtag="val_hex")
                    p._kv("Comment Length", comment_len, mono=False)
                    p._kv("Commenter", str(c.get("commenter") or "-"), mono=True, vtag="val_addr")
                    amt = c.get("amount")
                    if amt is not None:
                        p._kv("Amount", self._fmt_tsar_amount(amt), mono=True, vtag="val_num")
            if payouts:
                for pay in payouts:
                    art_id = pay.get("art_id") or "-"
                    epoch = pay.get("epoch")    
                    recipients = pay.get("recipients", [])
                    if type(recipients) is dict:
                        recipients = [{"addr": a, "amount": amt} for a, amt in recipients.items()]
                    p._kv("TxID", str(pay.get("txid") or "-"), mono=True, vtag="val_hex")
                    p._kv("Art ID", str(art_id or "-"), mono=True, vtag="val_hex")
                    p._kv("Epoch", str(epoch or "-"), mono=True, vtag="val_num")
                    p._writeln("Recipients: ", "key")
                    if not recipients:
                        p._writeln("  -", "mono", "muted")
                    else:
                        for rec in recipients:
                            addr = str(rec.get("addr", "")).strip()
                            amt = rec.get("amount")
                            addr_tags = ("mono", "val_addr") if addr else ("mono", "muted")
                            p.text.insert("end", "  - ", ("mono",))
                            p.text.insert("end", addr or "-", addr_tags)
                            if amt is not None:
                                p.text.insert("end", "  ", ("mono",))
                                p.text.insert("end", self._fmt_tsar_amount(amt), ("mono", "val_num"))
                            p.text.insert("end", "\n", ("mono",))

        p._section(f"Transactions ({len(txs)})")
        if not txs:
            p._writeln("No transactions.", "muted")
        else:
            for t in txs:
                txid = t.get("txid", "-")
                vin = len(t.get("inputs") or t.get("vin", []))
                vout = len(t.get("outputs") or t.get("vout", []))

                p.text.insert("end", "- ", ("mono",))
                p.text.insert("end", txid, ("mono", "val_hex"))
                p.text.insert("end", f"   ({vin} → {vout})\n", ("mono",))
        p._finish_render(f"Block {h}")
