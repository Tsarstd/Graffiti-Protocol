# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, TYPE_CHECKING

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.explore.txid_search")

if TYPE_CHECKING:  # pragma: no cover
    from .main_tab import ExplorePanel


class TxSearch:
    """Handler for fetching and rendering transactions in Explorer."""

    def __init__(self, panel: "ExplorePanel", fmt_tsar_amount: Callable[[Any], str]) -> None:
        self.panel = panel
        self._fmt_tsar_amount = fmt_tsar_amount

    # ---------- entrypoints ----------

    def open_tx_or_block(self, hx: str) -> None:
        hx = str(hx or "").strip()
        get_tx = self.panel.providers.get("get_tx")
        get_block = self.panel.providers.get("get_block")
        if not callable(get_block) and not callable(get_tx):
            self.panel._render_error("Providers not available")
            self.panel._finish_search(False)
            return

        def worker():
            done = False
            b = None
            if callable(get_block):
                b = get_block(hx)
            if b and type(b) is dict and not b.get("error") and (b.get("hash") or b.get("transactions") or b.get("tx")):
                done = True
                self.panel._ui(self.panel.block_search.render_block, b)
                self.panel._ui(self.panel._finish_search, True)
                return

            if callable(get_tx):
                t = get_tx(hx)
                if t and type(t) is dict and not t.get("error"):
                    tx_inner = t.get("tx")
                    if type(tx_inner) is dict:
                        t = tx_inner
                    txid_disp = t.get("txid") or hx
                    done = True
                    self.panel._ui(self.render_tx, txid_disp, t)
                    self.panel._ui(self.panel._finish_search, True)
                    return

            self.panel._ui(self.panel._render_error, "Not found")
            self.panel._ui(self.panel._finish_search, done)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- renderers ----------
    def render_tx(self, txid: str, t: Dict) -> None:
        p = self.panel
        p._clear_text()
        fee = t.get("fee", "-")
        conf = t.get("confirmations", 0)
        height = t.get("block_height", t.get("height", "-"))
        status = t.get("status", "unconfirmed" if int(conf or 0) == 0 else "confirmed")
        coinbase = bool(t.get("is_coinbase"))

        p._section("Transaction")
        p._kv("TxID", txid, mono=True, vtag="val_hex")
        tag = "confirmed" if str(status).lower().startswith("conf") or int(conf or 0) > 0 else "unconfirmed"
        p._kv("Status", str(status), mono=True, vtag=tag)
        p._kv("Conf", str(conf), mono=True, vtag="val_num")
        p._kv("Block", str(height), mono=True, vtag="val_num")
        if fee != "-":
            p._kv("Fee", self._fmt_tsar_amount(fee), mono=True, vtag="val_num")
        p._kv("Coinbase", str(coinbase))

        vin = t.get("inputs", [])
        vout = t.get("outputs", [])

        p._section("Inputs")
        if not vin:
            p._writeln("No inputs (coinbase?)", "muted")
        else:
            for vi in vin:
                src = vi.get("txid", "-")
                addr = vi.get("address", "")
                amt = vi.get("amount")

                p.text.insert("end", "- ", ("mono",))
                p.text.insert("end", src, ("mono", "val_hex"))
                    
                if addr:
                    p.text.insert("end", "  ", ("mono",))
                    p.text.insert("end", addr, ("mono", "val_addr"))

                if amt is not None:
                    p.text.insert("end", "  ", ("mono",))
                    p.text.insert("end", self._fmt_tsar_amount(amt), ("mono", "val_num"))

                p.text.insert("end", "\n", ("mono",))

        p._section("Outputs")
        if not vout:
            p._writeln("No outputs", "muted")
        else:
            for i, vo in enumerate(vout):
                val = vo.get("amount", "-")
                p.text.insert("end", f"- [{i}] ", ("mono",))
                p.text.insert("end", self._fmt_tsar_amount(val) + "\n", "val_num")
        p._finish_render("Tx detail")
