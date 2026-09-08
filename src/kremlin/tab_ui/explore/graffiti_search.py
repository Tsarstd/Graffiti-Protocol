# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import os
import pymupdf as fitz
import threading
import tkinter as tk

from glob import glob
from io import BytesIO
from decimal import Decimal
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

from PIL import Image, ImageTk
from tkinter import ttk, messagebox

from ...theme import FONT
from ...services.media import TkVLCPlayer
from tsarchain.utils import config as CFG
from ...services.graffiti_service import build_comment_plan

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.explore.graffiti_search")

if TYPE_CHECKING:  # pragma: no cover
    from .main_tab import ExplorePanel


class GraffitiSearch:
    """Handlers for fetch, render, and interact with Graffiti comments."""

    def __init__(
        self,
        panel: "ExplorePanel",
        fmt_ts: Callable[[Optional[int | float]], str],
        fmt_tsar_amount: Callable[[Any], str],
    ) -> None:
        
        self.panel = panel
        self._fmt_ts = fmt_ts
        self._fmt_tsar_amount = fmt_tsar_amount
        
        self._pdf_doc = None
        self._pdf_current_page = 0
        self._pdf_total_pages = 0

    # ---------- entrypoints ----------
    def open_graffiti(self, art_id: str) -> None:
        get_graffiti = self.panel.providers.get("get_graffiti")
        get_comments = self.panel.providers.get("get_graffiti_comments")
        fetch_file = self.panel.providers.get("fetch_graffiti_file")
        if not callable(get_graffiti):
            self.panel._render_error("Provider get_graffiti not available")
            self.panel._finish_search(False)
            return

        def worker():
            done = False
            try:
                post_resp = get_graffiti(art_id)
                post = None
                if post_resp.get("error"):
                    self.panel._ui(self.panel._render_error, f"Graffiti error: {post_resp.get('error')}")
                    return
                post = post_resp.get("post") or post_resp

                if not post:
                    self.panel._ui(self.panel._render_error, "Graffiti Not Found.")
                    return
                comments = []
                if callable(get_comments):
                    c = get_comments(post.get("art_id") or art_id)
                    comments = c.get("comments") or []

                img_bytes = None
                img_meta = None
                cache_path = None
                if callable(fetch_file):
                    f = fetch_file(post, art_id)
                    if f.get("status") == "ok":
                        img_bytes = f.get("bytes")
                        img_meta = f.get("meta")
                        cache_path = f.get("cache_path")
                    else:
                        err = f.get("reason") or f.get("error")
                        self.panel._ui(self.panel._render_error, f"fetch_graffiti_file error: {err}")


                done = True
                self.panel._ui(self.render_graffiti, post, comments, img_bytes, img_meta or {}, cache_path)
            finally:
                self.panel._ui(self.panel._finish_search, done)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- renderers ----------
    def render_graffiti(
        self,
        post: Dict,
        comments: list[Dict],
        img_bytes: bytes | None,
        img_meta: Dict,
        cache_path: str | None = None,
    ) -> None:
        p = self.panel
        p._clear_text()
        p._img_refs.clear()
        p._current_graffiti_post = post
        p._comment_status_var.set("")
        p._comment_text_widget = None
        p._comment_btn = None
        
        if self._pdf_doc:
            try:
                self._pdf_doc.close()
            except Exception:
                pass
            self._pdf_doc = None

        art_id = str((post or {}).get("art_id") or "-")
        creator = str((post or {}).get("creator") or "-")
        mime = str((post or {}).get("mime") or post.get("mime_type") or img_meta.get("mime") or img_meta.get("mime_type") or "-").lower()
        size = int((post or {}).get("size") or (post or {}).get("size_bytes") or img_meta.get("size_bytes") or 0)
        block_h = int((post or {}).get("block_height") or 0)
        txid = str((post or {}).get("txid") or "-")
        sha256 = str((post or {}).get("sha256") or "-")
        mroot = str((post or {}).get("mroot") or "-")
        mcount = str((post or {}).get("mcount") or "-")
        mchunk = str((post or {}).get("mchunk") or "-")
        stats = (post or {}).get("stats") or {}
        preview_max_w, preview_max_h = 854, 480
        log.debug("explorer: render graffiti art_id=%s creator=%s comments=%s", art_id, creator, len(comments))

        def _fmt_size_h(bytes_val: int) -> str:
            b = int(bytes_val)
            units = ["bytes", "KB", "MB", "GB"]
            val = float(b)
            u = 0
            while val >= 1024 and u < len(units) - 1:
                val /= 1024
                u += 1
            if u == 0:
                return f"{int(val):,} {units[u]}"
            return f"{val:.2f} {units[u]}"

        # Use one container so the center is neat
        container = tk.Frame(p.text, bg=p.card_bg, bd=1, highlightthickness=1, highlightbackground=p.border)
        p._window_create_center(container, target_width=920, pady=10)
        p._bind_mousewheel_forward(container)

        info = tk.Frame(container, bg=p.card_bg)
        info.pack(fill="x", pady=(8, 6))

        def _lbl(text: str, **kwargs):
            lbl = tk.Label(info, text=text, bg=p.card_bg, **kwargs)
            lbl.pack(anchor="center")
            p._bind_copyable(lbl, lambda t=text: t)
            return lbl

        _lbl(f"Graffiti #Block {block_h}", fg=p.fg, font=(FONT, 12, "bold"))
        _lbl(f"{mime} | {_fmt_size_h(size)}", fg=p.fg, font=("Consolas", 10))
        _lbl("--------------", fg=p.fg)
        _lbl(f"Art ID | {art_id}", fg=p.fg, font=("Consolas", 10))
        _lbl("--------------", fg=p.fg)
        _lbl(f"TxID | {txid}", fg=p.value_id, font=("Consolas", 10))
        _lbl(f"SHA256 | {sha256}", fg=p.value_id, font=("Consolas", 10))
        _lbl(f"Graffiti Merkle | {mroot}", fg=p.value_id, font=("Consolas", 10))
        _lbl(f"Merkle Count | {mcount}", fg=p.value_id, font=("Consolas", 10))
        _lbl(f"Merkle Chunk | {mchunk}", fg=p.value_id, font=("Consolas", 10))
        _lbl("--------------", fg=p.fg)
        _lbl(f"Creator | {creator}", fg=p.accent, font=("Consolas", 10))
        _lbl(f"Total Comments | {stats.get('comments', 0)}", fg=p.value_num, font=("Consolas", 10))

        # preview: image or video
        cache_guess = cache_path
        if not cache_guess:
            matches = glob(os.path.join(CFG.WALLET_DATA_DIR, "graffiti_cache", f"{art_id}.*"))
            for m in matches:
                if os.path.isfile(m):
                    cache_guess = m
                    break

        ext = os.path.splitext(cache_guess or "")[1].lower()
        is_video = ("video" in mime) or ext == ".mp4" or mime.endswith("mp4")
        is_pdf = mime == "application/pdf" or ext == ".pdf"
        
        media_holder = tk.Frame(container, bg=p.card_bg)
        media_holder.pack(pady=8)
        # Video (mp4 & mkv)
        if is_video:
            if cache_guess and os.path.isfile(cache_guess):
                status_var = tk.StringVar(value="")
                video_inner_frame = tk.Frame(media_holder, bg=p.card_bg)
                video_inner_frame.pack()
                player_obj = TkVLCPlayer(
                    video_inner_frame,
                    width=preview_max_w,
                    height=preview_max_h,
                    max_width=preview_max_w,
                    max_height=preview_max_h,
                    bg=p.card_bg,
                    fg=p.fg,
                    accent=p.accent,
                    on_error=lambda m: status_var.set(m),
                )
                player_obj.frame.pack(fill="both", expand=True, pady=(4, 2))
                player_obj.load(cache_guess, autoplay=True)
                p._media_players.append(player_obj)
                status_label = tk.Label(media_holder, textvariable=status_var, bg=p.card_bg, fg=p.muted, font=("Consolas", 9))
                status_label.pack(anchor="center")
                p._bind_copyable(status_label, lambda: status_var.get())
            else:
                missing = tk.Label(media_holder, text="(video cache not found)", bg=p.card_bg, fg=p.muted, font=("Consolas", 10))
                missing.pack(anchor="center")
                p._bind_copyable(missing, lambda: missing.cget("text"))
        # PDF Document
        elif is_pdf:
            if cache_guess and os.path.isfile(cache_guess):
                try:
                    self._pdf_doc = fitz.open(cache_guess)
                    self._pdf_total_pages = len(self._pdf_doc)
                    self._pdf_current_page = 0
                    
                    # Buat frame untuk PDF preview
                    pdf_container = tk.Frame(media_holder, bg=p.card_bg)
                    pdf_container.pack()
                    
                    # Frame untuk navigasi
                    nav_frame = tk.Frame(pdf_container, bg=p.card_bg)
                    nav_frame.pack(fill="x", pady=(0, 5))
                    
                    # Info halaman
                    page_var = tk.StringVar()
                    page_label = tk.Label(
                        nav_frame,
                        textvariable=page_var,
                        bg=p.card_bg,
                        fg=p.fg,
                        font=("Consolas", 9)
                    )
                    page_label.pack(side=tk.LEFT, padx=(10, 5))
                    
                    # Tombol navigasi
                    btn_style = {"bg": p.accent, "fg": p.bg, "bd": 0, "relief": tk.FLAT, "cursor": "hand2"}
                    
                    btn_first = tk.Button(
                        nav_frame,
                        text="⏮",
                        command=lambda: self._show_explorer_pdf_page(0, pdf_container, page_var),
                        **btn_style
                    )
                    btn_first.pack(side=tk.LEFT, padx=2)
                    
                    btn_prev = tk.Button(
                        nav_frame,
                        text="◀",
                        command=lambda: self._show_explorer_pdf_page(
                            max(0, self._pdf_current_page - 1), pdf_container, page_var
                        ),
                        **btn_style
                    )
                    btn_prev.pack(side=tk.LEFT, padx=2)
                    
                    btn_next = tk.Button(
                        nav_frame,
                        text="▶",
                        command=lambda: self._show_explorer_pdf_page(
                            min(self._pdf_total_pages - 1, self._pdf_current_page + 1), pdf_container, page_var
                        ),
                        **btn_style
                    )
                    btn_next.pack(side=tk.LEFT, padx=2)
                    
                    btn_last = tk.Button(
                        nav_frame,
                        text="⏭",
                        command=lambda: self._show_explorer_pdf_page(self._pdf_total_pages - 1, pdf_container, page_var),
                        **btn_style
                    )
                    btn_last.pack(side=tk.LEFT, padx=2)
                    
                    # Frame untuk menampilkan halaman
                    self._pdf_display_frame = tk.Frame(pdf_container, bg=p.card_bg)
                    self._pdf_display_frame.pack()
                    
                    # Tampilkan halaman pertama
                    self._show_explorer_pdf_page(0, pdf_container, page_var)
                    
                except Exception as e:
                    error_msg = tk.Label(
                        media_holder,
                        text=f"PDF preview failed: {str(e)}",
                        bg=p.card_bg,
                        fg=p.muted,
                        font=("Consolas", 10)
                    )
                    error_msg.pack(anchor="center")
                    p._bind_copyable(error_msg, lambda: error_msg.cget("text"))
            else:
                missing = tk.Label(media_holder, text="(PDF cache not found)", bg=p.card_bg, fg=p.muted, font=("Consolas", 10))
                missing.pack(anchor="center")
                p._bind_copyable(missing, lambda: missing.cget("text"))
        
        # Image (jpeg atau jpg)
        else:
            if img_bytes:
                buf = BytesIO(img_bytes)
                img = Image.open(buf)
                img.thumbnail((preview_max_w, preview_max_h))
                photo = ImageTk.PhotoImage(img)
                p._img_refs.append(photo)
                tk.Label(media_holder, image=photo, bg=p.card_bg).pack()
            else:
                missing = tk.Label(media_holder, text="(graffiti not found)", bg=p.card_bg, fg=p.muted, font=("Consolas", 10))
                missing.pack(anchor="center")
                p._bind_copyable(missing, lambda: missing.cget("text"))

        # comments section
        comments_wrap = tk.Frame(container, bg=p.card_bg)
        comments_wrap.pack(anchor="center", pady=(10, 6))
        tk.Label(comments_wrap, text=f"Comments ({len(comments)})", bg=p.card_bg, fg=p.fg, font=(FONT, 11, "bold")).pack(anchor="center")
        comments_inner = tk.Frame(comments_wrap, bg=p.card_bg)
        comments_inner.pack(anchor="center")

        def _decode_comment(hx: str) -> str:
            return bytes.fromhex(hx or "").decode("utf-8", errors="replace")

        if not comments:
            tk.Label(comments_inner, text="No Comment yet.", bg=p.card_bg, fg=p.muted, font=("Consolas", 10)).pack(anchor="center", pady=4)
        else:
            for c in comments:
                ts_fmt = self._fmt_ts(c.get("ts"))
                commenter = str(c.get("commenter") or "-")
                amt = self._fmt_tsar_amount(c.get("amount"))
                tip = c.get("tip")
                text = _decode_comment(c.get("comment") or c.get("comment_hex") or "")
                excerpt = text if len(text) <= 320 else text[:320]
                separator = "---------------"

                card = tk.Frame(comments_inner, bg=p.card_bg, bd=1, highlightthickness=1, highlightbackground=p.border)
                card.pack(anchor="center", fill="x", padx=10, pady=4)
                head = tk.Frame(card, bg=p.card_bg)
                head.pack(fill="x", padx=10, pady=(6, 2))
                ts_lbl = tk.Label(head, text=ts_fmt, bg=p.card_bg, fg=p.muted, font=("Consolas", 8))
                ts_lbl.pack(side="top")
                p._bind_copyable(ts_lbl, lambda t=ts_fmt: t)
                name_lbl = tk.Label(head, text=commenter, bg=p.card_bg, fg=p.accent, font=("Consolas", 10, "bold"))
                name_lbl.pack(side="top")
                p._bind_copyable(name_lbl, lambda t=commenter: t)
                meta = tk.Frame(card, bg=p.card_bg)
                meta.pack(fill="x", padx=10, pady=(0, 6))
                amt_text = f"Amount: {amt}"
                amt_lbl = tk.Label(meta, text=amt_text, bg=p.card_bg, fg=p.value_num, font=("Consolas", 8))
                amt_lbl.pack(side="top")
                p._bind_copyable(amt_lbl, lambda t=amt_text: t)
                if tip:
                    tip_text = f"Tip: {self._fmt_tsar_amount(tip)}"
                    tip_lbl = tk.Label(meta, text=tip_text, bg=p.card_bg, fg=p.value_num, font=("Consolas", 8))
                    tip_lbl.pack(side="top", padx=(12, 0))
                    p._bind_copyable(tip_lbl, lambda t=tip_text: t)
                
                sep = tk.Label(card, text=separator, bg=p.card_bg, fg=p.fg, justify="center", wraplength=760)
                sep.pack(fill="x", padx=10, pady=(0, 4))
                p._bind_copyable(sep, lambda t=separator: t)
                body = tk.Label(card, text=excerpt, bg=p.card_bg, fg=p.fg, justify="center", wraplength=760, font=("Consolas", 12, "bold"))
                body.pack(fill="x", padx=10, pady=(0, 4))
                p._bind_copyable(body, lambda t=excerpt: t)

        self.build_comment_composer(post, art_id, container)
        p._finish_render("Graffiti detail")

    # ---------- comments ----------
    def comment_base_tsar_str(self) -> str:
        val = Decimal(int(CFG.GRAFFITI_COMMENT_MIN_FEE)) / Decimal(CFG.TSAR)
        txt = format(val.normalize(), "f")
        txt = txt.rstrip("0").rstrip(".") or "0"
        return txt

    def build_comment_composer(self, post: Dict, art_id: str, parent: tk.Widget) -> None:
        p = self.panel
        try:
            wallets = list(p.app.wallets or [])
        except AttributeError:
            wallets = []
        log.debug("explorer: build comment composer art_id=%s wallets=%s", art_id, len(wallets))
        outer = tk.Frame(parent, bg=p.card_bg)
        outer.pack(anchor="center", pady=8, fill="x")

        frame = tk.Frame(outer, bg=p.card_bg, bd=1, highlightthickness=1, highlightbackground=p.border)
        frame.pack(anchor="center", padx=6, fill="x")

        tk.Label(frame, text="Write a Comment", bg=p.card_bg, fg=p.fg, font=(FONT, 11, "bold")).pack(anchor="center", padx=10, pady=(8, 2))
        p._comment_text_widget = tk.Text(frame, width=90, height=3, wrap="word", bg=p.card_bg, fg=p.fg, insertbackground=p.fg, relief="flat")
        p._comment_text_widget.pack(fill="x", padx=10, pady=(0, 6))
        info_text = f"Comment fee: {self.comment_base_tsar_str()} TSAR"
        p._comment_status_var.set(info_text if wallets else "Add wallet to comment.")
        tk.Label(frame, textvariable=p._comment_status_var, bg=p.card_bg, fg=p.muted, font=("Consolas", 9)).pack(anchor="center", padx=10)

        btn_row = tk.Frame(frame, bg=p.card_bg)
        btn_row.pack(fill="x", padx=10, pady=(4, 10))
        p._comment_btn = tk.Button(
            btn_row,
            text="Comment",
            bg=p.accent,
            fg=p.bg,
            bd=0,
            relief=tk.FLAT,
            cursor="hand2",
            command=lambda: self.on_comment_submit(post, art_id),
            state=("normal" if wallets else "disabled"),
        )
        p._comment_btn.pack(side="left")
        if not wallets:
            tk.Label(frame, text="The wallet is not yet available. Open the Wallet tab to load the address.", bg=p.card_bg, fg=p.muted, font=("Consolas", 9)).pack(anchor="center", padx=10, pady=(0, 4))

        p._bind_mousewheel_forward(frame)

    def on_comment_submit(self, post: Dict, art_id: str) -> None:
        p = self.panel
        if not p._comment_text_widget:
            return
        comment_txt = p._comment_text_widget.get("1.0", "end").strip()
        if not comment_txt:
            p._comment_status_var.set("Please Input your voice first.")
            return
        log.debug("explorer: comment submit art_id=%s len=%s", art_id, len(comment_txt))
        try:
            wallets = list(p.app.wallets or [])
        except AttributeError:
            wallets = []
        if not wallets:
            p._comment_status_var.set("No wallet Address")
            messagebox.showinfo("Explorer", "Create or load a wallet first.")
            return
        self.open_comment_dialog(post, art_id, comment_txt, wallets)

    def open_comment_dialog(self, post: Dict, art_id: str, comment_txt: str, wallets: list[str]) -> None:
        p = self.panel
        log.debug("explorer: open comment dialog art_id=%s", art_id)
        dlg = tk.Toplevel(p)
        dlg.title("Comment Graffiti")
        dlg.configure(bg=p.bg)
        dlg.grab_set()
        wallet_var = tk.StringVar(value=wallets[0] if wallets else "")
        tip_var = tk.StringVar(value="0")

        tk.Label(dlg, text="Select commentator wallet", bg=p.bg, fg=p.fg).pack(anchor="w", padx=10, pady=(10, 4))
        combo = ttk.Combobox(dlg, values=wallets, textvariable=wallet_var, state="readonly", width=46)
        combo.pack(fill="x", padx=10)
        tk.Label(dlg, text="Give a tip to the creator (Optional)", bg=p.bg, fg=p.muted, font=("Consolas", 9)).pack(anchor="w", padx=10, pady=(8, 2))
        tip_entry = tk.Entry(dlg, textvariable=tip_var, bg=p.card_bg, fg=p.fg, insertbackground=p.fg)
        tip_entry.pack(fill="x", padx=10)

        btns = tk.Frame(dlg, bg=p.bg)
        btns.pack(fill="x", padx=10, pady=(10, 12))
        tk.Button(btns, text="Cancel", command=lambda: dlg.destroy(), bg=p.card_bg, fg=p.fg, bd=0, relief=tk.FLAT).pack(side="left")
        tk.Button(btns, text="Sign", command=lambda: (dlg.destroy(), self.broadcast_comment(post, art_id, wallet_var.get(), tip_var.get(), comment_txt)), bg=p.accent, fg=p.bg, bd=0, relief=tk.FLAT).pack(side="right")

    def broadcast_comment(self, post: Dict, art_id: str, commenter: str, tip_raw: str, comment_txt: str) -> None:
        p = self.panel
        try:
            svc = p.app.send_svc
        except AttributeError:
            svc = None
        try:
            rpc_send = p.app.rpc_send
        except AttributeError:
            rpc_send = None
        if not rpc_send:
            try:
                rpc_send = p.app.rpc.send_async
            except AttributeError:
                rpc_send = None
        if not svc or not rpc_send:
            messagebox.showerror("Explorer", "Send service not available.")
            return

        try:
            fee_rate_var = p.app.send_tab.fee_rate_var
        except AttributeError:
            fee_rate_var = None
        try:
            fee_rate_val = int(fee_rate_var.get()) if fee_rate_var else int(CFG.MIN_FEE_RATE_SATVB)
        except Exception:
            fee_rate_val = int(CFG.MIN_FEE_RATE_SATVB)
        try:
            ask_pwd = p.app._ask_password
        except AttributeError:
            ask_pwd = None
        pw_provider = (lambda addr: ask_pwd("Unlock Address", f"Input Password for {addr}:")) if ask_pwd else (lambda _addr: None)

        base_raw = self.comment_base_tsar_str()
        try:
            plan = build_comment_plan(
                art=post,
                commenter_addr=commenter,
                base_amount_raw=base_raw,
                tip_amount_raw=(tip_raw or "0"),
                comment_text=comment_txt,
            )
        except ValueError as exc:
            p._comment_status_var.set(str(exc))
            messagebox.showwarning("Explorer", str(exc))
            return
        except Exception as exc:
            log.debug("explorer: build_comment_plan failed", exc_info=True)
            messagebox.showerror("Explorer", f"Invalid comment : {exc}")
            return

        p._comment_status_var.set("Broadcasting COMMENT transaction...")
        if p._comment_btn:
            p._comment_btn.config(state="disabled")
        log.debug("explorer: broadcasting comment art=%s commenter=%s tip=%s", art_id, commenter, tip_raw)

        def on_progress(msg: str) -> None:
            p._comment_status_var.set(msg)

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            def finish():
                if resp.get("status") in (None, "ok"):
                    txid = resp.get("txid") or (resp.get("data") or {}).get("txid") or "?"
                    p._comment_status_var.set(f"COMMENT broadcasted (txid: {txid})")
                    if p._comment_text_widget:
                        p._comment_text_widget.delete("1.0", "end")
                else:
                    p._comment_status_var.set(f"COMMENT failed: {resp}")

                if p._comment_btn:
                    p._comment_btn.config(state="normal")
            p._ui(finish)

        try:
            svc.create_sign_broadcast(
                from_addr=commenter,
                to_addr="",
                amount_sats=0,
                password_provider=pw_provider,
                rpc_send=rpc_send,
                fee_rate=fee_rate_val,
                on_progress=on_progress,
                on_done=on_done,
                opret_hex=plan["opret_hex"],
                extra_outputs=plan["outputs"],
            )
        except Exception as exc:
            log.debug("explorer: broadcast comment failed", exc_info=True)
            messagebox.showerror("Explorer", f"COMMENT Broadcast failed: {exc}")
            if p._comment_btn:
                p._comment_btn.config(state="normal")
                
    def _show_explorer_pdf_page(self, page_num: int, container: tk.Frame, page_var: tk.StringVar) -> None:
        if not self._pdf_doc:
            return
        
        try:
            self._pdf_current_page = page_num
            
            # Hapus display frame sebelumnya
            for child in (container.winfo_children()):
                if child.winfo_class() != "Frame" or child == self._pdf_display_frame:
                    continue
                child.destroy()
            
            # Dapatkan halaman
            page = self._pdf_doc[page_num]
            
            # Render halaman ke gambar
            mat = fitz.Matrix(1.5, 1.5)  # Scale factor untuk kualitas yang lebih baik
            pix = page.get_pixmap(matrix=mat)
            
            # Konversi ke PIL Image
            img_data = pix.tobytes("ppm")
            from io import BytesIO
            img = Image.open(BytesIO(img_data))
            
            # Resize untuk preview
            img.thumbnail((854, 480))
            
            # Tampilkan gambar
            photo = ImageTk.PhotoImage(img)
            self.panel._img_refs.append(photo)  # Simpan reference
            
            # Hapus konten sebelumnya di display frame
            for child in self._pdf_display_frame.winfo_children():
                child.destroy()
            
            # Tambahkan gambar ke display frame
            label = tk.Label(self._pdf_display_frame, image=photo, bg=self.panel.card_bg)
            label.pack()
            
            # Update info halaman
            page_var.set(f"Pages {page_num + 1}/{self._pdf_total_pages}")
            
        except Exception as e:
            log.exception("Unhandled exception")
            error_label = tk.Label(
                container,
                text=f"Failed to display PDF page: {str(e)}",
                bg=self.panel.card_bg,
                fg=self.panel.muted,
                font=("Consolas", 10)
            )
            error_label.pack()
