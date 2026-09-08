# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import time
import pymupdf as fitz
import threading
import tkinter as tk

from PIL import Image, ImageTk
from decimal import Decimal, ROUND_DOWN
from typing import Any, Dict, Optional
from tkinter import ttk, filedialog, messagebox, StringVar

from tsarchain.contracts.graffiti import calc_comment_split, calc_upload_fee_sats
from ..services.media import TkVLCPlayer
from tsarchain.utils import config as CFG
from ..theme import GraffitiTheme, lighten
from ..services.graffiti_service import (
    build_comment_plan,
    build_post_plan,
    build_upload_context,
    filter_online_storers,
    parse_amount_str,
    read_graffiti_file_info,
    select_upload_storers,
    upload_graffiti,
)

from tsarchain.utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.wallet.tab_ui.graffiti_tab")


# Constants for UI styling & messages
STYLE_FRAME = "Tsar.TFrame"
STYLE_LABELFRAME = "Tsar.TLabelframe"
STYLE_CARD_MONO_LABEL = "Tsar.Card.Mono.TLabel"
STYLE_BUTTON = "Tsar.TButton"
STYLE_SEC_BUTTON = "Tsar.Secondary.TButton"
STYLE_H_PROGRESS = "Horizontal.Tsar.TProgressbar"
TEXT_RECEIPT_NONE = "receipt: -"
MSG_UNHANDLED_EXC = "Unhandled exception"


class GraffitiController:
    def __init__(self, app):
        self.app = app
        self.reset_state()

    def reset_state(self):
        self.selected_path: str | None = None
        self.selected_sha: str | None = None
        self.selected_size: int | None = None
        self.selected_mime: str | None = None
        self.selected_merkle_root: str | None = None
        self.selected_merkle_chunk: int | None = None
        self.selected_merkle_count: int | None = None
        self.receipt_id: str | None = None
        self.opret_hex: str | None = None
        self.uploading = False
        self.assigned_storers: list[Dict[str, Any]] = []
        self._upload_candidates: list[Dict[str, Any]] = []
        self._active_storer: Optional[Dict[str, Any]] = None
        self._upload_ctx: dict[str, Any] = {}
        self._post_plan: Optional[Dict[str, Any]] = None

    def fetch_storers_sync(self) -> list[Dict[str, Any]]:
        try:
            rpc = self.app.rpc
            rpc_send = rpc.send
        except AttributeError:
            rpc_send = None
        if not callable(rpc_send):
            return []
        resp = rpc_send({"type": "STOR_LIST"}) or {}
        return select_upload_storers(resp, replication_r=CFG.GRAFFITI_REPLICATION_R)

    def process_file(self, path: str):
        info = read_graffiti_file_info(path)
        self.selected_path = path
        self.selected_size = info.get("size")
        self.selected_mime = info.get("mime")
        self.selected_sha = info.get("sha")
        self.selected_merkle_root = info.get("merkle_root")
        self.selected_merkle_chunk = info.get("merkle_chunk")
        self.selected_merkle_count = info.get("merkle_count")
        self.receipt_id = None
        self.opret_hex = None
        return info

    def calc_fee_tsar(self) -> float:
        if not self.selected_size:
            return 0.0
        fee_sats = calc_upload_fee_sats(int(self.selected_size))
        return float(fee_sats / CFG.TSAR)

    def prepare_upload(self, creator_addr: str) -> bool:
        storers = self.fetch_storers_sync()
        online = filter_online_storers(storers)
        if not online:
            raise ValueError("Storage node unavailable. Please try again when a storage node is online.")
        
        self.assigned_storers = online
        upload_ctx = build_upload_context(self.selected_sha, creator_addr)
        
        self._upload_candidates = list(online)
        self._upload_ctx = {
            "gid": upload_ctx.get("graffiti_id"),
            "receipt_id": upload_ctx.get("receipt_id"),
            "art_id": upload_ctx.get("art_id"),
            "creator": creator_addr
        }
        self.uploading = True
        self._post_plan = None
        self.opret_hex = None
        self.receipt_id = None
        return True

    def perform_upload_step(self, progress_cb, done_cb):
        if not self._upload_candidates:
            done_cb({"error": "no storage node available"})
            return
            
        storer = self._upload_candidates.pop(0)
        self._active_storer = storer
        
        def work():
            res = upload_graffiti(
                storer_meta=storer,
                file_path=self.selected_path,
                creator_addr=self._upload_ctx.get("creator"),
                graffiti_id=self._upload_ctx.get("gid"),
                sha256_hex=self.selected_sha,
                art_id=self._upload_ctx.get("art_id"),
                receipt_id=self._upload_ctx.get("receipt_id"),
                merkle_root=self.selected_merkle_root,
                merkle_chunk=self.selected_merkle_chunk,
                merkle_count=self.selected_merkle_count,
                progress_cb=progress_cb,
            )
            done_cb(res)
            
        threading.Thread(target=work, daemon=True).start()

    def process_upload_result(self, res: dict):
        self.uploading = False
        try:
            if res.get("status") != "ok":
                return False, res
        except AttributeError:
            return False, res

        receipt = res.get("receipt") or {}
        fallback_sha = (self.selected_sha or "")[:12]
        rcpt_id = receipt.get("id") or receipt.get("receipt_id") or f"rcpt-{fallback_sha or int(time.time())}"
        self.receipt_id = rcpt_id
        return True, res

    def prepare_post_plan(self, storer_meta: dict, creator_addr: str) -> dict:
        if not (self.selected_sha and self.selected_size is not None and self.selected_mime and self.receipt_id):
            raise RuntimeError("upload metadata incomplete")
            
        plan = build_post_plan(
            sha256_hex=self.selected_sha,
            size_bytes=int(self.selected_size),
            mime=self.selected_mime,
            creator_addr=creator_addr,
            storer_meta=storer_meta,
            receipt_id=self.receipt_id,
            merkle_root=self.selected_merkle_root,
            merkle_chunk=self.selected_merkle_chunk,
            merkle_count=self.selected_merkle_count,
        )
        self.opret_hex = plan["opret_hex"]
        self._post_plan = plan
        return plan

    def get_post_plan(self):
        return self._post_plan
        
    def broadcast_post(self, creator_addr, fee_rate, ask_pwd, on_progress, on_done):
        plan = self._post_plan
        if not plan:
            raise ValueError("No post plan available")
        
        try:
            svc = self.app.send_svc
        except AttributeError:
            svc = None
        try:
            rpc_send = self.app.rpc_send
        except AttributeError:
            rpc_send = None
        if not rpc_send:
            try:
                rpc_send = self.app.rpc.send_async
            except AttributeError:
                rpc_send = None
        if not svc or not rpc_send:
            raise ValueError("Send service is not available")
        
        if ask_pwd:
            pw_provider = lambda addr: ask_pwd("Unlock Address", f"Enter password for {addr}:")
        else:
            pw_provider = lambda _addr: None
            
        svc.create_sign_broadcast(
            from_addr=creator_addr,
            to_addr=plan["pool_addr"],
            amount_sats=plan["fee_sats"],
            password_provider=pw_provider,
            rpc_send=rpc_send,
            fee_rate=fee_rate,
            on_progress=on_progress,
            on_done=on_done,
            opret_hex=plan["opret_hex"],
        )

    def broadcast_comment(self, art, commenter, base_raw, tip_raw, text, fee_rate, ask_pwd, on_progress, on_done):
        plan = build_comment_plan(
            art=art,
            commenter_addr=commenter,
            base_amount_raw=base_raw,
            tip_amount_raw=tip_raw,
            comment_text=text,
        )
        
        try:
            svc = self.app.send_svc
        except AttributeError:
            svc = None
        try:
            rpc_send = self.app.rpc_send
        except AttributeError:
            rpc_send = None
        if not rpc_send:
            try:
                rpc_send = self.app.rpc.send_async
            except AttributeError:
                rpc_send = None
        if not svc or not rpc_send:
            raise ValueError("Send service tidak tersedia.")
            
        if ask_pwd:
            pw_provider = lambda addr: ask_pwd("Unlock Address", f"Masukkan password untuk {addr}:")
        else:
            pw_provider = lambda _addr: None
            
        svc.create_sign_broadcast(
            from_addr=commenter,
            to_addr="",
            amount_sats=0,
            password_provider=pw_provider,
            rpc_send=rpc_send,
            fee_rate=fee_rate,
            on_progress=on_progress,
            on_done=on_done,
            opret_hex=plan["opret_hex"],
            extra_outputs=plan["outputs"],
        )

    @staticmethod
    def decode_comment_hex(comment_hex: Optional[str]) -> str:
        raw = bytes.fromhex(comment_hex or "")
        text = raw.decode("utf-8", errors="replace")
        return text[:80] + ("..." if len(text) > 80 else "")

    @staticmethod
    def format_ts(ts_value: Any) -> str:
        ts = int(ts_value)
        if ts <= 0: return "-"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

    @staticmethod
    def format_tsar(sats: Any) -> str:
        dec = Decimal(int(sats)) / Decimal(CFG.TSAR)
        quant = Decimal("1").scaleb(-CFG.MAX_DECIMALS)
        val = dec.quantize(quant, rounding=ROUND_DOWN)
        txt = format(val, "f").rstrip("0").rstrip(".")
        return txt or "0"


# ========= Graffiti Tab (UI) =========
class GraffitiTab(ttk.Frame):
    PREVIEW_MAX_W = 854
    PREVIEW_MAX_H = 480

    def __init__(self, app, theme: GraffitiTheme, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = app
        self.theme = theme
        self.controller = GraffitiController(self.app)
        self.storer_info: StringVar | None = None
        self.creator_var = StringVar()
        self.creator_cb: ttk.Combobox | None = None
        self.cost_info_var = StringVar(value="Pilih file untuk menampilkan biaya & detail.")
        self.preview_status_var = StringVar(value="Belum ada preview.")
        self.preview_frame: tk.Frame | None = None
        self._preview_img_ref = None
        self._video_player: TkVLCPlayer | None = None
        self._catalog_map_local: dict[str, Dict[str, Any]] = {}
        
        self._current_pdf_doc = None
        self._pdf_current_page = 0
        self._pdf_total_pages = 0
        self._pdf_page_var: StringVar | None = None
        self._pdf_nav_frame: tk.Frame | None = None

        self.post_send_btn: ttk.Button | None = None
        self.catalog_posts: list[Dict[str, Any]] = []
        self._catalog_map: dict[str, Dict[str, Any]] = {}
        self._selected_art: Optional[Dict[str, Any]] = None
        self.catalog_tree: ttk.Treeview | None = None
        
        self.comment_tree: ttk.Treeview | None = None
        self.comment_text: tk.Text | None = None
        self.comment_wallet_var = StringVar()
        self.comment_wallet_cb: ttk.Combobox | None = None
        self.comment_amount_var = StringVar()
        self.comment_tip_var = StringVar(value="0")
        self.comment_status_var = StringVar(value="Select artwork to comment.")
        
        self.catalog_status_var = StringVar(value="Catalog belum dimuat.")
        self.art_info_var = StringVar(value="Pilih karya untuk melihat detail.")
        self.comment_split_var = StringVar(value="")
        self.comment_send_btn: ttk.Button | None = None
        self.payout_tree: ttk.Treeview | None = None
        self.payout_status_var = StringVar(value="Payout history pending.")
        self._upload_start_time: float = 0.0

        self._build_style()
        self.configure()
        self._build_ui()
        self._refresh_creator_wallets()

    def _build_style(self):
        t = self.theme
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(STYLE_FRAME, background=t.bg)
        style.configure("Tsar.Card.TFrame", background=t.card_bg)
        style.configure(STYLE_LABELFRAME, background=t.card_bg, foreground=t.fg)
        style.configure("Tsar.TLabelframe.Label", background=t.card_bg, foreground=t.fg, font=("Consolas", 11, "bold"))
        style.configure("Tsar.Header.TLabel", background=t.bg, foreground=t.accent, font=("Consolas", 14, "bold"))
        style.configure("Tsar.Card.TLabel", background=t.card_bg, foreground=t.fg)
        style.configure("Tsar.Mono.TLabel", background=t.bg, foreground=t.muted, font=("Consolas", 10))
        style.configure(STYLE_CARD_MONO_LABEL, background=t.card_bg, foreground=t.muted, font=("Consolas", 10))
        style.configure(STYLE_BUTTON, padding=8, background=t.accent, foreground="#ffffff")
        style.map(
            STYLE_BUTTON,
            background=[("active", lighten(t.accent, 0.12)), ("disabled", t.border)],
            foreground=[("disabled", t.muted)],
        )
        style.configure(STYLE_SEC_BUTTON, padding=8, background=t.card_bg, foreground=t.fg)
        style.map(STYLE_SEC_BUTTON, background=[("active", lighten(t.card_bg, 0.08))])
        style.configure("Tsar.TEntry", fieldbackground=t.card_bg, foreground=t.fg, background=t.card_bg)
        style.configure("Tsar.TCombobox", fieldbackground=t.card_bg, foreground=t.fg, background=t.card_bg)
        # Progressbar styles require explicit horizontal/vertical layouts.
        h_layout = style.layout("Horizontal.TProgressbar")
        v_layout = style.layout("Vertical.TProgressbar")
        style.layout(STYLE_H_PROGRESS, h_layout)
        style.layout("Vertical.Tsar.TProgressbar", v_layout)
        style.configure(STYLE_H_PROGRESS, troughcolor=t.card_bg, background=t.accent)
        style.configure("Vertical.Tsar.TProgressbar", troughcolor=t.card_bg, background=t.accent)
        self._style = style

    # ---- layout utama ----
    def _build_ui(self):
        outer = ttk.Frame(self, style=STYLE_FRAME)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=self.theme.bg, highlightthickness=0, bd=0)
        vscroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill="both", expand=True)

        root = ttk.Frame(canvas, padding=12, style=STYLE_FRAME)
        root_id = canvas.create_window((0, 0), window=root, anchor="nw")

        def _sync_scrollregion(_event=None):
            if not canvas.winfo_exists():
                return
            canvas.configure(scrollregion=canvas.bbox("all") or (0, 0, 0, 0))
            canvas.itemconfigure(root_id, width=canvas.winfo_width())

        root.bind("<Configure>", _sync_scrollregion)
        canvas.bind("<Configure>", _sync_scrollregion)

        header_row = ttk.Frame(root, style=STYLE_FRAME)
        header_row.pack(fill="x")
        ttk.Label(header_row, text="Graffiti Uploader", style="Tsar.Header.TLabel").pack(side=tk.LEFT, anchor="w")
        ttk.Button(header_row, text="View Catalog", style=STYLE_SEC_BUTTON, command=self._open_creator_catalog)\
            .pack(side=tk.RIGHT, padx=4)
        ttk.Label(root, text="Alur: pilih wallet -> pilih & preview file -> upload & sign.", style=STYLE_CARD_MONO_LABEL)\
            .pack(anchor="w", pady=(2, 8))

        # 1) Creator wallet
        creator_fr = ttk.LabelFrame(root, text="1) Wallet Creator", style=STYLE_LABELFRAME)
        creator_fr.pack(fill="x", pady=(4, 6))
        ttk.Label(creator_fr, text="Gunakan alamat ini untuk membayar POST fee:", style=STYLE_CARD_MONO_LABEL)\
            .grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        self.creator_cb = ttk.Combobox(
            creator_fr,
            textvariable=self.creator_var,
            state="readonly",
            width=50,
            style="Tsar.TCombobox",
        )
        self.creator_cb.grid(row=0, column=1, padx=6, pady=(8, 2), sticky="w")
        ttk.Button(creator_fr, text="Refresh wallets", style=STYLE_SEC_BUTTON, command=self._refresh_creator_wallets)\
            .grid(row=0, column=2, padx=6, pady=(8, 2), sticky="e")

        # 2) File + Preview
        file_fr = ttk.LabelFrame(root, text="2) Media & Preview", style=STYLE_LABELFRAME)
        file_fr.pack(fill="both", expand=True, pady=(6, 6))
        file_fr.columnconfigure(0, weight=1)
        file_fr.columnconfigure(1, weight=0)

        self.file_var = StringVar(value="(belum ada file)")
        ttk.Label(file_fr, textvariable=self.file_var, style=STYLE_CARD_MONO_LABEL).grid(row=0, column=0, padx=8, pady=(8, 2), sticky="w")
        ttk.Button(file_fr, text="Pilih File...", style=STYLE_BUTTON, command=self.pick_file)\
            .grid(row=0, column=1, padx=8, pady=(8, 2), sticky="e")

        self.meta_var = StringVar(value="size: -, mime: -, sha256: -")
        ttk.Label(file_fr, textvariable=self.meta_var, style=STYLE_CARD_MONO_LABEL)\
            .grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 4), sticky="w")
        ttk.Label(file_fr, textvariable=self.cost_info_var, style=STYLE_CARD_MONO_LABEL)\
            .grid(row=2, column=0, columnspan=2, padx=8, pady=(0, 6), sticky="w")

        preview_shell = ttk.Frame(file_fr, style="Tsar.Card.TFrame")
        preview_shell.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=8, pady=(2, 8))
        preview_shell.rowconfigure(0, weight=1)
        preview_shell.columnconfigure(0, weight=1)
        self.preview_frame = tk.Frame(preview_shell, background=self.theme.card_bg, height=260)
        self.preview_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.preview_frame, textvariable=self.preview_status_var, style=STYLE_CARD_MONO_LABEL)\
            .pack(anchor="center", pady=8)

        # 3) Upload & Broadcast
        post_fr = ttk.LabelFrame(root, text="3) Upload & Broadcast POST", style=STYLE_LABELFRAME)
        post_fr.pack(fill="x", pady=(2, 4))
        self.post_info_var = StringVar(value="Pilih file, lalu upload. Password akan diminta saat sign.")
        ttk.Label(post_fr, textvariable=self.post_info_var, style=STYLE_CARD_MONO_LABEL)\
            .grid(row=0, column=0, columnspan=3, padx=8, pady=(8, 4), sticky="w")
        self.post_send_btn = ttk.Button(
            post_fr,
            text="Upload & Broadcast POST",
            style=STYLE_BUTTON,
            state="disabled",
            command=self._start_upload_and_broadcast,
        )
        self.post_send_btn.grid(row=1, column=0, padx=8, pady=(4, 8), sticky="w")
        ttk.Label(post_fr, text="Send tab akan di-prefill untuk review manual bila perlu.", style=STYLE_CARD_MONO_LABEL)\
            .grid(row=1, column=1, padx=8, pady=(4, 8), sticky="e")
        self.pbar = ttk.Progressbar(
            post_fr,
            mode="determinate",
            length=320,
            style=STYLE_H_PROGRESS,
            maximum=100,
            value=0,
        )
        self.pbar.grid(row=2, column=0, columnspan=3, padx=8, pady=(0, 6), sticky="we")
        self.receipt_var = StringVar(value=TEXT_RECEIPT_NONE)
        ttk.Label(post_fr, textvariable=self.receipt_var, style=STYLE_CARD_MONO_LABEL)\
            .grid(row=3, column=0, columnspan=3, padx=8, pady=(0, 8), sticky="w")

    # ---- actions ----
    def refresh_storers(self):
        try:
            rpc = self.app.rpc
        except AttributeError:
            rpc = None
        if not rpc:
            return

        def handle(resp: Optional[Dict[str, Any]]):
            self.assigned_storers = select_upload_storers(resp, replication_r=CFG.GRAFFITI_REPLICATION_R)
        rpc.send_async({"type": "STOR_LIST"}, handle)

    def _fetch_storers_sync(self) -> list[Dict[str, Any]]:
        return self.controller.fetch_storers_sync()

    def _refresh_creator_wallets(self):
        if not self.creator_cb:
            return
        try:
            wallets = list(self.app.wallets or [])
        except AttributeError:
            wallets = []
        self.creator_cb["values"] = wallets
        if wallets:
            current = self.creator_var.get()
            if current and current in wallets:
                self.creator_cb.set(current)
            else:
                self.creator_cb.current(0)
                self.creator_var.set(wallets[0])
        else:
            self.creator_cb.set("")
            self.creator_var.set("")
        if self.comment_wallet_cb:
            self.comment_wallet_cb["values"] = wallets
            if wallets:
                current = self.comment_wallet_var.get()
                if current and current in wallets:
                    self.comment_wallet_cb.set(current)
                else:
                    self.comment_wallet_cb.current(0)
                    self.comment_wallet_var.set(wallets[0])
            else:
                self.comment_wallet_cb.set("")
                self.comment_wallet_var.set("")

    def _clear_preview(self) -> None:
        """Bersihkan preview media (image/video/PDF)."""
        if self._video_player:
            try:
                self._video_player.dispose()
            except Exception:
                log.exception("graffiti_tab: dispose video player failed")
            self._video_player = None
        
        # Tutup PDF dokumen jika ada
        if self._current_pdf_doc:
            try:
                self._current_pdf_doc.close()
            except Exception:
                pass
            self._current_pdf_doc = None
            self._pdf_current_page = 0
            self._pdf_total_pages = 0
        
        self._preview_img_ref = None
        
        # Hapus PDF navigation frame jika ada
        if self._pdf_nav_frame and self._pdf_nav_frame.winfo_exists():
            self._pdf_nav_frame.destroy()
            self._pdf_nav_frame = None
        
        if self.preview_frame and self.preview_frame.winfo_exists():
            for child in (self.preview_frame.winfo_children()):
                child.destroy()
        
        if self.preview_status_var:
            self.preview_status_var.set("Belum ada preview.")

    def _render_preview(self) -> None:
        """Render preview for selected file (image/mp4/pdf)."""
        if not self.preview_frame or not self.controller.selected_path or not self.controller.selected_mime:
            return
        self._clear_preview()
        path = self.controller.selected_path
        mime = (self.controller.selected_mime or "").lower()
        # Video (mp4 & mkv)
        if "video" in mime or path.lower().endswith(".mp4"):
            container = tk.Frame(self.preview_frame, bg=self.theme.card_bg)
            container.pack(pady=6)
            player = TkVLCPlayer(
                container,
                width=self.PREVIEW_MAX_W,
                height=self.PREVIEW_MAX_H,
                max_width=self.PREVIEW_MAX_W,
                max_height=self.PREVIEW_MAX_H,
                bg=self.theme.card_bg,
                fg=self.theme.fg,
                accent=self.theme.accent,
                on_error=lambda msg: self.preview_status_var.set(msg),
            )
            player.frame.pack()
            try:
                player.load(path, autoplay=True)
            except Exception:
                tk.Label(
                    container,
                    text="Video preview failed to load.",
                    bg=self.theme.card_bg,
                    fg=self.theme.muted,
                    font=("Consolas", 10),
                ).pack(anchor="center", pady=8)
            self._video_player = player
            return

        # PDF document
        elif mime == "application/pdf" or path.lower().endswith(".pdf"):
            try:
                self._current_pdf_doc = fitz.open(path)
                self._pdf_total_pages = len(self._current_pdf_doc)
                self._pdf_current_page = 0
                
                # Buat frame untuk navigasi halaman
                self._pdf_nav_frame = tk.Frame(self.preview_frame, bg=self.theme.card_bg)
                self._pdf_nav_frame.pack(fill="x", pady=(5, 0))
                
                # Label untuk info halaman
                self._pdf_page_var = StringVar()
                page_label = tk.Label(
                    self._pdf_nav_frame,
                    textvariable=self._pdf_page_var,
                    bg=self.theme.card_bg,
                    fg=self.theme.fg,
                    font=("Consolas", 9)
                )
                page_label.pack(side=tk.LEFT, padx=(10, 5))
                
                # Tombol navigasi
                btn_style = {"bg": self.theme.accent, "fg": "#ffffff", "bd": 0, "relief": tk.FLAT}
                
                btn_first = tk.Button(
                    self._pdf_nav_frame,
                    text="⏮",
                    command=lambda: self._show_pdf_page(0),
                    **btn_style
                )
                btn_first.pack(side=tk.LEFT, padx=2)
                
                btn_prev = tk.Button(
                    self._pdf_nav_frame,
                    text="◀",
                    command=lambda: self._show_pdf_page(max(0, self._pdf_current_page - 1)),
                    **btn_style
                )
                btn_prev.pack(side=tk.LEFT, padx=2)
                
                btn_next = tk.Button(
                    self._pdf_nav_frame,
                    text="▶",
                    command=lambda: self._show_pdf_page(min(self._pdf_total_pages - 1, self._pdf_current_page + 1)),
                    **btn_style
                )
                btn_next.pack(side=tk.LEFT, padx=2)
                
                btn_last = tk.Button(
                    self._pdf_nav_frame,
                    text="⏭",
                    command=lambda: self._show_pdf_page(self._pdf_total_pages - 1),
                    **btn_style
                )
                btn_last.pack(side=tk.LEFT, padx=2)
                
                # Tampilkan halaman pertama
                self._show_pdf_page(0)
                
            except Exception as e:
                log.exception(MSG_UNHANDLED_EXC)
                tk.Label(
                    self.preview_frame,
                    text=f"PDF preview gagal: {str(e)}",
                    bg=self.theme.card_bg,
                    fg=self.theme.muted,
                    font=("Consolas", 10),
                ).pack(anchor="center", pady=8)
            return

        # Image (jpeg atau jpg)
        try:
            img = Image.open(path)
            img.thumbnail((self.PREVIEW_MAX_W, self.PREVIEW_MAX_H))
            photo = ImageTk.PhotoImage(img)
            self._preview_img_ref = photo
            tk.Label(self.preview_frame, image=photo, bg=self.theme.card_bg).pack(pady=6)
            self.preview_status_var.set("Preview gambar.")
        except Exception:
            log.exception("graffiti_tab: load image preview failed")
            tk.Label(
                self.preview_frame,
                text="Preview gambar gagal dimuat.",
                bg=self.theme.card_bg,
                fg=self.theme.muted,
                font=("Consolas", 10),
            ).pack(anchor="center", pady=8)
            
    def _show_pdf_page(self, page_num: int) -> None:
        """Tampilkan halaman spesifik dari PDF."""
        if not self._current_pdf_doc or not self.preview_frame:
            return
        
        try:
            # Hapus konten sebelumnya
            for child in (self.preview_frame.winfo_children()):
                if child != self._pdf_nav_frame:
                    child.destroy()
            
            self._pdf_current_page = page_num
            
            # Dapatkan halaman
            page = self._current_pdf_doc[page_num]
            
            # Render halaman ke gambar
            mat = fitz.Matrix(1.5, 1.5)  # Scale factor untuk kualitas yang lebih baik
            pix = page.get_pixmap(matrix=mat)
            
            # Konversi ke PIL Image
            img_data = pix.tobytes("ppm")
            from io import BytesIO
            img = Image.open(BytesIO(img_data))
            
            # Resize untuk preview
            img.thumbnail((self.PREVIEW_MAX_W, self.PREVIEW_MAX_H))
            
            # Tampilkan gambar
            photo = ImageTk.PhotoImage(img)
            self._preview_img_ref = photo
            label = tk.Label(self.preview_frame, image=photo, bg=self.theme.card_bg)
            label.pack(pady=6)
            
            # Update info halaman
            if self._pdf_page_var:
                self._pdf_page_var.set(f"Pages {page_num + 1}/{self._pdf_total_pages}")
            
            self.preview_status_var.set(f"PDF preview (Pages {page_num + 1}/{self._pdf_total_pages})")
            
        except Exception as e:
            log.exception(MSG_UNHANDLED_EXC)
            tk.Label(
                self.preview_frame,
                text=f"Failed to Preview PDF Pages: {str(e)}",
                bg=self.theme.card_bg,
                fg=self.theme.muted,
                font=("Consolas", 10),
            ).pack(anchor="center", pady=8)

    def _update_cost_info(self) -> None:
        """Calculate upload cost info based on size."""
        if not self.cost_info_var:
            return
        if not self.controller.selected_size or not self.controller.selected_mime:
            self.cost_info_var.set("Select a file to display costs.")
            return
        fee_tsar = self.controller.calc_fee_tsar()
        self.cost_info_var.set(f"Est. fee: {fee_tsar:.8f} TSAR")

    def _open_creator_catalog(self) -> None:
        """Open the catalog of works for the current wallet creator."""
        creator = (self.creator_var.get() or "").strip().lower()
        try:
            rpc = self.app.rpc
            rpc_send_async = rpc.send_async
        except AttributeError:
            rpc_send_async = None
        if not creator:
            messagebox.showinfo("Graffiti", "Select the wallet creator first.")
            return
        if not callable(rpc_send_async):
            messagebox.showwarning("Graffiti", "Offline wallet or RPC is not available.")
            return

        top = tk.Toplevel(self)
        top.title(f"Catalog - {creator[:64]}")
        top.configure(bg=self.theme.bg)
        cols = ("art_id", "height", "size", "comments")
        tv = ttk.Treeview(top, columns=cols, show="headings", height=12)
        for c, w in [("art_id", 420), ("height", 70), ("size", 120), ("comments", 90)]:
            tv.heading(c, text=c)
            tv.column(c, width=w, stretch=(c == "art_id"))
        tv.pack(fill="both", expand=True, padx=8, pady=8)
        status_var = StringVar(value="Load catalog...")
        ttk.Label(top, textvariable=status_var, style=STYLE_CARD_MONO_LABEL).pack(anchor="w", padx=8, pady=(0, 8))
        self._catalog_map_local = {}

        menu = tk.Menu(top, tearoff=0)
        def _show_menu(event):
            iid = tv.identify_row(event.y)
            if not iid:
                return
            tv.selection_set(iid)
            art_obj = self._catalog_map_local.get(iid, {})
            art_id_full = art_obj.get("art_id") or iid
            def _copy():
                top.clipboard_clear()
                top.clipboard_append(art_id_full)
                status_var.set("Art ID copied.")
                
            def _open():
                try:
                    app = self.app
                    if app:
                        app.switch_tab("explorer")
                        nav = app.explore_panel.navigate_to_art
                        if callable(nav):
                            nav(art_id_full)
                except Exception:
                    log.exception("graffiti_tab: open explorer failed")

            menu.delete(0, tk.END)
            menu.add_command(label="Copy art id", command=_copy)
            menu.add_command(label="Open in Explorer", command=_open)
            menu.tk_popup(event.x_root, event.y_root)
        tv.bind("<Button-3>", _show_menu)

        def handle(resp: Optional[Dict[str, Any]]):
            def apply():
                posts = (resp or {}).get("posts") or []
                filtered = [p for p in posts if (p.get("creator") or "").strip().lower() == creator]
                tv.delete(*tv.get_children())
                for post in filtered:
                    aid_full = str(post.get("art_id") or "")[:64]
                    height = int(post.get("block_height") or 0)
                    size = int(post.get("size") or post.get("size_bytes") or 0)
                    comments = int((post.get("stats") or {}).get("comments", 0))
                    tv.insert("", tk.END, iid=aid_full, values=(aid_full, height, f"{size:,} B", comments))
                    self._catalog_map_local[aid_full] = post
                status_var.set(f"{len(filtered)} karya ditemukan untuk {creator}.")
            self.after(0, apply)

        rpc.send_async({"type": "GRAFFITI_GET_POSTS", "limit": 200}, handle)

    def pick_file(self):
        path = filedialog.askopenfilename(title="Select file for Graffiti")
        if not path:
            return
        self.file_var.set(path)

        # compute
        try:
            self.controller.process_file(path)
        except Exception as e:
            log.exception(MSG_UNHANDLED_EXC)
            messagebox.showerror("Graffiti", f"Failed to read file: {e}")
            return

        self.meta_var.set(
            f"size: {self.controller.selected_size} bytes, file: {self.controller.selected_mime}, sha256: {str(self.controller.selected_sha)[:64]}"
        )
        if self.controller.selected_merkle_root:
            log.info(
                "graffiti_tab: merkle root=%s mchunk=%s mcount=%s",
                str(self.controller.selected_merkle_root)[:16],
                self.controller.selected_merkle_chunk,
                self.controller.selected_merkle_count,
            )
        log.debug(
            "graffiti_tab: file selected path=%s size=%s mime=%s sha=%s",
            path,
            self.controller.selected_size,
            self.controller.selected_mime,
            self.controller.selected_sha,
        )
        self._render_preview()
        self._update_cost_info()
        self.receipt_var.set(TEXT_RECEIPT_NONE)
        if self.post_info_var:
            self.post_info_var.set("The file is ready. Click Upload & Broadcast when ready.")
        if self.post_send_btn:
            self.post_send_btn.config(state="normal")

    def _start_upload_and_broadcast(self):
        if self.controller.uploading:
            return
        if not self.controller.selected_path or not self.controller.selected_sha or self.controller.selected_size is None or not self.controller.selected_mime:
            messagebox.showwarning("Graffiti", "Select a file first.")
            return
        creator_addr = (self.creator_var.get() or "").strip()
        if not creator_addr:
            messagebox.showwarning("Graffiti", "Select a creator wallet first.")
            return
        try:
            self.controller.prepare_upload(creator_addr)
        except Exception as exc:
            log.exception(MSG_UNHANDLED_EXC)
            messagebox.showerror("Graffiti", f"Failed to compute art_id: {exc}")
            return

        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")
        self.pbar["value"] = 0
        self.receipt_var.set(TEXT_RECEIPT_NONE)
        if self.post_info_var:
            self.post_info_var.set("Uploading blob to storage node...")
        self._begin_upload()

    def _begin_upload(self) -> None:
        self._upload_start_time = time.time()
        def progress(sent: int, total: int):
            self.after(0, lambda: self._update_progress(sent, total))
        def done(res: dict):
            self.after(0, lambda: self._handle_upload_result(res, trigger_broadcast=True))
        
        self.controller.perform_upload_step(progress_cb=progress, done_cb=done)

    @staticmethod
    def _format_speed(bytes_per_sec: float) -> str:
        if bytes_per_sec >= 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
        elif bytes_per_sec >= 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        return f"{bytes_per_sec:.0f} B/s"

    @staticmethod
    def _format_size(num_bytes: int) -> str:
        if num_bytes >= 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"
        elif num_bytes >= 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.2f} MB"
        elif num_bytes >= 1024:
            return f"{num_bytes / 1024:.1f} KB"
        return f"{num_bytes} B"

    def _update_progress(self, sent: int, total: int) -> None:
        total = max(total, 1)
        pct = min(100.0, (sent / total) * 100.0)
        self.pbar["value"] = pct
        start_t = self._upload_start_time or time.time()
        elapsed = max(0.05, time.time() - start_t)
        speed = sent / elapsed
        speed_str = self._format_speed(speed)
        sent_str = self._format_size(sent)
        total_str = self._format_size(total)
        self.receipt_var.set(f"Uploading: {sent_str} / {total_str} ({pct:.1f}%) • {speed_str}")

    def _handle_upload_result(self, res: Optional[Dict[str, Any]], *, trigger_broadcast: bool = True, txid: Optional[str] = None) -> None:
        ok, res = self.controller.process_upload_result(res or {})
        
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled" if trigger_broadcast else "normal")
            
        if not ok:
            self.pbar["value"] = 0
            detail = (res or {}).get("reason") or (res or {}).get("error") or (res or {}).get("stage") or "upload_failed"
            extra = (res or {}).get("resp") or {}
            try:
                reason = extra.get("reason")
                if reason:
                    detail = f"{detail} ({reason})"
            except AttributeError:
                pass
            messagebox.showerror("Graffiti", f"Upload failed: {detail}")
            self.receipt_var.set(TEXT_RECEIPT_NONE)
            if self.controller._upload_candidates:
                if self.post_info_var:
                    self.post_info_var.set("Retrying upload on another storage node...")
                self.controller.uploading = True
                self._begin_upload()
                return
            self._reset_upload_state("Upload failed. No storage node reachable.")
            return

        self.receipt_var.set(f"receipt: {self.controller.receipt_id}")
        self.pbar["value"] = 100
        try:
            if trigger_broadcast:
                self._prepare_post_tx(res)
                self._broadcast_post_tx(auto=True)
            else:
                if txid:
                    self.post_info_var.set(f"Upload complete (txid: {txid})")
                else:
                    self.post_info_var.set("Upload complete.")
        except Exception as exc:
            log.exception(MSG_UNHANDLED_EXC)
            messagebox.showerror("Graffiti", f"Prepare POST failed: {exc}")

    def _prepare_post_plan_preupload(self, storer_meta: Dict[str, Any], receipt_id: str, art_id: str) -> None:
        creator = (self.creator_var.get() or "").strip().lower()
        plan = self.controller.prepare_post_plan(storer_meta, creator)
        info = f"Pool: {plan['pool_addr']} | Fee: {plan['tsar_fee']:.8f} TSAR ({plan['fee_sats']} sats)."
        if self.post_info_var:
            self.post_info_var.set(info + " Ready to sign.")

    def _prepare_post_tx(self, upload_result: Dict[str, Any]) -> None:
        storer_meta = upload_result.get("storer") or {}
        creator = (self.creator_var.get() or "").strip().lower()
        plan = self.controller.prepare_post_plan(storer_meta, creator)
        info = f"Pool: {plan['pool_addr']} | Fee: {plan['tsar_fee']:.8f} TSAR ({plan['fee_sats']} sats)."
        if self.post_info_var:
            self.post_info_var.set(info + " Ready to broadcast.")

        try:
            self.app.send_tab.set_recipient(plan["pool_addr"])
            self.app.send_tab.set_amount(str(plan["fee_sats"]))
            self.app.send_tab.set_opret_hex(plan["opret_hex"])
        except Exception as exc:
            log.exception(MSG_UNHANDLED_EXC)
            raise RuntimeError(f"prefill send tab failed: {exc}") from exc

    def _broadcast_post_tx(self, auto: bool = False, after_success=None) -> None:
        plan = self.controller.get_post_plan()
        if not plan:
            if not auto:
                messagebox.showwarning("Graffiti", "Upload first before broadcast.")
            return
        creator = (self.creator_var.get() or "").strip().lower()
        if not creator:
            messagebox.showwarning("Graffiti", "Select the wallet creator first.")
            return
        self.post_info_var.set("Broadcasting POST transaction...")
        if self.post_send_btn:
            self.post_send_btn.config(state="disabled")

        try:
            send_tab = self.app.send_tab
        except AttributeError:
            send_tab = None
        if send_tab:
            send_tab.clear_opret_hex()

        def on_progress(msg: str) -> None:
            self.post_info_var.set(msg)

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            try:
                st = self.app.send_tab
            except AttributeError:
                st = None
            if st:
                st.clear_opret_hex()
            def _update():
                try:
                    if resp.get("status") in (None, "ok"):
                        txid = resp.get("txid") or (resp.get("data") or {}).get("txid") or "?"
                        self.post_info_var.set(f"POST broadcasted (txid: {txid})")
                        self._post_plan = None
                        if after_success:
                            after_success(txid)
                    else:
                        raise ValueError()
                except Exception:
                    self.post_info_var.set(f"POST failed: {resp}")
                    self.uploading = False
                    self._upload_candidates = []
                    if self.post_send_btn:
                        self.post_send_btn.config(state="normal")
            self.after(0, _update)

        try:
            try:
                fee_rate = int(self.app.send_tab.fee_rate_var.get())
            except (AttributeError, ValueError, TypeError):
                fee_rate = int(CFG.MIN_FEE_RATE_SATVB)
            try:
                ask_pwd = self.app._ask_password
            except AttributeError:
                ask_pwd = None
            
            self.controller.broadcast_post(
                creator_addr=creator,
                fee_rate=fee_rate,
                ask_pwd=ask_pwd,
                on_progress=on_progress,
                on_done=on_done
            )
        except Exception as exc:
            log.exception(MSG_UNHANDLED_EXC)
            try:
                st = self.app.send_tab
            except AttributeError:
                st = None
            if st:
                st.clear_opret_hex()
            messagebox.showerror("Graffiti", f"Broadcast failed: {exc}")
            if self.post_send_btn:
                self.post_send_btn.config(state="normal")

    def _refresh_current_comments(self) -> None:
        if self._selected_art:
            self._refresh_comments_for(self._selected_art.get("art_id"))

    def _refresh_comments_for(self, art_id: Optional[str]) -> None:
        if not art_id:
            return
        try:
            rpc = self.app.rpc
        except AttributeError:
            rpc = None
        if not rpc:
            return
        def handle(resp: Optional[Dict[str, Any]]):
            self.after(0, lambda: self._apply_comments(resp))
        rpc.send_async({"type": "GRAFFITI_GET_COMMENTS", "art_id": art_id, "limit": 100}, handle)

    def _apply_comments(self, resp: Optional[Dict[str, Any]]) -> None:
        if not self.comment_tree:
            return
        comments = (resp or {}).get("comments") or []
        self.comment_tree.delete(*self.comment_tree.get_children())
        for entry in comments:
            ts = self._format_ts(entry.get("ts"))
            commenter = (entry.get("commenter") or entry.get("creator") or "")[:20]
            amt_tsar = self._format_tsar(entry.get("amount", 0))
            excerpt = self._decode_comment_hex(entry.get("comment"))
            self.comment_tree.insert("", tk.END, values=(ts, commenter, f"{amt_tsar} TSAR", excerpt))
        if not comments:
            self.comment_status_var.set("Belum ada komentar untuk karya ini.")

    def _decode_comment_hex(self, comment_hex: Optional[str]) -> str:
        return GraffitiController.decode_comment_hex(comment_hex)

    def _format_ts(self, ts_value: Any) -> str:
        return GraffitiController.format_ts(ts_value)

    def _format_tsar(self, sats: Any) -> str:
        return GraffitiController.format_tsar(sats)

    def _update_comment_split_preview(self) -> None:
        base = parse_amount_str(self.comment_amount_var.get(), int(CFG.GRAFFITI_COMMENT_MIN_FEE))
        tip = parse_amount_str(self.comment_tip_var.get(), 0) if self.comment_tip_var.get().strip() else 0
        split = calc_comment_split(base, tip)
        creator = self._format_tsar(split["creator_total"])
        storage = self._format_tsar(split["storage"])
        miner = self._format_tsar(split["miner"])
        self.comment_split_var.set(f"Creator: {creator} TSAR | Storage pool: {storage} TSAR | Miner fee: {miner} TSAR")

    def _broadcast_comment_tx(self) -> None:
        commenter = (self.comment_wallet_var.get() or "").strip().lower()
        comment_txt = self.comment_text.get("1.0", tk.END).strip() if self.comment_text else ""
        
        self.comment_status_var.set("Broadcasting COMMENT transaction...")
        if self.comment_send_btn:
            self.comment_send_btn.config(state="disabled")

        def on_progress(msg: str) -> None:
            self.comment_status_var.set(msg)

        def on_done(resp: Optional[Dict[str, Any]]) -> None:
            def finish():
                try:
                    if resp.get("status") in (None, "ok"):
                        txid = resp.get("txid") or (resp.get("data") or {}).get("txid") or "?"
                        self.comment_status_var.set(f"COMMENT broadcasted (txid: {txid})")
                        if self.comment_text:
                            self.comment_text.delete("1.0", tk.END)
                        self._refresh_current_comments()
                    else:
                        self.comment_status_var.set(f"COMMENT failed: {resp}")
                except (AttributeError, TypeError):
                    self.comment_status_var.set(f"COMMENT failed: {resp}")
                if self.comment_send_btn:
                    self.comment_send_btn.config(state="normal")
            self.after(0, finish)

        try:
            try:
                fee_rate = int(self.app.send_tab.fee_rate_var.get())
            except (AttributeError, ValueError, TypeError):
                fee_rate = int(CFG.MIN_FEE_RATE_SATVB)
            try:
                ask_pwd = self.app._ask_password
            except AttributeError:
                ask_pwd = None
            
            self.controller.broadcast_comment(
                art=self._selected_art,
                commenter=commenter,
                base_raw=self.comment_amount_var.get(),
                tip_raw=self.comment_tip_var.get(),
                text=comment_txt,
                fee_rate=fee_rate,
                ask_pwd=ask_pwd,
                on_progress=on_progress,
                on_done=on_done
            )
        except Exception as exc:
            log.exception(MSG_UNHANDLED_EXC)
            messagebox.showerror("Graffiti", f"Broadcast COMMENT gagal: {exc}")
            if self.comment_send_btn:
                self.comment_send_btn.config(state="normal")

    def apply_theme(self, theme: GraffitiTheme) -> None:
        """Rebuild the tab using a new theme palette."""
        self.theme = theme
        self._build_style()
        
        # Tutup PDF doc sebelum rebuild
        if self._current_pdf_doc:
            try:
                self._current_pdf_doc.close()
            except Exception:
                pass
            self._current_pdf_doc = None
        
        for child in (self.winfo_children()):
            child.destroy()
        self._build_ui()
        self._refresh_creator_wallets()
        self.refresh_storers()
        self._clear_preview()
        log.debug("graffiti_tab: theme applied and UI rebuilt")
