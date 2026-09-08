# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: BIP141; BIP173

# ---------------- Imports (Module) ----------------
from __future__ import annotations

import os
import sys
import time
import random
import traceback
import tkinter as tk
import multiprocessing
import tkinter.font as tkfont
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------- UI MODULE ----------------
from kremlin.tab_ui.dev_tab import DevTab
from kremlin.tab_ui.chat_tab import ChatTab
from kremlin.tab_ui.send_tab import SendTab
from kremlin.tab_ui.network_tab import NetworkTab
from kremlin.tab_ui.history_tab import HistoryTab
from kremlin.tab_ui.graffiti_tab import GraffitiTab
from kremlin.tab_ui.app_sidebar import SidebarNavigator
from kremlin.tab_ui.explore.main_tab import ExplorePanel
from kremlin.tab_ui.wallet_tab import WalletsMixin, load_registry
from kremlin.tab_ui.lockscreen import should_show_password_lock, show_password_lockscreen

# ---------------- Security ----------------
from kremlin.security.chat.triple_xdh import ChatManager
from kremlin.security.data_security import list_addresses_in_keystore, create_keypair

# ---------------- Services ----------------
from kremlin.services.rpc_kremlin import NodeClient
from kremlin.services.send_service import SendService
from kremlin.services.tx_history import HistoryService
from kremlin.services.contact_management import ContactManager
from kremlin.services.explorer_providers import get_explorer_providers

# ---------------- UI Utility ----------------
from kremlin.ui_utils import show_toast, widget_exists
from kremlin.ui_state import BusyManager
from kremlin.theme import get_theme, install_ttk_styles, FONT

# ---------------- Local Project (With Node) ----------------
import tsarcore_native as native
from tsarchain.utils import config as CFG
from tsarchain.storage.kv import iter_prefix, batch

# ---------------- Logger ----------------
from tsarchain.utils.tsar_logging import setup_logging, get_ctx_logger
from kremlin.dialogs.log_viewer import open_log_toplevel
log = get_ctx_logger("tsarchain.wallet.gui")

# ---------------- Constants & Paths ----------------
manual_bootstrap: Optional[Tuple[str, int]] = None
USER_ID, USER_PUB, USER_PRIV = create_keypair("user_key")
USER_CTX = {"net_id": CFG.DEFAULT_NET_ID, "node_id": USER_ID, "pubkey": USER_PUB, "privkey": USER_PRIV}

def _load_peer_keys() -> dict:
    m = {}
    for k, v in iter_prefix('wallet_peer_keys', b'nid:'):
        nid = k.decode('utf-8')[4:]
        m[nid] = v.decode('utf-8')
    return m

def _save_peer_keys(d: dict) -> None:
    with batch('wallet_peer_keys') as b:
        for nid, pk in d.items():
            b.put(f"nid:{nid}".encode('utf-8'), pk.encode('utf-8'))

WALLET_PEER_KEYS = _load_peer_keys()

# ---------------- Main GUI ----------------
class KremlinWalletGUI(WalletsMixin):
    def __init__(self, root: tk.Tk, initial_keystore_password: Optional[str] = None):
        self.root = root

        # 0) Theme & styles
        self.current_theme = "dark"
        self.theme_set = get_theme(self.current_theme)
        self._set_theme_vars(self.theme_set)

        self._style = install_ttk_styles(self.root, self.theme_set)
        self._bind_shortcuts()
        self.busy_manager = BusyManager(self.root, toast_cb=lambda m, ms=1800, kind="info": show_toast(self, m, ms=ms, kind=kind))
        self._balance_countdown_job = None
        self._balance_next_sec = 0
        self._toasts = []
        self.contact_mgr = None
        self._request_locked = None
        self.wallet_count_label = None
        self.wallet_refresh_label = None
        self.send_to_combo = None

        root.title("Kremlin")
        root.geometry("1070x700")

        # 1) RPC client - MUST be initialized before services/tabs that use RPC
        self.rpc = NodeClient(
            cfg_module=None,
            user_ctx=USER_CTX,
            root=self.root,
            pinned_get=lambda nid: WALLET_PEER_KEYS.get(nid),
            pinned_set=lambda nid, pk: (WALLET_PEER_KEYS.__setitem__(nid, pk), _save_peer_keys(WALLET_PEER_KEYS)),
            manual_bootstrap=manual_bootstrap,
        )
        self.rpc_send  = self.rpc.send_async

        # 2) Services (can use RPC)
        self.send_svc = SendService()
        self.chat_mgr = ChatManager(
            rpc_send=self.rpc.send_async,
            password_prompt_cb=lambda addr: self._ask_password("Unlock Address", f"Enter password for {addr}:"),
        )
        self.exp_svc = HistoryService()

        # 3) State & cache
        self._chat_online = False
        self._chat_poll_job = None
        self._chat_priv_cache = self.chat_mgr.priv_cache
        self._chat_pub_cache  = self.chat_mgr.pub_cache
        self._read_sent       = self.chat_mgr.read_sent

        self.chat_textsize_var     = tk.StringVar(value="Medium")
        self.font_chat_body        = tkfont.Font(family=FONT, size=13)
        self.font_chat_meta_peer   = tkfont.Font(family=FONT, size=10)
        self.font_chat_meta_me     = tkfont.Font(family=FONT, size=10, weight="bold")
        self._msg_meta_map = {}
        self._chat_key_ttl_sec = 15 * 60
        self.chat_blocked = set()
        self.contacts: Dict[str, str] = {}
        self._ks_pwd_cache: Optional[Tuple[str, float]] = None
        self._ks_pwd_ttl_sec = 15 * 60
        if initial_keystore_password:
            self._ks_pwd_cache = (initial_keystore_password, time.time() + self._ks_pwd_ttl_sec)

        self._conn_online = False
        self._balance_poll_interval_ms = 30000
        self._balance_poll_job: Optional[str] = None
        self._balance_countdown_job: Optional[str] = None
        self._balance_next_sec: int = 0

        # 4) Tab state
        self._active_tab = "wallets"
        self._sidebar_buttons: dict[str, ttk.Button] = {}
        self.navigator = None
        self._conn_hb_job = None
        self.chat_tab = None
        self.explore_panel = None
        self.network_tab = None
        self.history_tab = None
        self.graffiti_tab = None
        self.dev_tab = None

        # 5) Build layout dasar
        self.wallets: List[str] = load_registry()
        self._init_core_ui()

        # 7) Build frames/tab
        self._build_wallets_frame()
        self._init_balance_cache()
        self._build_send_frame()
        self._build_network_frame()
        self._build_dev_frame()

        # 8) Activate tabs only once
        self.show_wallets_frame()
        self._activate_tab("wallets")

        # 9) Start heartbeat SETELAH network UI ada (label/status udah kebentuk)
        self._start_conn_heartbeat(interval_ms=10000)


    # ---------------- Theme / Layout ----------------
        
    # -------------- Theme palette & styles --------------
    def _set_theme_vars(self, theme_set) -> None:
        palette = theme_set.palette
        self.bg = palette.bg
        self.panel_bg = palette.panel_bg
        self.fg = palette.fg
        self.muted = palette.muted
        self.accent = palette.accent
        self.inf = palette.info
        self.border_color = palette.border
        self.card_bg = palette.card
        self.sidebar_bg = theme_set.wallet.sidebar_bg
        self.sidebar_active = theme_set.wallet.sidebar_active
        self.root.configure(bg=self.bg)

    def _set_theme(self, mode: str | None = None) -> None:
        if mode is not None:
            self.current_theme = mode.lower()
        self.theme_set = get_theme(self.current_theme or "dark")
        self._set_theme_vars(self.theme_set)

    def _toast(self, text: str, ms: int = 1800, kind: str = "info") -> None:
        show_toast(self, text, ms=ms, kind=kind)


    def _init_core_ui(self) -> None:
        self._build_layout()
        
        self.contact_mgr = ContactManager(
            self.root,
            get_password_cb=self._get_keystore_password,
            toast_cb=lambda m, ms=1800, kind='info': show_toast(self, m, ms=ms, kind=kind),
            theme=self.theme_set.contacts,
        )
        
        self.chat_tab = ChatTab(
            root=self.root,
            chat_mgr=self.chat_mgr,
            rpc_send=self.rpc.send,
            theme=self.theme_set.chat,
            toast_cb=lambda m, ms=1800, kind='info': show_toast(self, m, ms=ms, kind=kind),
            get_wallets_cb=lambda: list(self.wallets or []),
            contact_mgr=self.contact_mgr,
        )
        
        self.send_tab = SendTab(
            self.root,
            rpc_send=self.rpc_send,
            ask_password=lambda addr: self._ask_password("Unlock Address", f"Enter password for\n{addr}:"),
            toast=lambda m, ms=1800, kind='info': show_toast(self, m, ms=ms, kind=kind),
            addresses_provider=lambda: list(self.wallets or []),
            contact_manager=self.contact_mgr,
            busy_request=self._request_locked,
            theme=self.theme_set.send,
            on_sent=lambda addr_from: self._handle_balance_refresh_request(addresses=[addr_from], immediate=True),
        )

    def toggle_theme(self) -> None:
        self._hide_all_frames()
        self.frames.clear()

        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.theme_set = get_theme(self.current_theme)
        self._set_theme_vars(self.theme_set)
        self._style = install_ttk_styles(self.root, self.theme_set)
            
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self._init_core_ui()
        self._build_wallets_frame()
        self._build_send_frame()
        self._build_network_frame()
        self._build_dev_frame()
        self.show_wallets_frame()

    def _bind_shortcuts(self) -> None:
        self.root.bind_all("<Control-n>", lambda _e: self.create_wallet())
        self.root.bind_all("<Control-i>", lambda _e: self.import_by_mnemonic())
        self.root.bind_all("<Control-b>", lambda _e: self.backup_keystore())
        self.root.bind_all("<Control-o>", lambda _e: self.load_wallet_file())
        self.root.bind_all("<Control-s>", lambda _e: self.sync_from_keystore())
        self.root.bind_all("<Delete>",    lambda _e: self.delete_wallet_dialog())
        
        
    # --- Wallet Lock Screen helpers ---

    def _is_wallet_ready(self) -> bool:
        return bool(self.wallets)

    def _build_locked_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["locked"] = f

        wrap = tk.Frame(f, bg=self.bg)
        wrap.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(wrap, bg=self.panel_bg, padx=24, pady=22)
        card.place(relx=0.5, rely=0.5, anchor="center")

        self._lock_title = tk.Label(
            card, text="🔒 Locked", bg=self.panel_bg, fg=self.accent,
            font=(FONT, 18, "bold"))
        self._lock_title.pack(pady=(0, 6))

        self._lock_sub = tk.Label(
            card, text="Create or Load Your Wallet First",
            bg=self.panel_bg, fg=self.fg, font=("Segoe UI", 11))
        self._lock_sub.pack(pady=(0, 14))

        btns = tk.Frame(card, bg=self.panel_bg)
        btns.pack()
        ttk.Button(
            btns, text="Create / Load Wallet",
            command=lambda: (self.show_wallets_frame(), self._activate_tab("wallets"))
        ).pack(side=tk.LEFT, padx=6)
        ttk.Button(
            btns, text="Explore Without Wallet",
            command=lambda: (self.show_explorer_frame(), self._activate_tab("explorer"))
        ).pack(side=tk.LEFT, padx=6)

        tk.Label(
            card,
            text="Send, Chat, and History require at least one address.",
            bg=self.panel_bg, fg=self.muted, font=("Segoe UI", 9)
        ).pack(pady=(12, 0))

    def _show_locked_screen(self, source: str | None = None) -> None:
        self._hide_all_frames()
        if "locked" not in self.frames:
            self._build_locked_frame()
        title = f"🔒’ {source} is Locked" if source else "🔒 Locked"
        self._lock_title.config(text=title)
        self._lock_sub.config(text="Create or Load Your Wallet First")
        self.frames["locked"].pack(fill=tk.BOTH, expand=True)

    def _maybe_lock_redirect(self) -> None:
        if (not self._is_wallet_ready()) and (self._active_tab or "") in ("send", "chat", "history"):
            self._show_locked_screen(self._active_tab.capitalize())


    # --- Sidebar active/hover state ---
    
    def _activate_tab(self, tab: str) -> None:
        self._active_tab = tab
        self._refresh_sidebar_styles()

    def _refresh_sidebar_styles(self) -> None:
        active_fg = self.bg if self.current_theme == "dark" else self.fg
        if self.navigator:
            self.navigator.refresh_styles(self._active_tab or "", self.sidebar_bg, self.sidebar_active, self.fg, active_fg)

    _widget_exists = staticmethod(widget_exists)

    def _build_layout(self) -> None:
        self.sidebar_frame = tk.Frame(self.root, bg=self.sidebar_bg, width=100)
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.main = tk.Frame(self.root, bg=self.bg)
        self.main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.navigator = SidebarNavigator(
            self.root, self.sidebar_frame, self,
            self.sidebar_bg, self.sidebar_active, self.fg, self.bg if self.current_theme == "dark" else self.fg, self.accent
        )

        self.navigator.add_button("Wallets",  "wallets",  self.show_wallets_frame)
        self.navigator.add_button("Send",     "send",     self.show_send_frame)
        self.navigator.add_button("History",  "history",  self.show_history_frame)
        self.navigator.add_button("Chat",     "chat",     self.show_chat_frame)
        self.navigator.add_button("Graffiti", "graffiti", self.show_graffiti_frame)
        self.navigator.add_button("Explorer", "explorer", self.show_explorer_frame)
        self.navigator.add_button("Network",  "network",  self.show_network_frame)
        self.navigator.add_button("Dev",      "dev",      self.show_dev_frame)

        self.navigator.add_theme_toggle(self.toggle_theme)

        palette = self.theme_set.palette if self.theme_set else None
        offline_color = palette.danger if palette else "#d41c1c"
        self.conn_status = self.navigator.add_connection_status(offline_color)

        self.frames: Dict[str, tk.Frame] = {}

        if self._conn_online:
            self._set_conn_status(True)

        
        # ---------------- Connection status (UI + heartbeat) ----------------
    def _set_conn_status(self, ok: bool) -> None:
        prev = self._conn_online
        self._conn_online = bool(ok)
        palette = self.theme_set.palette if self.theme_set else None
        ok_color = palette.success if palette else "#17c964"
        fail_color = palette.danger if palette else "#d41c1c"
        if self._conn_online:
            self.conn_status.config(text="Connected", fg=ok_color)
        else:
            self.conn_status.config(text="Offline", fg=fail_color)

        if self._conn_online and not prev:
            if self._balance_poll_job:
                self.root.after_cancel(self._balance_poll_job)
                self._balance_poll_job = None
            if self.wallets:
                def _reschedule() -> None:
                    self._schedule_balance_refresh()
                self._request_balance_update(on_complete=_reschedule)
            else:
                self._schedule_balance_refresh()

    def _start_conn_heartbeat(self, interval_ms: int = 10000) -> None:
        self._conn_hb_interval = int(max(1000, interval_ms))
        if self._conn_hb_job:
            self.root.after_cancel(self._conn_hb_job)
            self._conn_hb_job = None

        def _next_delay() -> int:
            jitter = 0.2
            return int(self._conn_hb_interval * (1 + random.uniform(-jitter, jitter)))

        def _tick():
            self._conn_hb_job = None
            def _on(resp: Optional[Dict[str, Any]]) -> None:
                ok = bool(resp and not resp.get("error"))
                self._set_conn_status(ok)

            self.rpc.send_async({"type": "PING"}, _on)
            self._conn_hb_job = self.root.after(_next_delay(), _tick)
        self._conn_hb_job = self.root.after(600, _tick)

    # ---------------- Balance refresh helpers ----------------
    def _set_balance_refresh_label(self, text: str) -> None:
        if self.wallet_refresh_label:
            self.wallet_refresh_label.config(text=text)

    def _cancel_balance_countdown(self) -> None:
        if self._balance_countdown_job:
            self.root.after_cancel(self._balance_countdown_job)
            self._balance_countdown_job = None

    def _start_balance_countdown(self, seconds: int) -> None:
        self._cancel_balance_countdown()
        self._balance_next_sec = max(int(seconds), 0)

        def _tick():
            if self._balance_next_sec <= 0:
                self._set_balance_refresh_label("Refresh: now")
                self._balance_countdown_job = None
                return
            self._set_balance_refresh_label(f"Refresh: {self._balance_next_sec}s")
            self._balance_next_sec -= 1
            self._balance_countdown_job = self.root.after(1000, _tick)

        _tick()

    def _cancel_balance_poll(self) -> None:
        if self._balance_poll_job:
            self.root.after_cancel(self._balance_poll_job)
            self._balance_poll_job = None
        self._cancel_balance_countdown()
        self._set_balance_refresh_label("Refresh: paused")

    def _schedule_balance_refresh(self, delay_ms: Optional[int] = None) -> None:
        if delay_ms is None:
            delay_ms = self._balance_poll_interval_ms
        delay = int(max(0, delay_ms))
        if self._balance_poll_job:
            self.root.after_cancel(self._balance_poll_job)
        self._balance_poll_job = self.root.after(delay, self._run_balance_poll)
        self._start_balance_countdown(delay // 1000)

    def _run_balance_poll(self) -> None:
        self._balance_poll_job = None
        if not self._conn_online:
            self._schedule_balance_refresh()
            return
        if not self.wallets:
            self._schedule_balance_refresh()
            return

        def _reschedule() -> None:
            self._schedule_balance_refresh()

        self._request_balance_update(on_complete=_reschedule)

    def _handle_balance_refresh_request(
        self,
        addresses: Optional[Sequence[str]] = None,
        immediate: bool = False,
    ) -> None:
        addrs = [a for a in addresses if a] if addresses else None

        if immediate:
            if self._conn_online:
                self._request_balance_update(addresses=addrs)
                if self._active_tab == "wallets" and self._balance_poll_job is None:
                    self._schedule_balance_refresh()
                else:
                    self._cancel_balance_countdown()
            return

        if self._conn_online:
            if addrs:
                self._request_balance_update(addresses=addrs)
            if self._balance_poll_job is None:
                self._schedule_balance_refresh()

    # ---------------- Send Tab ----------------
    def _build_send_frame(self) -> None:
        fr = ttk.Frame(self.main, style="Tsar.TFrame")
        self.frames["send"] = fr
        self.send_tab.update_theme(self.theme_set.send)
        self.send_tab.build(fr)

    def reload_addresses(self) -> None:
        values = list(self.wallets or [])

        if self._widget_exists(self.wallet_count_label):
            self.wallet_count_label.config(text=f"Wallets: {len(values)}")

        if self._widget_exists(self.history_tab):
            self.history_tab.reload_addresses(values)

        if self.chat_tab:
            self.chat_tab.reload_addresses()
        
        # ---------------- Contact Management ----------------
    def _get_keystore_password(self) -> Optional[str]:
        if self._ks_pwd_cache and time.time() < self._ks_pwd_cache[1]:
            return self._ks_pwd_cache[0]
        pwd = simpledialog.askstring("Keystore Password", "Enter keystore password:", show="*")
        if not pwd:
            return None
        _ = list_addresses_in_keystore(pwd)
        self._ks_pwd_cache = (pwd, time.time() + self._ks_pwd_ttl_sec)
        return pwd

    def _refresh_contacts_ui(self) -> None:
        pairs = self.contact_mgr.pairs()   # List[(label, addr)]
        items = [label for (label, _addr) in pairs]
        self._contact_pairs = pairs
        for combo in (self.send_to_combo,):
            if combo is not None:
                combo["values"] = items

    # ---------------- History Frame ----------------
    def _build_history_frame(self) -> None:
        tab = HistoryTab(self, self.exp_svc, master=self.main)
        self.frames["history"] = tab
        self.history_tab = tab

    # === Explorer (BERSIH, SATU VERSI SAJA) ===

    def show_explorer_frame(self) -> None:
        self._hide_all_frames()
        if "explorer" not in self.frames:
            self._build_explorer_frame()
        self.frames["explorer"].pack(fill=tk.BOTH, expand=True)
        if self.explore_panel:
            self.explore_panel.on_activated()

    def _build_explorer_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["explorer"] = f

        # Panel Explore baru
        self.explore_panel = ExplorePanel(f, app=self, theme=self.theme_set.explorer)
        self.explore_panel.pack(fill=tk.BOTH, expand=True)
        self.explore_panel.set_provider(**get_explorer_providers(self.rpc))


    # ---------------- Graffiti Frame ----------------
    
    def _build_graffiti_frame(self) -> None:
        f = tk.Frame(self.main, bg=self.bg)
        self.frames["graffiti"] = f
        self.graffiti_tab = GraffitiTab(self, self.theme_set.graffiti, master=f)
        self.graffiti_tab.pack(fill="both", expand=True)
            
    # ---------------- Network Frame ----------------
    def _build_network_frame(self) -> None:
        tab = NetworkTab(self, master=self.main)
        self.frames["network"] = tab
        self.network_tab = tab

    # ---------------- Dev Frame ----------------
    def _build_dev_frame(self) -> None:
        tab = DevTab(self, master=self.main)
        self.frames["dev"] = tab
        self.dev_tab = tab

    # Quick tab switcher (used by GraffitiTab Prefill)
    def switch_tab(self, name: str) -> None:
        m = {
            "wallets": self.show_wallets_frame,
            "send": self.show_send_frame,
            "chat": self.show_chat_frame,
            "history": self.show_history_frame,
            "explorer": self.show_explorer_frame,
            "network": self.show_network_frame,
            "dev": self.show_dev_frame,
            "graffiti": self.show_graffiti_frame,
        }
        fn = m.get((name or '').lower())
        if fn:
            fn()
            self._activate_tab(name.lower())

# ---------------- Helpers: UI control ----------------
    def _hide_all_frames(self) -> None:
        if self._chat_poll_job:
            self.root.after_cancel(self._chat_poll_job)
            self._chat_poll_job = None
        if self.chat_tab and self.chat_tab._chat_poll_job:
            self.root.after_cancel(self.chat_tab._chat_poll_job)
            self.chat_tab._chat_poll_job = None
        for fr in self.frames.values():
            fr.pack_forget()
        if self.explore_panel:
            self.explore_panel.on_deactivated()
        if self.network_tab:
            self.network_tab.on_hide()

    def show_wallets_frame(self) -> None:
        self._hide_all_frames()
        # mark active tab early so schedulers see the right state
        self._active_tab = "wallets"
        self._refresh_sidebar_styles()
        self.frames["wallets"].pack(fill=tk.BOTH, expand=True)
        if self._conn_online:
            if self._balance_poll_job or self._balance_countdown_job:
                if self._balance_next_sec > 0:
                    self._set_balance_refresh_label(f"Refresh: {self._balance_next_sec}s")
                else:
                    self._set_balance_refresh_label("Refresh: now")
            else:
                self._schedule_balance_refresh()
        else:
            self._set_balance_refresh_label("Refresh: offline")

    def show_send_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("Send")
        self._hide_all_frames()
        if "send" not in self.frames:
            self._build_send_frame()
        fr = self.frames["send"]
        if not fr.winfo_children():
            try:
                self.send_tab.build(fr)
            except Exception as exc:
                for w in fr.winfo_children():
                    w.destroy()
                tk.Label(
                    fr, text=f"Send tab failed to render: {exc}",
                    bg=self.bg, fg=self.accent, font=("Consolas", 11, "bold")
                ).pack(anchor="w", padx=12, pady=12)
        fr.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("send")
        self.reload_addresses()
        self.send_tab.on_wallets_changed(self.wallets)
        self.send_tab.on_activated()
    
    def show_graffiti_frame(self) -> None:
        self._hide_all_frames()
        if "graffiti" not in self.frames:
            self._build_graffiti_frame()
        self.frames["graffiti"].pack(fill=tk.BOTH, expand=True)
        self._activate_tab("graffiti")

    def show_chat_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("Chat")

        self._hide_all_frames()
        chat_frame = self.frames.get("chat")
        chat_tab_frame = self.chat_tab.frame if self.chat_tab else None
        need_build = (
            chat_frame is None
            or chat_tab_frame is None
            or not widget_exists(chat_tab_frame)
        )
        if need_build:
            parent = tk.Frame(self.main, bg=self.bg)
            self.frames["chat"] = parent
            if self.chat_tab:
                self.chat_tab.set_palette(self.theme_set.chat)
                self.chat_tab.build(parent)
            chat_frame = parent
        chat_frame.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("chat")
        if self.chat_tab:
            self.chat_tab.reload_addresses()
            if self.chat_tab._chat_online:
                self.chat_tab._chat_schedule_next()
    
    def show_history_frame(self) -> None:
        if not self._is_wallet_ready():
            return self._show_locked_screen("History")

        self._hide_all_frames()
        history_frame = self.frames.get("history")
        if history_frame is None or not self._widget_exists(history_frame):
            self._build_history_frame()
            history_frame = self.frames["history"]

        history_frame.reload_addresses(self.wallets)
        history_frame.on_show()
        history_frame.pack(fill=tk.BOTH, expand=True)
        self._activate_tab("history")

    def show_network_frame(self) -> None:
        self._hide_all_frames()
        self.frames["network"].pack(fill=tk.BOTH, expand=True)
        if self.network_tab:
            self.network_tab.on_show()

    def show_dev_frame(self) -> None:
        self._hide_all_frames()
        self.frames["dev"].pack(fill=tk.BOTH, expand=True)

    # ---------------- Helper UX ----------------
        
    def _open_log_viewer(self):
        log_file = "logging/wallet.log"
        open_log_toplevel(self.root, log_file=log_file, attach_to_root=False)

    def _tv_insert_chunked(self, tv: ttk.Treeview, rows: list[tuple[tuple, tuple]], start: int = 0, chunk: int = CFG.GUI_TV_CHUNK,) -> None:
        end = min(start + chunk, len(rows))
        insert = tv.insert
        for vals, tags in rows[start:end]:
            insert("", tk.END, values=vals, tags=tags)
        if end < len(rows):
            self.root.after(0, self._tv_insert_chunked, tv, rows, end, chunk)

    def copy_to_clipboard(self, text: str, label: str = "Copied to clipboard!") -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copied", label)

# ---------------- Entry point ----------------
if __name__ == "__main__":
    multiprocessing.freeze_support()
    os.umask(0o077)

    setup_logging("logging/wallet.log", force=True)
    native.set_py_logger(get_ctx_logger("tsarchain.native"))

    root = tk.Tk()
    try:
        root.withdraw()
        initial_password: Optional[str] = None
        if should_show_password_lock():
            initial_password = show_password_lockscreen(root)
            if initial_password is None:
                root.destroy()
                sys.exit(0)
        root.deiconify()
        app = KremlinWalletGUI(root, initial_keystore_password=initial_password)
        root.mainloop()

    except Exception as e:
        log.exception("Unhandled exception")
        traceback.print_exc()
        try:
            messagebox.showerror("Fatal error", str(e))
        finally:
            root.destroy()
