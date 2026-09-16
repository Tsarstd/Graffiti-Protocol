# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from __future__ import annotations

import threading
from collections import deque


def init_chat_state(self) -> None:
    self.chat_lock = threading.RLock()
    self.chat_presence_pub = {}
    self.chat_presence_ts = {}
    self.chat_spend_pub = {}
    self.chat_mailbox = {}
    self.chat_global_count = 0
    self.chat_presence_seen = set()
    self.chat_presence_seen_order = deque(maxlen=10000)
    self.chat_seen_mid = {}
    self.chat_seen_max = 512
    self.chat_pull_seen = {}
    self.chat_deactivated_cd = {}
    self.rl_addr = {}
    self.rl_ip = {}
    self.backoff_until = {}
    self.chat_gc_last = 0
