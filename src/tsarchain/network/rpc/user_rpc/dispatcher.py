# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE
# Refs: see REFERENCES.md

from ..user_rpc import common as CM
from ..user_rpc.category import networking as NET
from ..user_rpc.category import explorer as EXP
from ..user_rpc.category import transactions as TXS
from ..user_rpc.category import chat as CHT
from ..user_rpc.category import graff_activities as GRAFF


# ---------------- Logger ----------------
from ....utils.tsar_logging import get_ctx_logger
log = get_ctx_logger("tsarchain.network.rpc.user_rpc.dispatcher")


HANDLER_MAP = {
    # Networking
    "PING": NET.ping,
    "GET_PEERS": NET.get_peers,
    "STOR_LIST": NET.stor_list,
    
    # Transactions
    "NEW_TX": TXS.new_tx,
    "CREATE_TX": TXS.create_tx,
    "CREATE_TX_MULTI": TXS.create_tx_multi,
    
    # Explorer
    "GET_BALANCES": EXP.get_balances,
    "GET_NETWORK_INFO": EXP.get_network_info,
    "GET_BLOCK": EXP.get_block,
    "GET_BLOCK_RANGE": EXP.get_block_range,
    "GET_MEMPOOL": EXP.get_mempool,
    "GET_TX_HISTORY": EXP.get_tx_history,
    "GET_TX_DETAIL": EXP.get_tx_detail,
    "GET_TOTAL_UTXO": EXP.get_total_utxo,
    
    # Chat
    "CHAT_REGISTER": CHT.chat_register,
    "CHAT_LOOKUP_PUB": CHT.chat_lookup_pub,
    "CHAT_CHECK_PREKEYS": CHT.chat_check_prekeys,
    "DEACTIVATE_CHAT": CHT.chat_deactivate,
    "CHAT_PRESENCE": CHT.chat_presence,
    "CHAT_GET_PREKEY": CHT.chat_get_prekey,
    "CHAT_PUBLISH_PREKEYS": CHT.chat_publish_prekeys,
    "CHAT_SEND": CHT.chat_send,
    "CHAT_READ": CHT.chat_read,
    "CHAT_PULL": CHT.chat_pull,
    "CHAT_RELAY": CHT.chat_relay,
    
    # Graffiti
    "GRAFFITI_GET_POSTS": GRAFF.get_posts,
    "GRAFFITI_GET_COMMENTS": GRAFF.get_comments,
    "GRAFFITI_GET_ART": GRAFF.get_art,
    "GRAFFITI_GET_PAYOUTS": GRAFF.get_payouts, # not implemented yet
}

def handle_user_rpc(self, message, addr, mtype, *, client_ip, is_miner_sender,
                    overlay_realtime_mempool_stats, choose_relay_route,
                    relay_chain, send_chat_relay):
    handler = HANDLER_MAP.get(mtype)
    if handler is None:
        return None

    pow_obj = message.get("pow")
    base_identity = CM.identity_from_msg(message)
    ip = client_ip()

    return handler(
        self,
        message,
        pow_obj=pow_obj,
        base_identity=base_identity,
        addr=addr,
        mtype=mtype,
        client_ip=ip,
        is_miner_sender=is_miner_sender,
        overlay_realtime_mempool_stats=overlay_realtime_mempool_stats,
        choose_relay_route=choose_relay_route,
        relay_chain=relay_chain,
        send_chat_relay=send_chat_relay,
    )
