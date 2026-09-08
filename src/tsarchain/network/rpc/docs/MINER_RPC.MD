# TsarChain Miner RPC Specification

Technical documentation for the **`MINER`** RPC category in the TsarChain P2P Network (`src/tsarchain/network/rpc/miner_rpc.py` and `src/tsarchain/network/rpc/processing_msg.py`).

---

## 1. Architecture & Miner Authorization

Miner RPC encompasses low-level peer-to-peer (P2P) communication protocols between miner nodes and full nodes for:
1. Peer discovery and initial handshake.
2. Blockchain synchronization (headers and full block bodies).
3. New block propagation (gossip).
4. Unconfirmed transaction pool synchronization (mempool push).

### A. Sender Authentication (`_is_miner_sender`)
Every incoming miner message undergoes sender identity verification in `processing_msg.py`:
- The receiving node verifies `src_node_id` and `src_pubkey`.
- The sender's public key must match the pinned entry in the node's `peer_pubkeys` table (`pinned public key`).
- If an unauthenticated sender calls a protected miner endpoint, the sender's IP is temporarily banned (`CFG.BAN_MALICIOUS_RPC`) and the message is dropped.

### B. Bootstrap Exceptions (`BOOTSTRAP_MINER_ALLOW`)
To enable fresh nodes to connect and perform initial header synchronization before identity pinning:
- **`HELLO`**
- **`GET_HEADERS`**

These two RPCs are permitted without prior pinned miner pubkey verification.

---

## 2. Endpoint Summary

| RPC Type | Description | Bootstrap Access | Rate Limit (Burst / Window) |
| :--- | :--- | :---: | :--- |
| **`HELLO`** | Handshake, peer exchange, initial mempool push | Yes | `CFG.MINER_INFO_RL_*` |
| **`GET_INFO`** | Fetch compact node blockchain status and metrics | No | `CFG.MINER_INFO_RL_*` |
| **`NEW_BLOCK`** | Broadcast newly mined block to peer network | No | `CFG.MINER_NEWBLOCK_RL_*` |
| **`MEMPOOL`** | Push batch of mempool transactions to peer | No | `CFG.MINER_MEMPOOL_RL_*` |
| **`GET_HEADERS`** | Header synchronization using block locators | Yes | `CFG.MINER_HEADERS_RL_*` |
| **`GET_BLOCKS`** | Download full block bodies by height list | No | `CFG.MINER_BLOCKS_RL_*` |
| **`GET_BLOCK_HASH`**| Retrieve block hash at specific height | No | `CFG.MINER_INFO_RL_*` |

---

## 3. Endpoint Specifications

### 1. `HELLO`
Performs the initial handshake between two nodes, registers peers, and aligns the chain tip.

- **Category**: `MINER_RPC_TYPES` (Bootstrap Allowed)
- **Internal Handler**: `handlers.handle_hello()`

#### Request Payload
```json
{
  "type": "HELLO",
  "ip": "192.168.1.100",
  "port": 9333,
  "height": 1050,
  "role": "NODE",
  "peers": [
    {"ip": "192.168.1.101", "port": 9333}
  ]
}
```

#### Response Payload
```json
{
  "type": "HELLO_RESPONSE",
  "port": 9333,
  "height": 1055,
  "peers": [
    {"ip": "192.168.1.102", "port": 9333},
    {"ip": "192.168.1.103", "port": 9333}
  ]
}
```
*Note: If the sender is a regular miner node and provides a valid listening port, the receiver automatically triggers `send_mempool_to_peer` to initialize mempool synchronization.*

---

### 2. `GET_INFO`
Retrieves internal metrics from the miner node (chain height, total blocks, mempool size, UTXO count, active peers).

- **Category**: `MINER_RPC_TYPES` (Miner Only)
- **Internal Handler**: `handle_miner_rpc(GET_INFO)`

#### Request Payload
```json
{
  "type": "GET_INFO"
}
```

#### Response Payload
```json
{
  "type": "INFO",
  "height": 1055,
  "blocks": 1056,
  "mempool": 4,
  "utxos": 1280,
  "peers": 8
}
```

---

### 3. `NEW_BLOCK`
Broadcasts a newly mined, validated block to the peer network in pure binary format (`Block.to_storage_bytes()` encoded as base64 string). Legacy JSON dict payloads are strictly rejected.

- **Category**: `MINER_RPC_TYPES` (Miner Only)
- **Internal Handler**: `self.broadcast.receive_block()`

#### Request Payload
```json
{
  "type": "NEW_BLOCK",
  "data": "<base64_encoded_storage_bytes>",
  "hash": "00000000a1b2c3d4e5f6...",
  "port": 8333
}
```
*(Note: `data` contains the Base64 representation of `Block.to_storage_bytes()`. `hash` is an optional 64-char hex hint allowing receiving nodes to filter seen/inflight blocks immediately without deserializing payload).*

#### Response Payload
```json
{
  "status": "ok"
}
```
*Error: Returns `{"type": "SYNC_REJECT", "error": "rate_limited", "retry_after": 10.0}` if block propagation frequency exceeds rate limits.*

---

### 4. `MEMPOOL`
Receives a batch of unconfirmed transactions pushed by a peer node to update the local mempool.

- **Category**: `MINER_RPC_TYPES` (Miner Only)
- **Internal Handler**: `_handle_miner_mempool()` $\rightarrow$ `self.broadcast.receive_mempool()`

#### Request Payload
```json
{
  "type": "MEMPOOL",
  "data": [
    {
      "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
      "version": 1,
      "locktime": 0,
      "inputs": [ ... ],
      "outputs": [ ... ]
    }
  ],
  "port": 9333
}
```

#### Response Payload
```json
{
  "status": "mempool received"
}
```

---

### 5. `GET_HEADERS`
Fetches a sequential batch of block headers for fast header-first blockchain synchronization.

- **Category**: `MINER_RPC_TYPES` (Bootstrap Allowed)
- **Internal Handler**: `handlers.handle_get_headers()`

#### Request Payload
```json
{
  "type": "GET_HEADERS",
  "locator": [
    "00000000a1b2c3...",
    "000000008f9e0d..."
  ],
  "limit": 500
}
```
- `locator`: Ordered list of latest known block hashes (from newest to oldest). The node finds the latest common ancestor (*fork point*) and replies with headers following that point.
- `limit`: Maximum number of headers requested (capped by `CFG.HEADERS_BATCH_MAX`).

#### Response Payload
```json
{
  "type": "HEADERS",
  "headers": [
    {
      "height": 1001,
      "hash": "00000000b4c5d6...",
      "prev_hash": "00000000a1b2c3...",
      "timestamp": 1739999000,
      "bits": 486604799
    }
  ],
  "more": true,
  "best_height": 1055
}
```

---

### 6. `GET_BLOCKS`
Downloads complete block data structures by a list of block heights.

- **Category**: `MINER_RPC_TYPES` (Miner Only)
- **Internal Handler**: `handlers.handle_get_blocks()`

#### Request Payload
```json
{
  "type": "GET_BLOCKS",
  "heights": [1001, 1002, 1003]
}
```
*Note: Batch size is capped by `CFG.BLOCK_DOWNLOAD_BATCH_MAX` (256).*

#### Response Payload (`BLOCKS_BIN`)
```json
{
  "type": "BLOCKS_BIN",
  "count": 3,
  "data": "<base64_encoded_packed_storage_bytes>"
}
```
*Note: Data contains concatenated `[4-byte little-endian length] + [raw_storage_bytes]` frames decoded via `Block.from_storage_bytes()`.*

---

### 7. `GET_BLOCK_HASH`
Fetches the block hash at a designated chain height.

- **Category**: `MINER_RPC_TYPES` (Miner Only)
- **Internal Handler**: `self.handle_get_block_hash(h)`

#### Request Payload
```json
{
  "type": "GET_BLOCK_HASH",
  "height": 1050
}
```

#### Response Payload
```json
{
  "type": "BLOCK_HASH",
  "height": 1050,
  "hash": "00000000c7d8e9..."
}
```
*If height is missing, invalid, or out of bounds: returns an appropriate error structure (e.g. `{"type": "BLOCK_HASH", "error": "missing_height" | "invalid_height" | "height_out_of_range"}`).*

---

## 4. Node Lifecycle & RPC Flow

```
[New Node A Starts]
        │
        ├── 1. Send "HELLO" (Bootstrap) ──────────────► [Node B Peer]
        │   ◄── Reply "HELLO_RESPONSE" (Peer List) ─────┤
        │                                               │
        ├── 2. Send "GET_HEADERS" (Locator Hashes) ───► │
        │   ◄── Reply "HEADERS" (Header Batch) ─────────┤
        │                                               │
        ├── 3. Send "GET_BLOCKS" (Heights List) ──────► │ (Once authenticated)
        │   ◄── Reply "BLOCKS" (Full Block Bodies) ─────┤
        │                                               │
[Node A Mines Block]                                    │
        ├── 4. Broadcast "NEW_BLOCK" ─────────────────► │
        │   ◄── Reply {"status": "ok"} ─────────────────┤
        │                                               │
[New Tx Ingested into Mempool]                          │
        └── 5. Push "MEMPOOL" (Tx Batch) ─────────────► │
            ◄── Reply {"status": "mempool received"} ───┘
```
