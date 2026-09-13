# TsarChain User RPC Specification

Technical documentation for the **`USER`** RPC category in the TsarChain Network (`src/tsarchain/network/rpc/user_rpc/` and `src/tsarchain/network/rpc/processing_msg.py`).

---

## 1. Architecture & Security Model

User RPC serves client applications, light wallets (Kremlin), explorers, and decentralized chat clients. Unlike private miner-to-miner RPCs, User RPC is publicly accessible but strictly guarded against Denial of Service (DoS) attacks.

### A. Anti-DoS Proof of Work (PoW)
To prevent API spam and brute-force attacks without requiring centralized API keys, User RPC uses dynamic Proof of Work challenges (`allow_rpc_with_pow`):
- **Read Requests** (`GET_*`, `PING`, `STOR_LIST`): Lower difficulty (`CFG.RPC_POW_DIFFICULTY_READ`).
- **Transaction Submissions** (`NEW_TX`, `CREATE_TX*`): Higher difficulty (`CFG.RPC_POW_DIFFICULTY_TX`).
- **Chat Relays & Registration** (`CHAT_*`): Chat-specific difficulty (`CFG.RPC_POW_DIFFICULTY_CHAT`).

If a client exceeds standard token bucket burst limits, the server challenges the client to attach a valid `pow` object:
```json
{
  "pow": {
    "nonce": 123456,
    "timestamp": 1740000000,
    "identity": "tsar1q...",
    "scope": "rpc:balance"
  }
}
```

### B. Dual Token-Bucket Rate Limiting
Rate limits are enforced at two tiers:
1. **IP Table (`rl_ip`)**: Prevents volume floods from single IPs.
2. **Address Table (`rl_addr`)**: Prevents Sybil attacks cycling through IPs against the same account identity.

---

## 2. Category Summary

| Category | Endpoints |
| :--- | :--- |
| **Networking** | `PING`, `GET_PEERS`, `STOR_LIST` |
| **Transactions & Mempool** | `NEW_TX`, `CREATE_TX`, `CREATE_TX_MULTI`, `GET_MEMPOOL` |
| **Blockchain Explorer** | `GET_BALANCES`, `GET_NETWORK_INFO`, `GET_BLOCK`, `GET_BLOCK_RANGE`, `GET_TX_HISTORY`, `GET_TX_DETAIL`, `GET_TOTAL_UTXO` |
| **Encrypted P2P Chat** | `CHAT_REGISTER`, `CHAT_LOOKUP_PUB`, `CHAT_CHECK_PREKEYS`, `CHAT_PRESENCE`, `CHAT_GET_PREKEY`, `CHAT_PUBLISH_PREKEYS`, `CHAT_SEND`, `CHAT_READ`, `CHAT_PULL`, `CHAT_RELAY` |
| **Graffiti Protocol** | `GRAFFITI_GET_POSTS`, `GRAFFITI_GET_COMMENTS`, `GRAFFITI_GET_ART`, `GRAFFITI_GET_PAYOUTS` |

---

## 3. Networking Endpoints

### 1. `PING`
Health check and connection latency probe.

- **Request**: `{"type": "PING"}`
- **Response**: `{"type": "PONG"}`

---

### 2. `GET_PEERS`
Returns active connected node peers (restricted to miners for full topology; returns empty list for anonymous users).

- **Request**: `{"type": "GET_PEERS"}`
- **Response**: `{"type": "PEERS", "peers": [["192.168.1.100", 9333]]}`

---

### 3. `STOR_LIST`
Lists discovered and verified Archivist Storage Nodes in the network.

- **Request**: `{"type": "STOR_LIST"}`
- **Response**:
```json
{
  "type": "STOR_LIST",
  "storers": [
    {
      "addr": "tsar1qstorage...",
      "url": "http://192.168.1.50:8080",
      "ip": "192.168.1.50",
      "port": 8080,
      "last_seen": 1740000000,
      "alive": true,
      "trusted": false,
      "node_id": "stor_node_1"
    }
  ]
}
```

---

## 4. Transactions & Mempool Endpoints

### 1. `NEW_TX`
Submits a signed raw transaction to the network. Propagates through Dandelion++ privacy routing (`stem` phase) if enabled.

#### Request Payload
```json
{
  "type": "NEW_TX",
  "from_addr": "tsar1qsender...",
  "data": {
    "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "version": 1,
    "locktime": 0,
    "inputs": [ ... ],
    "outputs": [ ... ]
  }
}
```

#### Response Payload
```json
{
  "status": "ok",
  "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
}
```
*Error: `{"status": "error", "reason": "missing_inputs"}`*

---

### 2. `CREATE_TX` / `CREATE_TX_MULTI`
Generates an unsigned transaction template using available UTXOs from the sender address.

#### Request Payload (`CREATE_TX`)
```json
{
  "type": "CREATE_TX",
  "from": "tsar1qsender...",
  "to": "tsar1qrecipient...",
  "amount": 1000000,
  "fee_rate": 2
}
```

#### Response Payload
```json
{
  "type": "TX_TEMPLATE",
  "data": {
    "inputs": [ ... ],
    "outputs": [ ... ],
    "fee": 450,
    "change": 999550
  }
}
```

---

### 3. `GET_MEMPOOL`
Queries unconfirmed transactions currently held in the local mempool.

- **Modes**:
  - `mode: "txids"` (Default): Returns list of TXID hex strings.
  - `mode: "inline"` / `"inline_full"`: Returns full transaction objects up to size limit (`CFG.MEMPOOL_INLINE_MAX_TX`).
  - `mode: "snapshot"`: Triggers peer P2P mempool push (miner-only).

#### Request Payload
```json
{
  "type": "GET_MEMPOOL",
  "mode": "txids"
}
```

#### Response Payload
```json
{
  "type": "MEMPOOL",
  "mode": "txids",
  "txs": [
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  ]
}
```

---

## 5. Blockchain Explorer Endpoints

### 1. `GET_BALANCES`
Queries confirmed, immature, and pending mempool balances for one or more addresses.

#### Request Payload
```json
{
  "type": "GET_BALANCES",
  "addresses": ["tsar1qalice..."]
}
```

#### Response Payload
```json
{
  "type": "BALANCES",
  "height": 1055,
  "items": {
    "tsar1qalice...": {
      "balance": 5000000,
      "spendable": 4500000,
      "immature": 500000,
      "pending_outgoing": 0,
      "pending_incoming": 200000,
      "maturity": 100
    }
  }
}
```

---

### 2. `GET_NETWORK_INFO`
Retrieves a snapshot of blockchain state (height, tip hash, difficulty, hashrate, mempool metrics).

- **Request**: `{"type": "GET_NETWORK_INFO"}`
- **Response**:
```json
{
  "type": "NETWORK_INFO",
  "data": {
    "height": 1055,
    "tip_hash": "00000000a1b2c3...",
    "difficulty": "0x1d00ffff",
    "transactions": {
      "mempool_txs": 4,
      "mempool_vbytes_estimate": 1024
    },
    "peers": {"count": 8}
  }
}
```

---

### 3. `GET_BLOCK` / `GET_BLOCK_RANGE`
Fetches block details by height, block hash, or sequential range.

- **Request (`GET_BLOCK`)**: `{"type": "GET_BLOCK", "height": 1050}` or `{"type": "GET_BLOCK", "hash": "00000000a1..."}`
- **Request (`GET_BLOCK_RANGE`)**: `{"type": "GET_BLOCK_RANGE", "start_height": 1050, "limit": 20}`

---

### 4. `GET_TX_HISTORY` / `GET_TX_DETAIL` / `GET_TOTAL_UTXO`
Address activity and transaction inspection.

- **`GET_TX_HISTORY`**: `{"type": "GET_TX_HISTORY", "address": "tsar1q...", "limit": 50, "offset": 0}`
- **`GET_TX_DETAIL`**: `{"type": "GET_TX_DETAIL", "txid": "4a5e1e..."}`
- **`GET_TOTAL_UTXO`**: `{"type": "GET_TOTAL_UTXO", "address": "tsar1q..."}`

---

## 6. Encrypted P2P Chat Endpoints (Signal X3DH / Double Ratchet)

Provides decentralized, end-to-end encrypted messaging via TsarChain's Signal-compatible cryptographic layer.

```
 Alice (Wallet)                          Node / Relay                           Bob (Wallet)
   │                                           │                                      │
   ├── 1. CHAT_PUBLISH_PREKEYS (IK, SPK, OPKs)►│                                      │
   │                                           │                                      │
   ├── 2. CHAT_GET_PREKEY (For Bob)───────────►│                                      │
   │   ◄── Returns Bob's Prekey Bundle ────────┤                                      │
   │                                           │                                      │
   ├── 3. Encrypt via Signal X3DH + Ratchet    │                                      │
   ├── 4. CHAT_SEND (Encrypted Envelope)──────►│    (Stores in RAM mailbox)           │
   │                                           │◄── 5. CHAT_PULL (Fetch Messages)─────┤
   │                                           ├──── Returns Encrypted Payload ──────►│
   │                                           │     (Instantly deleted from RAM)     │
   │                                           │◄── 6. CHAT_READ (Read Receipt)───────┤
```

### Endpoints Overview
1. **`CHAT_REGISTER`**: Registers account spend public key and identity public key with dual presence signatures.
2. **`CHAT_LOOKUP_PUB`**: Resolves an on-chain Tsar address to its chat identity public key.
3. **`CHAT_CHECK_PREKEYS`**: Read-only status query checking if an address has active prekeys and remaining OPKs in LMDB without consuming OPKs.
4. **`CHAT_PRESENCE`**: Updates node heartbeat presence for online routing.
5. **`CHAT_PUBLISH_PREKEYS`**: Publishes Signed Prekeys (SPK) and One-Time Prekeys (OPKs) for asynchronous X3DH key agreements.
6. **`CHAT_GET_PREKEY`**: Fetches a prekey bundle to initiate an encrypted session with a peer (consumes 1 OPK).
7. **`CHAT_SEND`**: Delivers an encrypted message envelope to the recipient's node mailbox.
8. **`CHAT_PULL`**: Fetches pending incoming encrypted envelopes.
9. **`CHAT_READ`**: Marks message IDs as delivered/read.
10. **`CHAT_RELAY`**: Multi-hop onion routing relay for privacy-preserving message transport.

---

### Endpoint Specification: `CHAT_CHECK_PREKEYS`
A non-destructive, read-only endpoint that inspects whether a wallet address has a valid prekey bundle (`ik`, `spk`, and `opk_list`) stored in the node's LMDB `chat_prekeys` database. Unlike `CHAT_GET_PREKEY`, this method **never consumes or pops OPKs**, making it safe for wallet import recovery and sovereign status verification.

#### Request Payload
```json
{
  "type": "CHAT_CHECK_PREKEYS",
  "address": "tsar1qalice..."
}
```

#### Response Payload
```json
{
  "type": "CHAT_PREKEYS_STATUS",
  "address": "tsar1qalice...",
  "registered": true,
  "has_ik": true,
  "has_spk": true,
  "opk_count": 8,
  "last_seen": 1726000000
}
```

- `registered` *(bool)*: `true` if both `ik` and authenticated `spk` exist.
- `has_ik` *(bool)*: Whether identity key is present.
- `has_spk` *(bool)*: Whether signed prekey and signature are present.
- `opk_count` *(int)*: Current quantity of unconsumed one-time prekeys remaining in pool.
- `last_seen` *(int | null)*: Unix epoch timestamp of last presence or prekey update.

---

### 🛡️ Node Architecture: Mailbox & Prekey Bundle Management

The node operates purely as a **Blind Relay & Ephemeral Mailbox Router** with zero ability to decrypt ciphertexts and zero permanent disk persistence for transient chat messages:

#### 1. Prekey Bundle Management (`chat_prekeys`)
* **Data Structure**: Dedicated LMDB binary database `LMDB_CHAT_PREKEYS` (`data/node/chat_prekeys`).
* **Bundle Components**:
  - `ik` *(Identity Key)*: User's long-term public X25519 identity key.
  - `spk` *(Signed Prekey)*: Semi-static ephemeral public key authenticated via ECDSA Secp256k1.
  - `sig`: Identity digital signature over the canonical payload `TSAR-SPK|<spk_bytes>|<spend_pub_bytes>`.
  - `spend_pub`: User's 33-byte compressed Secp256k1 public key (flag `0x08`) for signature verification.
  - `opk_list` *(One-Time Prekeys Pool)*: Pool of single-use ephemeral keys for maximum Forward Secrecy.
* **Compact Binary Encoding**: Packed into a zero-overhead raw binary structure (`<QB` header, 32B IK, 32B SPK, signature bytes, optional 33B spend pubkey, and contiguous 32B OPKs) for >60% storage reduction.
* **Node Restart Resilience (Auto-Rehydration)**:
  - `spend_pub` is persisted in LMDB alongside prekeys.
  - If the node restarts and RAM cache misses, `get_spend_pub(addr)` automatically lazy-loads `spend_pub` from LMDB into RAM, preventing `no_spend_pub` / `not_registered` errors on existing wallet sessions.
* **In-Memory `last_seen` Cache**:
  - Status lookups (`CHAT_LOOKUP_PUB`) read directly from `self.chat_presence_ts` in RAM (with fallback to LMDB only on cold cache miss), eliminating redundant disk I/O during periodic polling.
* **Bounded ThreadPool for Presence Gossip**:
  - Presence broadcasts are handled by a dedicated `ThreadPoolExecutor(max_workers=4, thread_name_prefix="presence_relay")`, avoiding OS thread exhaustion under high network load.
* **Low-Latency Transport (`TCP_NODELAY`)**:
  - Sockets disable Nagle's algorithm with `TCP_NODELAY` for immediate packet transmission without buffering delay.
* **Atomic Key Consumption (FIFO Pop)**:
  - When an initiator calls `CHAT_GET_PREKEY`, the node consumes the top OPK via `lst.pop(0)` and atomically updates the record in LMDB.
  - A consumed OPK is **never issued to any other peer**, ensuring each new cryptographic session begins with unique ephemeral entropy.
* **Capacity Management**: Backed by `CFG.LMDB_PREKEYS_SIZE_MAX = 250MB` with rate limiting and PoW verification on publish endpoints.

#### 2. Offline Message Mailbox Queue Management (`chat_mailbox`)
* **Data Structure**: In-memory FIFO queue per recipient: `self.chat_mailbox[addr] = collections.deque()`.
* **Strict Capacity Limits**:
  - `CFG.CHAT_MAILBOX_MAX = 1000`: Maximum queued messages per recipient address.
  - `CFG.CHAT_GLOBAL_QUEUE_MAX = 50_000`: Maximum global accumulation across all registered users on the node.
  - **Full Capacity Behavior**: If limits are reached, `mailbox_put` returns `{"type": "CHAT_ACK", "status": "mailbox_full"}` and the envelope is **dropped**. The sender receives an immediate visual failure status in the wallet UI (`× mailbox full`).
* **Lifecycle & Immediate FIFO Drain (`dq.popleft()`)**:
  - **Recipient Offline**: Transit payloads are held in node RAM.
  - **Recipient Online (`CHAT_PULL`)**: The node executes `dq.popleft()` for each retrieved message. The payload is **permanently and immediately deleted from node RAM on delivery**.
  - **Quota Reset**: The recipient's mailbox slot immediately returns to `0 / 250`.
* **Asynchronous Garbage Collection (`gc_mailboxes`)**:
  - Messages carry a time-to-live of `CFG.CHAT_TTL_S = 2 * 86400` (48 hours).
  - Background discovery loop automatically sweeps expired messages asynchronously, keeping client `CHAT_PULL` response latency minimal (sub-millisecond).
* **Privacy & Anti-Forensic Guarantee**:
  - The mailbox is **In-Memory Ephemeral (Zero Disk/LMDB Writes)**.
  - No plaintext, ciphertext, or transmission metadata is retained on storage media, ensuring high forensic privacy.

---



## 7. Graffiti Cultural Protocol Endpoints

Handles query endpoints for permanent on-chain ASCII art, posts, and comments.

1. **`GRAFFITI_GET_POSTS`**: Lists posts paginated by `limit` and `offset`.
   - Request: `{"type": "GRAFFITI_GET_POSTS", "limit": 50, "offset": 0}`
2. **`GRAFFITI_GET_COMMENTS`**: Lists on-chain threaded comments for an art ID.
   - Request: `{"type": "GRAFFITI_GET_COMMENTS", "art_id": "art_a1b2...", "limit": 50}`
3. **`GRAFFITI_GET_ART`**: Retrieves post metadata, storer information, and Merkle root for a specific art ID.
   - Request: `{"type": "GRAFFITI_GET_ART", "art_id": "art_a1b2..."}`
4. **`GRAFFITI_GET_PAYOUTS`**: Query epoch payouts for an art ID (*Reserved/Disabled*).
