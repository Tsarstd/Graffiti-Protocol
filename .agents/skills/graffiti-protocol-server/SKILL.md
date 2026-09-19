---
name: graffiti-protocol-server
description: Standard operating procedure for restarting and managing TsarChain (Graffiti-Protocol) node and network services in tmux.
---

# TsarChain Server Operations & Service Restart Procedure

Use this skill when performing operations, service restarts, and log rotation for the 5 TsarChain / Graffiti-Protocol services running on the VPS inside tmux.

---

## Prerequisites & Constraints
* All commands run inside existing tmux sessions: `node`, `archivist`, `web`, `snapshot`, `logging`.
* Working directory: `/root/project/Graffiti-Protocol`.
* Virtual environment must be activated: `source activate_env.sh`.
* **CRITICAL TMUX TARGETING RULE**: ALWAYS use exact target syntax `-t =<session>:0.0` (with `=` prefix and window/pane indices). NEVER use bare `-t node`, because `9router` runs Node.js (`node`) which can collide with `node` window names and terminate the 9router LLM gateway.

---

## Phase 1: Graceful Shutdown (Strict Order)

Send `C-c` (SIGINT) to allow in-flight LMDB transactions to flush cleanly.

1. **Web**:
   ```bash
   tmux send-keys -t =web:0.0 C-c
   ```
2. **Archivist**:
   ```bash
   tmux send-keys -t =archivist:0.0 C-c
   ```
3. **Node**:
   ```bash
   tmux send-keys -t =node:0.0 C-c
   ```
4. **Snapshot**:
   ```bash
   tmux send-keys -t =snapshot:0.0 C-c
   ```
5. **Logging**:
   ```bash
   tmux send-keys -t =logging:0.0 C-c
   ```

Wait 2-5 seconds and verify via `ps aux` that previous python processes have terminated cleanly:
```bash
ps aux | grep -E "cli_node_miner|cli_archivist|web_server|http.server 8121" | grep -v grep
```

---

## Phase 2: Log Rotation & Backup

1. Generate a timestamp directory:
   ```bash
   cd /root/project/Graffiti-Protocol
   TS=$(date +"%Y-%m-%d_%H-%M-%S")
   mkdir -p backup_logging/$TS
   ```
2. Move all `.log` files from `logging/` into `backup_logging/$TS/`:
   ```bash
   mv logging/*.log backup_logging/$TS/ 2>/dev/null || true
   ```
3. Confirm `logging/` has no leftover `.log` files so new files are cleanly generated upon startup:
   ```bash
   ls -la logging/
   ```

---

## Phase 3: Interactive Verification & Startup Flow

### Step 1: Prompt User for Node Parameters
ALWAYS confirm the following parameters before starting the node:
* **Mode**: Mining Mode (0) or Relay / Node-Only (1)
* **Miner Address**: e.g., `tsar1q5me8nctv2xjukhw65arshz6ufkpdtwqlhefqv3` or `tsar1qxd4pzxvuugjt6qawcynq6lyqzejjpwjaklpjxw`
* **Cores**: CPU threads assigned (e.g. 1)
* **RandomX Mode**: Light Mode (n) or Full Memory (y)

Launch command in `tmux: =node:0.0`:
```bash
tmux send-keys -t =node:0.0 "cd /root/project/Graffiti-Protocol && source activate_env.sh && python3 apps/cli_node_miner.py" C-m
```
Feed interactive wizard prompts sequentially using `tmux send-keys` based on user answers:
1. Select Mode: `tmux send-keys -t =node:0.0 "<mode>" C-m`
2. Wallet Address: `tmux send-keys -t =node:0.0 "<address>" C-m`
3. CPU Cores: `tmux send-keys -t =node:0.0 "<cores>" C-m`
4. RandomX Full Memory Mode [y/n]: `tmux send-keys -t =node:0.0 "<y/n>" C-m`

Wait until RPC port `38169` is active:
```bash
ss -tlpn | grep 38169
```

### Step 2: Start Archivist
* **Payout Address**: ALWAYS ask for the storage payout address (e.g., `tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07`).
* Target IP / Port: `127.0.0.1` / `38169`.

Launch command in `tmux: =archivist:0.0`:
```bash
tmux send-keys -t =archivist:0.0 "cd /root/project/Graffiti-Protocol && source activate_env.sh && python3 apps/cli_archivist.py" C-m
```
Feed wizard prompts:
1. Storage Payout Address: `tmux send-keys -t =archivist:0.0 "tsar1qzxzzf5az5guk43mf0z4d94uugat4jcejwglp07" C-m`
2. Target Host (default): `tmux send-keys -t =archivist:0.0 C-m`
3. Target RPC Port (default): `tmux send-keys -t =archivist:0.0 C-m`

Wait until port `39200` is active:
```bash
ss -tlpn | grep 39200
```

### Step 3: Start Web Server
```bash
tmux send-keys -t =web:0.0 "cd /root/project/Graffiti-Protocol && source activate_env.sh && python3 apps/web_server.py" C-m
```
Verify port `4000` is active:
```bash
ss -tlpn | grep 4000
```

### Step 4: Start Snapshot HTTP Server
```bash
tmux send-keys -t =snapshot:0.0 "cd /root/project/Graffiti-Protocol && python3 -m http.server 8121 --directory data/snapshot" C-m
```
Verify port `8121` is active:
```bash
ss -tlpn | grep 8121
```

### Step 5: Resume Logging Panes
In session `logging`:
* Pane 0.0 (`node.log`):
  ```bash
  tmux send-keys -t =logging:0.0 "cd /root/project/Graffiti-Protocol/logging && tail -n 50 -f node.log" C-m
  ```
* Pane 0.1 (`archivist.log`):
  ```bash
  tmux send-keys -t =logging:0.1 "cd /root/project/Graffiti-Protocol/logging && tail -n 50 -f archivist.log" C-m
  ```
* Pane 0.2 (`web.log`):
  ```bash
  tmux send-keys -t =logging:0.2 "cd /root/project/Graffiti-Protocol/logging && tail -n 50 -f web.log" C-m
  ```

---

## Verification Checklist
1. `ps aux | grep -E "cli_node_miner|cli_archivist|web_server|http.server 8121|9router"`: All running.
2. `ss -tlpn | grep -E "38169|39200|4000|8121|20128"`: All ports listening.
3. `9router` window name is preserved and unaffected.
