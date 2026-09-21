#!/usr/bin/env bash
set -e

# TsarChain — Sovereign Coturn STUN/TURN Setup Script
# Configures Coturn for WebRTC Voice & Video Calls on VPS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==>${NC} ${GREEN}TsarChain Coturn STUN/TURN Setup${NC}"

# Parameters with defaults
DETECTED_IP=$(curl -s --max-time 5 https://api.ipify.org || curl -s --max-time 5 https://ifconfig.me || echo "38.253.224.105")
PUBLIC_IP="${1:-$DETECTED_IP}"
TURN_USER="${2:-kremlin}"
TURN_PASS="${3:-kremlincall2026}"
TURN_PORT="${4:-3478}"

echo -e "${YELLOW}Server Configuration:${NC}"
echo -e "  Public IP    : ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  TURN User    : ${GREEN}${TURN_USER}${NC}"
echo -e "  TURN Port    : ${GREEN}${TURN_PORT}${NC}"
echo -e "  Realm        : ${GREEN}${PUBLIC_IP}${NC}"
echo ""

# 1. Install Coturn
echo -e "${BLUE}1/4: Checking and installing coturn...${NC}"
if ! command -v turnserver >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y coturn
else
    echo "Coturn is already installed."
fi

# 2. Enable daemon in /etc/default/coturn
echo -e "${BLUE}2/4: Enabling Coturn daemon in /etc/default/coturn...${NC}"
sudo sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn

# 3. Generate /etc/turnserver.conf
echo -e "${BLUE}3/4: Writing /etc/turnserver.conf...${NC}"
sudo tee /etc/turnserver.conf >/dev/null <<EOF
# Network and IP
listening-port=${TURN_PORT}
listening-ip=0.0.0.0
external-ip=${PUBLIC_IP}

# Range Port Media UDP (P2P Relay)
min-port=49152
max-port=49252

# Required for WebRTC
fingerprint
lt-cred-mech
realm=${PUBLIC_IP}

# Mobile App Credentials
user=${TURN_USER}:${TURN_PASS}

# Security & Quota Rate Limiting
user-quota=10
total-quota=100
max-bps=196608
no-multicast-peers

# Security and Optimization
no-cli
no-tls
no-dtls

# Logging
log-file=/var/log/turnserver.log
simple-log
verbose
EOF

# 4. Restart and Enable Service
echo -e "${BLUE}4/4: Starting Coturn service...${NC}"
sudo systemctl daemon-reload
sudo systemctl restart coturn
sudo systemctl enable coturn

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}Coturn STUN/TURN service is active and running!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "To configure Flutter (mobile app), insert into iceServers:"
echo ""
echo -e "${YELLOW}{"
echo -e "  'urls': ["
echo -e "    'stun:${PUBLIC_IP}:${TURN_PORT}',"
echo -e "    'turn:${PUBLIC_IP}:${TURN_PORT}',"
echo -e "  ],"
echo -e "  'username': '${TURN_USER}',"
echo -e "  'credential': '***',"
echo -e "}${NC}"
echo ""
EOF
