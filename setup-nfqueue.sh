#!/bin/bash
# setup-nfqueue.sh - NFQUEUEルールの設定

echo "Setting up NFQUEUE rules for Suricata IPS..."

# 既存のNFQUEUEルールをクリア
echo "Clearing existing NFQUEUE rules..."
sudo iptables -D INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0 2>/dev/null
sudo iptables -D OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0 2>/dev/null
sudo iptables -D FORWARD -p tcp --dport 8080 -j NFQUEUE --queue-num 0 2>/dev/null

# 新しいNFQUEUEルールを追加
echo "Adding NFQUEUE rules for port 8080 (Nginx)..."

# Inbound traffic to Nginx (port 8080)
sudo iptables -I INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0

# Outbound traffic from Nginx
sudo iptables -I OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0

# Forward traffic (Docker bridge)
sudo iptables -I FORWARD -p tcp --dport 8080 -j NFQUEUE --queue-num 0

echo "NFQUEUE rules configured successfully:"
sudo iptables -L | grep NFQUEUE

echo ""
echo "Starting Suricata in IPS mode..."
echo "Traffic to port 8080 will now be processed by Suricata."
echo ""
echo "To remove NFQUEUE rules later, run:"
echo "  sudo iptables -D INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0"
echo "  sudo iptables -D OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0"
echo "  sudo iptables -D FORWARD -p tcp --dport 8080 -j NFQUEUE --queue-num 0"
