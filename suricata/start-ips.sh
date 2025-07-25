#!/bin/bash
# start-ips.sh - Suricata IPS mode startup script

set -e

echo "Starting Suricata in IPS mode..."

# IPTables設定：HTTPトラフィックをNFQUEUEに送信
echo "Setting up iptables rules for IPS mode..."

# 受信トラフィック（HTTP/HTTPS）をNFQUEUEに送信
iptables -t filter -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -t filter -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -t filter -A FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 0
iptables -t filter -A FORWARD -p tcp --sport 443 -j NFQUEUE --queue-num 0

# 入力チェーン用（コンテナ内トラフィック）
iptables -t filter -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -t filter -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0

# 出力チェーン用
iptables -t filter -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
iptables -t filter -A OUTPUT -p tcp --sport 443 -j NFQUEUE --queue-num 0

echo "IPTables rules configured."

# Suricataをインラインモード（NFQUEUE）で起動
echo "Starting Suricata with NFQUEUE mode..."
exec suricata -c /etc/suricata/suricata.yaml -q 0 --runmode autofp -v
