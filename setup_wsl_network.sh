#!/bin/bash
# WSL2 ネットワーク設定スクリプト
# Windows側でポートフォワーディングを設定

# このスクリプトはWSL内で実行しますが、実際のポートフォワーディング設定は
# Windows側で管理者権限で実行する必要があります

WSL_IP="172.21.59.14"  # WSLのIPアドレス
HOST_IP="192.168.11.4"  # WindowsのWiFi IPアドレス

echo "=== WSL2 ネットワーク設定情報 ==="
echo "WSL IP: $WSL_IP"
echo "Host IP: $HOST_IP"
echo ""

echo "Windows側で以下のコマンドを管理者権限のPowerShellで実行してください："
echo ""
echo "# 外部からWSLへのポートフォワーディング設定"
echo "netsh interface portproxy add v4tov4 listenport=80 listenaddress=$HOST_IP connectport=80 connectaddress=$WSL_IP"
echo "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$HOST_IP connectport=8080 connectaddress=$WSL_IP"
echo "netsh interface portproxy add v4tov4 listenport=443 listenaddress=$HOST_IP connectport=443 connectaddress=$WSL_IP"
echo "netsh interface portproxy add v4tov4 listenport=5000 listenaddress=$HOST_IP connectport=5000 connectaddress=$WSL_IP"
echo ""
echo "# 設定確認"
echo "netsh interface portproxy show all"
echo ""
echo "# Windowsファイアウォール設定（必要に応じて）"
echo "New-NetFirewallRule -DisplayName 'WSL HTTP' -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow"
echo "New-NetFirewallRule -DisplayName 'WSL HTTP Alt' -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow"
echo "New-NetFirewallRule -DisplayName 'WSL HTTPS' -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow"
echo "New-NetFirewallRule -DisplayName 'WSL Flask' -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow"
echo ""

# WSL内での確認
echo "=== WSL内での現在の状況 ==="
echo "WSL IP アドレス:"
hostname -I

echo ""
echo "Docker コンテナ状態:"
docker compose ps

echo ""
echo "ポート使用状況:"
netstat -tlnp | grep -E ':(80|443|8080|5000)' || echo "指定ポートでリスニングしているプロセスがありません"
