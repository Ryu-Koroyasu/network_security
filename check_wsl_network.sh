#!/bin/bash

echo "=== WSL2 ネットワーク診断スクリプト ==="

# 色付きメッセージ用の関数
red() { echo -e "\033[31m$1\033[0m"; }
green() { echo -e "\033[32m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; }
blue() { echo -e "\033[34m$1\033[0m"; }

echo
yellow "1. 基本ネットワーク情報:"
echo "WSL2 IP アドレス:"
hostname -I
echo "デフォルトゲートウェイ:"
ip route | grep default

echo
yellow "2. Dockerコンテナ状態:"
if command -v docker &> /dev/null; then
    docker compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"
else
    red "Docker not found"
fi

echo
yellow "3. ローカル接続テスト:"
WSL_IP=$(hostname -I | awk '{print $1}')
echo "WSL IP: $WSL_IP"

# ローカル接続テスト
test_connection() {
    local url=$1
    local name=$2
    if timeout 5 curl -s "$url" > /dev/null 2>&1; then
        green "✓ $name: 接続成功"
    else
        red "✗ $name: 接続失敗"
    fi
}

test_connection "http://localhost:8080" "localhost:8080"
test_connection "http://127.0.0.1:8080" "127.0.0.1:8080"
test_connection "http://$WSL_IP:8080" "WSL IP:8080"

echo
yellow "4. Windows ホストへの接続テスト:"
# デフォルトゲートウェイ（通常はWindowsホスト）を取得
WINDOWS_HOST=$(ip route | grep default | awk '{print $3}')
echo "Windows Host IP: $WINDOWS_HOST"

test_connection "http://$WINDOWS_HOST:8080" "Windows Host:8080"

# 明示的に192.168.11.4もテスト
if [ "$WINDOWS_HOST" != "192.168.11.4" ]; then
    test_connection "http://192.168.11.4:8080" "192.168.11.4:8080"
fi

echo
yellow "5. ポート待機状態確認:"
echo "WSL2内でのポート待機状態:"
ss -tlnp | grep -E ':(80|443|5000|8080)'

echo
yellow "6. ネットワーク経路確認:"
echo "192.168.11.4への経路:"
if command -v traceroute &> /dev/null; then
    timeout 10 traceroute -m 3 192.168.11.4 2>/dev/null || echo "tracerouteタイムアウト"
else
    echo "traceroute not installed"
fi

echo
yellow "7. DNS解決確認:"
nslookup 192.168.11.4 2>/dev/null || echo "DNS解決できません"

echo
yellow "8. Windows側で実行すべきコマンド:"
blue "以下のコマンドをWindows側で管理者権限で実行してください:"
echo "1. PowerShellで診断スクリプトを実行:"
echo "   ./Check-WSL-Network.ps1"
echo
echo "2. 手動でポートプロキシを設定:"
echo "   netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=$WSL_IP"
echo
echo "3. ファイアウォールを確認:"
echo "   Get-NetFirewallRule -DisplayName \"WSL2-Port-*\""

echo
yellow "9. トラブルシューティングのヒント:"
echo "- WSL2のIPアドレスは起動の度に変わる可能性があります"
echo "- Windows側のポートプロキシ設定は正確なWSL IPを指定する必要があります"
echo "- Windowsファイアウォールが8080ポートを許可している必要があります"
echo "- 一部のアンチウイルスソフトがネットワーク接続をブロックする場合があります"

echo
green "=== 診断完了 ==="
