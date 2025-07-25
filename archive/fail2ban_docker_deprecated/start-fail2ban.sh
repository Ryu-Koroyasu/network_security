#!/bin/bash
# start-fail2ban.sh - Fail2ban startup script

set -e

echo "Starting Fail2ban protection system..."

# ソケットファイルのクリーンアップ
rm -f /var/run/fail2ban/fail2ban.sock
mkdir -p /var/run/fail2ban

# ログファイルの作成
touch /var/log/fail2ban/fail2ban.log

# IPTablesのセットアップを確認
echo "Checking iptables availability..."
iptables -L >/dev/null 2>&1 || {
    echo "Warning: iptables not available, fail2ban may not work properly"
}

# 設定ファイルのテスト
echo "Testing fail2ban configuration..."
fail2ban-client -t || {
    echo "Configuration test failed, please check jail.local and filter files"
    exit 1
}

echo "Configuration test passed."

# Fail2banをフォアグラウンドで起動
echo "Starting fail2ban-server in foreground mode..."
exec fail2ban-server -f
