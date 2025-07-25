#!/bin/bash
# 簡易攻撃テストスクリプト
# 他のPCからの攻撃をシミュレートするためのbashスクリプト

TARGET_IP="${1:-localhost}"
HTTP_PORT="${2:-8080}"
HTTPS_PORT="${3:-443}"

if [ "$TARGET_IP" = "localhost" ]; then
    echo "使用方法: $0 <TARGET_IP> [HTTP_PORT] [HTTPS_PORT]"
    echo "例: $0 192.168.1.100 8080 443"
    exit 1
fi

BASE_URL_HTTP="http://${TARGET_IP}:${HTTP_PORT}"
BASE_URL_HTTPS="https://${TARGET_IP}:${HTTPS_PORT}"

echo "🚀 簡易攻撃テスト開始"
echo "ターゲット: $TARGET_IP"
echo "HTTP URL: $BASE_URL_HTTP"
echo "HTTPS URL: $BASE_URL_HTTPS"
echo "================================"

# ログファイル
LOG_FILE="attack_test_$(date +%Y%m%d_%H%M%S).log"

# ログ関数
log_attack() {
    local attack_type="$1"
    local url="$2"
    local response_code="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $attack_type: $url -> $response_code" | tee -a "$LOG_FILE"
}

# 基本接続テスト
echo "🔍 基本接続テスト..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL_HTTP" 2>/dev/null || echo "000")
log_attack "Basic Connection" "$BASE_URL_HTTP" "$response"

if [ "$response" = "000" ]; then
    echo "⚠️  警告: ターゲットに接続できません"
    exit 1
fi

# SQLインジェクション攻撃
echo "🎯 SQLインジェクション攻撃..."
sql_payloads=(
    "1' OR '1'='1"
    "1; DROP TABLE users--"
    "1 UNION SELECT * FROM users"
    "admin'--"
    "' OR 'a'='a"
)

for payload in "${sql_payloads[@]}"; do
    encoded_payload=$(printf '%s' "$payload" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c3-)
    url="${BASE_URL_HTTP}?id=${encoded_payload}"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    log_attack "SQL Injection" "$url" "$response"
    sleep 0.5
done

# パストラバーサル攻撃
echo "🎯 パストラバーサル攻撃..."
path_payloads=(
    "../../../etc/passwd"
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "....//....//....//etc/passwd"
)

for payload in "${path_payloads[@]}"; do
    encoded_payload=$(printf '%s' "$payload" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c3-)
    url="${BASE_URL_HTTP}?file=${encoded_payload}"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    log_attack "Path Traversal" "$url" "$response"
    sleep 0.5
done

# 悪意のあるUser-Agent
echo "🎯 悪意のあるUser-Agent攻撃..."
malicious_uas=(
    "sqlmap/1.0"
    "Nikto/2.1.6"
    "w3af.org"
    "Nessus"
    "python-requests/2.25.1 (scanner)"
)

for ua in "${malicious_uas[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: $ua" "$BASE_URL_HTTP" 2>/dev/null || echo "000")
    log_attack "Malicious User-Agent" "$BASE_URL_HTTP (UA: $ua)" "$response"
    sleep 0.5
done

# 404スキャン攻撃
echo "🎯 404スキャン攻撃..."
scan_paths=(
    "/admin"
    "/phpmyadmin"
    "/backup"
    "/config.php"
    "/wp-admin"
    "/login"
    "/shell.php"
    "/cmd.php"
)

for path in "${scan_paths[@]}"; do
    url="${BASE_URL_HTTP}${path}"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    log_attack "404 Scan" "$url" "$response"
    sleep 0.2
done

# XSS攻撃
echo "🎯 XSS攻撃..."
xss_payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "javascript:alert('XSS')"
)

for payload in "${xss_payloads[@]}"; do
    encoded_payload=$(printf '%s' "$payload" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c3-)
    url="${BASE_URL_HTTP}?q=${encoded_payload}"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    log_attack "XSS Attack" "$url" "$response"
    sleep 0.5
done

# DoS攻撃（軽量版）
echo "🎯 DoS攻撃（10秒間）..."
end_time=$(($(date +%s) + 10))
dos_count=0
while [ $(date +%s) -lt $end_time ]; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL_HTTP" 2>/dev/null || echo "000")
    ((dos_count++))
    if [ $((dos_count % 10)) -eq 0 ]; then
        log_attack "DoS Attack" "$BASE_URL_HTTP (request #$dos_count)" "$response"
    fi
    sleep 0.1
done

# HTTPS攻撃テスト
echo "🎯 HTTPS攻撃テスト..."
response=$(curl -s -o /dev/null -w "%{http_code}" -k "$BASE_URL_HTTPS" 2>/dev/null || echo "000")
log_attack "HTTPS Test" "$BASE_URL_HTTPS" "$response"

echo "================================"
echo "✅ 攻撃テスト完了"
echo "📄 ログファイル: $LOG_FILE"
echo ""
echo "📊 結果サマリー:"
echo "総リクエスト数: $(wc -l < "$LOG_FILE")"
echo "ブロック数 (000): $(grep -c ' 000$' "$LOG_FILE")"
echo "404エラー: $(grep -c ' 404$' "$LOG_FILE")"
echo "成功 (200): $(grep -c ' 200$' "$LOG_FILE")"
echo ""
echo "詳細は $LOG_FILE を確認してください。"
