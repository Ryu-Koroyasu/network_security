# Windows側でWSL2のネットワーク設定を確認・修正するスクリプト
# 管理者権限で実行してください

Write-Host "=== WSL2 ネットワーク診断 & 修正スクリプト ===" -ForegroundColor Green

# 1. 現在のネットワーク設定を確認
Write-Host "`n1. 現在のポートプロキシ設定:" -ForegroundColor Yellow
try {
    $proxies = netsh interface portproxy show all
    if ($proxies -match "8080") {
        Write-Host $proxies -ForegroundColor Green
    } else {
        Write-Host "ポートプロキシが設定されていません" -ForegroundColor Red
    }
} catch {
    Write-Host "ポートプロキシの確認に失敗しました" -ForegroundColor Red
}

# 2. WSL2のIPアドレスを取得
Write-Host "`n2. WSL2のIPアドレス取得:" -ForegroundColor Yellow
try {
    $wslIp = (wsl hostname -I).Trim().Split()[0]
    Write-Host "WSL2 IP: $wslIp" -ForegroundColor Green
} catch {
    Write-Host "WSL2のIPアドレス取得に失敗しました" -ForegroundColor Red
    exit 1
}

# 3. ホストのIPアドレスを確認
Write-Host "`n3. ホストIPアドレス:" -ForegroundColor Yellow
$hostIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" | Where-Object {$_.IPAddress -like "192.168.*"}).IPAddress
if ($hostIp) {
    Write-Host "ホスト IP: $hostIp" -ForegroundColor Green
} else {
    Write-Host "Wi-Fi IPアドレスが見つかりません" -ForegroundColor Red
}

# 4. 既存のポートプロキシを削除
Write-Host "`n4. 既存のポートプロキシを削除中..." -ForegroundColor Yellow
@(80, 443, 5000, 8080) | ForEach-Object {
    netsh interface portproxy delete v4tov4 listenport=$_ listenaddress=0.0.0.0 2>$null
    netsh interface portproxy delete v4tov4 listenport=$_ listenaddress=$hostIp 2>$null
    netsh interface portproxy delete v4tov4 listenport=$_ listenaddress=192.168.11.4 2>$null
}

# 5. 新しいポートプロキシを設定
Write-Host "`n5. 新しいポートプロキシを設定中..." -ForegroundColor Yellow
$ports = @(80, 443, 5000, 8080)
foreach ($port in $ports) {
    $result = netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIp
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ ポート $port のプロキシ設定完了" -ForegroundColor Green
    } else {
        Write-Host "✗ ポート $port のプロキシ設定失敗: $result" -ForegroundColor Red
    }
}

# 6. ファイアウォール設定
Write-Host "`n6. Windowsファイアウォール設定..." -ForegroundColor Yellow
foreach ($port in $ports) {
    try {
        # 既存のルールを削除
        Remove-NetFirewallRule -DisplayName "WSL2-Port-$port" -ErrorAction SilentlyContinue
        
        # 新しいルールを追加
        New-NetFirewallRule -DisplayName "WSL2-Port-$port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
        Write-Host "✓ ポート $port のファイアウォール設定完了" -ForegroundColor Green
    } catch {
        Write-Host "✗ ポート $port のファイアウォール設定失敗" -ForegroundColor Red
    }
}

# 7. 設定後の確認
Write-Host "`n7. 設定後の確認:" -ForegroundColor Yellow
Write-Host "ポートプロキシ設定:" -ForegroundColor Cyan
netsh interface portproxy show all

Write-Host "`nファイアウォールルール:" -ForegroundColor Cyan
Get-NetFirewallRule -DisplayName "WSL2-Port-*" | Select-Object DisplayName, Enabled, Direction, Action

# 8. 接続テスト
Write-Host "`n8. 接続テスト..." -ForegroundColor Yellow
$testUrls = @(
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://$hostIp:8080"
)

foreach ($url in $testUrls) {
    try {
        $response = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing
        Write-Host "✓ $url : 接続成功 (Status: $($response.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "✗ $url : 接続失敗 ($($_.Exception.Message))" -ForegroundColor Red
    }
}

# 9. 追加の診断情報
Write-Host "`n9. 追加の診断情報:" -ForegroundColor Yellow
Write-Host "WSL2サービス状態:" -ForegroundColor Cyan
Get-Service LxssManager | Select-Object Name, Status

Write-Host "`nHyper-V関連サービス:" -ForegroundColor Cyan
Get-Service | Where-Object {$_.Name -like "*Hyper*" -or $_.Name -like "*vmcompute*"} | Select-Object Name, Status

Write-Host "`n=== 診断完了 ===" -ForegroundColor Green
Write-Host "問題が解決しない場合:" -ForegroundColor Yellow
Write-Host "1. WSLを再起動: wsl --shutdown; wsl" -ForegroundColor White
Write-Host "2. Dockerコンテナを再起動" -ForegroundColor White
Write-Host "3. Windows再起動を検討" -ForegroundColor White
