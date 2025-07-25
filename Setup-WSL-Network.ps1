# Windows PowerShell スクリプト（管理者権限で実行）
# WSL2への外部アクセスを有効にするためのポートフォワーディング設定

param(
    [string]$WSL_IP = "172.21.59.14",
    [string]$HOST_IP = "192.168.11.4"
)

Write-Host "=== WSL2 外部アクセス設定 ===" -ForegroundColor Green
Write-Host "WSL IP: $WSL_IP"
Write-Host "Host IP: $HOST_IP"

# 管理者権限チェック
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "このスクリプトは管理者権限で実行する必要があります。" -ForegroundColor Red
    Write-Host "PowerShellを管理者として再実行してください。" -ForegroundColor Red
    exit 1
}

Write-Host "`n--- 既存のポートプロキシ設定を削除 ---" -ForegroundColor Yellow
try {
    netsh interface portproxy delete v4tov4 listenport=80 listenaddress=$HOST_IP
    netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=$HOST_IP
    netsh interface portproxy delete v4tov4 listenport=443 listenaddress=$HOST_IP
    netsh interface portproxy delete v4tov4 listenport=5000 listenaddress=$HOST_IP
} catch {
    Write-Host "既存設定の削除中にエラーが発生しましたが、続行します。" -ForegroundColor Yellow
}

Write-Host "`n--- ポートフォワーディング設定 ---" -ForegroundColor Yellow

# HTTP (80)
Write-Host "HTTP ポート 80 を設定中..."
netsh interface portproxy add v4tov4 listenport=80 listenaddress=$HOST_IP connectport=80 connectaddress=$WSL_IP

# HTTP Alternative (8080)
Write-Host "HTTP代替 ポート 8080 を設定中..."
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$HOST_IP connectport=8080 connectaddress=$WSL_IP

# HTTPS (443)
Write-Host "HTTPS ポート 443 を設定中..."
netsh interface portproxy add v4tov4 listenport=443 listenaddress=$HOST_IP connectport=443 connectaddress=$WSL_IP

# Flask App (5000)
Write-Host "Flask ポート 5000 を設定中..."
netsh interface portproxy add v4tov4 listenport=5000 listenaddress=$HOST_IP connectport=5000 connectaddress=$WSL_IP

Write-Host "`n--- Windowsファイアウォール設定 ---" -ForegroundColor Yellow

# ファイアウォールルール作成
$rules = @(
    @{Name="WSL-HTTP-80"; Port=80; Description="WSL2 HTTP Access"},
    @{Name="WSL-HTTP-8080"; Port=8080; Description="WSL2 HTTP Alternative Access"},
    @{Name="WSL-HTTPS-443"; Port=443; Description="WSL2 HTTPS Access"},
    @{Name="WSL-Flask-5000"; Port=5000; Description="WSL2 Flask App Access"}
)

foreach ($rule in $rules) {
    Write-Host "ファイアウォールルール '$($rule.Name)' を設定中..."
    
    # 既存ルール削除
    try {
        Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    } catch {}
    
    # 新規ルール追加
    New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -LocalPort $rule.Port -Protocol TCP -Action Allow -Description $rule.Description
}

Write-Host "`n--- 設定確認 ---" -ForegroundColor Green

Write-Host "ポートプロキシ設定:"
netsh interface portproxy show all

Write-Host "`nファイアウォールルール:"
Get-NetFirewallRule -DisplayName "WSL-*" | Select-Object DisplayName, Enabled, Direction, Action

Write-Host "`n--- 接続テスト用のURL ---" -ForegroundColor Cyan
Write-Host "HTTP: http://$HOST_IP:8080/"
Write-Host "HTTPS: https://$HOST_IP/"
Write-Host "Flask直接: http://$HOST_IP:5000/"

Write-Host "`n--- 他のPCからのテスト方法 ---" -ForegroundColor Cyan
Write-Host "1. 他のPCから以下のURLにアクセス:"
Write-Host "   http://$HOST_IP:8080/"
Write-Host ""
Write-Host "2. 攻撃テストスクリプトを実行:"
Write-Host "   python remote_attack_tester.py --target $HOST_IP --port 8080"
Write-Host ""

Write-Host "設定完了！" -ForegroundColor Green
Write-Host "注意: WSLを再起動した場合、WSL_IPが変更される可能性があります。" -ForegroundColor Yellow
Write-Host "その場合は新しいIPアドレスでこのスクリプトを再実行してください。" -ForegroundColor Yellow
