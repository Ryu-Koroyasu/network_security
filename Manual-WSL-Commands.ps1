# WSL2ネットワーク設定 - 手動実行用コマンド集
# PowerShellの実行ポリシーエラーが発生した場合の対処法

Write-Host "=== PowerShell実行ポリシー問題の解決方法 ===" -ForegroundColor Green

Write-Host "`n方法1: 実行ポリシーを一時的に変更" -ForegroundColor Yellow
Write-Host "以下のコマンドを順番に実行してください:" -ForegroundColor White
Write-Host "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Cyan
Write-Host "その後、再度スクリプトを実行: ./Check-WSL-Network.ps1" -ForegroundColor Cyan

Write-Host "`n方法2: バイパスして実行" -ForegroundColor Yellow
Write-Host "PowerShell -ExecutionPolicy Bypass -File ""C:\Users\koror\OneDrive\デスクトップ\Check-WSL-Network.ps1""" -ForegroundColor Cyan

Write-Host "`n方法3: 手動で各コマンドを実行" -ForegroundColor Yellow
Write-Host "以下のコマンドを順番にコピー&ペーストして実行:" -ForegroundColor White

$commands = @"

# === 手動実行用コマンド ===

# 1. WSL2のIPアドレス取得
`$wslIp = (wsl hostname -I).Trim().Split()[0]
Write-Host "WSL2 IP: `$wslIp" -ForegroundColor Green

# 2. ホストIPアドレス確認
`$hostIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi*" | Where-Object {`$_.IPAddress -like "192.168.*"}).IPAddress
if (`$hostIp) { Write-Host "ホスト IP: `$hostIp" -ForegroundColor Green } else { Write-Host "Wi-Fi IPアドレスが見つかりません" -ForegroundColor Red }

# 3. 既存ポートプロキシ削除
@(80, 443, 5000, 8080) | ForEach-Object { netsh interface portproxy delete v4tov4 listenport=`$_ listenaddress=0.0.0.0 2>`$null }

# 4. 新しいポートプロキシ設定（最重要）
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=`$wslIp
netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=80 connectaddress=`$wslIp
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=`$wslIp
netsh interface portproxy add v4tov4 listenport=5000 listenaddress=0.0.0.0 connectport=5000 connectaddress=`$wslIp

# 5. ファイアウォール設定
New-NetFirewallRule -DisplayName "WSL2-Port-8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Force
New-NetFirewallRule -DisplayName "WSL2-Port-80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Force
New-NetFirewallRule -DisplayName "WSL2-Port-443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Force
New-NetFirewallRule -DisplayName "WSL2-Port-5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow -Force

# 6. 設定確認
Write-Host "`n=== 設定確認 ===" -ForegroundColor Green
netsh interface portproxy show all
Get-NetFirewallRule -DisplayName "WSL2-Port-*" | Select-Object DisplayName, Enabled

# 7. 接続テスト
Write-Host "`n=== 接続テスト ===" -ForegroundColor Green
try { `$r = Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 5 -UseBasicParsing; Write-Host "localhost:8080 OK" -ForegroundColor Green } catch { Write-Host "localhost:8080 NG" -ForegroundColor Red }
try { `$r = Invoke-WebRequest -Uri "http://192.168.11.4:8080" -TimeoutSec 5 -UseBasicParsing; Write-Host "192.168.11.4:8080 OK" -ForegroundColor Green } catch { Write-Host "192.168.11.4:8080 NG" -ForegroundColor Red }

"@

Write-Host $commands -ForegroundColor White

Write-Host "`n=== 注意事項 ===" -ForegroundColor Red
Write-Host "- 管理者権限のPowerShellで実行してください" -ForegroundColor White
Write-Host "- WSL2のIPアドレス（`$wslIp）は正確である必要があります" -ForegroundColor White
Write-Host "- すべてのコマンドを順番に実行してください" -ForegroundColor White
