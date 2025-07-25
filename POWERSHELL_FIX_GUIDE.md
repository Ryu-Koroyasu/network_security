# WSL2ネットワーク設定 - 緊急用ワンライナーコマンド

## 🚨 PowerShell実行ポリシーエラーの解決方法

### 最も簡単な解決方法（推奨）
**Windows PowerShell（管理者権限）で以下を実行:**

```powershell
# 実行ポリシーを一時的に変更
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# その後、スクリプトを実行
./Check-WSL-Network.ps1
```

### 代替方法1: バイパス実行
```powershell
PowerShell -ExecutionPolicy Bypass -File "C:\Users\koror\OneDrive\デスクトップ\Check-WSL-Network.ps1"
```

### 代替方法2: 手動コマンド実行
**以下のコマンドを管理者PowerShellで順番に実行:**

```powershell
# 1. WSL2 IP取得
$wslIp = (wsl hostname -I).Trim().Split()[0]; Write-Host "WSL2 IP: $wslIp" -ForegroundColor Green

# 2. 既存プロキシ削除
@(80, 443, 5000, 8080) | ForEach-Object { netsh interface portproxy delete v4tov4 listenport=$_ listenaddress=0.0.0.0 2>$null }

# 3. ポートプロキシ設定（最重要）
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=$wslIp
netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=80 connectaddress=$wslIp
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=$wslIp

# 4. ファイアウォール設定
New-NetFirewallRule -DisplayName "WSL2-Port-8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Force
New-NetFirewallRule -DisplayName "WSL2-Port-80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Force
New-NetFirewallRule -DisplayName "WSL2-Port-443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Force

# 5. 設定確認
netsh interface portproxy show all
Get-NetFirewallRule -DisplayName "WSL2-Port-*" | Select-Object DisplayName, Enabled

# 6. 接続テスト
Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 5 -UseBasicParsing
Invoke-WebRequest -Uri "http://192.168.11.4:8080" -TimeoutSec 5 -UseBasicParsing
```

### 代替方法3: CMD経由での実行
```cmd
powershell -ExecutionPolicy Bypass -Command "& {[WSL2設定コマンド]}"
```

## ⚡ 最速解決手順

1. **Windows キー + X** → **Windows PowerShell (管理者)**を選択
2. 以下をコピー&ペースト実行:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
   ```
3. 「Y」を入力してEnter
4. 元のスクリプトを再実行:
   ```powershell
   ./Check-WSL-Network.ps1
   ```

## 🔍 実行ポリシーについて

- **Restricted**: デフォルト、スクリプト実行不可
- **RemoteSigned**: ローカルスクリプトは実行可能
- **Unrestricted**: すべてのスクリプト実行可能（非推奨）

現在の設定確認:
```powershell
Get-ExecutionPolicy
```

## 📋 トラブルシューティング

### エラー: "UnauthorizedAccess"
- 管理者権限で実行していない
- 実行ポリシーが制限されている

### エラー: "wsl command not found"
- WSL2がインストールされていない
- WSLサービスが停止している

### エラー: "netsh access denied"
- 管理者権限で実行していない
- UACが有効になっている

解決後、192.168.11.4:8080でアクセス可能になります！
