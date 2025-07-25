# WSL2 外部アクセス 緊急修正ガイド

## 📋 現在の状況
- ✅ WSL2内部でDockerコンテナは正常動作
- ✅ WSL2 IP (172.21.59.14) で内部アクセス可能
- ❌ Windows Host (192.168.11.4:8080) での外部アクセス不可
- ❌ ポートプロキシ設定が不完全

## 🚀 即座に実行する手順

### Step 1: Windows側でのポートプロキシ設定
**Windows PowerShell（管理者権限）で実行:**

```powershell
# 1. 診断スクリプト実行
./Check-WSL-Network.ps1

# 2. 手動修正（診断スクリプトが失敗した場合）
# WSL2のIPアドレス取得
$wslIp = (wsl hostname -I).Trim().Split()[0]
Write-Host "WSL2 IP: $wslIp"

# ポートプロキシ設定
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=$wslIp
netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=80 connectaddress=$wslIp
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=$wslIp

# ファイアウォール設定
New-NetFirewallRule -DisplayName "WSL2-Port-8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
New-NetFirewallRule -DisplayName "WSL2-Port-80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "WSL2-Port-443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# 設定確認
netsh interface portproxy show all
```

### Step 2: 接続テスト
**Windows PowerShell で:**
```powershell
# ローカルテスト
Invoke-WebRequest -Uri "http://localhost:8080" -TimeoutSec 5
Invoke-WebRequest -Uri "http://192.168.11.4:8080" -TimeoutSec 5
```

**WSL2内で:**
```bash
# ホストIPへの接続テスト
curl -v http://192.168.11.4:8080
```

### Step 3: 外部PCからのテスト
**他のPC（同じWi-Fiネットワーク）から:**
```bash
curl -v http://192.168.11.4:8080
# または
./quick_attack_test.py --target 192.168.11.4
```

## 🔧 トラブルシューティング

### 問題1: "接続が拒否されました"
**原因:** ポートプロキシが設定されていない  
**解決:** Step 1を再実行

### 問題2: "タイムアウト"
**原因:** Windowsファイアウォールがブロック  
**解決:** 
```powershell
# ファイアウォール無効化（テスト用）
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### 問題3: WSL IPアドレスが変わった
**原因:** WSL2再起動でIPが変更  
**解決:** 
```powershell
# 古いプロキシ削除
netsh interface portproxy reset
# 新しいIPで再設定
./Check-WSL-Network.ps1
```

### 問題4: Docker接続エラー
**解決:**
```bash
# WSL2内で
docker compose down
docker compose up -d
./check_wsl_network.sh
```

## ⚡ 今すぐ実行するコマンド

### Windows（管理者PowerShell）:
```powershell
cd C:\path\to\network
./Check-WSL-Network.ps1
```

### WSL2:
```bash
cd /home/koror/study/network
./check_wsl_network.sh
```

## 📊 動作確認チェックリスト

- [ ] Docker containers running (`docker compose ps`)
- [ ] WSL2 local access working (`curl localhost:8080`)
- [ ] Windows portproxy configured (`netsh interface portproxy show all`)
- [ ] Windows firewall rules added (`Get-NetFirewallRule -DisplayName "WSL2-Port-*"`)
- [ ] Host IP accessible from WSL2 (`curl 192.168.11.4:8080`)
- [ ] External PC can connect (`curl 192.168.11.4:8080`)
- [ ] Attack simulation working (`./quick_attack_test.py`)

## 🆘 緊急時の最終手段

1. **WSL2完全再起動:**
   ```cmd
   wsl --shutdown
   wsl
   ```

2. **Hyper-V再起動:**
   ```powershell
   Restart-Service vmcompute
   ```

3. **Windows再起動** (最後の手段)

成功すれば、192.168.11.4:8080で外部アクセスが可能になります！
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
# WSL2環境での外部アクセス設定手順

このガイドは、WSL2内のDockerコンテナに外部（他のPC）からアクセスできるようにするための手順です。

## 📋 環境情報
- **WSL IP**: 172.21.59.14
- **Host IP**: 192.168.11.4 
- **プロトコル**: WiFi接続

## 🚀 セットアップ手順

### 1. WSL内での準備（完了済み）
```bash
# セキュリティシステムの起動
cd /home/koror/study/network
docker compose up -d

# 状態確認
docker compose ps
```

### 2. Windows側での設定（要管理者権限）

Windows側で **管理者権限** でPowerShellを開いて以下を実行：

#### A. ポートフォワーディング設定
```powershell
# WSL2へのポートフォワーディング設定
$WSL_IP = "172.21.59.14"
$HOST_IP = "192.168.11.4"

# 既存設定削除（エラーが出ても問題なし）
netsh interface portproxy delete v4tov4 listenport=80 listenaddress=$HOST_IP
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=$HOST_IP  
netsh interface portproxy delete v4tov4 listenport=443 listenaddress=$HOST_IP
netsh interface portproxy delete v4tov4 listenport=5000 listenaddress=$HOST_IP

# ポートフォワーディング追加
netsh interface portproxy add v4tov4 listenport=80 listenaddress=$HOST_IP connectport=80 connectaddress=$WSL_IP
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$HOST_IP connectport=8080 connectaddress=$WSL_IP
netsh interface portproxy add v4tov4 listenport=443 listenaddress=$HOST_IP connectport=443 connectaddress=$WSL_IP
netsh interface portproxy add v4tov4 listenport=5000 listenaddress=$HOST_IP connectport=5000 connectaddress=$WSL_IP

# 設定確認
netsh interface portproxy show all
```

#### B. ファイアウォール設定
```powershell
# 既存ルール削除（エラーが出ても問題なし）
Remove-NetFirewallRule -DisplayName "WSL-HTTP-80" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "WSL-HTTP-8080" -ErrorAction SilentlyContinue  
Remove-NetFirewallRule -DisplayName "WSL-HTTPS-443" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "WSL-Flask-5000" -ErrorAction SilentlyContinue

# ファイアウォールルール追加
New-NetFirewallRule -DisplayName "WSL-HTTP-80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "WSL-HTTP-8080" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "WSL-HTTPS-443" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow  
New-NetFirewallRule -DisplayName "WSL-Flask-5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow

# ファイアウォールルール確認
Get-NetFirewallRule -DisplayName "WSL-*" | Select-Object DisplayName, Enabled, Direction, Action
```

### 3. 自動設定スクリプトの使用（推奨）

WSLプロジェクトディレクトリ内に`Setup-WSL-Network.ps1`があります：

```powershell
# Windows側で実行（管理者権限）
.\Setup-WSL-Network.ps1
```

## 🔍 接続テスト

### WSL内からのテスト
```bash
# WSL内での基本接続テスト
curl http://localhost:8080/
curl http://127.0.0.1:8080/

# クイック攻撃テスト（ホストIP向け）
python3 quick_attack_test.py 192.168.11.4 8080
```

### 他のPCからのテスト
他のPC（同一WiFiネットワーク上）から：

```bash
# 基本接続テスト
curl http://192.168.11.4:8080/

# 攻撃シミュレーション（Linux/macOS）
python3 remote_attack_tester.py --target 192.168.11.4 --port 8080

# 攻撃シミュレーション（Windows PowerShell）
.\Attack-Test.ps1 -TargetIP "192.168.11.4" -HttpPort 8080 -HttpsPort 443
```

### ブラウザでのテスト
```
http://192.168.11.4:8080/
https://192.168.11.4/ （自己署名証明書のため警告が出る）
```

## 🛠️ トラブルシューティング

### 1. ポートフォワーディングが効かない場合
```powershell
# 現在の設定確認
netsh interface portproxy show all

# WSLのIPアドレス確認（WSL内で実行）
hostname -I

# WSLのIPが変わった場合は設定し直す
```

### 2. ファイアウォールで止められる場合
```powershell
# Windows Defender ファイアウォールの無効化（一時的）
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# テスト後は有効化を忘れずに
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

### 3. 会社/学校のネットワークの場合
- ネットワーク管理者に確認
- プライベートIPアドレス範囲の制限確認
- 企業ファイアウォールの設定確認

## 📊 動作確認

正常に設定された場合、以下が観察できるはずです：

### 他のPCからのアクセス時：
1. **成功**: HTTP 200応答
2. **攻撃検出**: Fail2banがログに記録
3. **IPブロック**: 連続攻撃後にアクセス拒否（HTTP 0応答）

### WSL内での確認：
```bash
# Fail2banの状態
docker compose exec fail2ban fail2ban-client status

# Nginxログ
docker compose exec nginx tail -f /var/log/nginx/access.log

# iptablesルール
docker compose exec fail2ban iptables -L -n | grep REJECT
```

## ⚠️ 重要な注意事項

1. **セキュリティ**: この設定により外部からアクセス可能になります
2. **一時的使用**: テスト完了後はポートフォワーディングを削除することを推奨
3. **ネットワーク**: 同一WiFiネットワーク上のデバイスのみアクセス可能
4. **IP変更**: WSL再起動時にIPが変更される可能性があります

## 🔄 設定の削除

テスト完了後、設定を削除する場合：

```powershell
# ポートフォワーディング削除
netsh interface portproxy delete v4tov4 listenport=80 listenaddress=192.168.11.4
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=192.168.11.4
netsh interface portproxy delete v4tov4 listenport=443 listenaddress=192.168.11.4
netsh interface portproxy delete v4tov4 listenport=5000 listenaddress=192.168.11.4

# ファイアウォールルール削除
Remove-NetFirewallRule -DisplayName "WSL-HTTP-80"
Remove-NetFirewallRule -DisplayName "WSL-HTTP-8080"
Remove-NetFirewallRule -DisplayName "WSL-HTTPS-443"
Remove-NetFirewallRule -DisplayName "WSL-Flask-5000"
```
