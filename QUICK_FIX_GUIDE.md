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
