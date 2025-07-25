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
