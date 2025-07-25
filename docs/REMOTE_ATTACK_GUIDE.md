# リモート攻撃テストガイド

このディレクトリには、他のPCからセキュリティシステムをテストするためのツールが含まれています。

## 📋 ファイル一覧

1. **remote_attack_tester.py** - Python製の包括的攻撃テストツール
2. **simple_attack_test.sh** - Bash製の簡易攻撃テストスクリプト
3. **Attack-Test.ps1** - Windows PowerShell製攻撃テストスクリプト

## 🔧 セットアップ手順

### 1. サーバー側（セキュリティシステム）の準備

まず、攻撃対象となるサーバーの設定を確認します：

```bash
# コンテナの状態確認
docker compose ps

# サーバーのIPアドレス確認
ip addr show | grep inet

# ファイアウォールの設定確認（必要に応じて）
sudo ufw status

# ポートが開いているか確認
sudo netstat -tulpn | grep -E ':(80|443|8080)'
```

### 2. ネットワーク設定

サーバーが他のPCからアクセス可能であることを確認：

```bash
# 外部からのアクセスを許可（必要に応じて）
sudo ufw allow 8080/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Docker Compose設定でポートバインディング確認
grep -A 5 -B 5 "ports:" docker-compose.yml
```

## 🚀 攻撃テストの実行方法

### Python版（推奨）

```bash
# 依存関係のインストール
pip3 install requests

# 基本的な使用方法
python3 remote_attack_tester.py --target 192.168.1.100

# 特定のポートを指定
python3 remote_attack_tester.py --target 192.168.1.100 --port 8080 --https-port 443

# 特定の攻撃タイプのみ実行
python3 remote_attack_tester.py --target 192.168.1.100 --test sql
python3 remote_attack_tester.py --target 192.168.1.100 --test xss
python3 remote_attack_tester.py --target 192.168.1.100 --test dos
```

### Bash版（Linux/macOS）

```bash
# 実行権限を付与
chmod +x simple_attack_test.sh

# 実行
./simple_attack_test.sh 192.168.1.100 8080 443
```

### PowerShell版（Windows）

```powershell
# PowerShell を管理者として起動
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 実行
.\Attack-Test.ps1 -TargetIP "192.168.1.100" -HttpPort 8080 -HttpsPort 443
```

## 🎯 攻撃テストの種類

### 1. SQLインジェクション攻撃
- `1' OR '1'='1`
- `1; DROP TABLE users--`
- `1 UNION SELECT * FROM users`

### 2. クロスサイトスクリプティング（XSS）
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `javascript:alert('XSS')`

### 3. パストラバーサル攻撃
- `../../../etc/passwd`
- `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `....//....//....//etc/passwd`

### 4. 悪意のあるUser-Agent
- `sqlmap/1.0`
- `Nikto/2.1.6`
- `w3af.org`

### 5. 404スキャン攻撃
- `/admin`, `/phpmyadmin`, `/backup`
- `/config.php`, `/wp-admin`, `/login`

### 6. DoS攻撃（軽量版）
- 短時間での大量リクエスト送信

### 7. SSL/TLS攻撃
- 不正なSSLハンドシェイク
- 古いTLSバージョンでの接続試行

## 📊 結果の確認方法

### 攻撃テスト結果
- Python版: JSON形式のレポートファイルが生成されます
- Bash版: テキスト形式のログファイルが生成されます
- PowerShell版: テキスト形式のログファイルが生成されます

### サーバー側での確認

```bash
# Fail2banの状態確認
docker compose exec fail2ban fail2ban-client status

# 各ジェイルの詳細確認
docker compose exec fail2ban fail2ban-client status nginx-http-attack
docker compose exec fail2ban fail2ban-client status nginx-malicious-ua

# Nginxログの確認
docker compose exec nginx tail -f /var/log/nginx/access.log

# Suricataログの確認
docker compose exec suricata tail -f /var/log/suricata/eve.json

# iptablesルールの確認
docker compose exec fail2ban iptables -L -n
```

## 🔍 期待される結果

正常に動作している場合：

1. **攻撃検出**: Fail2banが攻撃パターンを検出
2. **IPブロック**: 攻撃者のIPアドレスがiptablesでブロック
3. **ログ記録**: 攻撃の詳細がログファイルに記録
4. **アラート生成**: Suricataが異常なトラフィックを検出

### ブロック後の現象
- HTTP応答コード: `0` (接続拒否)
- タイムアウト: リクエストが応答しない
- iptablesルール: 攻撃者IPが`REJECT`ルールに追加

## ⚠️ 注意事項

1. **合法性**: 必ず自分が所有するシステムに対してのみテストを実行してください
2. **ネットワーク負荷**: DoS攻撃テストは軽量版ですが、ネットワークに負荷をかける可能性があります
3. **ログ容量**: 大量のログが生成される可能性があるため、ディスク容量を確認してください
4. **ファイアウォール**: 企業ネットワークの場合、ファイアウォールでブロックされる可能性があります

## 🛠️ トラブルシューティング

### 接続できない場合
1. ターゲットIPアドレスとポート番号の確認
2. ファイアウォール設定の確認
3. Dockerコンテナの状態確認
4. ネットワーク設定の確認

### 攻撃が検出されない場合
1. Fail2banの設定ファイル確認
2. ログファイルのパスとアクセス権限確認
3. 正規表現パターンの確認

### ブロックされない場合
1. iptablesルールの確認
2. Dockerネットワーク設定の確認
3. Fail2banのアクション設定確認

## 📈 結果の解釈

- **ブロック率が高い**: セキュリティシステムが正常に動作
- **200応答が多い**: フィルタリング設定の見直しが必要
- **タイムアウトが多い**: ネットワーク設定に問題がある可能性

攻撃テストの結果を基に、セキュリティ設定の調整を行ってください。
