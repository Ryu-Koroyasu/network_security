# IPS/IDS 検証ガイド

SuricataとFail2banで構築したIPS/IDSシステムの検証方法について説明します。

## 🚀 システム起動

```bash
# システム全体を起動
docker-compose up -d

# ログを確認
docker-compose logs -f
```

## 🧪 検証スクリプト

### 1. メイン検証スクリプト (`test_ips_ids.py`)

包括的なシステム検証を行います：

```bash
# 基本的な検証実行
python3 test_ips_ids.py

# システム起動も含めて実行
python3 test_ips_ids.py --start
```

**実行される検証項目：**
- コンテナ起動状態の確認
- 基本的な接続テスト
- Suricata検知テスト（curlユーザーエージェント）
- HTTPパスアクセス検知テスト
- Fail2banブロック機能テスト
- iptablesルール確認
- ログ出力確認

### 2. 攻撃シミュレーター (`attack_simulator.py`)

様々な攻撃パターンをシミュレートします：

```bash
# 包括的な攻撃シミュレーション
python3 attack_simulator.py all

# 個別の攻撃タイプ
python3 attack_simulator.py curl      # curlユーザーエージェント攻撃
python3 attack_simulator.py path      # パストラバーサル攻撃
python3 attack_simulator.py sql       # SQLインジェクション攻撃
python3 attack_simulator.py brute     # ブルートフォース攻撃
python3 attack_simulator.py dos       # DoS攻撃（軽微）
```

### 3. リアルタイムログモニター (`log_monitor.py`)

SuricataとFail2banのログをリアルタイムで監視します：

```bash
# 60秒間監視（デフォルト）
python3 log_monitor.py

# 指定時間監視（例：120秒）
python3 log_monitor.py 120
```

## 📊 手動検証方法

### curlを使った攻撃シミュレーション

```bash
# Suricataルールに引っかかるリクエスト
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/

# 複数回実行してFail2banをトリガー
for i in {1..5}; do
  curl -H "User-Agent: curl/7.68.0" http://localhost:8080/test
  sleep 1
done
```

### ブラウザでの検証

以下のURLにアクセスしてSuricataの反応を確認：

- `http://localhost:8080/test` - テストエンドポイント
- `http://localhost:8080/admin` - 管理者エンドポイント
- `http://localhost:8080/api/data` - APIエンドポイント
- `http://localhost:8080/search?q=test` - 検索エンドポイント

### SQLインジェクション攻撃のテスト

```bash
# SQLインジェクションペイロード
curl "http://localhost:8080/search?q=test' OR '1'='1"
curl "http://localhost:8080/search?q=admin' UNION SELECT * FROM users--"
```

## 🔍 ログの確認方法

### Suricataログの確認

```bash
# リアルタイムでアラートログを監視
docker exec suricata_ids tail -f /var/log/suricata/eve.json

# 最新のアラートを確認
docker exec suricata_ids tail -20 /var/log/suricata/eve.json | grep alert
```

### Fail2banログの確認

```bash
# Fail2banのログを確認
docker exec fail2ban_ips tail -f /var/log/fail2ban/fail2ban.log

# 現在のBANリストを確認
docker exec fail2ban_ips fail2ban-client status suricata-alerts
```

### iptablesルールの確認

```bash
# 現在のiptablesルールを確認
docker exec fail2ban_ips iptables -L -n --line-numbers

# Fail2banが作成したチェーンを確認
docker exec fail2ban_ips iptables -L f2b-suricata-alerts -n
```

## 📈 期待される結果

### 正常動作時の期待値：

1. **Suricata検知**
   - curlユーザーエージェントでアラート発生
   - `/test`パスアクセスでアラート発生
   - SQLインジェクション試行でアラート発生

2. **Fail2ban動作**
   - 複数回のアラートでIPアドレスがBAN
   - iptablesにブロックルールが追加
   - 指定時間後に自動UNBAN

3. **システム連携**
   - Suricataのアラート → Fail2banでの検知 → iptablesでのブロック

## 🛠️ トラブルシューティング

### コンテナが起動しない場合

```bash
# コンテナの状態を確認
docker-compose ps

# ログでエラーを確認
docker-compose logs [container_name]

# 個別にコンテナを起動してデバッグ
docker-compose up [service_name]
```

### Suricataが検知しない場合

```bash
# Suricataの設定を確認
docker exec suricata_ids suricata --dump-config

# ルールファイルの構文チェック
docker exec suricata_ids suricata -T -c /etc/suricata/suricata.yaml
```

### Fail2banが動作しない場合

```bash
# Fail2banの状態を確認
docker exec fail2ban_ips fail2ban-client status

# ログファイルのパーミッションを確認
docker exec fail2ban_ips ls -la /var/log/suricata/

# フィルターテスト
docker exec fail2ban_ips fail2ban-regex /var/log/suricata/eve.json /etc/fail2ban/filter.d/suricata.conf
```

## 🔧 設定のカスタマイズ

### Suricataルールの追加

`suricata/rules/local.rules`にカスタムルールを追加：

```bash
# 例：特定のIPアドレスを監視
alert tcp 192.168.1.100 any -> any any (msg:"Suspicious IP"; sid:9000001; rev:1;)
```

### Fail2ban設定の調整

`fail2ban/jail.local`でBANの条件を調整：

```ini
# より厳しい設定
maxretry = 1
findtime = 60
bantime = 3600
```

## 📝 検証レポートの例

```
=== IPS/IDS 検証結果 ===
日時: 2025-06-30 12:00:00
システム構成: Suricata + Fail2ban + Nginx + Flask

✅ コンテナ起動確認: PASS
✅ 基本接続テスト: PASS  
✅ Suricata検知テスト: PASS (curl攻撃検知)
✅ Fail2banブロックテスト: PASS (IP BAN実行)
✅ iptablesルール確認: PASS

検知されたアラート数: 15
ブロックされたIP数: 2
システム稼働時間: 30分

結論: IPS/IDSシステムは正常に動作している
```

## 🚨 重要な注意事項

1. **テスト環境での実行**: 本番環境では実行しないでください
2. **リソース監視**: DoS攻撃テストはシステムリソースを消費します
3. **ネットワーク設定**: Docker networkの設定によっては動作が異なる場合があります
4. **権限**: Fail2banはiptables操作のため特権が必要です

## 📚 参考資料

- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Fail2ban Manual](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Docker Compose Network Guide](https://docs.docker.com/compose/networking/)
