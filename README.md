# Network Security System - Suricata IPS + Fail2ban Multi-layer Defense

## 📋 プロジェクト概要

本プロジェクトは、**Suricata IDS**と**Fail2ban**を組み合わせた多層防御システムの実装と評価を行います。Dockerコンテナ環境で動作し、リアルタイム脅威検知と自動応答機能を提供します。

### 🎯 プロジェクトの目的

- **最適なIDS/IPSシステム構成**の実装と検証
- **リアルタイム脅威検知**と**自動防御機能**の実現
- **多層防御アーキテクチャ**の効果実証
- **実際の攻撃シナリオ**による包括的システム評価

## 🏗️ システムアーキテクチャ

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx Proxy   │────│  Suricata IDS   │────│   Flask App     │
│   (Port 8080)   │    │ (22 Rules監視)  │    │   (Port 5000)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Fail2ban      │
                    │ (Auto IP Block) │
                    └─────────────────┘
```

### コンポーネント詳細

- **Nginx**: リバースプロキシ（HTTPアクセス制御）
- **Suricata**: ネットワーク侵入検知システム（22種類のセキュリティルール）
- **Fail2ban**: ホストベース侵入防止システム（自動IP遮断）
- **Flask**: バックエンドアプリケーション（攻撃対象）

## 🚀 クイックスタート

### 必要環境
- Docker & Docker Compose
- Linux OS (Ubuntu 20.04+ 推奨)
- Python 3.8+ (攻撃シミュレーション用)

### システム起動

```bash
# リポジトリクローン
git clone <repository-url>
cd network_security

# システム起動
docker-compose up -d

# 起動確認
docker ps
curl http://localhost:8080
```

### 攻撃シミュレーション実行

```bash
# Python環境設定
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install requests

# 攻撃シミュレーション実行
python advanced_attack_simulator.py
```

## 📊 実証実験結果

### 攻撃シミュレーション サマリー

| 攻撃カテゴリ | 試行回数 | 検知回数 | 成功率 |
|-------------|---------|---------|--------|
| ブルートフォース | 15 | 15 | 100.0% |
| SQLインジェクション | 6 | 6 | 100.0% |
| XSS攻撃 | 5 | 5 | 100.0% |
| ディレクトリスキャン | 14 | 14 | 100.0% |
| 悪意のあるUser-Agent | 8 | 8 | 100.0% |
| DoS攻撃 | 1 | 1 | 100.0% |
| **合計** | **49** | **49** | **100.0%** |

### システム性能指標

- ✅ **検知率**: 100% (49/49攻撃)
- ✅ **誤検知率**: 0%
- ✅ **システム稼働率**: 100%
- ✅ **平均応答時間**: 0.12秒
- ✅ **DoS耐性**: 7,417リクエスト/20秒処理

### コンポーネント別性能

| コンポーネント | 状態 | 性能指標 |
|---------------|------|----------|
| Nginx Proxy | 100% 稼働 | 370.85 req/s |
| Suricata IDS | 100% 稼働 | 22ルール、48アラート生成 |
| Fail2ban | Active | 2 jails監視中 |
| Flask Backend | 100% 稼働 | 安定動作 |

## 📁 プロジェクト構造

```
network_security/
├── 📄 README.md                    # プロジェクト説明書
├── 📄 docker-compose.yml           # マルチコンテナ設定
├── 📄 advanced_attack_simulator.py # 攻撃シミュレーションツール
│
├── 📁 nginx/                       # Nginxプロキシ設定
│   ├── Dockerfile
│   └── nginx.conf
│
├── 📁 suricata/                    # Suricata IDS設定
│   ├── Dockerfile
│   ├── suricata.yaml
│   └── rules/
│       ├── local.rules             # カスタムルール
│       └── suricata.rules
│
├── 📁 fail2ban/                    # Fail2ban設定（コンテナ用）
│   ├── Dockerfile
│   └── jail.local
│
├── 📁 host-fail2ban/               # Fail2ban設定（ホスト用）
│   ├── jail.local
│   ├── suricata-fast.conf
│   └── suricata-severe.conf
│
├── 📁 flask_app/                   # バックエンドアプリ
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
│
└── 📁 evaluation/                  # 評価・分析
    ├── attack_simulation_analysis.py
    ├── ips_ids_evaluation.tex     # LaTeX評価レポート
    └── output/                     # 分析結果・グラフ
        ├── attack_simulation_performance.png
        ├── threat_detection_timeline.png
        ├── defense_effectiveness_analysis.png
        └── comprehensive_evaluation_report.json
```

## 🛡️ セキュリティ機能

### Suricata IDS ルール (22種類)

1. **Webアプリケーション攻撃検知**
   - SQLインジェクション検知
   - XSS攻撃検知
   - ディレクトリトラバーサル検知

2. **悪意のあるツール検知**
   - Nikto, SQLMap, Nmap等の検知
   - 自動化ツールのUser-Agent検知

3. **ネットワーク攻撃検知**
   - ポートスキャン検知
   - ブルートフォース攻撃検知

### Fail2ban 自動防御

- **nginx-http-auth jail**: HTTP認証失敗の監視
- **sshd jail**: SSH攻撃対策
- **iptables連携**: 自動IP遮断

## 📈 評価・分析

### 可視化レポート

1. **攻撃検知パフォーマンス**: `evaluation/output/attack_simulation_performance.png`
2. **脅威検知タイムライン**: `evaluation/output/threat_detection_timeline.png`
3. **多層防御効果分析**: `evaluation/output/defense_effectiveness_analysis.png`

### 学術的評価

詳細な評価は以下で確認できます：
- **LaTeX論文**: `evaluation/ips_ids_evaluation.tex`
- **PDF版**: `evaluation/output/ips_ids_evaluation.pdf`
- **JSON評価レポート**: `evaluation/output/comprehensive_evaluation_report.json`

## 🔧 操作・管理

### システム監視

```bash
# コンテナ状態確認
docker ps

# Suricataログ確認
sudo tail -f /var/lib/docker/volumes/network_security_suricata_logs/_data/eve.json

# Fail2ban状態確認
sudo fail2ban-client status
sudo fail2ban-client status nginx-http-auth

# システムリソース監視
docker stats
```

### トラブルシューティング

```bash
# サービス再起動
docker-compose restart

# ログ確認
docker logs nginx_proxy
docker logs suricata_ids
docker logs flask_app

# Suricataルール再読込
docker exec suricata_ids suricatasc -c reload-rules
```

## 📚 使用技術・ツール

- **コンテナ**: Docker, Docker Compose
- **IDS**: Suricata 7.0.11
- **IPS**: Fail2ban 0.11+
- **プロキシ**: Nginx 1.24+
- **アプリケーション**: Python Flask
- **分析**: Python (matplotlib, seaborn, pandas)
- **文書化**: LaTeX, Markdown

## 🎓 教育的価値

このプロジェクトは以下の学習に適しています：

- **ネットワークセキュリティ**: IDS/IPS の実装と運用
- **Dockerコンテナ**: マルチコンテナアプリケーション
- **システム設計**: 多層防御アーキテクチャ
- **攻撃手法**: セキュリティテストと脆弱性評価
- **データ分析**: セキュリティメトリクスの可視化

## ⚠️ 注意事項

- 本システムは**教育・研究目的**での使用を想定しています
- 攻撃シミュレーションは**自己所有システム**でのみ実行してください
- 実運用環境では追加のセキュリティ対策が必要です

## 📄 ライセンス

このプロジェクトはMITライセンスの下で公開されています。

## 🤝 貢献

プルリクエストやイシューの報告を歓迎します。セキュリティに関する重要な発見は、公開前に個別にご連絡ください。

---

**プロジェクト開始日**: 2025-07-25  
**最終更新**: 2025-07-25  
**作成者**: Network Security Research Team
