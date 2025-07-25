# Network Security Project - ディレクトリ構造

## 📁 プロジェクト構成

```
network_security/
├── 📄 README.md                    # メインドキュメント
├── 🐍 attack_simulator.py          # メイン攻撃シミュレーター
├── 🐍 remote_attack_tester.py      # リモート攻撃テスター
├── 🐳 docker-compose.yml           # Docker構成ファイル
│
├── 📚 docs/                        # ドキュメント
│   ├── COMPREHENSIVE_SECURITY_EVALUATION_REPORT.md
│   ├── PROJECT_CLEANUP.md
│   ├── REMOTE_ATTACK_GUIDE.md
│   ├── VALIDATION_COMPLETE.md
│   ├── WSL_SETUP_GUIDE.md
│   └── PROJECT_STRUCTURE.md
│
├── 🔧 tools/                       # 分析・監視ツール
│   ├── comprehensive_security_test.py
│   ├── log_monitor.py
│   ├── realtime_security_monitor.py
│   └── test_ips_ids.py
│
├── 📜 scripts/                     # シェルスクリプト・PowerShell
│   ├── *.sh                       # Linux/WSLスクリプト
│   └── *.ps1                      # Windows PowerShellスクリプト
│
├── 🐳 Docker関連ディレクトリ/
│   ├── nginx/                     # Nginxリバースプロキシ
│   ├── flask_app/                 # Flaskバックエンド
│   ├── suricata/                  # Suricata IDS/IPS
│   └── fail2ban/                  # Fail2ban IPS
│
├── 📊 evaluation/                  # 実験評価・分析
│   ├── *.py                       # データ分析スクリプト
│   ├── *.tex                      # LaTeX学術論文
│   └── output/                    # 分析結果出力
│
├── 📤 output/                      # 実行結果出力
│   ├── *.png                      # グラフ・可視化
│   ├── *.csv                      # データファイル
│   └── *.json                     # 結果レポート
│
└── ⚙️ host-fail2ban/              # ホスト側Fail2ban設定
    ├── jail.local
    ├── suricata-fast.conf
    └── suricata-severe.conf
```

## 🚀 使用方法

### メイン機能
```bash
# 攻撃シミュレーション（最重要）
python attack_simulator.py all

# リモート攻撃テスト
python remote_attack_tester.py --target <IP>
```

### ツール類
```bash
# システム検証
python tools/test_ips_ids.py

# リアルタイム監視
python tools/realtime_security_monitor.py

# 包括的セキュリティテスト
python tools/comprehensive_security_test.py
```

### システム管理
```bash
# システム起動
docker compose up -d

# WSLネットワーク設定（Windows）
./scripts/Setup-WSL-Network.ps1

# 最終レポート生成
./scripts/generate_final_report.sh
```

## 📋 整理で削除されたファイル

### 削除されたファイル（統合済み）
- `advanced_attack_simulator.py` → `attack_simulator.py`に統合
- `https_attack_simulator.py` → 機能を`attack_simulator.py`に統合
- `quick_attack_test.py` → 機能を`remote_attack_tester.py`に統合
- `setup-nfqueue.sh` → 使用されていない設定
- `nginx-*.conf` → `host-fail2ban/`に移動
- `QUICK_FIX_GUIDE.md` → `WSL_SETUP_GUIDE.md`に統合
- `POWERSHELL_FIX_GUIDE.md` → `WSL_SETUP_GUIDE.md`に統合
- `WSL_EXTERNAL_ACCESS_SETUP.md` → `WSL_SETUP_GUIDE.md`に統合
- `VALIDATION_GUIDE.md` → `VALIDATION_COMPLETE.md`に統合
- `VALIDATION_REPORT.md` → `VALIDATION_COMPLETE.md`に統合

### バックアップ・一時ファイル
- `*.backup`, `*.json`, `*.csv`, `*.png`（ルート）
- `*.aux`, `*.log`, `*.out`, `*.synctex.gz`

## 🎯 整理の効果

1. **ファイル数削減**: 70+ → 51ファイル
2. **重複解消**: 攻撃シミュレーター5個 → 2個
3. **構造明確化**: 機能別ディレクトリ分離
4. **メンテナンス性向上**: 関連ファイルの集約
5. **ドキュメント統合**: 分散情報の集約

## ✨ 主要改善点

- ✅ **メイン機能の明確化**: `attack_simulator.py`をメインツールに
- ✅ **機能別整理**: tools/, scripts/, docs/の分離
- ✅ **重複排除**: 類似機能ファイルの統合
- ✅ **ドキュメント整理**: 関連情報の統合
- ✅ **保守性向上**: ファイル探索が容易に
