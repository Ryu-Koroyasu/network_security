# Network Security Project - File Organization

## 古いファイルと新しいファイルの対応関係

### メインツール
- `advanced_attack_simulator.py` ✅ (最新版 - 2025-07-25)
- `attack_simulator.py` ❌ (旧版 - 削除対象)

### テストファイル
- `test_ips_ids.py` ❓ (評価に使用された可能性あり - 確認要)
- `log_monitor.py` ❓ (独立機能 - 確認要)

### ドキュメント
- `README.md` ✅ (最新版 - 包括的)
- `VALIDATION_GUIDE.md` ❓ (確認要)
- `VALIDATION_REPORT.md` ❓ (確認要)

### 設定ファイル
- `docker-compose.yml` ✅ (メイン設定)
- `setup-nfqueue.sh` ❓ (使用されていない可能性)

## 推奨整理アクション

1. 旧版ファイルの削除または統合
2. 使用されていないファイルの確認
3. ドキュメントの整合性確認
4. ディレクトリ構造の最適化
