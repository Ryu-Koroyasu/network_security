#!/usr/bin/env python3
"""
日本語フォントテスト
"""
import matplotlib.pyplot as plt
import japanize_matplotlib

# 日本語フォント設定
japanize_matplotlib.japanize()

# テストチャート
fig, ax = plt.subplots(figsize=(8, 6))

categories = ['ブルートフォース', 'SQLインジェクション', 'XSS攻撃', 'DoS攻撃']
values = [10, 8, 12, 6]

bars = ax.bar(categories, values, color=['#ff7f7f', '#7fbf7f', '#7f7fff', '#ffbf7f'])
ax.set_title('攻撃種別検知テスト', fontsize=14, fontweight='bold')
ax.set_xlabel('攻撃カテゴリ', fontsize=12)
ax.set_ylabel('検知回数', fontsize=12)

plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('output/japanese_font_test.png', dpi=300, bbox_inches='tight')
plt.close()

print("日本語フォントテスト完了: output/japanese_font_test.png")
