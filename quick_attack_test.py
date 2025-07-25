#!/usr/bin/env python3
"""
クイック攻撃テスト - 同一ネットワークから実行
"""

import requests
import time
import sys

def quick_test(target_ip="192.168.11.4", port=8080):
    base_url = f"http://{target_ip}:{port}"
    
    print(f"🚀 クイック攻撃テスト開始")
    print(f"ターゲット: {base_url}")
    print("=" * 50)
    
    # SSL警告を抑制
    requests.packages.urllib3.disable_warnings()
    
    attacks = [
        # 基本接続
        ("基本接続", base_url, {}),
        
        # SQLインジェクション
        ("SQLインジェクション", base_url, {"id": "1' OR '1'='1"}),
        ("SQLインジェクション", base_url, {"user": "admin'--"}),
        
        # XSS
        ("XSS攻撃", base_url, {"q": "<script>alert('XSS')</script>"}),
        
        # パストラバーサル
        ("パストラバーサル", base_url, {"file": "../../../etc/passwd"}),
        
        # 404スキャン
        ("404スキャン", f"{base_url}/admin", {}),
        ("404スキャン", f"{base_url}/phpmyadmin", {}),
        ("404スキャン", f"{base_url}/backup", {}),
    ]
    
    blocked_count = 0
    
    for attack_type, url, params in attacks:
        try:
            response = requests.get(url, params=params, timeout=5)
            status = response.status_code
            result = f"✅ {status}"
        except requests.exceptions.ConnectionError:
            status = 0
            result = "🚫 BLOCKED"
            blocked_count += 1
        except requests.exceptions.Timeout:
            status = 408
            result = "⏰ TIMEOUT"
        except Exception as e:
            status = 0
            result = f"❌ ERROR: {e}"
        
        print(f"{attack_type}: {result}")
        time.sleep(0.5)
    
    # 悪意のあるUser-Agent
    print("\n悪意のあるUser-Agentテスト:")
    malicious_uas = ["sqlmap/1.0", "Nikto/2.1.6", "w3af.org"]
    
    for ua in malicious_uas:
        try:
            headers = {"User-Agent": ua}
            response = requests.get(base_url, headers=headers, timeout=5)
            print(f"User-Agent {ua}: ✅ {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"User-Agent {ua}: 🚫 BLOCKED")
            blocked_count += 1
        except Exception as e:
            print(f"User-Agent {ua}: ❌ ERROR")
        
        time.sleep(0.5)
    
    print("\n" + "=" * 50)
    print(f"📊 結果: {blocked_count}個の攻撃がブロックされました")
    
    if blocked_count > 0:
        print("🎉 セキュリティシステムが正常に動作しています！")
    else:
        print("⚠️  セキュリティシステムの設定を確認してください")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.11.4"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    quick_test(target, port)
