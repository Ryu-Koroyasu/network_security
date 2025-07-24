#!/usr/bin/env python3
"""
IPS/IDS攻撃シミュレーションスクリプト
様々な攻撃パターンをシミュレートしてSuricataとFail2banの反応をテスト
"""

import requests
import time
import threading
import random
import subprocess
from urllib.parse import urljoin

class AttackSimulator:
    def __init__(self, target_url="http://localhost:8080"):
        self.target_url = target_url
        self.session = requests.Session()
        
    def simulate_curl_user_agent_attack(self, count=5):
        """curl User-Agentを使った攻撃シミュレーション"""
        print(f"🔥 Simulating curl user-agent attacks ({count} requests)...")
        
        for i in range(count):
            try:
                headers = {'User-Agent': 'curl/7.68.0'}
                response = self.session.get(self.target_url, headers=headers, timeout=5)
                print(f"  Request {i+1}: Status {response.status_code}")
                time.sleep(1)
            except Exception as e:
                print(f"  Request {i+1} failed: {e}")
    
    def simulate_path_traversal_attack(self):
        """パストラバーサル攻撃シミュレーション"""
        print("🔥 Simulating path traversal attacks...")
        
        malicious_paths = [
            "/test",
            "/../../../etc/passwd",
            "/test/../admin",
            "/test?id=1' OR '1'='1",
            "/test?file=../../../etc/shadow"
        ]
        
        for path in malicious_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5)
                print(f"  Path {path}: Status {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  Path {path} failed: {e}")
    
    def simulate_sql_injection_attack(self):
        """SQLインジェクション攻撃シミュレーション"""
        print("🔥 Simulating SQL injection attacks...")
        
        sql_payloads = [
            "?id=1' OR '1'='1",
            "?user=admin'--",
            "?id=1; DROP TABLE users;--",
            "?login=admin' UNION SELECT * FROM users--"
        ]
        
        for payload in sql_payloads:
            try:
                url = self.target_url + payload
                response = self.session.get(url, timeout=5)
                print(f"  SQL payload {payload}: Status {response.status_code}")
                time.sleep(0.5)
            except Exception as e:
                print(f"  SQL payload {payload} failed: {e}")
    
    def simulate_brute_force_attack(self, count=10):
        """ブルートフォース攻撃シミュレーション"""
        print(f"🔥 Simulating brute force attacks ({count} requests)...")
        
        for i in range(count):
            try:
                # 異なるUser-Agentでリクエストを送信
                user_agents = [
                    'curl/7.68.0',
                    'wget/1.20.3',
                    'Python-requests/2.25.1',
                    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'
                ]
                
                headers = {'User-Agent': random.choice(user_agents)}
                response = self.session.get(f"{self.target_url}/admin", headers=headers, timeout=5)
                print(f"  Brute force {i+1}: Status {response.status_code}")
                time.sleep(0.2)
            except Exception as e:
                print(f"  Brute force {i+1} failed: {e}")
    
    def simulate_dos_attack(self, duration=30, threads=5):
        """DoS攻撃シミュレーション（軽微）"""
        print(f"🔥 Simulating DoS attack ({duration}s with {threads} threads)...")
        
        def dos_worker():
            end_time = time.time() + duration
            request_count = 0
            while time.time() < end_time:
                try:
                    headers = {'User-Agent': 'curl/7.68.0'}
                    response = self.session.get(self.target_url, headers=headers, timeout=2)
                    request_count += 1
                    time.sleep(0.1)
                except:
                    pass
            print(f"  Thread completed: {request_count} requests")
        
        # 複数スレッドで同時攻撃
        threads_list = []
        for i in range(threads):
            t = threading.Thread(target=dos_worker)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
    
    def check_if_blocked(self):
        """IPがブロックされているかチェック"""
        print("🔍 Checking if IP is blocked...")
        try:
            response = self.session.get(self.target_url, timeout=5)
            print(f"  Connection test: Status {response.status_code}")
            return False
        except Exception as e:
            print(f"  Connection blocked or failed: {e}")
            return True
    
    def run_comprehensive_attack_simulation(self):
        """包括的な攻撃シミュレーション"""
        print("🚨 Starting Comprehensive Attack Simulation")
        print("=" * 60)
        
        # 1. 基本的な攻撃パターン
        self.simulate_curl_user_agent_attack(3)
        time.sleep(5)
        
        self.simulate_path_traversal_attack()
        time.sleep(5)
        
        self.simulate_sql_injection_attack()
        time.sleep(5)
        
        # 2. より激しい攻撃でFail2banトリガーを狙う
        print("\n🎯 Intensive attacks to trigger Fail2ban...")
        self.simulate_brute_force_attack(8)
        time.sleep(10)
        
        # 3. ブロック状態チェック
        self.check_if_blocked()
        
        # 4. DoS攻撃（短時間）
        self.simulate_dos_attack(20, 3)
        time.sleep(5)
        
        # 5. 最終チェック
        self.check_if_blocked()
        
        print("\n✅ Attack simulation completed")

def main():
    import sys
    
    simulator = AttackSimulator()
    
    if len(sys.argv) > 1:
        attack_type = sys.argv[1]
        
        if attack_type == "curl":
            simulator.simulate_curl_user_agent_attack(5)
        elif attack_type == "path":
            simulator.simulate_path_traversal_attack()
        elif attack_type == "sql":
            simulator.simulate_sql_injection_attack()
        elif attack_type == "brute":
            simulator.simulate_brute_force_attack(10)
        elif attack_type == "dos":
            simulator.simulate_dos_attack(30, 5)
        elif attack_type == "all":
            simulator.run_comprehensive_attack_simulation()
        else:
            print("Usage: python attack_simulator.py [curl|path|sql|brute|dos|all]")
    else:
        simulator.run_comprehensive_attack_simulation()

if __name__ == "__main__":
    main()
