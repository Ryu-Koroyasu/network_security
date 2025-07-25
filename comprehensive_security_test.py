#!/usr/bin/env python3
"""
外部攻撃テスト & 可視化ツール
WSL2セキュリティシステムに対する包括的な攻撃シミュレーションと結果分析
"""

import requests
import time
import json
import csv
import argparse
import socket
import ssl
import random
import string
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from collections import defaultdict
import subprocess
import sys
import os

# 日本語フォント設定
plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")

class SecurityTestSuite:
    def __init__(self, target_ip="192.168.11.4", http_port=8080, https_port=443):
        self.target_ip = target_ip
        self.http_port = http_port
        self.https_port = https_port
        self.base_url = f"http://{target_ip}:{http_port}"
        self.https_url = f"https://{target_ip}:{https_port}"
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityTestSuite/1.0'
        })
        
    def log_result(self, test_type, payload, response_code, response_time, blocked=False, error=None):
        """テスト結果をログに記録"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'test_type': test_type,
            'payload': payload[:100] if payload else '',  # 長いペイロードは切り詰め
            'response_code': response_code,
            'response_time': response_time,
            'blocked': blocked,
            'success': response_code == 200,
            'error': str(error) if error else None,
            'target': f"{self.target_ip}:{self.http_port}"
        }
        self.results.append(result)
        
        # リアルタイム出力
        status = "🔴 BLOCKED" if blocked else "🟢 SUCCESS" if response_code == 200 else "🟡 ERROR"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {status} {test_type}: {response_code} ({response_time:.2f}s)")
        
    def test_sql_injection(self, num_tests=10):
        """SQLインジェクション攻撃テスト"""
        print("\n🎯 SQLインジェクション攻撃テスト開始...")
        
        sql_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "' OR 1=1--",
            "admin'--",
            "' OR 'a'='a",
            "1'; EXEC sp_configure 'xp_cmdshell', 1--",
            "1' UNION SELECT username, password FROM users--",
            "' OR 1=1 LIMIT 1--",
            "1' AND (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        for i in range(num_tests):
            payload = random.choice(sql_payloads)
            start_time = time.time()
            
            try:
                response = self.session.get(
                    f"{self.base_url}/search",
                    params={'q': payload},
                    timeout=10
                )
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                self.log_result('SQL_Injection', payload, response.status_code, response_time, blocked)
                
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                self.log_result('SQL_Injection', payload, 0, response_time, True, e)
            
            time.sleep(0.5)  # レート制限回避
    
    def test_xss_attacks(self, num_tests=8):
        """XSS攻撃テスト"""
        print("\n🎯 XSS攻撃テスト開始...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            start_time = time.time()
            
            try:
                response = self.session.post(
                    f"{self.base_url}/comment",
                    data={'comment': payload},
                    timeout=10
                )
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                self.log_result('XSS_Attack', payload, response.status_code, response_time, blocked)
                
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                self.log_result('XSS_Attack', payload, 0, response_time, True, e)
            
            time.sleep(0.5)
    
    def test_path_traversal(self, num_tests=6):
        """パストラバーサル攻撃テスト"""
        print("\n🎯 パストラバーサル攻撃テスト開始...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        for payload in traversal_payloads:
            start_time = time.time()
            
            try:
                response = self.session.get(
                    f"{self.base_url}/file",
                    params={'path': payload},
                    timeout=10
                )
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                self.log_result('Path_Traversal', payload, response.status_code, response_time, blocked)
                
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                self.log_result('Path_Traversal', payload, 0, response_time, True, e)
            
            time.sleep(0.5)
    
    def test_malicious_user_agents(self, num_tests=5):
        """悪意のあるUser-Agent攻撃テスト"""
        print("\n🎯 悪意のあるUser-Agent攻撃テスト開始...")
        
        malicious_uas = [
            "sqlmap/1.0-dev",
            "Nikto/2.1.6",
            "w3af.org",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            "() { :; }; echo; echo; /bin/bash -c \"cat /etc/passwd\""
        ]
        
        for ua in malicious_uas:
            start_time = time.time()
            
            try:
                headers = {'User-Agent': ua}
                response = requests.get(f"{self.base_url}/", headers=headers, timeout=10)
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                self.log_result('Malicious_UA', ua, response.status_code, response_time, blocked)
                
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                self.log_result('Malicious_UA', ua, 0, response_time, True, e)
            
            time.sleep(0.5)
    
    def test_directory_scanning(self, num_tests=10):
        """ディレクトリスキャン攻撃テスト"""
        print("\n🎯 ディレクトリスキャン攻撃テスト開始...")
        
        scan_paths = [
            "/admin", "/phpmyadmin", "/wp-admin", "/backup",
            "/config.php", "/login", "/admin.php", "/test",
            "/secret", "/hidden"
        ]
        
        for path in scan_paths:
            start_time = time.time()
            
            try:
                response = self.session.get(f"{self.base_url}{path}", timeout=10)
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                self.log_result('Directory_Scan', path, response.status_code, response_time, blocked)
                
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                self.log_result('Directory_Scan', path, 0, response_time, True, e)
            
            time.sleep(0.3)
    
    def test_dos_attack(self, num_requests=20):
        """軽量DoS攻撃テスト"""
        print(f"\n🎯 DoS攻撃テスト開始... ({num_requests}リクエスト)")
        
        def send_request(i):
            start_time = time.time()
            try:
                response = requests.get(f"{self.base_url}/", timeout=5)
                response_time = time.time() - start_time
                blocked = response.status_code in [403, 406, 444] or response.status_code == 0
                return ('DoS_Attack', f'request_{i}', response.status_code, response_time, blocked, None)
            except requests.exceptions.RequestException as e:
                response_time = time.time() - start_time
                return ('DoS_Attack', f'request_{i}', 0, response_time, True, e)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_request, i) for i in range(num_requests)]
            
            for future in as_completed(futures):
                test_type, payload, code, resp_time, blocked, error = future.result()
                self.log_result(test_type, payload, code, resp_time, blocked, error)
    
    def test_ssl_attacks(self):
        """SSL/TLS攻撃テスト"""
        print("\n🎯 SSL/TLS攻撃テスト開始...")
        
        # 古いTLSバージョンでの接続試行
        tls_versions = [
            ('TLS_1_0', ssl.PROTOCOL_TLSv1),
            ('TLS_1_1', ssl.PROTOCOL_TLSv1_1),
            ('TLS_1_2', ssl.PROTOCOL_TLSv1_2)
        ]
        
        for version_name, protocol in tls_versions:
            start_time = time.time()
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, self.https_port), timeout=10) as sock:
                    with context.wrap_socket(sock) as ssock:
                        ssock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                        response = ssock.recv(1024)
                        
                response_time = time.time() - start_time
                self.log_result('SSL_Attack', version_name, 200, response_time, False)
                
            except Exception as e:
                response_time = time.time() - start_time
                self.log_result('SSL_Attack', version_name, 0, response_time, True, e)
    
    def run_comprehensive_test(self):
        """包括的なセキュリティテストの実行"""
        print(f"🚀 包括的セキュリティテスト開始: {self.target_ip}:{self.http_port}")
        print(f"開始時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # ベースライン接続テスト
        print("\n🔍 ベースライン接続テスト...")
        start_time = time.time()
        try:
            response = self.session.get(self.base_url, timeout=10)
            response_time = time.time() - start_time
            self.log_result('Baseline', 'normal_request', response.status_code, response_time)
            print(f"✅ ベースライン接続成功: {response.status_code}")
        except Exception as e:
            print(f"❌ ベースライン接続失敗: {e}")
            return
        
        # 各種攻撃テストの実行
        self.test_sql_injection()
        self.test_xss_attacks()
        self.test_path_traversal()
        self.test_malicious_user_agents()
        self.test_directory_scanning()
        self.test_dos_attack()
        self.test_ssl_attacks()
        
        print(f"\n✅ 全テスト完了: {len(self.results)}件のテスト実行")
        
    def generate_report(self):
        """テスト結果の分析とレポート生成"""
        if not self.results:
            print("❌ テスト結果がありません")
            return
        
        print("\n📊 レポート生成中...")
        
        # データフレームに変換
        df = pd.DataFrame(self.results)
        
        # 基本統計
        total_tests = len(df)
        blocked_tests = len(df[df['blocked'] == True])
        successful_attacks = len(df[(df['response_code'] == 200) & (df['test_type'] != 'Baseline')])
        
        # 攻撃タイプ別の統計を生成
        attack_type_stats = {}
        for test_type in df['test_type'].unique():
            type_df = df[df['test_type'] == test_type]
            attack_type_stats[test_type] = {
                'total_count': len(type_df),
                'blocked_count': int(type_df['blocked'].sum()),
                'success_count': int(type_df['success'].sum()),
                'avg_response_time': float(type_df['response_time'].mean()),
                'block_rate': float((type_df['blocked'].sum() / len(type_df)) * 100) if len(type_df) > 0 else 0
            }
        
        # レポートデータ
        report_data = {
            'test_summary': {
                'total_tests': total_tests,
                'blocked_attacks': blocked_tests,
                'successful_attacks': successful_attacks,
                'block_rate': (blocked_tests / total_tests) * 100 if total_tests > 0 else 0,
                'test_duration': (pd.to_datetime(df['timestamp']).max() - pd.to_datetime(df['timestamp']).min()).total_seconds(),
                'target': f"{self.target_ip}:{self.http_port}"
            },
            'attack_types': attack_type_stats,
            'timeline': df[['timestamp', 'test_type', 'blocked', 'response_code']].to_dict('records')
        }
        
        # JSONレポート保存
        with open('security_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2, default=str)
        
        # CSVレポート保存
        df.to_csv('security_test_results.csv', index=False, encoding='utf-8')
        
        print(f"📄 レポートファイル生成完了:")
        print(f"  - security_test_report.json")
        print(f"  - security_test_results.csv")
        
        return report_data
    
    def create_visualizations(self, report_data):
        """可視化グラフの生成"""
        print("\n📈 可視化グラフ生成中...")
        
        df = pd.DataFrame(self.results)
        
        # 図のサイズとレイアウト設定
        plt.style.use('default')
        fig = plt.figure(figsize=(20, 16))
        
        # 1. 攻撃タイプ別ブロック率
        plt.subplot(2, 3, 1)
        attack_summary = df.groupby('test_type').agg({
            'blocked': ['count', 'sum']
        })
        attack_summary.columns = ['total', 'blocked']
        attack_summary['block_rate'] = (attack_summary['blocked'] / attack_summary['total']) * 100
        
        colors = ['#ff4444' if x < 50 else '#ffaa00' if x < 80 else '#44ff44' for x in attack_summary['block_rate']]
        bars = plt.bar(range(len(attack_summary)), attack_summary['block_rate'], color=colors)
        plt.title('Attack Type Block Rate (%)', fontsize=14, fontweight='bold')
        plt.ylabel('Block Rate (%)')
        plt.xticks(range(len(attack_summary)), attack_summary.index, rotation=45, ha='right')
        plt.ylim(0, 100)
        
        # 数値ラベル追加
        for i, bar in enumerate(bars):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f'{height:.1f}%', ha='center', va='bottom')
        
        # 2. レスポンスコード分布
        plt.subplot(2, 3, 2)
        response_counts = df['response_code'].value_counts()
        colors_pie = ['#ff4444', '#44ff44', '#ffaa00', '#4444ff', '#ff44ff']
        plt.pie(response_counts.values, labels=[f'Code {x}' for x in response_counts.index], 
                autopct='%1.1f%%', colors=colors_pie[:len(response_counts)])
        plt.title('Response Code Distribution', fontsize=14, fontweight='bold')
        
        # 3. 時系列攻撃検出
        plt.subplot(2, 3, 3)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_sorted = df.sort_values('timestamp')
        df_sorted['cumulative_blocked'] = df_sorted['blocked'].cumsum()
        
        plt.plot(df_sorted['timestamp'], df_sorted['cumulative_blocked'], 
                linewidth=2, color='#ff4444', marker='o', markersize=3)
        plt.title('Cumulative Blocked Attacks Over Time', fontsize=14, fontweight='bold')
        plt.ylabel('Cumulative Blocked Attacks')
        plt.xlabel('Time')
        plt.xticks(rotation=45)
        
        # 4. 攻撃タイプ別レスポンス時間
        plt.subplot(2, 3, 4)
        response_times = df.groupby('test_type')['response_time'].mean().sort_values(ascending=False)
        bars = plt.bar(range(len(response_times)), response_times.values, 
                      color='#4488ff', alpha=0.7)
        plt.title('Average Response Time by Attack Type', fontsize=14, fontweight='bold')
        plt.ylabel('Response Time (seconds)')
        plt.xticks(range(len(response_times)), response_times.index, rotation=45, ha='right')
        
        # 数値ラベル追加
        for i, bar in enumerate(bars):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{height:.2f}s', ha='center', va='bottom')
        
        # 5. セキュリティ効果分析
        plt.subplot(2, 3, 5)
        security_metrics = {
            'Total Attacks': len(df[df['test_type'] != 'Baseline']),
            'Blocked': len(df[df['blocked'] == True]),
            'Successful': len(df[(df['response_code'] == 200) & (df['test_type'] != 'Baseline')]),
            'Errors/Timeouts': len(df[df['response_code'] == 0])
        }
        
        colors_security = ['#ffaa00', '#44ff44', '#ff4444', '#888888']
        bars = plt.bar(security_metrics.keys(), security_metrics.values(), color=colors_security)
        plt.title('Security System Effectiveness', fontsize=14, fontweight='bold')
        plt.ylabel('Number of Requests')
        plt.xticks(rotation=45, ha='right')
        
        # 数値ラベル追加
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                    f'{int(height)}', ha='center', va='bottom')
        
        # 6. 攻撃成功率マトリックス
        plt.subplot(2, 3, 6)
        attack_matrix = df.groupby(['test_type']).agg({
            'success': 'sum',
            'blocked': 'sum'
        })
        attack_matrix['total'] = attack_matrix['success'] + attack_matrix['blocked']
        attack_matrix['success_rate'] = (attack_matrix['success'] / attack_matrix['total'] * 100).fillna(0)
        
        y_pos = range(len(attack_matrix))
        plt.barh(y_pos, attack_matrix['success_rate'], color='#ff6666', alpha=0.7)
        plt.title('Attack Success Rate by Type (%)', fontsize=14, fontweight='bold')
        plt.xlabel('Success Rate (%)')
        plt.yticks(y_pos, attack_matrix.index)
        plt.xlim(0, 100)
        
        # 全体のレイアウト調整
        plt.tight_layout(pad=3.0)
        
        # 保存
        plt.savefig('security_test_visualization.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("📊 可視化グラフ保存完了: security_test_visualization.png")

def main():
    parser = argparse.ArgumentParser(description='WSL2セキュリティシステム攻撃テストスイート')
    parser.add_argument('--target', default='192.168.11.4', help='ターゲットIPアドレス')
    parser.add_argument('--port', type=int, default=8080, help='HTTPポート')
    parser.add_argument('--https-port', type=int, default=443, help='HTTPSポート')
    parser.add_argument('--test', choices=['sql', 'xss', 'path', 'ua', 'scan', 'dos', 'ssl', 'all'], 
                        default='all', help='実行するテストタイプ')
    parser.add_argument('--output', default='security_test', help='出力ファイルのプレフィックス')
    
    args = parser.parse_args()
    
    # テストスイート初期化
    test_suite = SecurityTestSuite(args.target, args.port, args.https_port)
    
    # テスト実行
    if args.test == 'all':
        test_suite.run_comprehensive_test()
    else:
        # 個別テスト実行
        test_methods = {
            'sql': test_suite.test_sql_injection,
            'xss': test_suite.test_xss_attacks,
            'path': test_suite.test_path_traversal,
            'ua': test_suite.test_malicious_user_agents,
            'scan': test_suite.test_directory_scanning,
            'dos': test_suite.test_dos_attack,
            'ssl': test_suite.test_ssl_attacks
        }
        test_methods[args.test]()
    
    # レポート生成
    report_data = test_suite.generate_report()
    
    # 可視化
    try:
        test_suite.create_visualizations(report_data)
    except Exception as e:
        print(f"⚠️ 可視化の生成に失敗しました: {e}")
        print("matplotlib, seaborn, pandasがインストールされていることを確認してください")
    
    # サマリー出力
    print("\n" + "="*60)
    print("🎯 セキュリティテスト結果サマリー")
    print("="*60)
    summary = report_data['test_summary']
    print(f"ターゲット: {summary['target']}")
    print(f"総テスト数: {summary['total_tests']}")
    print(f"ブロック数: {summary['blocked_attacks']}")
    print(f"攻撃成功数: {summary['successful_attacks']}")
    print(f"ブロック率: {summary['block_rate']:.1f}%")
    print(f"テスト時間: {summary['test_duration']:.1f}秒")
    
    if summary['block_rate'] >= 80:
        print("🛡️ セキュリティレベル: 優秀")
    elif summary['block_rate'] >= 60:
        print("🔶 セキュリティレベル: 良好")
    else:
        print("🔴 セキュリティレベル: 要改善")

if __name__ == '__main__':
    main()
