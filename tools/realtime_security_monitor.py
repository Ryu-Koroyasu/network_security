#!/usr/bin/env python3
"""
リアルタイムセキュリティログ監視ツール
Fail2ban、Suricata、Nginxのログをリアルタイムで監視し、攻撃検出状況を表示
"""

import subprocess
import json
import time
import re
from datetime import datetime
from collections import defaultdict, deque
import threading
import signal
import sys

class SecurityLogMonitor:
    def __init__(self):
        self.running = True
        self.attack_stats = defaultdict(int)
        self.blocked_ips = set()
        self.recent_events = deque(maxlen=50)
        self.lock = threading.Lock()
        
        # 信号ハンドラー設定
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Ctrl+Cでの終了処理"""
        print("\n🛑 監視を停止中...")
        self.running = False
        sys.exit(0)
    
    def log_event(self, event_type, source, details, ip=None):
        """イベントをログに記録"""
        with self.lock:
            timestamp = datetime.now().strftime('%H:%M:%S')
            event = {
                'timestamp': timestamp,
                'type': event_type,
                'source': source,
                'details': details,
                'ip': ip
            }
            self.recent_events.append(event)
            self.attack_stats[event_type] += 1
            
            if ip:
                self.blocked_ips.add(ip)
            
            # リアルタイム表示
            color = {
                'BLOCK': '\033[91m',  # 赤
                'DETECT': '\033[93m', # 黄
                'ALERT': '\033[95m',  # マゼンタ
                'INFO': '\033[92m'    # 緑
            }.get(event_type, '\033[0m')
            
            print(f"{color}[{timestamp}] {event_type:<6} {source:<10} {details}\033[0m")
    
    def monitor_fail2ban(self):
        """Fail2banログ監視"""
        try:
            cmd = ["docker", "compose", "exec", "-T", "fail2ban", "tail", "-f", "/var/log/fail2ban.log"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                     universal_newlines=True, bufsize=1)
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Fail2banのログパターンマッチング
                if "Ban" in line:
                    ip_match = re.search(r'Ban (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        self.log_event('BLOCK', 'Fail2ban', f'IP {ip} banned', ip)
                
                elif "Found" in line and any(x in line for x in ['nginx-http-attack', 'nginx-malicious-ua', 'nginx-dos']):
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    jail_match = re.search(r'\[(nginx-[^\]]+)\]', line)
                    if ip_match and jail_match:
                        ip = ip_match.group(1)
                        jail = jail_match.group(1)
                        self.log_event('DETECT', 'Fail2ban', f'{jail} detected from {ip}', ip)
                
        except Exception as e:
            self.log_event('INFO', 'Monitor', f'Fail2ban monitoring error: {e}')
    
    def monitor_suricata(self):
        """Suricataログ監視"""
        try:
            cmd = ["docker", "compose", "exec", "-T", "suricata", "tail", "-f", "/var/log/suricata/eve.json"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, bufsize=1)
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                try:
                    event = json.loads(line.strip())
                    if event.get('event_type') == 'alert':
                        src_ip = event.get('src_ip', 'unknown')
                        signature = event.get('alert', {}).get('signature', 'Unknown alert')
                        severity = event.get('alert', {}).get('severity', 3)
                        
                        if severity <= 2:  # 高優先度アラート
                            self.log_event('ALERT', 'Suricata', f'HIGH: {signature[:50]} from {src_ip}', src_ip)
                        else:
                            self.log_event('DETECT', 'Suricata', f'{signature[:50]} from {src_ip}', src_ip)
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    continue
        
        except Exception as e:
            self.log_event('INFO', 'Monitor', f'Suricata monitoring error: {e}')
    
    def monitor_nginx(self):
        """Nginxアクセスログ監視"""
        try:
            cmd = ["docker", "compose", "exec", "-T", "nginx", "tail", "-f", "/var/log/nginx/access.log"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, bufsize=1)
            
            suspicious_patterns = [
                r"(?i)(union|select|drop|insert|delete|update|script|alert|eval)",
                r"\.\.\/",
                r"%2e%2e%2f",
                r"(?i)(sqlmap|nikto|nmap|w3af)",
                r"(?i)(php|jsp|asp|cgi)"
            ]
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                # アクセスログの解析
                ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                status_match = re.search(r'" (\d{3}) ', line)
                
                if ip_match and status_match:
                    ip = ip_match.group(1)
                    status = int(status_match.group(1))
                    
                    # 疑わしいパターンの検出
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line):
                            self.log_event('DETECT', 'Nginx', f'Suspicious request from {ip} (Status: {status})', ip)
                            break
                    
                    # 403/404の大量発生を検出
                    if status in [403, 404]:
                        self.log_event('INFO', 'Nginx', f'Status {status} from {ip}')
        
        except Exception as e:
            self.log_event('INFO', 'Monitor', f'Nginx monitoring error: {e}')
    
    def display_stats(self):
        """統計情報の定期表示"""
        while self.running:
            time.sleep(10)  # 10秒ごとに統計表示
            
            with self.lock:
                print("\n" + "="*60)
                print(f"📊 セキュリティ監視統計 [{datetime.now().strftime('%H:%M:%S')}]")
                print("="*60)
                print(f"🔍 検出イベント: {self.attack_stats['DETECT']}")
                print(f"🚫 ブロックイベント: {self.attack_stats['BLOCK']}")
                print(f"⚠️ アラート: {self.attack_stats['ALERT']}")
                print(f"📍 ユニークIP数: {len(self.blocked_ips)}")
                
                if self.blocked_ips:
                    print(f"🔒 ブロック済みIP: {', '.join(list(self.blocked_ips)[-5:])}")  # 最新5件
                
                print("="*60 + "\n")
    
    def run(self):
        """監視開始"""
        print("🔍 リアルタイムセキュリティログ監視を開始...")
        print("Ctrl+C で停止\n")
        
        # 各監視スレッドを開始
        threads = [
            threading.Thread(target=self.monitor_fail2ban, daemon=True),
            threading.Thread(target=self.monitor_suricata, daemon=True),
            threading.Thread(target=self.monitor_nginx, daemon=True),
            threading.Thread(target=self.display_stats, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        try:
            # メインスレッドで待機
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
        
        print("\n🛑 監視終了")

def main():
    monitor = SecurityLogMonitor()
    monitor.run()

if __name__ == '__main__':
    main()
