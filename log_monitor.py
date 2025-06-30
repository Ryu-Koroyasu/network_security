#!/usr/bin/env python3
"""
IPS/IDS リアルタイムログモニター
SuricataとFail2banのログをリアルタイムで監視・分析
"""

import subprocess
import json
import time
import threading
from datetime import datetime
import re

class LogMonitor:
    def __init__(self):
        self.monitoring = False
        self.suricata_alerts = []
        self.fail2ban_actions = []
        
    def monitor_suricata_logs(self):
        """Suricataのログをリアルタイム監視"""
        print("🔍 Starting Suricata log monitoring...")
        
        try:
            # docker execでtail -fを実行
            process = subprocess.Popen([
                'docker', 'exec', 'suricata_ids',
                'tail', '-f', '/var/log/suricata/eve.json'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            while self.monitoring:
                line = process.stdout.readline()
                if line:
                    self.process_suricata_log(line.strip())
                time.sleep(0.1)
                
        except Exception as e:
            print(f"❌ Error monitoring Suricata logs: {e}")
    
    def monitor_fail2ban_logs(self):
        """Fail2banのログをリアルタイム監視"""
        print("🔍 Starting Fail2ban log monitoring...")
        
        try:
            process = subprocess.Popen([
                'docker', 'exec', 'fail2ban_ips',
                'tail', '-f', '/var/log/fail2ban/fail2ban.log'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            while self.monitoring:
                line = process.stdout.readline()
                if line:
                    self.process_fail2ban_log(line.strip())
                time.sleep(0.1)
                
        except Exception as e:
            print(f"❌ Error monitoring Fail2ban logs: {e}")
    
    def process_suricata_log(self, log_line):
        """Suricataログエントリを処理"""
        try:
            if log_line.strip():
                log_entry = json.loads(log_line)
                
                if log_entry.get('event_type') == 'alert':
                    alert_info = {
                        'timestamp': log_entry.get('timestamp'),
                        'src_ip': log_entry.get('src_ip'),
                        'dest_ip': log_entry.get('dest_ip'),
                        'signature': log_entry.get('alert', {}).get('signature'),
                        'severity': log_entry.get('alert', {}).get('severity'),
                        'category': log_entry.get('alert', {}).get('category')
                    }
                    
                    self.suricata_alerts.append(alert_info)
                    self.print_suricata_alert(alert_info)
                    
        except json.JSONDecodeError:
            # JSONでない行は無視
            pass
        except Exception as e:
            print(f"⚠️  Error processing Suricata log: {e}")
    
    def process_fail2ban_log(self, log_line):
        """Fail2banログエントリを処理"""
        try:
            # Fail2banのログ形式を解析
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', log_line)
            
            if 'Ban' in log_line or 'ban' in log_line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
                jail_match = re.search(r'\[(.*?)\]', log_line)
                
                action_info = {
                    'timestamp': timestamp_match.group(1) if timestamp_match else 'Unknown',
                    'action': 'BAN',
                    'ip': ip_match.group(1) if ip_match else 'Unknown',
                    'jail': jail_match.group(1) if jail_match else 'Unknown',
                    'raw_log': log_line
                }
                
                self.fail2ban_actions.append(action_info)
                self.print_fail2ban_action(action_info)
                
            elif 'Unban' in log_line or 'unban' in log_line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
                jail_match = re.search(r'\[(.*?)\]', log_line)
                
                action_info = {
                    'timestamp': timestamp_match.group(1) if timestamp_match else 'Unknown',
                    'action': 'UNBAN',
                    'ip': ip_match.group(1) if ip_match else 'Unknown',
                    'jail': jail_match.group(1) if jail_match else 'Unknown',
                    'raw_log': log_line
                }
                
                self.fail2ban_actions.append(action_info)
                self.print_fail2ban_action(action_info)
                
        except Exception as e:
            print(f"⚠️  Error processing Fail2ban log: {e}")
    
    def print_suricata_alert(self, alert_info):
        """Suricataアラートを整形して表示"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n🚨 [{timestamp}] SURICATA ALERT")
        print(f"  Signature: {alert_info['signature']}")
        print(f"  Source IP: {alert_info['src_ip']}")
        print(f"  Dest IP: {alert_info['dest_ip']}")
        print(f"  Severity: {alert_info['severity']}")
        print(f"  Category: {alert_info['category']}")
    
    def print_fail2ban_action(self, action_info):
        """Fail2banアクションを整形して表示"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        action_emoji = "🔨" if action_info['action'] == 'BAN' else "🔓"
        print(f"\n{action_emoji} [{timestamp}] FAIL2BAN {action_info['action']}")
        print(f"  IP: {action_info['ip']}")
        print(f"  Jail: {action_info['jail']}")
        print(f"  Time: {action_info['timestamp']}")
    
    def show_statistics(self):
        """統計情報を表示"""
        print("\n" + "=" * 60)
        print("📊 MONITORING STATISTICS")
        print("=" * 60)
        
        print(f"Suricata Alerts: {len(self.suricata_alerts)}")
        if self.suricata_alerts:
            print("Recent alerts:")
            for alert in self.suricata_alerts[-5:]:  # 最新5件
                print(f"  - {alert['signature']} ({alert['src_ip']})")
        
        print(f"\nFail2ban Actions: {len(self.fail2ban_actions)}")
        if self.fail2ban_actions:
            print("Recent actions:")
            for action in self.fail2ban_actions[-5:]:  # 最新5件
                print(f"  - {action['action']} {action['ip']} in {action['jail']}")
    
    def show_current_bans(self):
        """現在のBANリストを表示"""
        print("\n🔍 Current Fail2ban Status:")
        try:
            # Fail2banの現在の状態を確認
            result = subprocess.run([
                'docker', 'exec', 'fail2ban_ips',
                'fail2ban-client', 'status'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print("Could not retrieve Fail2ban status")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def show_iptables_rules(self):
        """現在のiptablesルールを表示"""
        print("\n🔍 Current iptables rules:")
        try:
            result = subprocess.run([
                'docker', 'exec', 'fail2ban_ips',
                'iptables', '-L', '-n', '--line-numbers'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print("Could not retrieve iptables rules")
                
        except Exception as e:
            print(f"Error: {e}")
    
    def start_monitoring(self, duration=60):
        """監視を開始"""
        print("🚀 Starting IPS/IDS Log Monitoring")
        print(f"Monitoring for {duration} seconds...")
        print("Press Ctrl+C to stop early")
        print("=" * 60)
        
        self.monitoring = True
        
        # 監視スレッドを開始
        suricata_thread = threading.Thread(target=self.monitor_suricata_logs)
        fail2ban_thread = threading.Thread(target=self.monitor_fail2ban_logs)
        
        suricata_thread.daemon = True
        fail2ban_thread.daemon = True
        
        suricata_thread.start()
        fail2ban_thread.start()
        
        try:
            # 指定時間監視
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        
        self.monitoring = False
        
        # 結果表示
        self.show_statistics()
        self.show_current_bans()
        self.show_iptables_rules()

def main():
    import sys
    
    monitor = LogMonitor()
    
    duration = 60  # デフォルト60秒
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Usage: python log_monitor.py [duration_in_seconds]")
            return
    
    monitor.start_monitoring(duration)

if __name__ == "__main__":
    main()
