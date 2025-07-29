#!/usr/bin/env python3

import json
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import re

def parse_log_line(line):
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None

def analyze_logs(log_file, hours=24):
    attacks = []
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                log_entry = parse_log_line(line)
                if log_entry and log_entry.get('event_type') == 'log4shell_attempt':
                    timestamp = datetime.fromisoformat(log_entry['timestamp'].replace('Z', '+00:00'))
                    if timestamp >= cutoff_time:
                        attacks.append(log_entry)
    except FileNotFoundError:
        print(f"Log file {log_file} not found")
        return
    
    if not attacks:
        print(f"No Log4Shell attacks detected in the last {hours} hours")
        return
    
    print(f"=== Log4Shell Honeypot Analysis (Last {hours} hours) ===")
    print(f"Total attacks detected: {len(attacks)}")
    print()
    
    source_ips = Counter(attack['source_ip'] for attack in attacks)
    print("Top attacking IPs:")
    for ip, count in source_ips.most_common(10):
        print(f"  {ip}: {count} attempts")
    print()
    
    user_agents = Counter(attack['user_agent'] for attack in attacks if attack['user_agent'])
    print("Top User Agents:")
    for ua, count in user_agents.most_common(5):
        print(f"  {ua[:80]}{'...' if len(ua) > 80 else ''}: {count}")
    print()
    
    patterns = Counter()
    for attack in attacks:
        for pattern in attack.get('detected_patterns', []):
            patterns[pattern] += 1
    
    print("Detected patterns:")
    for pattern, count in patterns.most_common():
        print(f"  {pattern}: {count}")
    print()
    
    detection_sources = Counter(attack['detection_source'] for attack in attacks)
    print("Detection sources:")
    for source, count in detection_sources.most_common():
        print(f"  {source}: {count}")
    print()
    
    hourly_attacks = defaultdict(int)
    for attack in attacks:
        hour = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:00')
        hourly_attacks[hour] += 1
    
    print("Attacks by hour:")
    for hour in sorted(hourly_attacks.keys()):
        print(f"  {hour}: {hourly_attacks[hour]} attacks")

def tail_logs(log_file):
    try:
        with open(log_file, 'r') as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    log_entry = parse_log_line(line)
                    if log_entry and log_entry.get('event_type') == 'log4shell_attempt':
                        print(f"[{log_entry['timestamp']}] Attack from {log_entry['source_ip']}")
                        print(f"  Patterns: {', '.join(log_entry.get('detected_patterns', []))}")
                        print(f"  Source: {log_entry['detection_source']}")
                        print(f"  User-Agent: {log_entry.get('user_agent', 'N/A')}")
                        print()
                else:
                    import time
                    time.sleep(1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except FileNotFoundError:
        print(f"Log file {log_file} not found")

def main():
    parser = argparse.ArgumentParser(description='Log4Shell Honeypot Log Analyzer')
    parser.add_argument('--log-file', default='/var/log/log4shell-honeypot.log', 
                       help='Path to log file')
    parser.add_argument('--hours', type=int, default=24, 
                       help='Hours to analyze (default: 24)')
    parser.add_argument('--tail', action='store_true', 
                       help='Tail logs in real-time')
    
    args = parser.parse_args()
    
    if args.tail:
        print("Monitoring logs in real-time (Ctrl+C to stop)...")
        tail_logs(args.log_file)
    else:
        analyze_logs(args.log_file, args.hours)

if __name__ == '__main__':
    main()
