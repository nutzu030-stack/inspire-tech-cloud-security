import json
import os


def load_benchmarks():
    config_path = os.path.join(
        os.path.dirname(__file__), '../config/benchmarks.json'
    )
    with open(config_path, 'r') as f:
        return json.load(f)


def analyze_logs(config):
    print('--- Running Benchmark: Cloud Trail & Access Log Analysis ---')
    
    # Getting threshold from config or using a default fallback
    log_config = config.get('benchmarks', {}).get('log_analysis', {})
    max_failed_attempts = log_config.get('max_failed_login_attempts', 3)

    # Simulated log events (in a real app, this could read from CloudWatch or a log file)
    sample_logs = [
        {'user': 'admin', 'action': 'ConsoleLogin', 'status': 'Success', 'ip': '192.168.1.50'},
        {'user': 'root', 'action': 'ConsoleLogin', 'status': 'Failure', 'ip': '203.0.113.42'},
        {'user': 'root', 'action': 'ConsoleLogin', 'status': 'Failure', 'ip': '203.0.113.42'},
        {'user': 'root', 'action': 'ConsoleLogin', 'status': 'Failure', 'ip': '203.0.113.42'},
        {'user': 'root', 'action': 'ConsoleLogin', 'status': 'Failure', 'ip': '203.0.113.42'}, # Exceeds threshold
        {'user': 'developer', 'action': 'RunInstances', 'status': 'Success', 'ip': '10.0.0.15'}
    ]

    failed_attempts = {}
    violations = 0

    for log in sample_logs:
        if log['status'] == 'Failure' and log['action'] == 'ConsoleLogin':
            user = log['user']
            failed_attempts[user] = failed_attempts.get(user, 0) + 1

    for user, count in failed_attempts.items():
        if count >= max_failed_attempts:
            violations += 1
            print(f'[!] VULNERABILITY FOUND: User "{user}" triggered {count} failed login attempts (Threshold: {max_failed_attempts})')

    if violations == 0:
        print('[+] PASSED: Log analysis shows no abnormal brute-force patterns.')
    else:
        print(f'[-] FAILED: Detected {violations} log anomaly violation(s).')


if __name__ == '__main__':
    print('=== Inspire Tech Solution: Log Security Analyzer ===\n')
    benchmark_config = load_benchmarks()
    analyze_logs(benchmark_config)
    print('\n=== Log Analysis Complete ===')