#!/usr/bin/env python3
"""
Quick Security Scan for Aether AI
Focuses on high-priority security issues
"""

import os
import re
from pathlib import Path
from collections import defaultdict

class QuickSecurityScanner:
    def __init__(self):
        self.project_root = Path.cwd()
        self.issues = defaultdict(list)
        self.excluded_dirs = {'venv', 'node_modules', 'dist', 'build', '__pycache__', '.git', 'htmlcov', 'test_data'}
        
    def scan(self):
        print("="* 60)
        print("AETHER AI - QUICK SECURITY SCAN")
        print("=" * 60)
        
        # Scan critical areas
        self.scan_api_keys()
        self.scan_dangerous_code()
        self.scan_auth_issues()
        self.scan_sql_injection()
        self.scan_command_injection()
        
        self.print_report()
        
    def should_skip(self, path):
        """Check if path should be skipped"""
        path_str = str(path)
        return any(excluded in path_str for excluded in self.excluded_dirs)
        
    def scan_api_keys(self):
        """Scan for exposed API keys"""
        print("\n[*] Scanning for exposed secrets...")
        
        patterns = {
            'OpenAI': r'sk-[A-Za-z0-9]{20,}',
            'Google': r'AIza[0-9A-Za-z_\-]{35}',
            'Generic Key': r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']'
        }
        
        count = 0
        for py_file in self.project_root.rglob("*.py"):
            if self.should_skip(py_file):
                continue
                
            count += 1
            if count % 50 == 0:
                print(f"  Scanned {count} Python files...")
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Skip .env.example
                    if ".example" in str(py_file):
                        continue
                        
                    for key_type, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            self.issues['CRITICAL'].append({
                                'title': f'Exposed {key_type} Found',
                                'file': str(py_file.relative_to(self.project_root)),
                                'desc': f'Potential API key exposure',
                                'cwe': 'CWE-798'
                            })
            except:
                pass
                
    def scan_dangerous_code(self):
        """Scan for dangerous code patterns"""
        print("\n[*] Scanning for dangerous code...")
        
        dangerous = {
            'eval()': r'\beval\(',
            'exec()': r'\bexec\(',
            'pickle.loads': r'pickle\.loads\(',
            '__import__': r'__import__\('
        }
        
        count = 0
        for py_file in self.project_root.rglob("*.py"):
            if self.should_skip(py_file):
                continue
                
            count += 1
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        for danger_name, pattern in dangerous.items():
                            if re.search(pattern, line):
                                self.issues['HIGH'].append({
                                    'title': f'Dangerous {danger_name} Usage',
                                    'file': f"{py_file.relative_to(self.project_root)}:{line_num}",
                                    'desc': f'Found: {line.strip()[:80]}',
                                    'cwe': 'CWE-95'
                                })
            except:
                pass
                
    def scan_auth_issues(self):
        """Scan for authentication issues"""
        print("\n[*] Scanning for auth issues...")
        
        api_routes = list(self.project_root.rglob("src/api/routes/*.py"))
        
        for route_file in api_routes:
            try:
                with open(route_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Check if routes have auth
                    if '@router' in content or '@app' in content:
                        if 'Depends' not in content and 'auth' not in content.lower():
                            self.issues['MEDIUM'].append({
                                'title': 'Missing Authentication',
                                'file': str(route_file.relative_to(self.project_root)),
                                'desc': 'API routes without authentication middleware',
                                'cwe': 'CWE-306'
                            })
            except:
                pass
                
    def scan_sql_injection(self):
        """Scan for SQL injection risks"""
        print("\n[*] Scanning for SQL injection...")
        
        sql_patterns = [
            r'execute\(["\'].*%s.*["\'].*%',
            r'cursor\.execute\(.*\+',
            r'\.format\(.*SELECT'
        ]
        
        for py_file in self.project_root.rglob("src/**/*.py"):
            if self.should_skip(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        for pattern in sql_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.issues['CRITICAL'].append({
                                    'title': 'Potential SQL Injection',
                                    'file': f"{py_file.relative_to(self.project_root)}:{line_num}",
                                    'desc': f'{line.strip()[:80]}',
                                    'cwe': 'CWE-89'
                                })
            except:
                pass
                
    def scan_command_injection(self):
        """Scan for command injection"""
        print("\n[*] Scanning for command injection...")
        
        cmd_patterns = [
            r'os\.system\(',
            r'subprocess\.(call|run|Popen)\(.*shell=True'
        ]
        
        for py_file in self.project_root.rglob("src/**/*.py"):
            if self.should_skip(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        for pattern in cmd_patterns:
                            if re.search(pattern, line):
                                self.issues['CRITICAL'].append({
                                    'title': 'Potential Command Injection',
                                    'file': f"{py_file.relative_to(self.project_root)}:{line_num}",
                                    'desc': f'{line.strip()[:80]}',
                                    'cwe': 'CWE-78'
                                })
            except:
                pass
                
    def print_report(self):
        """Print security report"""
        print("\n" + "=" * 60)
        print("SECURITY SCAN RESULTS")
        print("=" * 60)
        
        total = sum(len(issues) for issues in self.issues.values())
        
        print(f"\n[+] Total Issues Found: {total}")
        print(f"    CRITICAL: {len(self.issues['CRITICAL'])}")
        print(f"    HIGH: {len(self.issues['HIGH'])}")
        print(f"    MEDIUM: {len(self.issues['MEDIUM'])}")
        
        if total == 0:
            print("\n[+] No security issues found! System is secure.")
            return
            
        # Print details
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
            if self.issues[severity]:
                print(f"\n[{severity}] Severity:")
                print("-" * 60)
                
                for issue in self.issues[severity][:10]:
                    print(f"\n  [*] {issue['title']}")
                    print(f"      File: {issue['file']}")
                    print(f"      Description: {issue['desc']}")
                    print(f"      CWE: {issue['cwe']}")
                    
                if len(self.issues[severity]) > 10:
                    print(f"\n  ... and {len(self.issues[severity]) - 10} more issues")
                    
        # Risk score
        risk_score = min(
            len(self.issues['CRITICAL']) * 10 +
            len(self.issues['HIGH']) * 5 +
            len(self.issues['MEDIUM']) * 2,
            100
        )
        
        print(f"\n[+] Overall Risk Score: {risk_score}/100")
        
        if risk_score >= 70:
            print("    [!] HIGH RISK - Immediate action required!")
        elif risk_score >= 40:
            print("    [!] MEDIUM RISK - Action recommended")
        else:
            print("    [+] LOW RISK - Good security posture")

if __name__ == "__main__":
    scanner = QuickSecurityScanner()
    scanner.scan()
    print("\n[+] Quick security scan complete!")
