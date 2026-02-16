#!/usr/bin/env python3
"""
Aether AI - Comprehensive Security Audit & Bug Bounty Testing
Performs automated security testing on the Aether AI system
"""

import os
import sys
import json
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    title: str
    severity: Severity
    description: str
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0

class SecurityAuditor:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.vulnerabilities: List[Vulnerability] = []
        self.files_scanned = 0
        self.lines_scanned = 0
        
    def scan_all(self):
        """Run all security scans"""
        print("AETHER AI SECURITY AUDIT")
        print("=" * 60)
        
        # Scan Python files
        self.scan_python_files()
        
        # Scan TypeScript/JavaScript files
        self.scan_ts_js_files()
        
        # Scan configuration files
        self.scan_config_files()
        
        # Scan API endpoints
        self.scan_api_security()
        
        # Scan dependencies
        self.scan_dependencies()
        
        # Generate report
        self.generate_report()
        
    def scan_python_files(self):
        """Scan Python files for security issues"""
        print("\n[*] Scanning Python files...")
        
        python_files = list(self.project_root.rglob("*.py"))
        
        for file_path in python_files:
            if "venv" in str(file_path) or "node_modules" in str(file_path):
                continue
                
            self.files_scanned += 1
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    self.lines_scanned += len(lines)
                    
                    # Check for security issues
                    self._check_hardcoded_secrets(file_path, lines)
                    self._check_sql_injection(file_path, lines)
                    self._check_command_injection(file_path, lines)
                    self._check_path_traversal(file_path, lines)
                    self._check_insecure_deserialization(file_path, lines)
                    self._check_weak_crypto(file_path, lines)
                    self._check_xxe(file_path, lines)
                    
            except Exception as e:
                print(f"[!] Error scanning {file_path}: {e}")
                
    def scan_ts_js_files(self):
        """Scan TypeScript/JavaScript files"""
        print("\n[*] Scanning TypeScript/JavaScript files...")
        
        ts_js_files = []
        ts_js_files.extend(self.project_root.rglob("*.ts"))
        ts_js_files.extend(self.project_root.rglob("*.js"))
        ts_js_files.extend(self.project_root.rglob("*.jsx"))
        ts_js_files.extend(self.project_root.rglob("*.tsx"))
        
        for file_path in ts_js_files:
            if "node_modules" in str(file_path) or "dist" in str(file_path):
                continue
                
            self.files_scanned += 1
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    self.lines_scanned += len(lines)
                    
                    self._check_xss(file_path, lines)
                    self._check_prototype_pollution(file_path, lines)
                    self._check_insecure_storage(file_path, lines)
                    
            except Exception as e:
                print(f"[!] Error scanning {file_path}: {e}")
                
    def scan_config_files(self):
        """Scan configuration files"""
        print("\n[*] Scanning configuration files...")
        
        config_patterns = ["*.json", "*.yaml", "*.yml", "*.env*", "*.config.js"]
        
        for pattern in config_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "node_modules" in str(file_path):
                    continue
                    
                self._check_exposed_secrets(file_path)
                
    def scan_api_security(self):
        """Scan API security"""
        print("\n[*] Scanning API security...")
        
        api_files = list(self.project_root.rglob("**/routes/*.py"))
        
        for file_path in api_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                    self._check_missing_auth(file_path, lines)
                    self._check_missing_rate_limiting(file_path, lines)
                    self._check_cors_misconfiguration(file_path, lines)
                    
            except Exception as e:
                print(f"[!] Error scanning {file_path}: {e}")
                
    def scan_dependencies(self):
        """Scan for vulnerable dependencies"""
        print("\n[*] Scanning dependencies...")
        
        # Check requirements.txt
        req_file = self.project_root / "requirements.txt"
        if req_file.exists():
            self._check_python_dependencies(req_file)
            
        # Check package.json
        pkg_file = self.project_root / "ui" / "package.json"
        if pkg_file.exists():
            self._check_npm_dependencies(pkg_file)
            
    # Vulnerability Check Methods
    
    def _check_hardcoded_secrets(self, file_path: Path, lines: List[str]):
        """Check for hardcoded secrets"""
        secret_patterns = [
            (r'api_key\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
            (r'password\s*=\s*["\'](.+)["\']', "Password"),
            (r'secret\s*=\s*["\'](.+)["\']', "Secret"),
            (r'token\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Token"),
            (r'(sk-[A-Za-z0-9]{20,})', "OpenAI API Key"),
            (r'(AIza[0-9A-Za-z_\-]{35})', "Google API Key"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, name in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        title=f"Hardcoded {name} Detected",
                        severity=Severity.CRITICAL,
                        description=f"Hardcoded {name} found in source code",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use environment variables or secure vaults for secrets",
                        cwe_id="CWE-798",
                        cvss_score=9.0
                    ))
                    
    def _check_sql_injection(self, file_path: Path, lines: List[str]):
        """Check for SQL injection vulnerabilities"""
        sql_patterns = [
            r'execute\(["\'].*%s.*["\'].*%',
            r'cursor\.execute\(.*\+.*\)',
            r'\.format\(.*SELECT.*FROM',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential SQL Injection",
                        severity=Severity.HIGH,
                        description="Unsanitized SQL query construction detected",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use parameterized queries or ORM",
                        cwe_id="CWE-89",
                        cvss_score=8.5
                    ))
                    
    def _check_command_injection(self, file_path: Path, lines: List[str]):
        """Check for command injection"""
        cmd_patterns = [
            r'os\.system\(',
            r'subprocess\.call\(.*shell=True',
            r'subprocess\.run\(.*shell=True',
            r'eval\(',
            r'exec\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in cmd_patterns:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential Command Injection",
                        severity=Severity.CRITICAL,
                        description="Unsafe command execution detected",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use subprocess with shell=False and validate inputs",
                        cwe_id="CWE-78",
                        cvss_score=9.5
                    ))
                    
    def _check_path_traversal(self, file_path: Path, lines: List[str]):
        """Check for path traversal"""
        path_patterns = [
            r'open\([^)]*\+',
            r'Path\([^)]*\+',
            r'os\.path\.join\([^)]*request',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in path_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential Path Traversal",
                        severity=Severity.HIGH,
                        description="Unsanitized file path detected",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Validate and sanitize file paths",
                        cwe_id="CWE-22",
                        cvss_score=7.5
                    ))
                    
    def _check_insecure_deserialization(self, file_path: Path, lines: List[str]):
        """Check for insecure deserialization"""
        deser_patterns = [
            r'pickle\.loads\(',
            r'yaml\.load\([^,]*\)',  # Without safe_load
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in deser_patterns:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        title="Insecure Deserialization",
                        severity=Severity.CRITICAL,
                        description="Unsafe deserialization method detected",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use safe deserialization methods",
                        cwe_id="CWE-502",
                        cvss_score=9.0
                    ))
                    
    def _check_weak_crypto(self, file_path: Path, lines: List[str]):
        """Check for weak cryptography"""
        crypto_patterns = [
            (r'hashlib\.md5\(', "MD5 is cryptographically broken"),
            (r'hashlib\.sha1\(', "SHA1 is weak"),
            (r'random\.random\(', "Use secrets module for crypto"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in crypto_patterns:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        title="Weak Cryptography",
                        severity=Severity.MEDIUM,
                        description=desc,
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use SHA-256 or stronger algorithms",
                        cwe_id="CWE-327",
                        cvss_score=5.0
                    ))
                    
    def _check_xxe(self, file_path: Path, lines: List[str]):
        """Check for XML External Entity attacks"""
        xxe_patterns = [
            r'xml\.etree\.ElementTree\.parse\(',
            r'lxml\.etree\.parse\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in xxe_patterns:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential XXE Vulnerability",
                        severity=Severity.HIGH,
                        description="XML parser without XXE protection",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Disable external entity processing",
                        cwe_id="CWE-611",
                        cvss_score=7.0
                    ))
                    
    def _check_xss(self, file_path: Path, lines: List[str]):
        """Check for XSS vulnerabilities"""
        xss_patterns = [
            r'dangerouslySetInnerHTML',
            r'innerHTML\s*=',
            r'document\.write\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in xss_patterns:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential XSS Vulnerability",
                        severity=Severity.HIGH,
                        description="Unsafe HTML rendering detected",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Sanitize user input and use safe rendering",
                        cwe_id="CWE-79",
                        cvss_score=7.5
                    ))
                    
    def _check_prototype_pollution(self, file_path: Path, lines: List[str]):
        """Check for prototype pollution"""
        proto_patterns = [
            r'Object\.assign\(',
            r'\.\.\.',  # Spread operator
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in proto_patterns:
                if re.search(pattern, line) and "__proto__" in line:
                    self.vulnerabilities.append(Vulnerability(
                        title="Potential Prototype Pollution",
                        severity=Severity.MEDIUM,
                        description="Unsafe object manipulation",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Validate object keys",
                        cwe_id="CWE-1321",
                        cvss_score=6.0
                    ))
                    
    def _check_insecure_storage(self, file_path: Path, lines: List[str]):
        """Check for insecure storage"""
        storage_patterns = [
            r'localStorage\.setItem\(',
            r'sessionStorage\.setItem\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in storage_patterns:
                if re.search(pattern, line) and any(word in line.lower() for word in ['token', 'password', 'secret', 'key']):
                    self.vulnerabilities.append(Vulnerability(
                        title="Insecure Storage",
                        severity=Severity.HIGH,
                        description="Sensitive data in browser storage",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use encrypted storage or httpOnly cookies",
                        cwe_id="CWE-312",
                        cvss_score=7.0
                    ))
                    
    def _check_exposed_secrets(self, file_path: Path):
        """Check for exposed secrets in config files"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Skip .env.example files
                if ".example" in str(file_path):
                    return
                    
                secret_patterns = [
                    r'sk-[A-Za-z0-9]{20,}',
                    r'AIza[0-9A-Za-z_\-]{35}',
                    r'[0-9a-f]{32}',  # API keys
                ]
                
                for pattern in secret_patterns:
                    if re.search(pattern, content):
                        self.vulnerabilities.append(Vulnerability(
                            title="Exposed Secret in Config",
                            severity=Severity.CRITICAL,
                            description="Secret found in configuration file",
                            file_path=str(file_path),
                            recommendation="Move secrets to .env and add to .gitignore",
                            cwe_id="CWE-798",
                            cvss_score=9.5
                        ))
        except:
            pass
            
    def _check_missing_auth(self, file_path: Path, lines: List[str]):
        """Check for missing authentication"""
        has_auth = False
        has_route = False
        
        for line in lines:
            if "@router" in line or "@app" in line:
                has_route = True
            if "Depends" in line or "auth" in line.lower():
                has_auth = True
                
        if has_route and not has_auth:
            self.vulnerabilities.append(Vulnerability(
                title="Missing Authentication",
                severity=Severity.HIGH,
                description="API endpoint without authentication",
                file_path=str(file_path),
                recommendation="Add authentication middleware",
                cwe_id="CWE-306",
                cvss_score=8.0
            ))
            
    def _check_missing_rate_limiting(self, file_path: Path, lines: List[str]):
        """Check for missing rate limiting"""
        content = "\n".join(lines)
        
        if "@router" in content and "limiter" not in content.lower():
            self.vulnerabilities.append(Vulnerability(
                title="Missing Rate Limiting",
                severity=Severity.MEDIUM,
                description="API endpoint without rate limiting",
                file_path=str(file_path),
                recommendation="Add rate limiting middleware",
                cwe_id="CWE-770",
                cvss_score=5.5
            ))
            
    def _check_cors_misconfiguration(self, file_path: Path, lines: List[str]):
        """Check for CORS misconfiguration"""
        for i, line in enumerate(lines, 1):
            if "allow_origins" in line and "*" in line:
                self.vulnerabilities.append(Vulnerability(
                    title="CORS Misconfiguration",
                    severity=Severity.MEDIUM,
                    description="CORS allows all origins",
                    file_path=str(file_path),
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Restrict CORS to specific origins",
                    cwe_id="CWE-942",
                    cvss_score=5.0
                ))
                
    def _check_python_dependencies(self, file_path: Path):
        """Check Python dependencies for known vulnerabilities"""
        # This would normally use tools like safety or pip-audit
        # For now, we'll just check for old versions
        
        known_vulnerable = {
            "urllib3": ["1.26.4", "1.26.5"],  # Example
            "requests": ["2.25.0"],
        }
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    for pkg, vuln_versions in known_vulnerable.items():
                        if pkg in line:
                            for version in vuln_versions:
                                if version in line:
                                    self.vulnerabilities.append(Vulnerability(
                                        title="Vulnerable Dependency",
                                        severity=Severity.HIGH,
                                        description=f"{pkg} {version} has known vulnerabilities",
                                        file_path=str(file_path),
                                        recommendation=f"Update {pkg} to latest version",
                                        cwe_id="CWE-1035",
                                        cvss_score=7.5
                                    ))
        except:
            pass
            
    def _check_npm_dependencies(self, file_path: Path):
        """Check npm dependencies"""
        # Similar to Python dependencies
        pass
        
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "=" * 60)
        print("SECURITY AUDIT RESULTS")
        print("=" * 60)
        
        print(f"\n[+] Scan Statistics:")
        print(f"  Files scanned: {self.files_scanned}")
        print(f"  Lines scanned: {self.lines_scanned:,}")
        print(f"  Vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Group by severity
        by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
            Severity.INFO: []
        }
        
        for vuln in self.vulnerabilities:
            by_severity[vuln.severity].append(vuln)
            
        print(f"\n[CRITICAL] Critical: {len(by_severity[Severity.CRITICAL])}")
        print(f"[HIGH] High: {len(by_severity[Severity.HIGH])}")
        print(f"[MEDIUM] Medium: {len(by_severity[Severity.MEDIUM])}")
        print(f"[LOW] Low: {len(by_severity[Severity.LOW])}")
        print(f"[INFO] Info: {len(by_severity[Severity.INFO])}")
        
        # Print detailed findings
        print("\n" + "=" * 60)
        print("DETAILED FINDINGS")
        print("=" * 60)
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            if by_severity[severity]:
                print(f"\n{severity.value} SEVERITY:")
                print("-" * 60)
                
                for vuln in by_severity[severity][:10]:  # Show top 10 per severity
                    print(f"\n  [*] {vuln.title}")
                    print(f"     File: {vuln.file_path}")
                    if vuln.line_number:
                        print(f"     Line: {vuln.line_number}")
                    print(f"     Description: {vuln.description}")
                    if vuln.code_snippet:
                        print(f"     Code: {vuln.code_snippet[:100]}")
                    print(f"     Fix: {vuln.recommendation}")
                    print(f"     CWE: {vuln.cwe_id} | CVSS: {vuln.cvss_score}")
                    
        # Save JSON report
        self.save_json_report()
        
        # Calculate risk score
        risk_score = self.calculate_risk_score()
        print(f"\n[+] Overall Risk Score: {risk_score}/100")
        
        if risk_score >= 70:
            print("   [!] HIGH RISK - Immediate action required!")
        elif risk_score >= 40:
            print("   [!] MEDIUM RISK - Action recommended")
        else:
            print("   [+] LOW RISK - Good security posture")
            
    def save_json_report(self):
        """Save report as JSON"""
        report = {
            "scan_stats": {
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
                "total_vulnerabilities": len(self.vulnerabilities)
            },
            "vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description,
                    "file": v.file_path,
                    "line": v.line_number,
                    "code": v.code_snippet,
                    "recommendation": v.recommendation,
                    "cwe": v.cwe_id,
                    "cvss": v.cvss_score
                }
                for v in self.vulnerabilities
            ]
        }
        
        report_path = self.project_root / "security_audit_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n[+] Full report saved to: {report_path}")
        
    def calculate_risk_score(self) -> int:
        """Calculate overall risk score"""
        score = 0
        
        for vuln in self.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                score += 10
            elif vuln.severity == Severity.HIGH:
                score += 5
            elif vuln.severity == Severity.MEDIUM:
                score += 2
            elif vuln.severity == Severity.LOW:
                score += 1
                
        # Cap at 100
        return min(score, 100)

def main():
    project_root = os.getcwd()
    
    auditor = SecurityAuditor(project_root)
    auditor.scan_all()
    
    print("\n[+] Security audit complete!")

if __name__ == "__main__":
    main()
