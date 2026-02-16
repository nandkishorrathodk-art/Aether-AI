#!/usr/bin/env python3
"""
Aether AI - Professional Bug Bounty Automation System
Comprehensive security testing and professional report generation
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    """Security finding/vulnerability"""
    id: str
    title: str
    severity: Severity
    cwe: str
    cvss_score: float
    description: str
    impact: str
    affected_files: List[str]
    proof_of_concept: str
    recommendation: str
    status: str = "Open"
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

class BugBountyAutomation:
    """Professional bug bounty automation system"""
    
    def __init__(self):
        self.project_root = Path.cwd()
        self.findings: List[Finding] = []
        self.scan_stats = {
            'files_scanned': 0,
            'lines_scanned': 0,
            'start_time': datetime.now(),
            'end_time': None
        }
        
    def run_full_scan(self):
        """Execute comprehensive security scan"""
        print("=" * 70)
        print("AETHER AI - BUG BOUNTY AUTOMATION SYSTEM")
        print("Professional Security Assessment")
        print("=" * 70)
        
        self.scan_secrets()
        self.scan_injection_vulnerabilities()
        self.scan_authentication_issues()
        self.scan_cryptography()
        self.scan_data_exposure()
        self.scan_business_logic()
        
        self.scan_stats['end_time'] = datetime.now()
        
        self.generate_professional_report()
        
    def scan_secrets(self):
        """Scan for exposed secrets and credentials"""
        print("\n[1/6] Scanning for exposed secrets...")
        
        patterns = {
            'OpenAI API Key': (r'sk-[A-Za-z0-9]{20,}', 9.0, 'CWE-798'),
            'Anthropic API Key': (r'sk-ant-[A-Za-z0-9\-]{20,}', 9.0, 'CWE-798'),
            'Google API Key': (r'AIza[0-9A-Za-z_\-]{35}', 9.0, 'CWE-798'),
            'AWS Access Key': (r'AKIA[0-9A-Z]{16}', 9.5, 'CWE-798'),
            'Private Key': (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 9.8, 'CWE-312'),
            'Generic API Key': (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 7.5, 'CWE-798'),
            'Password': (r'password\s*=\s*["\']([^"\']{6,})["\']', 7.0, 'CWE-798'),
            'Database URL': (r'(mysql|postgres|mongodb)://[^"\'\s]+', 8.0, 'CWE-312'),
        }
        
        for py_file in self.project_root.rglob("*.py"):
            if self._should_skip(py_file):
                continue
                
            self.scan_stats['files_scanned'] += 1
            
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    self.scan_stats['lines_scanned'] += len(lines)
                    
                    if '.example' in str(py_file) or 'test_' in str(py_file):
                        continue
                        
                    for secret_type, (pattern, cvss, cwe) in patterns.items():
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            
                            finding = Finding(
                                id=f"AETHER-{len(self.findings) + 1:04d}",
                                title=f"Exposed {secret_type} in Source Code",
                                severity=Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH,
                                cwe=cwe,
                                cvss_score=cvss,
                                description=f"Hardcoded {secret_type} found in source code at line {line_num}",
                                impact=f"Attackers can extract {secret_type} and gain unauthorized access to systems/APIs",
                                affected_files=[f"{py_file.relative_to(self.project_root)}:{line_num}"],
                                proof_of_concept=f"File: {py_file.name}\nLine {line_num}: {lines[line_num-1].strip()[:100]}",
                                recommendation=f"Remove hardcoded {secret_type}, use environment variables (.env), add to .gitignore, revoke and regenerate key",
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                                    f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"
                                ]
                            )
                            self.findings.append(finding)
            except:
                pass
                
    def scan_injection_vulnerabilities(self):
        """Scan for injection vulnerabilities"""
        print("\n[2/6] Scanning for injection vulnerabilities...")
        
        injection_patterns = {
            'SQL Injection': [
                (r'execute\(["\'].*%s.*["\'].*%', 'String formatting in SQL', 'CWE-89', 8.5),
                (r'cursor\.execute\(.*\+', 'String concatenation in SQL', 'CWE-89', 8.5),
                (r'\.format\(.*SELECT.*FROM', 'Format strings in SQL', 'CWE-89', 8.5),
            ],
            'Command Injection': [
                (r'os\.system\(', 'Direct system command execution', 'CWE-78', 9.5),
                (r'subprocess\.(call|run|Popen)\(.*shell=True', 'Shell command injection', 'CWE-78', 9.0),
            ],
            'Code Injection': [
                (r'\beval\(', 'Use of eval() function', 'CWE-95', 8.5),
                (r'\bexec\(', 'Use of exec() function', 'CWE-95', 8.5),
                (r'__import__\(', 'Dynamic module import', 'CWE-95', 7.5),
            ],
            'Path Traversal': [
                (r'open\([^)]*\+.*request', 'User input in file path', 'CWE-22', 7.5),
                (r'Path\([^)]*\+.*request', 'Unsanitized path construction', 'CWE-22', 7.5),
            ]
        }
        
        for vuln_type, patterns in injection_patterns.items():
            for py_file in self.project_root.rglob("src/**/*.py"):
                if self._should_skip(py_file):
                    continue
                    
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                        for line_num, line in enumerate(lines, 1):
                            for pattern, desc, cwe, cvss in patterns:
                                if re.search(pattern, line):
                                    # Skip false positives in comments and strings
                                    if line.strip().startswith('#') or line.strip().startswith('"""'):
                                        continue
                                        
                                    finding = Finding(
                                        id=f"AETHER-{len(self.findings) + 1:04d}",
                                        title=f"{vuln_type} Vulnerability",
                                        severity=Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH,
                                        cwe=cwe,
                                        cvss_score=cvss,
                                        description=f"{desc} detected at line {line_num}",
                                        impact=f"Attackers can execute arbitrary {vuln_type.split()[0].lower()} commands",
                                        affected_files=[f"{py_file.relative_to(self.project_root)}:{line_num}"],
                                        proof_of_concept=f"Code: {line.strip()[:100]}",
                                        recommendation=self._get_injection_fix(vuln_type),
                                        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"]
                                    )
                                    self.findings.append(finding)
                except:
                    pass
                    
    def scan_authentication_issues(self):
        """Scan for authentication and authorization issues"""
        print("\n[3/6] Scanning for authentication issues...")
        
        api_routes = list(self.project_root.rglob("src/api/routes/*.py"))
        
        for route_file in api_routes:
            try:
                with open(route_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    has_routes = '@router' in content or '@app' in content
                    has_auth = 'Depends' in content and 'auth' in content.lower()
                    
                    if has_routes and not has_auth:
                        finding = Finding(
                            id=f"AETHER-{len(self.findings) + 1:04d}",
                            title="Missing Authentication on API Endpoints",
                            severity=Severity.MEDIUM,
                            cwe="CWE-306",
                            cvss_score=7.0,
                            description="API endpoints exposed without authentication middleware",
                            impact="Unauthorized users can access sensitive API functionality and data",
                            affected_files=[str(route_file.relative_to(self.project_root))],
                            proof_of_concept=f"curl http://localhost:8000/api/v1/... -X POST (no auth required)",
                            recommendation="Implement JWT/OAuth authentication, add Depends(verify_token) to all routes",
                            references=["https://owasp.org/www-project-api-security/"]
                        )
                        self.findings.append(finding)
            except:
                pass
                
    def scan_cryptography(self):
        """Scan for weak cryptography"""
        print("\n[4/6] Scanning for cryptographic issues...")
        
        weak_crypto = [
            (r'hashlib\.md5\(', 'MD5 is cryptographically broken', 'CWE-327', 5.0),
            (r'hashlib\.sha1\(', 'SHA1 is weak and deprecated', 'CWE-327', 5.0),
            (r'random\.random\(', 'Use secrets module for cryptographic randomness', 'CWE-338', 6.0),
        ]
        
        for py_file in self.project_root.rglob("src/**/*.py"):
            if self._should_skip(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        for pattern, desc, cwe, cvss in weak_crypto:
                            if re.search(pattern, line):
                                finding = Finding(
                                    id=f"AETHER-{len(self.findings) + 1:04d}",
                                    title="Weak Cryptographic Algorithm",
                                    severity=Severity.MEDIUM,
                                    cwe=cwe,
                                    cvss_score=cvss,
                                    description=desc,
                                    impact="Cryptographic weaknesses can lead to data compromise",
                                    affected_files=[f"{py_file.relative_to(self.project_root)}:{line_num}"],
                                    proof_of_concept=f"Line {line_num}: {line.strip()[:100]}",
                                    recommendation="Use SHA-256 or stronger, use secrets module for random values",
                                    references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"]
                                )
                                self.findings.append(finding)
            except:
                pass
                
    def scan_data_exposure(self):
        """Scan for sensitive data exposure"""
        print("\n[5/6] Scanning for data exposure risks...")
        
        # Check for logging of sensitive data
        sensitive_keywords = ['password', 'token', 'api_key', 'secret', 'credit_card']
        
        for py_file in self.project_root.rglob("src/**/*.py"):
            if self._should_skip(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        if 'logger.' in line or 'print(' in line:
                            for keyword in sensitive_keywords:
                                if keyword in line.lower():
                                    finding = Finding(
                                        id=f"AETHER-{len(self.findings) + 1:04d}",
                                        title="Potential Sensitive Data in Logs",
                                        severity=Severity.LOW,
                                        cwe="CWE-532",
                                        cvss_score=4.0,
                                        description=f"Possible logging of sensitive data ({keyword})",
                                        impact="Sensitive information may be exposed in log files",
                                        affected_files=[f"{py_file.relative_to(self.project_root)}:{line_num}"],
                                        proof_of_concept=f"Line {line_num}: {line.strip()[:100]}",
                                        recommendation="Sanitize logs, redact sensitive data, use structured logging",
                                        references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]
                                    )
                                    self.findings.append(finding)
                                    break
            except:
                pass
                
    def scan_business_logic(self):
        """Scan for business logic flaws"""
        print("\n[6/6] Scanning for business logic issues...")
        
        # Check for missing rate limiting
        if (self.project_root / "src" / "api" / "main.py").exists():
            try:
                with open(self.project_root / "src" / "api" / "main.py", 'r') as f:
                    content = f.read()
                    
                    if 'limiter' not in content.lower() and 'rate' not in content.lower():
                        finding = Finding(
                            id=f"AETHER-{len(self.findings) + 1:04d}",
                            title="Missing Rate Limiting",
                            severity=Severity.MEDIUM,
                            cwe="CWE-770",
                            cvss_score=5.5,
                            description="API lacks rate limiting protection",
                            impact="Vulnerable to brute force, DoS, and resource exhaustion attacks",
                            affected_files=["src/api/main.py"],
                            proof_of_concept="Unlimited API requests possible",
                            recommendation="Implement rate limiting (e.g., 60 req/min per IP)",
                            references=["https://owasp.org/www-project-api-security/"]
                        )
                        self.findings.append(finding)
            except:
                pass
                
    def generate_professional_report(self):
        """Generate professional bug bounty report"""
        print("\n" + "=" * 70)
        print("GENERATING PROFESSIONAL BUG BOUNTY REPORT")
        print("=" * 70)
        
        # Group findings by severity
        by_severity = {severity: [] for severity in Severity}
        for finding in self.findings:
            by_severity[finding.severity].append(finding)
            
        # Calculate metrics
        duration = (self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds()
        
        # Generate Markdown report
        report_md = self._generate_markdown_report(by_severity, duration)
        
        # Generate JSON report
        report_json = self._generate_json_report(by_severity, duration)
        
        # Generate HTML report
        report_html = self._generate_html_report(by_severity, duration)
        
        # Save reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        md_path = self.project_root / f"bugbounty_report_{timestamp}.md"
        json_path = self.project_root / f"bugbounty_report_{timestamp}.json"
        html_path = self.project_root / f"bugbounty_report_{timestamp}.html"
        
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(report_md)
            
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_json, f, indent=2)
            
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
            
        # Print summary
        print(f"\n[+] Scan Complete!")
        print(f"    Duration: {duration:.1f} seconds")
        print(f"    Files Scanned: {self.scan_stats['files_scanned']}")
        print(f"    Lines Scanned: {self.scan_stats['lines_scanned']:,}")
        print(f"    Total Findings: {len(self.findings)}")
        print(f"\n[+] Severity Breakdown:")
        print(f"    CRITICAL: {len(by_severity[Severity.CRITICAL])}")
        print(f"    HIGH: {len(by_severity[Severity.HIGH])}")
        print(f"    MEDIUM: {len(by_severity[Severity.MEDIUM])}")
        print(f"    LOW: {len(by_severity[Severity.LOW])}")
        print(f"    INFO: {len(by_severity[Severity.INFO])}")
        
        # Calculate risk score
        risk_score = min(
            len(by_severity[Severity.CRITICAL]) * 10 +
            len(by_severity[Severity.HIGH]) * 5 +
            len(by_severity[Severity.MEDIUM]) * 2 +
            len(by_severity[Severity.LOW]) * 1,
            100
        )
        
        print(f"\n[+] Risk Score: {risk_score}/100")
        
        if risk_score >= 70:
            print("    Status: HIGH RISK - Immediate action required")
        elif risk_score >= 40:
            print("    Status: MEDIUM RISK - Action recommended")
        else:
            print("    Status: LOW RISK - Good security posture")
            
        print(f"\n[+] Reports Generated:")
        print(f"    Markdown: {md_path.name}")
        print(f"    JSON: {json_path.name}")
        print(f"    HTML: {html_path.name}")
        
    def _should_skip(self, path: Path) -> bool:
        """Check if path should be skipped"""
        excluded = {'venv', 'node_modules', 'dist', 'build', '__pycache__', '.git', 'htmlcov', 'test_data', 'security_backups'}
        return any(ex in str(path) for ex in excluded)
        
    def _get_injection_fix(self, vuln_type: str) -> str:
        """Get fix recommendation for injection vulnerability"""
        fixes = {
            'SQL Injection': 'Use parameterized queries or ORM (SQLAlchemy)',
            'Command Injection': 'Use subprocess with shell=False and validate inputs',
            'Code Injection': 'Replace eval() with ast.literal_eval(), avoid exec()',
            'Path Traversal': 'Validate and sanitize file paths, use os.path.abspath()'
        }
        return fixes.get(vuln_type, 'Sanitize and validate all user inputs')
        
    def _generate_markdown_report(self, by_severity: Dict, duration: float) -> str:
        """Generate Markdown format report"""
        report = f"""# Bug Bounty Security Assessment Report

**Target**: Aether AI Virtual Assistant  
**Assessment Date**: {datetime.now().strftime('%B %d, %Y')}  
**Duration**: {duration:.1f} seconds  
**Total Findings**: {len(self.findings)}

---

## Executive Summary

This security assessment identified **{len(self.findings)} vulnerabilities** across the Aether AI codebase.

### Severity Distribution

| Severity | Count | CVSS Range |
|----------|-------|------------|
| CRITICAL | {len(by_severity[Severity.CRITICAL])} | 9.0 - 10.0 |
| HIGH | {len(by_severity[Severity.HIGH])} | 7.0 - 8.9 |
| MEDIUM | {len(by_severity[Severity.MEDIUM])} | 4.0 - 6.9 |
| LOW | {len(by_severity[Severity.LOW])} | 0.1 - 3.9 |
| INFO | {len(by_severity[Severity.INFO])} | 0.0 |

---

## Detailed Findings

"""
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            if by_severity[severity]:
                report += f"\n### {severity.value} Severity\n\n"
                
                for finding in by_severity[severity][:20]:  # Top 20 per severity
                    report += f"""
#### {finding.id}: {finding.title}

**Severity**: {finding.severity.value} (CVSS {finding.cvss_score})  
**CWE**: {finding.cwe}  
**Status**: {finding.status}

**Description**:  
{finding.description}

**Impact**:  
{finding.impact}

**Affected Files**:  
{chr(10).join(f'- `{f}`' for f in finding.affected_files)}

**Proof of Concept**:  
```
{finding.proof_of_concept}
```

**Recommendation**:  
{finding.recommendation}

**References**:  
{chr(10).join(f'- {ref}' for ref in finding.references) if finding.references else 'N/A'}

---

"""
        
        return report
        
    def _generate_json_report(self, by_severity: Dict, duration: float) -> Dict:
        """Generate JSON format report"""
        return {
            "metadata": {
                "target": "Aether AI Virtual Assistant",
                "scan_date": datetime.now().isoformat(),
                "duration_seconds": duration,
                "files_scanned": self.scan_stats['files_scanned'],
                "lines_scanned": self.scan_stats['lines_scanned']
            },
            "summary": {
                "total_findings": len(self.findings),
                "critical": len(by_severity[Severity.CRITICAL]),
                "high": len(by_severity[Severity.HIGH]),
                "medium": len(by_severity[Severity.MEDIUM]),
                "low": len(by_severity[Severity.LOW]),
                "info": len(by_severity[Severity.INFO])
            },
            "findings": [
                {
                    **asdict(finding),
                    'severity': finding.severity.value
                }
                for finding in self.findings
            ]
        }
        
    def _generate_html_report(self, by_severity: Dict, duration: float) -> str:
        """Generate HTML format report"""
        findings_html = ""
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            if by_severity[severity]:
                findings_html += f'<h2>{severity.value} Severity ({len(by_severity[severity])})</h2>\n'
                
                for finding in by_severity[severity][:20]:
                    findings_html += f"""
<div class="finding {severity.value.lower()}">
    <h3>{finding.id}: {finding.title}</h3>
    <p><strong>CVSS:</strong> {finding.cvss_score} | <strong>CWE:</strong> {finding.cwe}</p>
    <p><strong>Description:</strong> {finding.description}</p>
    <p><strong>Impact:</strong> {finding.impact}</p>
    <p><strong>Recommendation:</strong> {finding.recommendation}</p>
</div>
"""
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Aether AI - Bug Bounty Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ background: white; padding: 15px; margin: 15px 0; border-left: 4px solid; border-radius: 5px; }}
        .finding.critical {{ border-color: #e74c3c; }}
        .finding.high {{ border-color: #e67e22; }}
        .finding.medium {{ border-color: #f39c12; }}
        h1 {{ margin: 0; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Bug Bounty Security Assessment</h1>
        <p>Target: Aether AI Virtual Assistant</p>
        <p>Date: {datetime.now().strftime('%B %d, %Y')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Findings:</strong> {len(self.findings)}</p>
        <p><strong>Critical:</strong> {len(by_severity[Severity.CRITICAL])} | 
           <strong>High:</strong> {len(by_severity[Severity.HIGH])} | 
           <strong>Medium:</strong> {len(by_severity[Severity.MEDIUM])} | 
           <strong>Low:</strong> {len(by_severity[Severity.LOW])}</p>
        <p><strong>Scan Duration:</strong> {duration:.1f} seconds</p>
    </div>
    
    {findings_html}
</body>
</html>"""
        
        return html

if __name__ == "__main__":
    automation = BugBountyAutomation()
    automation.run_full_scan()
    print("\n[+] Bug bounty automation complete!")
