"""
BurpSuite Integration Module
Advanced BurpSuite automation for bug bounty hunting
Supports: Proxy, Scanner, Intruder, Repeater, Extensions
"""

import requests
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urljoin
import base64
import subprocess
import os

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    url: str
    vulnerability_type: str
    severity: str
    confidence: str
    evidence: str
    remediation: str
    issue_detail: str


@dataclass
class IntruderResult:
    payload: str
    status_code: int
    response_length: int
    response_time: float
    grep_match: bool


class BurpSuiteIntegration:
    """
    Advanced BurpSuite Integration
    
    Features:
    - REST API integration (Burp Suite Professional)
    - Automated scanning (active/passive)
    - Intruder attacks (brute force, fuzzing)
    - Proxy history analysis
    - Extension management
    - Report generation
    - AI-powered vulnerability analysis
    """
    
    def __init__(
        self, 
        api_url: str = "http://127.0.0.1:1337",
        api_key: Optional[str] = None,
        burp_executable: Optional[str] = None
    ):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.burp_executable = burp_executable
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'X-API-Key': api_key,
                'Content-Type': 'application/json'
            })
        
        logger.info("BurpSuite integration initialized")
    
    # ==================== BURP SUITE CONTROL ====================
    
    def start_burp(self, headless: bool = True, project_file: Optional[str] = None) -> bool:
        """Start BurpSuite programmatically"""
        if not self.burp_executable:
            logger.error("BurpSuite executable path not configured")
            return False
        
        try:
            cmd = [self.burp_executable]
            
            if headless:
                cmd.append('--headless')
            
            if project_file:
                cmd.extend(['--project-file', project_file])
            else:
                cmd.append('--use-temp-project')
            
            cmd.extend([
                '--listen-address', '127.0.0.1',
                '--listen-port', '8080'
            ])
            
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(5)
            logger.info("BurpSuite started successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to start BurpSuite: {e}")
            return False
    
    def check_burp_status(self) -> Dict[str, Any]:
        """Check if BurpSuite is running and accessible"""
        try:
            response = self.session.get(f"{self.api_url}/burp/versions")
            if response.status_code == 200:
                return {
                    "status": "running",
                    "version": response.json()
                }
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"status": "offline", "error": str(e)}
    
    # ==================== SCANNER ====================
    
    def scan_url(
        self, 
        url: str, 
        scan_type: str = "active",
        scope_only: bool = True
    ) -> Dict[str, Any]:
        """
        Scan a URL with BurpSuite scanner
        
        Args:
            url: Target URL
            scan_type: "active" or "passive"
            scope_only: Only scan URLs in scope
        """
        try:
            payload = {
                "urls": [url],
                "scan_configurations": [{
                    "type": scan_type,
                    "scope_only": scope_only
                }]
            }
            
            response = self.session.post(
                f"{self.api_url}/v0.1/scan",
                json=payload
            )
            
            if response.status_code == 201:
                task_id = response.headers.get('Location', '').split('/')[-1]
                logger.info(f"Scan initiated for {url}, task_id: {task_id}")
                return {
                    "success": True,
                    "task_id": task_id,
                    "url": url,
                    "scan_type": scan_type
                }
            
            return {"success": False, "error": response.text}
        
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_scan_status(self, task_id: str) -> Dict[str, Any]:
        """Get scan progress"""
        try:
            response = self.session.get(f"{self.api_url}/v0.1/scan/{task_id}")
            return response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def get_scan_issues(self, url: Optional[str] = None) -> List[ScanResult]:
        """Get scan results/issues"""
        try:
            endpoint = f"{self.api_url}/v0.1/knowledge_base/issue_definitions"
            response = self.session.get(endpoint)
            
            if response.status_code != 200:
                return []
            
            issues = response.json()
            scan_results = []
            
            for issue in issues:
                if url and issue.get('url') != url:
                    continue
                
                scan_results.append(ScanResult(
                    url=issue.get('url', ''),
                    vulnerability_type=issue.get('issue_type', {}).get('name', 'Unknown'),
                    severity=issue.get('severity', 'Unknown'),
                    confidence=issue.get('confidence', 'Unknown'),
                    evidence=issue.get('evidence', ''),
                    remediation=issue.get('remediation', ''),
                    issue_detail=issue.get('issue_detail', '')
                ))
            
            return scan_results
        
        except Exception as e:
            logger.error(f"Failed to get scan issues: {e}")
            return []
    
    # ==================== INTRUDER ====================
    
    def intruder_attack(
        self,
        url: str,
        payloads: List[str],
        attack_type: str = "sniper",
        positions: Optional[List[int]] = None
    ) -> List[IntruderResult]:
        """
        Execute Intruder attack
        
        Args:
            url: Target URL
            payloads: List of payloads to test
            attack_type: sniper, battering_ram, pitchfork, cluster_bomb
            positions: Payload positions in request
        """
        results = []
        
        for payload in payloads:
            try:
                test_url = url.replace("FUZZ", payload) if "FUZZ" in url else url
                
                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                response_time = (time.time() - start_time) * 1000
                
                results.append(IntruderResult(
                    payload=payload,
                    status_code=response.status_code,
                    response_length=len(response.content),
                    response_time=response_time,
                    grep_match=self._check_grep_match(response.text, payload)
                ))
                
            except Exception as e:
                logger.warning(f"Intruder request failed for payload {payload}: {e}")
        
        return results
    
    def _check_grep_match(self, response: str, payload: str) -> bool:
        """Check if response contains interesting patterns"""
        patterns = [
            "error", "exception", "sql", "debug", "admin",
            "password", "token", "api_key", "secret"
        ]
        
        response_lower = response.lower()
        return any(pattern in response_lower for pattern in patterns)
    
    # ==================== PROXY HISTORY ====================
    
    def get_proxy_history(self, filter_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get proxy history"""
        try:
            response = self.session.get(f"{self.api_url}/v0.1/proxy/history")
            
            if response.status_code != 200:
                return []
            
            history = response.json()
            
            if filter_url:
                history = [item for item in history if filter_url in item.get('url', '')]
            
            return history
        
        except Exception as e:
            logger.error(f"Failed to get proxy history: {e}")
            return []
    
    def send_to_repeater(self, request_response_id: int) -> bool:
        """Send request to Repeater"""
        try:
            payload = {"request_response_id": request_response_id}
            response = self.session.post(
                f"{self.api_url}/v0.1/repeater",
                json=payload
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send to repeater: {e}")
            return False
    
    # ==================== SCOPE MANAGEMENT ====================
    
    def add_to_scope(self, url: str) -> bool:
        """Add URL to Burp scope"""
        try:
            parsed = urlparse(url)
            payload = {
                "protocol": parsed.scheme,
                "host": parsed.hostname,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "file": parsed.path
            }
            
            response = self.session.post(
                f"{self.api_url}/v0.1/scope",
                json=payload
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"Failed to add to scope: {e}")
            return False
    
    def get_scope(self) -> List[Dict[str, Any]]:
        """Get current scope"""
        try:
            response = self.session.get(f"{self.api_url}/v0.1/scope")
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            logger.error(f"Failed to get scope: {e}")
            return []
    
    # ==================== REPORTING ====================
    
    def generate_report(
        self, 
        output_file: str,
        report_type: str = "html",
        include_requests: bool = True
    ) -> bool:
        """
        Generate vulnerability report
        
        Args:
            output_file: Output file path
            report_type: html, xml, json
            include_requests: Include request/response details
        """
        try:
            issues = self.get_scan_issues()
            
            if report_type == "json":
                report_data = {
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "total_issues": len(issues),
                    "issues": [
                        {
                            "url": issue.url,
                            "type": issue.vulnerability_type,
                            "severity": issue.severity,
                            "confidence": issue.confidence,
                            "evidence": issue.evidence,
                            "remediation": issue.remediation
                        }
                        for issue in issues
                    ]
                }
                
                with open(output_file, 'w') as f:
                    json.dump(report_data, f, indent=2)
            
            elif report_type == "html":
                html_content = self._generate_html_report(issues)
                with open(output_file, 'w') as f:
                    f.write(html_content)
            
            logger.info(f"Report generated: {output_file}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False
    
    def _generate_html_report(self, issues: List[ScanResult]) -> str:
        """Generate HTML report"""
        severity_colors = {
            "High": "#ff4444",
            "Medium": "#ffaa00",
            "Low": "#44ff44",
            "Information": "#4444ff"
        }
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BurpSuite Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }}
        h1 {{ color: #00ff00; border-bottom: 2px solid #00ff00; }}
        .issue {{ 
            background: #2a2a2a; 
            border-left: 4px solid #00ff00; 
            padding: 15px; 
            margin: 15px 0;
            border-radius: 4px;
        }}
        .severity-high {{ border-left-color: #ff4444; }}
        .severity-medium {{ border-left-color: #ffaa00; }}
        .severity-low {{ border-left-color: #44ff44; }}
        .label {{ font-weight: bold; color: #00ff00; }}
        .evidence {{ background: #1a1a1a; padding: 10px; margin: 10px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>BurpSuite Vulnerability Scan Report</h1>
    <p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p>Total Issues: {len(issues)}</p>
    <hr>
"""
        
        for issue in issues:
            severity_class = f"severity-{issue.severity.lower()}"
            html += f"""
    <div class="issue {severity_class}">
        <h2>{issue.vulnerability_type}</h2>
        <p><span class="label">URL:</span> {issue.url}</p>
        <p><span class="label">Severity:</span> {issue.severity}</p>
        <p><span class="label">Confidence:</span> {issue.confidence}</p>
        <div class="evidence">
            <span class="label">Evidence:</span><br>
            {issue.evidence}
        </div>
        <div class="evidence">
            <span class="label">Details:</span><br>
            {issue.issue_detail}
        </div>
        <div class="evidence">
            <span class="label">Remediation:</span><br>
            {issue.remediation}
        </div>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    # ==================== ADVANCED AUTOMATION ====================
    
    def crawl_and_scan(
        self, 
        base_url: str,
        max_depth: int = 3,
        auto_scan: bool = True
    ) -> Dict[str, Any]:
        """
        Crawl website and automatically scan discovered endpoints
        """
        try:
            logger.info(f"Starting crawl and scan for {base_url}")
            
            self.add_to_scope(base_url)
            
            scan_result = self.scan_url(base_url, scan_type="active")
            
            if not scan_result.get("success"):
                return {"success": False, "error": "Scan initiation failed"}
            
            task_id = scan_result["task_id"]
            
            while True:
                status = self.get_scan_status(task_id)
                if status.get("scan_status") == "completed":
                    break
                time.sleep(5)
            
            issues = self.get_scan_issues(base_url)
            
            return {
                "success": True,
                "base_url": base_url,
                "issues_found": len(issues),
                "issues": issues
            }
        
        except Exception as e:
            logger.error(f"Crawl and scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def bulk_scan(self, urls: List[str]) -> Dict[str, List[ScanResult]]:
        """Scan multiple URLs"""
        results = {}
        
        for url in urls:
            logger.info(f"Scanning {url}")
            scan_result = self.scan_url(url)
            
            if scan_result.get("success"):
                time.sleep(2)
                issues = self.get_scan_issues(url)
                results[url] = issues
        
        return results
    
    # ==================== ADVANCED FEATURES ====================
    
    def test_waf_bypass(self, url: str, payload: str) -> Dict[str, Any]:
        """
        Test WAF bypass techniques
        """
        bypass_techniques = [
            payload,
            payload.replace(' ', '/**/'),
            payload.replace(' ', '%09'),
            payload.replace('=', '%3d'),
            payload.upper(),
            payload.replace("'", "%27"),
            f"/*{payload}*/",
            payload.encode('utf-16').decode('utf-16', errors='ignore')
        ]
        
        results = []
        for technique in bypass_techniques:
            try:
                test_url = url.replace("FUZZ", technique) if "FUZZ" in url else f"{url}?test={technique}"
                response = requests.get(test_url, timeout=10)
                
                results.append({
                    "payload": technique,
                    "status_code": response.status_code,
                    "length": len(response.content),
                    "blocked": response.status_code in [403, 406, 429]
                })
            except:
                pass
        
        return {
            "url": url,
            "original_payload": payload,
            "bypass_attempts": results,
            "successful_bypasses": [r for r in results if not r["blocked"]]
        }
    
    def advanced_intruder(
        self,
        url: str,
        base_payloads: List[str],
        mutation_count: int = 5
    ) -> List[IntruderResult]:
        """
        Advanced Intruder with payload mutation
        """
        mutated_payloads = []
        
        for payload in base_payloads:
            mutated_payloads.append(payload)
            
            mutated_payloads.append(payload.upper())
            mutated_payloads.append(payload.lower())
            
            if "'" in payload:
                mutated_payloads.append(payload.replace("'", '"'))
            
            mutated_payloads.append(f"/*{payload}*/")
            mutated_payloads.append(payload.replace(' ', '/**/'))
        
        return self.intruder_attack(url, list(set(mutated_payloads)))
    
    def smart_scan_queue(
        self,
        urls: List[str],
        priority_keywords: List[str] = None
    ) -> Dict[str, Any]:
        """
        Intelligent scan queue management
        """
        if priority_keywords is None:
            priority_keywords = ['admin', 'api', 'login', 'auth', 'upload', 'user']
        
        prioritized = []
        normal = []
        
        for url in urls:
            if any(kw in url.lower() for kw in priority_keywords):
                prioritized.append(url)
            else:
                normal.append(url)
        
        logger.info(f"Scan queue: {len(prioritized)} priority, {len(normal)} normal")
        
        all_results = {}
        
        for url in prioritized:
            result = self.scan_url(url, scan_type="active")
            if result.get("success"):
                all_results[url] = result
                time.sleep(1)
        
        for url in normal:
            result = self.scan_url(url, scan_type="passive")
            if result.get("success"):
                all_results[url] = result
        
        return {
            "total_scanned": len(all_results),
            "priority_count": len(prioritized),
            "results": all_results
        }
    
    def get_collaborator_interactions(self) -> List[Dict[str, Any]]:
        """
        Get Burp Collaborator interactions (OAST)
        """
        try:
            response = self.session.get(f"{self.api_url}/v0.1/collaborator/interactions")
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Failed to get collaborator interactions: {e}")
            return []
    
    def test_ssrf_with_collaborator(self, url: str, param: str) -> Dict[str, Any]:
        """
        Test SSRF using Burp Collaborator
        """
        try:
            collab_response = self.session.post(f"{self.api_url}/v0.1/collaborator/generate")
            if collab_response.status_code != 200:
                return {"success": False, "error": "Failed to generate collaborator URL"}
            
            collab_url = collab_response.json().get("collaborator_url")
            
            test_url = f"{url}?{param}={collab_url}"
            requests.get(test_url, timeout=10)
            
            time.sleep(5)
            
            interactions = self.get_collaborator_interactions()
            
            return {
                "success": True,
                "collaborator_url": collab_url,
                "interactions_received": len(interactions),
                "vulnerable": len(interactions) > 0,
                "interactions": interactions
            }
        
        except Exception as e:
            logger.error(f"SSRF test failed: {e}")
            return {"success": False, "error": str(e)}
    
    def export_state(self, output_file: str) -> bool:
        """
        Export complete Burp state
        """
        try:
            state = {
                "scope": self.get_scope(),
                "proxy_history": self.get_proxy_history(),
                "scan_issues": [
                    {
                        "url": issue.url,
                        "type": issue.vulnerability_type,
                        "severity": issue.severity,
                        "confidence": issue.confidence,
                        "evidence": issue.evidence
                    }
                    for issue in self.get_scan_issues()
                ],
                "exported_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(output_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"Burp state exported to {output_file}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to export state: {e}")
            return False
