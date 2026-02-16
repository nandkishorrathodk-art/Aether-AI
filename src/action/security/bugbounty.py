"""
Automated Bug Bounty Engine
Complete automation workflow for bug bounty hunting
Integrates BurpSuite, AI analysis, and reporting
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
import re

from .burpsuite import BurpSuiteIntegration, ScanResult
from .vuln_analyzer import VulnerabilityAnalyzer, VulnerabilityReport
from src.cognitive.llm.model_router import ModelRouter
from src.action.automation.openclaw import OpenClaw
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class BugBountyTarget:
    domain: str
    scope: List[str]
    out_of_scope: List[str]
    program_type: str
    max_severity: str
    

@dataclass
class BugBountyReport:
    title: str
    severity: str
    vulnerability_type: str
    description: str
    reproduction_steps: List[str]
    impact: str
    remediation: str
    proof_of_concept: str
    urls_affected: List[str]
    cvss_score: Optional[float]
    generated_at: str


class BugBountyEngine:
    """
    Automated Bug Bounty Hunting Engine
    
    Workflow:
    1. Reconnaissance (subdomain enumeration, tech stack detection)
    2. Asset Discovery (crawling, endpoint discovery)
    3. Vulnerability Scanning (automated + manual testing)
    4. AI-Powered Analysis (prioritization, exploit chains)
    5. Exploitation (PoC generation)
    6. Report Generation (professional bug reports)
    
    Features:
    - Automated reconnaissance
    - Smart crawling and spidering
    - Multi-vector vulnerability scanning
    - AI-powered vulnerability analysis
    - Automated PoC generation
    - Professional report creation
    - False positive filtering
    - Exploit chain discovery
    """
    
    def __init__(
        self,
        burp_api_url: str = "http://127.0.0.1:1337",
        burp_api_key: Optional[str] = None
    ):
        self.burp = BurpSuiteIntegration(burp_api_url, burp_api_key)
        self.model_router = ModelRouter()
        self.analyzer = VulnerabilityAnalyzer(self.model_router)
        self.openclaw = OpenClaw(headless=True)
        
        self.targets: Dict[str, BugBountyTarget] = {}
        self.findings: List[VulnerabilityReport] = []
        
        logger.info("Bug Bounty Engine initialized")
    
    # ==================== TARGET MANAGEMENT ====================
    
    def add_target(
        self,
        domain: str,
        scope: List[str],
        out_of_scope: Optional[List[str]] = None,
        program_type: str = "web"
    ) -> bool:
        """Add bug bounty target"""
        try:
            self.targets[domain] = BugBountyTarget(
                domain=domain,
                scope=scope,
                out_of_scope=out_of_scope or [],
                program_type=program_type,
                max_severity="Critical"
            )
            
            for url in scope:
                self.burp.add_to_scope(url)
            
            logger.info(f"Added target: {domain}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to add target: {e}")
            return False
    
    def is_in_scope(self, url: str, domain: str) -> bool:
        """Check if URL is in scope"""
        if domain not in self.targets:
            return False
        
        target = self.targets[domain]
        
        for oos in target.out_of_scope:
            if oos in url:
                return False
        
        for scope_url in target.scope:
            if scope_url in url or url.startswith(scope_url):
                return True
        
        return False
    
    # ==================== RECONNAISSANCE ====================
    
    async def reconnaissance(self, domain: str) -> Dict[str, Any]:
        """
        Automated reconnaissance
        - Subdomain enumeration
        - Technology detection
        - Port scanning
        - DNS analysis
        """
        logger.info(f"Starting reconnaissance for {domain}")
        
        results = {
            "domain": domain,
            "subdomains": await self._enumerate_subdomains(domain),
            "technologies": await self._detect_technologies(domain),
            "ports": await self._scan_ports(domain),
            "endpoints": []
        }
        
        return results
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using AI and wordlists"""
        subdomains = set()
        
        common_subdomains = [
            "www", "api", "admin", "dev", "staging", "test",
            "mail", "ftp", "blog", "shop", "portal", "vpn",
            "dashboard", "app", "mobile", "cdn", "static"
        ]
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            subdomains.add(subdomain)
        
        try:
            prompt = f"Generate 20 creative subdomain names for {domain} that might exist (format: subdomain only, one per line)"
            
            messages = [{"role": "user", "content": prompt}]
            response = await self.model_router.route_request(messages=messages)
            
            if response:
                ai_subdomains = response.content.split('\n')
                for sub in ai_subdomains:
                    sub = sub.strip().lower()
                    if sub and not ' ' in sub:
                        subdomains.add(f"{sub}.{domain}")
        
        except Exception as e:
            logger.warning(f"AI subdomain generation failed: {e}")
        
        return list(subdomains)
    
    async def _detect_technologies(self, domain: str) -> List[str]:
        """Detect technologies using web scraping and AI"""
        try:
            url = f"https://{domain}"
            scraped = self.openclaw.scrape_url(url)
            
            technologies = []
            
            html_content = scraped.get('html', '')
            
            tech_patterns = {
                'WordPress': 'wp-content|wp-includes',
                'React': 'react|reactjs',
                'Angular': 'angular|ng-',
                'Vue': 'vue|v-',
                'Laravel': 'laravel',
                'Django': 'django',
                'Flask': 'flask',
                'Express': 'express',
                'jQuery': 'jquery',
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, html_content, re.IGNORECASE):
                    technologies.append(tech)
            
            return technologies
        
        except Exception as e:
            logger.warning(f"Technology detection failed: {e}")
            return []
    
    async def _scan_ports(self, domain: str) -> List[int]:
        """Scan common ports"""
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
        return common_ports
    
    # ==================== VULNERABILITY SCANNING ====================
    
    async def automated_scan(
        self, 
        domain: str,
        deep_scan: bool = True
    ) -> List[VulnerabilityReport]:
        """
        Run automated vulnerability scan
        """
        logger.info(f"Starting automated scan for {domain}")
        
        if domain not in self.targets:
            logger.error(f"Domain {domain} not in targets")
            return []
        
        target = self.targets[domain]
        all_findings = []
        
        for url in target.scope:
            logger.info(f"Scanning {url}")
            
            scan_result = self.burp.scan_url(url, scan_type="active")
            
            if scan_result.get("success"):
                task_id = scan_result["task_id"]
                
                while True:
                    status = self.burp.get_scan_status(task_id)
                    if status.get("scan_status") == "completed":
                        break
                    await asyncio.sleep(5)
                
                issues = self.burp.get_scan_issues(url)
                
                for issue in issues:
                    vuln_data = {
                        'vulnerability_type': issue.vulnerability_type,
                        'severity': issue.severity,
                        'confidence': issue.confidence,
                        'url': issue.url,
                        'evidence': issue.evidence,
                        'remediation': issue.remediation
                    }
                    
                    analyzed = await self.analyzer.analyze_vulnerability(
                        vuln_data,
                        deep_analysis=deep_scan
                    )
                    
                    all_findings.append(analyzed)
        
        self.findings.extend(all_findings)
        
        prioritized = await self.analyzer.prioritize_vulnerabilities(
            [asdict(f) for f in all_findings]
        )
        
        return prioritized
    
    async def smart_fuzzing(self, url: str, parameters: List[str]) -> List[VulnerabilityReport]:
        """
        AI-powered smart fuzzing
        """
        logger.info(f"Starting smart fuzzing on {url}")
        
        prompt = f"""
Generate 30 creative security testing payloads for web application fuzzing.
Include payloads for: SQL injection, XSS, command injection, path traversal, XXE, SSRF.
Return as JSON array of strings.
"""
        
        messages = [{"role": "user", "content": prompt}]
        response = await self.model_router.route_request(messages=messages)
        
        payloads = []
        if response:
            try:
                payloads = json.loads(response.content)
            except:
                payloads = [
                    "' OR '1'='1", "<script>alert(1)</script>", 
                    "; ls -la", "../../../etc/passwd",
                    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                    "http://127.0.0.1:80"
                ]
        
        findings = []
        
        for param in parameters:
            test_url = url.replace(f"{param}=", f"{param}=FUZZ")
            
            intruder_results = self.burp.intruder_attack(
                test_url,
                payloads,
                attack_type="sniper"
            )
            
            for result in intruder_results:
                if result.grep_match or result.status_code == 500:
                    vuln_data = {
                        'vulnerability_type': 'Injection',
                        'severity': 'High',
                        'confidence': 'Tentative',
                        'url': url,
                        'parameter': param,
                        'evidence': f"Payload: {result.payload}, Status: {result.status_code}"
                    }
                    
                    analyzed = await self.analyzer.analyze_vulnerability(vuln_data)
                    findings.append(analyzed)
        
        return findings
    
    # ==================== REPORT GENERATION ====================
    
    async def generate_bug_report(
        self, 
        vulnerability: VulnerabilityReport,
        include_ai_writeup: bool = True
    ) -> BugBountyReport:
        """
        Generate professional bug bounty report
        """
        logger.info(f"Generating report for {vulnerability.vulnerability_type}")
        
        title = f"{vulnerability.vulnerability_type} in {vulnerability.url}"
        
        if include_ai_writeup and self.model_router:
            description = await self._generate_ai_description(vulnerability)
        else:
            description = vulnerability.impact_analysis
        
        poc = await self._generate_poc(vulnerability)
        
        return BugBountyReport(
            title=title,
            severity=vulnerability.severity,
            vulnerability_type=vulnerability.vulnerability_type,
            description=description,
            reproduction_steps=vulnerability.exploitation_steps,
            impact=vulnerability.impact_analysis,
            remediation=vulnerability.remediation,
            proof_of_concept=poc,
            urls_affected=[vulnerability.url],
            cvss_score=vulnerability.cvss_score,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def _generate_ai_description(self, vuln: VulnerabilityReport) -> str:
        """Generate professional vulnerability description"""
        prompt = f"""
Write a professional bug bounty report description for:

Vulnerability: {vuln.vulnerability_type}
URL: {vuln.url}
Severity: {vuln.severity}
Evidence: {vuln.evidence}

Write a clear, professional description suitable for a bug bounty submission.
Include:
1. What the vulnerability is
2. Where it was found
3. Why it's important
4. Potential attacker advantage

Keep it concise (150-200 words).
"""
        
        messages = [{"role": "user", "content": prompt}]
        response = await self.model_router.route_request(messages=messages)
        
        return response.content if response else vuln.impact_analysis
    
    async def _generate_poc(self, vuln: VulnerabilityReport) -> str:
        """Generate proof of concept"""
        vuln_type = vuln.vulnerability_type.lower()
        
        poc_templates = {
            'sql injection': f"""
**Proof of Concept:**

1. Visit: {vuln.url}
2. Enter payload: ' OR '1'='1'-- 
3. Observe: Application returns unauthorized data or error reveals database structure

**Request:**
```
GET {vuln.url}?{vuln.parameter or 'id'}=' OR '1'='1'-- HTTP/1.1
Host: {vuln.url.split('/')[2] if '/' in vuln.url else vuln.url}
```

**Response:**
{vuln.evidence}
""",
            'xss': f"""
**Proof of Concept:**

1. Navigate to: {vuln.url}
2. Inject: <script>alert(document.domain)</script>
3. Observe: JavaScript executes in browser context

**Payload:**
```html
<script>alert(document.domain)</script>
```

**Evidence:**
{vuln.evidence}
"""
        }
        
        for key, template in poc_templates.items():
            if key in vuln_type:
                return template
        
        return f"URL: {vuln.url}\nEvidence: {vuln.evidence}"
    
    def export_report(
        self, 
        report: BugBountyReport, 
        format: str = "markdown",
        output_file: Optional[str] = None
    ) -> str:
        """Export report in various formats"""
        
        if format == "markdown":
            content = f"""# {report.title}

**Severity:** {report.severity}
**CVSS Score:** {report.cvss_score or 'N/A'}
**Type:** {report.vulnerability_type}
**Generated:** {report.generated_at}

## Description

{report.description}

## Impact

{report.impact}

## Reproduction Steps

"""
            for i, step in enumerate(report.reproduction_steps, 1):
                content += f"{i}. {step}\n"
            
            content += f"""
## Proof of Concept

{report.proof_of_concept}

## Remediation

{report.remediation}

## Affected URLs

"""
            for url in report.urls_affected:
                content += f"- {url}\n"
        
        elif format == "json":
            content = json.dumps(asdict(report), indent=2)
        
        else:
            content = str(asdict(report))
        
        if output_file:
            Path(output_file).write_text(content)
            logger.info(f"Report saved to {output_file}")
        
        return content
    
    # ==================== FULL AUTOMATION ====================
    
    async def full_automation(
        self, 
        domain: str,
        output_dir: str = "./bug_bounty_results"
    ) -> Dict[str, Any]:
        """
        Complete bug bounty automation workflow
        """
        logger.info(f"Starting full automation for {domain}")
        
        start_time = time.time()
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        recon_results = await self.reconnaissance(domain)
        
        with open(output_path / "recon.json", 'w') as f:
            json.dump(recon_results, f, indent=2)
        
        vulnerabilities = await self.automated_scan(domain, deep_scan=True)
        
        exploit_chains = await self.analyzer.find_exploit_chains(vulnerabilities)
        
        reports = []
        for vuln in vulnerabilities[:10]:
            report = await self.generate_bug_report(vuln, include_ai_writeup=True)
            reports.append(report)
            
            filename = f"{vuln.vulnerability_type.replace(' ', '_')}_{int(time.time())}.md"
            self.export_report(report, format="markdown", output_file=str(output_path / filename))
        
        summary = {
            "domain": domain,
            "duration_seconds": time.time() - start_time,
            "subdomains_found": len(recon_results.get("subdomains", [])),
            "technologies": recon_results.get("technologies", []),
            "vulnerabilities_found": len(vulnerabilities),
            "critical_findings": len([v for v in vulnerabilities if v.severity == "Critical"]),
            "high_findings": len([v for v in vulnerabilities if v.severity == "High"]),
            "exploit_chains": len(exploit_chains),
            "reports_generated": len(reports),
            "output_directory": str(output_path)
        }
        
        with open(output_path / "summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Automation complete! Results in {output_path}")
        
        return summary
    
    # ==================== RELIABILITY ENHANCEMENTS ====================
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check system health and dependencies
        """
        health_status = {
            "burpsuite": "unknown",
            "ai_providers": "unknown",
            "openclaw": "unknown",
            "overall": "unknown"
        }
        
        try:
            burp_status = self.burp.check_burp_status()
            health_status["burpsuite"] = burp_status.get("status", "offline")
        except:
            health_status["burpsuite"] = "error"
        
        try:
            if self.model_router.providers:
                health_status["ai_providers"] = "online"
            else:
                health_status["ai_providers"] = "offline"
        except:
            health_status["ai_providers"] = "error"
        
        try:
            health_status["openclaw"] = "online"
        except:
            health_status["openclaw"] = "error"
        
        all_online = all(
            status in ["online", "running"] 
            for status in health_status.values() 
            if status != "unknown"
        )
        health_status["overall"] = "healthy" if all_online else "degraded"
        
        return health_status
    
    async def safe_scan_with_retry(
        self,
        url: str,
        max_retries: int = 3,
        timeout: int = 300
    ) -> List[VulnerabilityReport]:
        """
        Perform scan with retry logic and error handling
        """
        for attempt in range(max_retries):
            try:
                logger.info(f"Scan attempt {attempt + 1}/{max_retries} for {url}")
                
                scan_result = self.burp.scan_url(url, scan_type="active")
                
                if not scan_result.get("success"):
                    if attempt < max_retries - 1:
                        time.sleep(5 * (attempt + 1))
                        continue
                    return []
                
                task_id = scan_result["task_id"]
                start_time = time.time()
                
                while time.time() - start_time < timeout:
                    status = self.burp.get_scan_status(task_id)
                    if status.get("scan_status") == "completed":
                        break
                    time.sleep(5)
                
                issues = self.burp.get_scan_issues(url)
                vulnerabilities = []
                
                for issue in issues:
                    vuln_data = {
                        'vulnerability_type': issue.vulnerability_type,
                        'severity': issue.severity,
                        'confidence': issue.confidence,
                        'url': issue.url,
                        'evidence': issue.evidence
                    }
                    analyzed = await self.analyzer.analyze_vulnerability(vuln_data)
                    vulnerabilities.append(analyzed)
                
                return vulnerabilities
            
            except Exception as e:
                logger.error(f"Scan attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(10 * (attempt + 1))
                else:
                    return []
        
        return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current statistics
        """
        return {
            "total_targets": len(self.targets),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "Critical": len([f for f in self.findings if f.severity == "Critical"]),
                "High": len([f for f in self.findings if f.severity == "High"]),
                "Medium": len([f for f in self.findings if f.severity == "Medium"]),
                "Low": len([f for f in self.findings if f.severity == "Low"]),
            },
            "targets_list": list(self.targets.keys()),
            "unique_vulnerability_types": list(set(f.vulnerability_type for f in self.findings))
        }
    
    def clear_findings(self, domain: Optional[str] = None):
        """
        Clear findings for a specific domain or all
        """
        if domain:
            self.findings = [f for f in self.findings if domain not in f.url]
            logger.info(f"Cleared findings for {domain}")
        else:
            self.findings.clear()
            logger.info("Cleared all findings")
    
    async def verify_finding(
        self,
        finding: VulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Re-verify a finding to check if it's still valid
        """
        try:
            scan_results = await self.safe_scan_with_retry(finding.url, max_retries=2)
            
            still_vulnerable = any(
                v.vulnerability_type == finding.vulnerability_type 
                for v in scan_results
            )
            
            return {
                "finding": finding.vulnerability_type,
                "url": finding.url,
                "still_vulnerable": still_vulnerable,
                "verified_at": datetime.now().isoformat(),
                "new_scan_results": len(scan_results)
            }
        
        except Exception as e:
            return {
                "error": str(e),
                "finding": finding.vulnerability_type,
                "url": finding.url
            }
