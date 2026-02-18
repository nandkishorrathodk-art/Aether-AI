"""
Test Suite for Autonomous System v2.0

Tests all autonomous components to ensure bulletproof operation.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.autonomous.autonomous_brain import AutonomousBrain, AgentState
from src.autonomous.vision_system import VisionSystem
from src.autonomous.self_coder import SelfCoder
from src.autonomous.decision_engine import DecisionEngine
from src.autonomous.auto_executor import AutoExecutor


class TestAutonomousBrain:
    """Test Autonomous Brain component"""
    
    @pytest.fixture
    def brain(self):
        return AutonomousBrain()
    
    def test_brain_initialization(self, brain):
        """Test brain initializes correctly"""
        assert brain.state == AgentState.IDLE
        assert brain.current_task is None
        assert brain.findings == []
    
    @pytest.mark.asyncio
    async def test_create_master_plan(self, brain):
        """Test master plan creation"""
        goal = "Find bugs on example.com"
        
        with patch.object(brain.llm, 'get_completion') as mock_llm:
            mock_llm.return_value = '''```json
{
  "goal": "Find bugs on example.com",
  "estimated_duration_minutes": 120,
  "steps": [
    {
      "step_number": 1,
      "action": "Open Burp Suite",
      "method": "pc_control",
      "parameters": {"app": "burp"},
      "success_criteria": "Burp running",
      "wait_after": 3
    }
  ]
}
```'''
            
            plan = await brain._create_master_plan(goal)
            
            assert plan["goal"] == goal
            assert "steps" in plan
            assert len(plan["steps"]) > 0
            assert plan["steps"][0]["action"] == "Open Burp Suite"
    
    @pytest.mark.asyncio
    async def test_extract_target_from_goal(self, brain):
        """Test target extraction from goal"""
        goal1 = "Find bugs on apple.com"
        target1 = brain._extract_target_from_goal(goal1)
        assert "apple.com" in target1
        
        goal2 = "Scan https://example.com for vulnerabilities"
        target2 = brain._extract_target_from_goal(goal2)
        assert "example.com" in target2


class TestVisionSystem:
    """Test Vision System (OCR + AI)"""
    
    @pytest.fixture
    def vision(self):
        return VisionSystem()
    
    def test_vision_initialization(self, vision):
        """Test vision system initializes"""
        assert vision.llm is not None
    
    @pytest.mark.asyncio
    async def test_detect_application_burp(self, vision):
        """Test Burp Suite detection"""
        with patch.object(vision, '_extract_text') as mock_ocr:
            mock_ocr.return_value = """
            Burp Suite Professional
            Proxy Intercept Target Intruder Repeater
            HTTP history
            """
            
            detected = await vision.detect_application("fake_screenshot.png", "Burp Suite")
            
            assert detected is True
    
    @pytest.mark.asyncio
    async def test_analyze_burp_findings(self, vision):
        """Test Burp findings analysis"""
        with patch.object(vision, '_extract_text') as mock_ocr:
            mock_ocr.return_value = """
            Issue: SQL Injection
            Severity: High
            URL: https://example.com/api/user?id=1
            Evidence: SQL syntax error detected
            """
            
            with patch.object(vision.llm, 'get_completion') as mock_llm:
                mock_llm.return_value = '''{
  "bugs_found": [
    {
      "type": "SQL Injection",
      "location": "/api/user?id=1",
      "evidence": "SQL syntax error",
      "severity": "high",
      "confidence": 0.85
    }
  ]
}'''
                
                result = await vision.analyze_burp_findings("fake_screenshot.png")
                
                assert result["success"] is True
                assert len(result["bugs_found"]) > 0
                assert result["bugs_found"][0]["type"] == "SQL Injection"


class TestSelfCoder:
    """Test Self-Coder (AI writes code)"""
    
    @pytest.fixture
    def coder(self):
        return SelfCoder()
    
    def test_coder_initialization(self, coder):
        """Test coder initializes"""
        assert coder.llm is not None
        assert coder.code_history == []
    
    @pytest.mark.asyncio
    async def test_write_exploit_code(self, coder):
        """Test exploit code generation"""
        requirements = {
            "vulnerability_type": "sqli",
            "target_url": "https://example.com/login",
            "description": "SQL injection in login form"
        }
        
        with patch.object(coder.llm, 'get_completion') as mock_llm:
            mock_llm.return_value = '''```python
import requests

url = "https://example.com/login"
payload = "' OR '1'='1"

response = requests.post(url, data={"username": payload, "password": payload})
print(response.text)
```'''
            
            code = await coder.write_exploit_code(requirements)
            
            assert "import requests" in code
            assert "example.com" in code
            assert len(coder.code_history) == 1
    
    @pytest.mark.asyncio
    async def test_execute_code_success(self, coder):
        """Test code execution (safe code)"""
        safe_code = '''
print("Hello from Aether AI!")
result = 2 + 2
print(f"Result: {result}")
'''
        
        result = await coder.execute_code(safe_code, timeout=5)
        
        assert result["success"] is True
        assert "Hello from Aether AI!" in result["stdout"]


class TestDecisionEngine:
    """Test Decision Engine (AI decisions)"""
    
    @pytest.fixture
    def engine(self):
        return DecisionEngine()
    
    def test_engine_initialization(self, engine):
        """Test engine initializes"""
        assert engine.llm is not None
        assert engine.decision_history == []
    
    @pytest.mark.asyncio
    async def test_is_this_a_bug_positive(self, engine):
        """Test bug validation - positive case"""
        finding = {
            "type": "SQL Injection",
            "location": "/api/user",
            "evidence": "SQL syntax error in response",
            "context": "Error message exposes database structure"
        }
        
        with patch.object(engine.llm, 'get_completion') as mock_llm:
            mock_llm.return_value = '''{
  "is_bug": true,
  "severity": "high",
  "exploitable": true,
  "confidence": 0.9,
  "reasoning": "Clear SQL injection with error-based exploitation",
  "false_positive_risk": 0.1
}'''
            
            decision = await engine.is_this_a_bug(finding)
            
            assert decision["is_bug"] is True
            assert decision["severity"] == "high"
            assert decision["confidence"] >= 0.7
    
    @pytest.mark.asyncio
    async def test_should_exploit_high_confidence(self, engine):
        """Test exploitation decision - should exploit"""
        bug = {
            "severity": "high",
            "confidence": 0.85,
            "type": "IDOR"
        }
        
        decision = await engine.should_exploit(bug)
        
        assert "should_exploit" in decision
        assert "risk_level" in decision
    
    @pytest.mark.asyncio
    async def test_should_submit_report_high_quality(self, engine):
        """Test submission decision - high quality report"""
        bug = {"type": "XSS", "severity": "medium"}
        report = {
            "title": "Reflected XSS in Search Parameter on example.com",
            "description": "A reflected cross-site scripting vulnerability exists in the search functionality. This allows attackers to inject malicious JavaScript that executes in victim's browser context.",
            "steps_to_reproduce": "1. Navigate to https://example.com/search\n2. Enter payload: <script>alert(document.cookie)</script>\n3. Submit search\n4. Observe JavaScript execution in response",
            "impact": "Attackers can steal session cookies, perform actions on behalf of users, and compromise user accounts through phishing attacks.",
            "proof_of_concept": "curl 'https://example.com/search?q=<script>alert(1)</script>'",
            "attachments": ["screenshot1.png", "screenshot2.png"]
        }
        
        decision = await engine.should_submit_report(bug, report)
        
        assert "should_submit" in decision
        assert "report_score" in decision


class TestAutoExecutor:
    """Test Auto Executor (Full end-to-end)"""
    
    @pytest.fixture
    def executor(self):
        return AutoExecutor()
    
    def test_executor_initialization(self, executor):
        """Test executor initializes all components"""
        assert executor.brain is not None
        assert executor.vision is not None
        assert executor.coder is not None
        assert executor.decision_engine is not None
    
    @pytest.mark.asyncio
    async def test_phase_1_setup(self, executor):
        """Test Phase 1: Setup"""
        with patch.object(executor.pc_controller, 'launch_app') as mock_launch:
            mock_launch.return_value = {"success": True}
            
            result = await executor._phase_1_setup("example.com")
            
            assert result["success"] is True
    
    def test_generate_reproduction_steps(self, executor):
        """Test reproduction steps generation"""
        bug = {
            "type": "SQL Injection",
            "location": "/api/user?id=1",
            "evidence": "SQL error message"
        }
        
        steps = executor._generate_reproduction_steps(bug)
        
        assert "Navigate to" in steps
        assert "/api/user?id=1" in steps
        assert "SQL Injection" in steps
    
    def test_get_impact_description(self, executor):
        """Test impact descriptions"""
        impact_sqli = executor._get_impact_description("SQL Injection")
        assert "database" in impact_sqli.lower()
        
        impact_xss = executor._get_impact_description("XSS")
        assert "javascript" in impact_xss.lower() or "cookie" in impact_xss.lower()
        
        impact_idor = executor._get_impact_description("IDOR")
        assert "access" in impact_idor.lower()


@pytest.mark.integration
class TestIntegrationAutonomous:
    """Integration tests for full autonomous workflow"""
    
    @pytest.mark.asyncio
    async def test_full_workflow_mock(self):
        """Test complete autonomous workflow with mocks"""
        executor = AutoExecutor()
        
        # This is a dry-run test with all external dependencies mocked
        # Real integration test would require Burp Suite running
        
        with patch.object(executor.pc_controller, 'launch_app'):
            with patch.object(executor.vision, 'analyze_burp_findings') as mock_analyze:
                mock_analyze.return_value = {
                    "success": True,
                    "bugs_found": [
                        {
                            "type": "IDOR",
                            "location": "/api/user/profile",
                            "evidence": "Can access other users",
                            "severity": "high",
                            "confidence": 0.85
                        }
                    ]
                }
                
                # Test would run full workflow here
                # For now, just verify components are wired correctly
                assert executor.brain is not None
                assert executor.vision is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
