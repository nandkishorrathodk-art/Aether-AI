# 🧪 Aether AI v2.0 - Testing & Quality Assurance Guide

## 📋 Overview

This guide covers testing the **FULL AUTONOMOUS MODE** and all v2.0 features.

---

## 🚀 Quick Test

```bash
# Run all tests
python run_tests.bat

# Or with pytest directly
pytest tests/ -v
```

---

## 🧩 Test Suites

### **1. Autonomous System Tests** (`test_autonomous_system.py`)

Tests complete autonomous workflow:

- ✅ Autonomous Brain (planning & execution)
- ✅ Vision System (OCR + screen analysis)
- ✅ Self-Coder (code generation & execution)
- ✅ Decision Engine (bug validation & decisions)
- ✅ Auto Executor (end-to-end workflow)

**Run:**
```bash
pytest tests/test_autonomous_system.py -v
```

### **2. Bug Bounty Enhancements** (`test_bugbounty_enhancements.py`)

Tests advanced bug bounty features:

- ✅ AI PoC Generator
- ✅ WAF Bypass Techniques
- ✅ Report Quality Scorer

**Run:**
```bash
pytest tests/test_bugbounty_enhancements.py -v
```

---

## 🎯 Manual Testing Scenarios

### **Scenario 1: Basic Autonomous Workflow**

**Goal:** Test end-to-end autonomous mode with mocked components

**Steps:**
1. Start Aether AI backend:
   ```bash
   python -m uvicorn src.api.main:app --reload
   ```

2. Start autonomous hunt (dry run):
   ```bash
   curl -X POST http://localhost:8000/api/v1/autonomous/simple-start \
     -H "Content-Type: application/json" \
     -d "{\"target\": \"example.com\"}"
   ```

3. Check status:
   ```bash
   curl http://localhost:8000/api/v1/autonomous/status
   ```

4. Stop if needed:
   ```bash
   curl -X POST http://localhost:8000/api/v1/autonomous/stop
   ```

**Expected Result:**
- ✅ System starts without errors
- ✅ Status shows "running"
- ✅ Can stop gracefully

---

### **Scenario 2: Vision System Test**

**Goal:** Test screen reading and OCR

**Steps:**
1. Create test screenshot with text:
   - Open Burp Suite
   - Take screenshot (save as `test_burp.png`)

2. Test OCR:
   ```python
   from src.autonomous.vision_system import VisionSystem
   import asyncio
   
   vision = VisionSystem()
   
   async def test():
       result = await vision.detect_application("test_burp.png", "Burp Suite")
       print(f"Detected: {result}")
   
   asyncio.run(test())
   ```

**Expected Result:**
- ✅ Detects "Burp Suite" correctly
- ✅ Extracts text from screenshot

---

### **Scenario 3: Self-Coder Test**

**Goal:** Test AI code generation and execution

**Steps:**
```python
from src.autonomous.self_coder import SelfCoder
import asyncio

coder = SelfCoder()

async def test():
    # Generate exploit code
    code = await coder.write_exploit_code({
        "vulnerability_type": "xss",
        "target_url": "https://example.com/search",
        "description": "XSS in search parameter"
    })
    
    print("Generated Code:")
    print(code)
    
    # Execute safe code
    safe_code = 'print("Hello from AI!")'
    result = await coder.execute_code(safe_code)
    
    print("\nExecution Result:")
    print(result)

asyncio.run(test())
```

**Expected Result:**
- ✅ Generates valid Python exploit code
- ✅ Executes safe code successfully
- ✅ Returns proper execution results

---

### **Scenario 4: Decision Engine Test**

**Goal:** Test AI decision making

**Steps:**
```python
from src.autonomous.decision_engine import DecisionEngine
import asyncio

engine = DecisionEngine()

async def test():
    # Test bug validation
    finding = {
        "type": "SQL Injection",
        "location": "/api/user?id=1",
        "evidence": "SQL syntax error in response",
        "context": "Database error message exposed"
    }
    
    decision = await engine.is_this_a_bug(finding)
    
    print("Bug Decision:")
    print(f"  Is Bug: {decision['is_bug']}")
    print(f"  Severity: {decision['severity']}")
    print(f"  Confidence: {decision['confidence']}")
    print(f"  Reasoning: {decision['reasoning']}")

asyncio.run(test())
```

**Expected Result:**
- ✅ Correctly identifies bug
- ✅ Assigns appropriate severity
- ✅ Provides confidence score
- ✅ Gives clear reasoning

---

### **Scenario 5: WAF Bypass Test**

**Goal:** Test WAF bypass payload generation

**Steps:**
```python
from src.bugbounty.waf_bypass import WAFBypass

waf = WAFBypass()

# Generate SQL injection bypass payloads
original = "' OR 1=1--"
payloads = waf.generate_bypass_payloads(original, "sqli")

print(f"Generated {len(payloads)} bypass variants:")
for i, p in enumerate(payloads[:10], 1):
    print(f"\n{i}. {p['technique']}")
    print(f"   Payload: {p['payload']}")
```

**Expected Result:**
- ✅ Generates 20+ bypass variants
- ✅ Includes URL encoding, case variation, comment injection
- ✅ Each payload has technique description

---

### **Scenario 6: Report Scorer Test**

**Goal:** Test report quality scoring

**Steps:**
```python
from src.bugbounty.report_scorer import ReportScorer

scorer = ReportScorer()

# Test with sample report
report = {
    "title": "SQL Injection in Login Form Allows Authentication Bypass",
    "description": "A SQL injection vulnerability exists in the login form...",
    "steps_to_reproduce": "1. Navigate to /login\n2. Enter ' OR '1'='1 in username\n3. Click Submit",
    "impact": "Attackers can bypass authentication and access any account",
    "proof_of_concept": "curl -X POST https://example.com/login -d \"username=' OR '1'='1&password=x\"",
    "attachments": ["screenshot.png", "burp_log.txt"]
}

result = scorer.score_report(report)

print(f"Report Score: {result['percentage']}%")
print(f"Quality: {result['quality_rating']}")
print(f"Recommendation: {result['submit_recommendation']}")
print("\nBreakdown:")
for item in result['breakdown']:
    print(f"  {item['category']}: {item['percentage']}% {item['status']}")
```

**Expected Result:**
- ✅ Scores between 0-100%
- ✅ Provides quality rating
- ✅ Gives submission recommendation
- ✅ Shows category breakdown

---

## 🐛 Troubleshooting

### **Test Failures**

**Problem:** `ImportError: No module named 'src.autonomous'`

**Solution:**
```bash
# Run from project root
cd C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo
set PYTHONPATH=%CD%
pytest tests/
```

**Problem:** `pytesseract.TesseractNotFoundError`

**Solution:**
1. Download Tesseract OCR: https://github.com/UB-Mannheim/tesseract/wiki
2. Install to `C:\Program Files\Tesseract-OCR\`
3. Add to PATH or set in code:
   ```python
   pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
   ```

**Problem:** LLM tests fail with "API key not set"

**Solution:**
```bash
# Set test API key in .env
OPENAI_API_KEY=test_key_for_testing
# Or use mocks in tests (already done)
```

---

## 📊 Coverage Reports

Generate HTML coverage report:

```bash
pytest tests/ --cov=src --cov-report=html
```

Open `htmlcov/index.html` in browser.

**Target Coverage:**
- Core modules: 80%+
- Autonomous system: 70%+
- Overall: 75%+

---

## ✅ Pre-Release Checklist

Before releasing v2.0:

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Coverage > 75%
- [ ] Manual test scenarios completed
- [ ] No critical errors in logs
- [ ] Dependencies documented
- [ ] README updated
- [ ] SECURITY.md reviewed
- [ ] Example scenarios tested
- [ ] Error messages are helpful
- [ ] Performance benchmarks met

---

## 🚀 Continuous Testing

**During Development:**
```bash
# Watch mode (re-run on file changes)
pytest-watch tests/

# Fast tests only
pytest tests/ -m "not slow"

# Specific test
pytest tests/test_autonomous_system.py::TestAutonomousBrain::test_brain_initialization -v
```

**Before Commit:**
```bash
# Run all tests + linting
pytest tests/ -v
flake8 src/
mypy src/
```

---

## 📞 Support

Issues with tests?
- Check logs: `logs/test_*.log`
- Review test output carefully
- Check dependencies: `pip list`
- Ensure Tesseract OCR installed
- Verify Python 3.11+

---

**Happy Testing! 🎉**
