"""
Comprehensive Aether AI Test Suite
Tests all features including Chat, Security, BurpSuite, and Bug Bounty
"""

import requests
import json
import time
import sys

API_URL = "http://127.0.0.1:8000"
test_results = {
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "tests": []
}


def print_header(title, char="="):
    width = 70
    print(f"\n{char * width}")
    print(f"  {title.center(width - 4)}")
    print(f"{char * width}\n")


def test_result(test_name, success, message="", skip=False):
    """Record test result"""
    global test_results
    
    status = "SKIP" if skip else ("PASS" if success else "FAIL")
    symbol = "⊘" if skip else ("✓" if success else "✗")
    
    print(f"{symbol} {test_name}: {status}")
    if message:
        print(f"  → {message}")
    
    test_results["tests"].append({
        "name": test_name,
        "status": status,
        "message": message
    })
    
    if skip:
        test_results["skipped"] += 1
    elif success:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1


def test_server_health():
    """Test if server is running"""
    print_header("SERVER HEALTH CHECK")
    
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            test_result("Server Health", True, f"Status: {data.get('status')}")
            return True
        else:
            test_result("Server Health", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Server Health", False, f"Server not reachable: {e}")
        return False


def test_ai_providers():
    """Test AI provider initialization"""
    print_header("AI PROVIDERS")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/chat/providers", timeout=10)
        if response.status_code == 200:
            data = response.json()
            providers = data.get("available_providers", [])
            
            test_result("Provider List", len(providers) > 0, f"Found {len(providers)} providers")
            
            for provider in providers[:5]:
                test_result(f"  {provider.capitalize()}", True, "Initialized")
            
            return True
        else:
            test_result("AI Providers", False, "Failed to get providers")
            return False
    except Exception as e:
        test_result("AI Providers", False, str(e))
        return False


def test_chat_endpoint():
    """Test basic chat functionality"""
    print_header("CHAT API")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/chat/conversation",
            json={
                "message": "Hello! Reply with just 'Hi' and nothing else.",
                "session_id": "test_session_all",
                "provider": "groq",
                "stream": False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            reply = data.get("response", "")
            test_result("Chat Conversation", True, f"Got response: {reply[:50]}...")
            return True
        else:
            test_result("Chat Conversation", False, f"HTTP {response.status_code}: {response.text[:100]}")
            return False
    except Exception as e:
        test_result("Chat Conversation", False, str(e))
        return False


def test_openclaw():
    """Test OpenClaw web scraping"""
    print_header("OPENCLAW WEB SCRAPING")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/openclaw/scrape",
            json={"url": "https://example.com"},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            content = data.get("content", "")
            test_result("OpenClaw Scraping", True, f"Scraped {len(content)} chars")
            return True
        else:
            test_result("OpenClaw Scraping", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("OpenClaw Scraping", False, str(e))
        return False


def test_security_status():
    """Test security module status"""
    print_header("SECURITY MODULE")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/status", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            test_result("Security Module", True, f"Status: {data.get('status', 'active')}")
            
            burp_status = data.get("burp_suite", {}).get("status", "unknown")
            test_result("  BurpSuite Connection", burp_status != "error", f"Status: {burp_status}")
            
            ai_status = data.get("ai_analyzer", "unknown")
            test_result("  AI Analyzer", ai_status != "error", f"Status: {ai_status}")
            
            return True
        else:
            test_result("Security Module", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Security Module", False, str(e))
        return False


def test_vulnerability_analysis():
    """Test AI-powered vulnerability analysis"""
    print_header("VULNERABILITY ANALYSIS")
    
    try:
        vuln_data = {
            "vulnerability_type": "SQL Injection",
            "severity": "High",
            "confidence": "Certain",
            "url": "https://testapp.example.com/api/users?id=1",
            "parameter": "id",
            "evidence": "MySQL syntax error detected in response"
        }
        
        response = requests.post(
            f"{API_URL}/api/v1/security/analyze/vulnerability",
            json={
                "vulnerability_data": vuln_data,
                "deep_analysis": True
            },
            timeout=45
        )
        
        if response.status_code == 200:
            data = response.json()
            test_result("Vulnerability Analysis", True, f"CVSS: {data.get('cvss_score')}")
            test_result("  CWE Mapping", data.get('cwe_id') is not None, f"CWE: {data.get('cwe_id')}")
            test_result("  OWASP Category", data.get('owasp_category') is not None, data.get('owasp_category', ''))
            test_result("  Exploitation Steps", len(data.get('exploitation_steps', [])) > 0, 
                       f"{len(data.get('exploitation_steps', []))} steps")
            return True
        else:
            test_result("Vulnerability Analysis", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Vulnerability Analysis", False, str(e))
        return False


def test_payload_generation():
    """Test AI payload generation"""
    print_header("PAYLOAD GENERATION")
    
    try:
        response = requests.get(
            f"{API_URL}/api/v1/security/payloads/SQL Injection",
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            payloads = data.get("payloads", [])
            test_result("Payload Generation", len(payloads) > 0, f"Generated {len(payloads)} payloads")
            
            if len(payloads) > 0:
                test_result("  Sample Payload", True, payloads[0][:50])
            
            return True
        else:
            test_result("Payload Generation", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Payload Generation", False, str(e))
        return False


def test_bug_bounty_target():
    """Test bug bounty target management"""
    print_header("BUG BOUNTY ENGINE")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/target",
            json={
                "domain": "testapp.example.com",
                "scope": ["https://testapp.example.com/*"],
                "out_of_scope": [],
                "program_type": "web"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            test_result("Add Target", True, f"Domain: {data.get('domain')}")
            return True
        else:
            test_result("Add Target", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Add Target", False, str(e))
        return False


def test_cost_tracking():
    """Test cost tracking"""
    print_header("COST TRACKING")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/chat/cost-stats", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            total_cost = data.get("total_cost_usd", 0)
            test_result("Cost Tracking", True, f"Total: ${total_cost:.4f}")
            test_result("  Request Count", data.get("total_requests", 0) > 0, 
                       f"{data.get('total_requests', 0)} requests")
            return True
        else:
            test_result("Cost Tracking", False, f"HTTP {response.status_code}")
            return False
    except Exception as e:
        test_result("Cost Tracking", False, str(e))
        return False


def print_summary():
    """Print test summary"""
    print_header("TEST SUMMARY", "=")
    
    total = test_results["passed"] + test_results["failed"] + test_results["skipped"]
    passed_pct = (test_results["passed"] / total * 100) if total > 0 else 0
    
    print(f"  Total Tests:    {total}")
    print(f"  ✓ Passed:       {test_results['passed']} ({passed_pct:.1f}%)")
    print(f"  ✗ Failed:       {test_results['failed']}")
    print(f"  ⊘ Skipped:      {test_results['skipped']}")
    print()
    
    if test_results["failed"] == 0:
        print("  🎉 ALL TESTS PASSED! Aether AI is fully operational!")
    elif test_results["passed"] > test_results["failed"]:
        print("  ⚠ MOST TESTS PASSED. Some features may need attention.")
    else:
        print("  ❌ MULTIPLE FAILURES. Please check configuration.")
    
    print("\n" + "=" * 70 + "\n")
    
    with open("test-results.json", 'w') as f:
        json.dump(test_results, f, indent=2)
    
    print("  Detailed results saved to: test-results.json\n")


def main():
    """Run all tests"""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + "  AETHER AI - COMPREHENSIVE TEST SUITE".center(68) + "║")
    print("║" + "  Testing All Features & Integrations".center(68) + "║")
    print("╚" + "=" * 68 + "╝")
    
    print(f"\n  Testing against: {API_URL}")
    print(f"  Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    if not test_server_health():
        print("\n❌ Server is not running! Please start the server first.")
        print("   Run: python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000\n")
        sys.exit(1)
    
    test_ai_providers()
    test_chat_endpoint()
    test_openclaw()
    test_security_status()
    test_vulnerability_analysis()
    test_payload_generation()
    test_bug_bounty_target()
    test_cost_tracking()
    
    print_summary()
    
    if test_results["failed"] == 0:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Tests interrupted by user\n")
        print_summary()
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}\n")
        sys.exit(1)
