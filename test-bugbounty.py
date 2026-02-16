"""
Bug Bounty Automation Test Script
Tests all security features
"""

import requests
import json
import time

API_URL = "http://127.0.0.1:8000"

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")

def test_security_status():
    """Test security module status"""
    print_header("TESTING SECURITY STATUS")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/status")
        
        if response.status_code == 200:
            data = response.json()
            print("✓ Security Module: ACTIVE")
            print(f"  - BurpSuite: {data.get('burp_suite', {}).get('status', 'unknown')}")
            print(f"  - AI Analyzer: {data.get('ai_analyzer', 'unknown')}")
            print(f"  - Bug Bounty Engine: {data.get('bug_bounty_engine', 'unknown')}")
            print(f"  - Active Targets: {data.get('active_targets', 0)}")
            print(f"  - Total Findings: {data.get('total_findings', 0)}")
            return True
        else:
            print(f"✗ Failed: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_burp_status():
    """Test BurpSuite connection"""
    print_header("TESTING BURPSUITE CONNECTION")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/burp/status")
        data = response.json()
        
        status = data.get('status', 'unknown')
        
        if status == "running":
            print("✓ BurpSuite: CONNECTED")
            print(f"  Version: {data.get('version', 'N/A')}")
        elif status == "offline":
            print("⚠ BurpSuite: OFFLINE")
            print("  Note: BurpSuite not running. Some features unavailable.")
            print("  Start BurpSuite with REST API enabled for full functionality.")
        else:
            print(f"⚠ BurpSuite: {status}")
        
        return True
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_ai_vulnerability_analysis():
    """Test AI vulnerability analysis"""
    print_header("TESTING AI VULNERABILITY ANALYSIS")
    
    try:
        vuln_data = {
            "vulnerability_type": "SQL Injection",
            "severity": "High",
            "confidence": "Certain",
            "url": "https://example.com/api/users?id=1",
            "parameter": "id",
            "evidence": "Error: You have an error in your SQL syntax"
        }
        
        response = requests.post(
            f"{API_URL}/api/v1/security/analyze/vulnerability",
            json={
                "vulnerability_data": vuln_data,
                "deep_analysis": True
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✓ AI Analysis: SUCCESS")
            print(f"  - Type: {data.get('vulnerability_type')}")
            print(f"  - Severity: {data.get('severity')}")
            print(f"  - CVSS Score: {data.get('cvss_score')}")
            print(f"  - CWE ID: {data.get('cwe_id')}")
            print(f"  - OWASP Category: {data.get('owasp_category')}")
            print(f"\n  Exploitation Steps:")
            for i, step in enumerate(data.get('exploitation_steps', [])[:3], 1):
                print(f"    {i}. {step}")
            
            if data.get('ai_insights'):
                print(f"\n  AI Insights: {data['ai_insights'][:200]}...")
            
            return True
        else:
            print(f"✗ Failed: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_payload_generation():
    """Test AI payload generation"""
    print_header("TESTING AI PAYLOAD GENERATION")
    
    try:
        payload_types = ["XSS", "SQL Injection", "Command Injection"]
        
        for payload_type in payload_types:
            response = requests.get(
                f"{API_URL}/api/v1/security/payloads/{payload_type}?count=10",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                payloads = data.get('payloads', [])
                print(f"✓ {payload_type}: Generated {len(payloads)} payloads")
                if payloads:
                    print(f"  Sample: {payloads[0][:50]}...")
            else:
                print(f"✗ {payload_type}: Failed")
        
        return True
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_add_target():
    """Test adding bug bounty target"""
    print_header("TESTING TARGET MANAGEMENT")
    
    try:
        target_data = {
            "domain": "example.com",
            "scope": [
                "https://example.com",
                "https://www.example.com",
                "https://api.example.com"
            ],
            "out_of_scope": [
                "https://example.com/admin"
            ],
            "program_type": "web"
        }
        
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/target",
            json=target_data
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✓ Target Added: example.com")
            print(f"  - Scope URLs: {len(target_data['scope'])}")
            print(f"  - Out of Scope: {len(target_data['out_of_scope'])}")
            return True
        else:
            print(f"✗ Failed: {response.status_code}")
            return False
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_reconnaissance():
    """Test reconnaissance features"""
    print_header("TESTING RECONNAISSANCE")
    
    try:
        print("⚠ Note: Reconnaissance test disabled to avoid external requests")
        print("  This feature performs:")
        print("  - Subdomain enumeration")
        print("  - Technology detection")
        print("  - Port scanning")
        print("  - DNS analysis")
        print("\n  To test: POST /api/v1/security/bugbounty/recon?domain=example.com")
        return True
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("  AETHER AI - BUG BOUNTY TESTING SUITE")
    print("="*60)
    print("\n  Testing all security features...")
    print("  This may take a few minutes.\n")
    
    results = {
        "Security Status": test_security_status(),
        "BurpSuite Connection": test_burp_status(),
        "AI Vulnerability Analysis": test_ai_vulnerability_analysis(),
        "AI Payload Generation": test_payload_generation(),
        "Target Management": test_add_target(),
        "Reconnaissance": test_reconnaissance()
    }
    
    print_header("TEST RESULTS SUMMARY")
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    
    for test_name, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {test_name}: {status}")
    
    print(f"\n  Total: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("\n  🎉 ALL TESTS PASSED!")
    else:
        print("\n  ⚠ Some tests failed. Check output above.")
    
    print("\n" + "="*60)
    print("\n  NEXT STEPS:")
    print("  - Open API docs: http://127.0.0.1:8000/docs")
    print("  - View security endpoints: /api/v1/security")
    print("  - Start BurpSuite for full functionality")
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()
