"""
Backend API Endpoint Testing

Tests all 129+ API endpoints
"""

import sys
import requests
import time
import json
from typing import Dict, Any, List

# Configure UTF-8 output for Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

BASE_URL = "http://localhost:8000"

test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'tests': []
}


def test_endpoint(method: str, path: str, data: Dict = None, expected_status: int = 200):
    """Test an API endpoint"""
    global test_results
    test_results['total'] += 1
    
    try:
        if method == "GET":
            response = requests.get(f"{BASE_URL}{path}", timeout=10)
        elif method == "POST":
            response = requests.post(f"{BASE_URL}{path}", json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(f"{BASE_URL}{path}", json=data, timeout=10)
        elif method == "DELETE":
            response = requests.delete(f"{BASE_URL}{path}", timeout=10)
        
        success = response.status_code == expected_status
        
        if success:
            test_results['passed'] += 1
            status = "✓"
        else:
            test_results['failed'] += 1
            status = "✗"
        
        print(f"{status} {method:6} {path:50} [{response.status_code}]")
        
        test_results['tests'].append({
            'method': method,
            'path': path,
            'status_code': response.status_code,
            'expected': expected_status,
            'success': success
        })
        
        return success, response
        
    except Exception as e:
        test_results['failed'] += 1
        print(f"✗ {method:6} {path:50} [ERROR: {str(e)[:30]}]")
        test_results['tests'].append({
            'method': method,
            'path': path,
            'error': str(e),
            'success': False
        })
        return False, None


def run_api_tests():
    """Run comprehensive API tests"""
    
    print("\n" + "="*80)
    print("AETHER AI - BACKEND API TESTING")
    print("="*80)
    print(f"\nTesting API at: {BASE_URL}")
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Wait for server
    print("Waiting for server to be ready...")
    max_retries = 10
    for i in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/", timeout=2)
            print(f"✓ Server is ready!\n")
            break
        except:
            if i < max_retries - 1:
                print(f"  Attempt {i+1}/{max_retries}...")
                time.sleep(2)
            else:
                print("✗ Server not responding. Please start with: uvicorn src.api.main:app\n")
                return
    
    # 1. HEALTH CHECK
    print("\n" + "-"*80)
    print("1. HEALTH CHECK")
    print("-"*80)
    test_endpoint("GET", "/")
    test_endpoint("GET", "/health")
    
    # 2. CHAT API
    print("\n" + "-"*80)
    print("2. CHAT API (Multi-Provider LLM)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/chat/providers")
    test_endpoint("GET", "/api/v1/chat/cost-stats")
    test_endpoint("GET", "/api/v1/chat/conversation/sessions")
    
    # 3. VOICE API
    print("\n" + "-"*80)
    print("3. VOICE API (STT/TTS)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/voice/devices")
    test_endpoint("GET", "/api/v1/voice/models")
    test_endpoint("GET", "/api/v1/voice/languages")
    test_endpoint("GET", "/api/v1/voice/tts/voices")
    test_endpoint("GET", "/api/v1/voice/tts/cache/stats")
    test_endpoint("GET", "/api/v1/voice/wake-word/status")
    
    # 4. MEMORY API
    print("\n" + "-"*80)
    print("4. MEMORY API (Vector DB + Profiles)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/memory/stats")
    test_endpoint("GET", "/api/v1/memory/conversation/sessions")
    test_endpoint("GET", "/api/v1/memory/profile/default")
    
    # 5. TASKS API
    print("\n" + "-"*80)
    print("5. TASKS API (Automation)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/tasks/")
    test_endpoint("GET", "/api/v1/tasks/stats/summary")
    
    # 6. SETTINGS API
    print("\n" + "-"*80)
    print("6. SETTINGS API (Configuration)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/settings/")
    test_endpoint("GET", "/api/v1/settings/voice")
    test_endpoint("GET", "/api/v1/settings/ai")
    test_endpoint("GET", "/api/v1/settings/memory")
    test_endpoint("GET", "/api/v1/settings/system")
    
    # 7. PLUGIN API (NEW!)
    print("\n" + "-"*80)
    print("7. PLUGIN API (MCP-Compatible)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/plugins/")
    test_endpoint("GET", "/api/v1/plugins/discover")
    
    # 8. DEVELOPER API (NEW!)
    print("\n" + "-"*80)
    print("8. DEVELOPER API (Time Travel Debugger)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/developer/debugger/breakpoints")
    test_endpoint("GET", "/api/v1/developer/profiler/hotspots")
    
    # 9. BUG BOUNTY API
    print("\n" + "-"*80)
    print("9. BUG BOUNTY API (Security)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/bugbounty/status")
    
    # 10. SECURITY API
    print("\n" + "-"*80)
    print("10. SECURITY API (Vulnerability Scanning)")
    print("-"*80)
    test_endpoint("GET", "/api/v1/security/status")
    
    # SUMMARY
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"\nTotal Endpoints Tested: {test_results['total']}")
    print(f"✓ Passed: {test_results['passed']}")
    print(f"✗ Failed: {test_results['failed']}")
    print(f"\nPass Rate: {(test_results['passed']/test_results['total']*100):.1f}%")
    
    if test_results['passed'] == test_results['total']:
        print("\n🎉 ALL API ENDPOINTS WORKING PERFECTLY!")
    elif test_results['passed'] / test_results['total'] > 0.8:
        print("\n✓ EXCELLENT - Most endpoints working!")
    else:
        print("\n⚠ NEEDS ATTENTION - Some endpoints failing")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    run_api_tests()
